//go:build windows

package main

import (
	"fmt"
	"math/bits"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

// Two scans for statically obfuscated values that the linear-relation scan
// can't catch because they aren't of the form a*real + b, or because the real
// value never changes by a clean ratio:
//
//   txscan  — value stored under a fixed reversible transform (negation,
//             bitwise NOT, byteswap, fixed-point scaling). One pass searches
//             for ALL transforms of the value at once and records which hit.
//
//   xorscan — value XOR'd with a key kept nearby in the same struct
//             (stored = real ^ key). XOR is not linear over integers, so the
//             relation scan is blind to it. Scans pairs of nearby slots.
//
// Both build scanner.Results plus a side map, mirroring the relation scan.

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

func maskFor(sz int) uint64 {
	if sz >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << (uint(sz) * 8)) - 1
}

// bitsAt reads sz bytes at off as a little-endian zero-extended uint64.
func bitsAt(data []byte, off, sz int) uint64 {
	var v uint64
	for i := 0; i < sz; i++ {
		v |= uint64(data[off+i]) << (8 * uint(i))
	}
	return v
}

func bitsToBytes(v uint64, sz int) []byte {
	b := make([]byte, sz)
	for i := 0; i < sz; i++ {
		b[i] = byte(v >> (8 * uint(i)))
	}
	return b
}

func encodeBits(dt DataType, real float64, sz int) uint64 {
	return bitsAt(encodeNumeric(dt, real), 0, sz) & maskFor(sz)
}

func decodeBits(dt DataType, v uint64, sz int) float64 {
	return toFloat64(dt, bitsToBytes(v, sz))
}

func bswapBits(v uint64, sz int) uint64 {
	return bits.ReverseBytes64(v) >> (8 * uint(8-sz))
}

// enumChunks builds the same 4MB chunk list FirstScan uses (writable-only by
// default, skipping regions > 128MB in that mode).
func enumChunks(handle windows.Handle, writable bool) []scanChunk {
	regions := EnumMemoryRegions(handle, writable)
	const chunkSize = 4 * 1024 * 1024
	const maxRegionSz = 128 * 1024 * 1024
	var chunks []scanChunk
	for _, r := range regions {
		if writable && r.RegionSize > maxRegionSz {
			continue
		}
		for off := uintptr(0); off < r.RegionSize; off += uintptr(chunkSize) {
			sz := r.RegionSize - off
			if sz > uintptr(chunkSize) {
				sz = uintptr(chunkSize)
			}
			chunks = append(chunks, scanChunk{r.BaseAddress + off, int(sz)})
		}
	}
	return chunks
}

// ---------------------------------------------------------------------------
// transform table
// ---------------------------------------------------------------------------

type xform struct {
	name    string
	intOnly bool
	// fwd: real value -> stored bits (masked). ok=false if N/A for this type.
	fwd func(real float64, dt DataType, sz int) (uint64, bool)
	// inv: stored bits -> real value.
	inv func(stored uint64, dt DataType, sz int) float64
}

var txScales = []float64{2, 4, 8, 10, 16, 100, 256, 1000}

func buildXforms() []xform {
	xs := []xform{
		{"id", false,
			func(r float64, dt DataType, sz int) (uint64, bool) { return encodeBits(dt, r, sz), true },
			func(s uint64, dt DataType, sz int) float64 { return decodeBits(dt, s, sz) }},
		{"neg", false,
			func(r float64, dt DataType, sz int) (uint64, bool) { return encodeBits(dt, -r, sz), true },
			func(s uint64, dt DataType, sz int) float64 { return -decodeBits(dt, s, sz) }},
		{"not", true,
			func(r float64, dt DataType, sz int) (uint64, bool) {
				return (^encodeBits(dt, r, sz)) & maskFor(sz), true
			},
			func(s uint64, dt DataType, sz int) float64 { return decodeBits(dt, (^s)&maskFor(sz), sz) }},
		{"bswap", true,
			func(r float64, dt DataType, sz int) (uint64, bool) { return bswapBits(encodeBits(dt, r, sz), sz), true },
			func(s uint64, dt DataType, sz int) float64 { return decodeBits(dt, bswapBits(s, sz), sz) }},
	}
	for _, c := range txScales {
		c := c
		xs = append(xs, xform{
			name:    "x" + strconv.FormatFloat(c, 'f', -1, 64),
			intOnly: false,
			fwd:     func(r float64, dt DataType, sz int) (uint64, bool) { return encodeBits(dt, r*c, sz), true },
			inv:     func(s uint64, dt DataType, sz int) float64 { return decodeBits(dt, s, sz) / c },
		})
	}
	return xs
}

var xforms = buildXforms()

func isIntType(dt DataType) bool {
	return dt != TypeFloat32 && dt != TypeFloat64 && dt != TypeString && dt != TypeBytes
}

// ---------------------------------------------------------------------------
// transform scan
// ---------------------------------------------------------------------------

type txHit struct {
	res  ScanResult
	idxs []int
}

func (ms *MemoryScanner) transformScan(dt DataType, real float64, writable bool) int {
	defer debug.FreeOSMemory()
	sz := dataTypeSize(dt)
	mask := maskFor(sz)

	// Build needle -> transform indices. Dedup identical encodings (e.g. id and
	// a scale both yield 0 when real == 0) so one slot can list every transform.
	needle := make(map[uint64][]int)
	for i, x := range xforms {
		if x.intOnly && !isIntType(dt) {
			continue
		}
		v, ok := x.fwd(real, dt, sz)
		if !ok {
			continue
		}
		needle[v&mask] = append(needle[v&mask], i)
	}
	if len(needle) == 0 {
		fmt.Println("No applicable transforms for this type")
		return 0
	}

	chunks := enumChunks(ms.handle, writable)
	total := len(chunks)
	fmt.Printf("  scanning %d chunks for %d transform pattern(s)...\n", total, len(needle))

	jobs := make(chan scanChunk, total)
	for _, c := range chunks {
		jobs <- c
	}
	close(jobs)

	numCPU := runtime.NumCPU()
	hitCh := make(chan []txHit, numCPU*2)
	var done, found int64
	doneCh := make(chan struct{})
	go txProgress(doneCh, &done, &found, total)

	var wg sync.WaitGroup
	for w := 0; w < numCPU; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				data, err := ReadMemory(ms.handle, c.addr, c.size)
				atomic.AddInt64(&done, 1)
				if err != nil || len(data) < sz {
					continue
				}
				startOff := 0
				if sz > 1 {
					if rem := int(c.addr) % sz; rem != 0 {
						startOff = sz - rem
					}
				}
				var local []txHit
				for i := startOff; i <= len(data)-sz; i += sz {
					v := bitsAt(data, i, sz) & mask
					if idxs, ok := needle[v]; ok {
						local = append(local, txHit{
							res:  ScanResult{Address: c.addr + uintptr(i), Value: bitsToBytes(v, sz)},
							idxs: idxs,
						})
					}
				}
				if len(local) > 0 {
					atomic.AddInt64(&found, int64(len(local)))
					hitCh <- local
				}
			}
		}()
	}
	go func() { wg.Wait(); close(hitCh) }()

	var results []ScanResult
	txMap := make(map[uintptr][]int)
	capped := false
	for batch := range hitCh {
		for _, h := range batch {
			if len(results) >= diskResThreshold {
				capped = true
				continue
			}
			results = append(results, h.res)
			txMap[h.res.Address] = h.idxs
		}
	}
	close(doneCh)
	fmt.Println()
	if capped {
		fmt.Printf("  capped at %d hits; value may be too small/common. Pick a more distinctive value.\n", diskResThreshold)
	}
	ms.Results = results
	ms.txMap = txMap
	Log.Info("transformScan: %d hits", len(results))
	return len(results)
}

func txProgress(doneCh chan struct{}, done, found *int64, total int) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-doneCh:
			return
		case <-tick.C:
			d := atomic.LoadInt64(done)
			f := atomic.LoadInt64(found)
			fmt.Printf("\r  ... %d/%d chunks | %d hits   ", d, total, f)
		}
	}
}

// transformVerify keeps addresses where at least one recorded transform still
// encodes the new real value, narrowing each address's candidate set.
func (ms *MemoryScanner) transformVerify(dt DataType, real float64) int {
	sz := dataTypeSize(dt)
	mask := maskFor(sz)
	var kept []ScanResult
	newMap := make(map[uintptr][]int)
	for _, res := range ms.Results {
		idxs, ok := ms.txMap[res.Address]
		if !ok {
			continue
		}
		buf, err := ReadMemory(ms.handle, res.Address, sz)
		if err != nil || len(buf) < sz {
			continue
		}
		live := bitsAt(buf, 0, sz) & mask
		var still []int
		for _, idx := range idxs {
			want, okf := xforms[idx].fwd(real, dt, sz)
			if okf && (want&mask) == live {
				still = append(still, idx)
			}
		}
		if len(still) > 0 {
			nr := res
			nr.Value = buf
			kept = append(kept, nr)
			newMap[res.Address] = still
		}
	}
	ms.Results = kept
	ms.txMap = newMap
	Log.Info("transformVerify: %d hits remain", len(kept))
	return len(kept)
}

func txNames(idxs []int) string {
	out := ""
	for i, idx := range idxs {
		if i > 0 {
			out += ","
		}
		out += xforms[idx].name
	}
	return out
}

// ---------------------------------------------------------------------------
// xor pair scan
// ---------------------------------------------------------------------------

const xorWindow = 64 // bytes each side to search for the key

type xorHit struct {
	valAddr, keyAddr uintptr
	valBytes         []byte
}

func (ms *MemoryScanner) xorScan(dt DataType, real float64, writable bool) int {
	defer debug.FreeOSMemory()
	sz := dataTypeSize(dt)
	mask := maskFor(sz)
	target := encodeBits(dt, real, sz) & mask
	if target == 0 {
		fmt.Println("XOR scan needs a non-zero value (0 ^ key == key matches everything).")
		return 0
	}

	chunks := enumChunks(ms.handle, writable)
	total := len(chunks)
	fmt.Printf("  scanning %d chunks for XOR pairs (key within %d bytes)...\n", total, xorWindow)

	jobs := make(chan scanChunk, total)
	for _, c := range chunks {
		jobs <- c
	}
	close(jobs)

	numCPU := runtime.NumCPU()
	hitCh := make(chan []xorHit, numCPU*2)
	var done, found int64
	doneCh := make(chan struct{})
	go txProgress(doneCh, &done, &found, total)

	span := xorWindow / sz
	var wg sync.WaitGroup
	for w := 0; w < numCPU; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				data, err := ReadMemory(ms.handle, c.addr, c.size)
				atomic.AddInt64(&done, 1)
				if err != nil || len(data) < sz {
					continue
				}
				startOff := 0
				if sz > 1 {
					if rem := int(c.addr) % sz; rem != 0 {
						startOff = sz - rem
					}
				}
				var local []xorHit
				for i := startOff; i <= len(data)-sz; i += sz {
					vi := bitsAt(data, i, sz) & mask
					for k := 1; k <= span; k++ {
						j := i + k*sz
						if j+sz > len(data) {
							break
						}
						vj := bitsAt(data, j, sz) & mask
						if (vi^vj)&mask == target {
							// Either slot could be the value; record both
							// orderings, refine disambiguates.
							local = append(local,
								xorHit{c.addr + uintptr(i), c.addr + uintptr(j), bitsToBytes(vi, sz)},
								xorHit{c.addr + uintptr(j), c.addr + uintptr(i), bitsToBytes(vj, sz)})
						}
					}
				}
				if len(local) > 0 {
					atomic.AddInt64(&found, int64(len(local)))
					hitCh <- local
				}
			}
		}()
	}
	go func() { wg.Wait(); close(hitCh) }()

	var results []ScanResult
	xorMap := make(map[uintptr]uintptr)
	capped := false
	for batch := range hitCh {
		for _, h := range batch {
			if len(results) >= diskResThreshold {
				capped = true
				continue
			}
			if _, seen := xorMap[h.valAddr]; seen {
				continue // one key per value addr is enough
			}
			results = append(results, ScanResult{Address: h.valAddr, Value: h.valBytes})
			xorMap[h.valAddr] = h.keyAddr
		}
	}
	close(doneCh)
	fmt.Println()
	if capped {
		fmt.Printf("  capped at %d pairs; value too common. Pick a more distinctive value.\n", diskResThreshold)
	}
	ms.Results = results
	ms.xorMap = xorMap
	Log.Info("xorScan: %d pairs", len(results))
	return len(results)
}

// xorVerify keeps pairs where val ^ key still equals the new real value.
func (ms *MemoryScanner) xorVerify(dt DataType, real float64) int {
	sz := dataTypeSize(dt)
	mask := maskFor(sz)
	target := encodeBits(dt, real, sz) & mask
	var kept []ScanResult
	newMap := make(map[uintptr]uintptr)
	for _, res := range ms.Results {
		keyAddr, ok := ms.xorMap[res.Address]
		if !ok {
			continue
		}
		vb, e1 := ReadMemory(ms.handle, res.Address, sz)
		kb, e2 := ReadMemory(ms.handle, keyAddr, sz)
		if e1 != nil || e2 != nil || len(vb) < sz || len(kb) < sz {
			continue
		}
		if (bitsAt(vb, 0, sz)^bitsAt(kb, 0, sz))&mask == target {
			nr := res
			nr.Value = vb
			kept = append(kept, nr)
			newMap[res.Address] = keyAddr
		}
	}
	ms.Results = kept
	ms.xorMap = newMap
	Log.Info("xorVerify: %d pairs remain", len(kept))
	return len(kept)
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

func parseRealArg(s string) (float64, bool) {
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil
}

func cmdTxScan(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if len(args) == 0 {
		fmt.Println("Usage: txscan <value> [all]   (searches negation, NOT, byteswap, x2..x1000 of value)")
		return
	}
	real, ok := parseRealArg(args[0])
	if !ok {
		fmt.Println("Invalid value:", args[0])
		return
	}
	writable := !(len(args) > 1 && args[1] == "all")
	scanner.resetForSpecialScan()
	setQuickEdit(false)
	defer setQuickEdit(true)
	start := time.Now()
	n := scanner.transformScan(currentDT, real, writable)
	fmt.Printf("%d transform hit(s) in %v\n", n, time.Since(start))
	if n > 0 {
		cmdTxList([]string{"10"})
		fmt.Println("Change the value in game, then refine: txnext <newValue>")
	}
}

func cmdTxNext(args []string) {
	if scanner == nil || len(scanner.txMap) == 0 {
		fmt.Println("No transform scan active. Run 'txscan <value>' first.")
		return
	}
	if len(args) == 0 {
		fmt.Println("Usage: txnext <currentValue>")
		return
	}
	real, ok := parseRealArg(args[0])
	if !ok {
		fmt.Println("Invalid value:", args[0])
		return
	}
	n := scanner.transformVerify(currentDT, real)
	fmt.Printf("%d hit(s) still consistent\n", n)
	cmdTxList([]string{"10"})
}

func cmdTxList(args []string) {
	if scanner == nil || len(scanner.txMap) == 0 {
		fmt.Println("No transform hits. Run 'txscan <value>' first.")
		return
	}
	n := 20
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}
	sz := dataTypeSize(currentDT)
	fmt.Printf("%-5s  %-20s  %-16s  %-18s  %s\n", "#", "Address", "Stored", "Transform(s)", "Decoded")
	fmt.Println("-------------------------------------------------------------------------------")
	shown := 0
	for i, res := range scanner.Results {
		if shown >= n {
			break
		}
		idxs, ok := scanner.txMap[res.Address]
		if !ok {
			continue
		}
		stored := bitsAt(res.Value, 0, sz) & maskFor(sz)
		dec := xforms[idxs[0]].inv(stored, currentDT, sz)
		fmt.Printf("%-5d  0x%-18X  %-16s  %-18s  %s\n", i+1, res.Address,
			relFmt(decodeBits(currentDT, stored, sz)), txNames(idxs), relFmt(dec))
		shown++
	}
	fmt.Printf("Shown %d of %d transform hit(s)\n", shown, len(scanner.txMap))
}

func cmdTxWrite(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if scanner == nil || len(scanner.txMap) == 0 {
		fmt.Println("No transform hits. Run 'txscan <value>' first.")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: txwrite <idx|range|list> <realValue>")
		return
	}
	real, ok := parseRealArg(args[1])
	if !ok {
		fmt.Println("Invalid value:", args[1])
		return
	}
	sz := dataTypeSize(currentDT)
	okc, failed := 0, 0
	for _, idx := range parseIndexSpec(args[0]) {
		if idx < 1 || idx > len(scanner.Results) {
			failed++
			continue
		}
		res := scanner.Results[idx-1]
		idxs, has := scanner.txMap[res.Address]
		if !has {
			failed++
			continue
		}
		bitsv, okf := xforms[idxs[0]].fwd(real, currentDT, sz)
		if !okf {
			failed++
			continue
		}
		if err := WriteMemory(currentHandle, res.Address, bitsToBytes(bitsv&maskFor(sz), sz)); err != nil {
			fmt.Printf("  [%d] 0x%X write failed: %v\n", idx, res.Address, err)
			failed++
		} else {
			fmt.Printf("  [%d] 0x%X = %s (real %s via %s)\n", idx, res.Address,
				relFmt(decodeBits(currentDT, bitsv&maskFor(sz), sz)), relFmt(real), xforms[idxs[0]].name)
			okc++
		}
	}
	fmt.Printf("Written %d/%d\n", okc, okc+failed)
}

func cmdXorScan(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if !isIntType(currentDT) {
		fmt.Println("XOR scan needs an integer type (use 'type i32', 'type i64', ...)")
		return
	}
	if len(args) == 0 {
		fmt.Println("Usage: xorscan <value> [all]   (finds stored = value ^ key, key within 64 bytes)")
		return
	}
	real, ok := parseRealArg(args[0])
	if !ok {
		fmt.Println("Invalid value:", args[0])
		return
	}
	writable := !(len(args) > 1 && args[1] == "all")
	scanner.resetForSpecialScan()
	setQuickEdit(false)
	defer setQuickEdit(true)
	start := time.Now()
	n := scanner.xorScan(currentDT, real, writable)
	fmt.Printf("%d XOR pair(s) in %v\n", n, time.Since(start))
	if n > 0 {
		cmdXorList([]string{"10"})
		fmt.Println("Change the value in game, then refine: xornext <newValue>")
	}
}

func cmdXorNext(args []string) {
	if scanner == nil || len(scanner.xorMap) == 0 {
		fmt.Println("No XOR scan active. Run 'xorscan <value>' first.")
		return
	}
	if len(args) == 0 {
		fmt.Println("Usage: xornext <currentValue>")
		return
	}
	real, ok := parseRealArg(args[0])
	if !ok {
		fmt.Println("Invalid value:", args[0])
		return
	}
	n := scanner.xorVerify(currentDT, real)
	fmt.Printf("%d pair(s) still consistent\n", n)
	cmdXorList([]string{"10"})
}

func cmdXorList(args []string) {
	if scanner == nil || len(scanner.xorMap) == 0 {
		fmt.Println("No XOR pairs. Run 'xorscan <value>' first.")
		return
	}
	n := 20
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}
	sz := dataTypeSize(currentDT)
	mask := maskFor(sz)
	fmt.Printf("%-5s  %-20s  %-20s  %-14s  %s\n", "#", "ValueAddr", "KeyAddr", "Stored", "Decoded")
	fmt.Println("-------------------------------------------------------------------------------")
	shown := 0
	for i, res := range scanner.Results {
		if shown >= n {
			break
		}
		keyAddr, ok := scanner.xorMap[res.Address]
		if !ok {
			continue
		}
		stored := bitsAt(res.Value, 0, sz) & mask
		kb, err := ReadMemory(currentHandle, keyAddr, sz)
		dec := "?"
		if err == nil && len(kb) >= sz {
			dec = relFmt(decodeBits(currentDT, (stored^bitsAt(kb, 0, sz))&mask, sz))
		}
		fmt.Printf("%-5d  0x%-18X  0x%-18X  %-14s  %s\n", i+1, res.Address, keyAddr,
			relFmt(decodeBits(currentDT, stored, sz)), dec)
		shown++
	}
	fmt.Printf("Shown %d of %d XOR pair(s)\n", shown, len(scanner.xorMap))
}

func cmdXorWrite(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if scanner == nil || len(scanner.xorMap) == 0 {
		fmt.Println("No XOR pairs. Run 'xorscan <value>' first.")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: xorwrite <idx|range|list> <realValue>")
		return
	}
	real, ok := parseRealArg(args[1])
	if !ok {
		fmt.Println("Invalid value:", args[1])
		return
	}
	sz := dataTypeSize(currentDT)
	mask := maskFor(sz)
	target := encodeBits(currentDT, real, sz) & mask
	okc, failed := 0, 0
	for _, idx := range parseIndexSpec(args[0]) {
		if idx < 1 || idx > len(scanner.Results) {
			failed++
			continue
		}
		res := scanner.Results[idx-1]
		keyAddr, has := scanner.xorMap[res.Address]
		if !has {
			failed++
			continue
		}
		kb, err := ReadMemory(currentHandle, keyAddr, sz)
		if err != nil || len(kb) < sz {
			failed++
			continue
		}
		stored := (target ^ (bitsAt(kb, 0, sz) & mask)) & mask
		if err := WriteMemory(currentHandle, res.Address, bitsToBytes(stored, sz)); err != nil {
			fmt.Printf("  [%d] 0x%X write failed: %v\n", idx, res.Address, err)
			failed++
		} else {
			fmt.Printf("  [%d] 0x%X = %s (real %s ^ key@0x%X)\n", idx, res.Address,
				relFmt(decodeBits(currentDT, stored, sz)), relFmt(real), keyAddr)
			okc++
		}
	}
	fmt.Printf("Written %d/%d\n", okc, okc+failed)
}
