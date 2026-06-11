//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Linear-relation scan: finds obfuscated values stored as stored = a*real + b
// (scaled, offset, negated encodings) without knowing the formula.
//
// Workflow:
//   scan unknown            (real value is r1 at snapshot time)
//   ... change the value in game to r2 ...
//   next rel r1 r2          establish: keep addrs whose delta fits a plausible
//                           linear relation; per-address (a, b) is recorded
//   ... change the value to r3 ...
//   next rel r3             refine: keep addrs still consistent with their (a, b)
//   rel                     list survivors with decoded real values
//   relwrite 1 999          write real value 999 through relation #1
//
// Establish also works on an existing result set, RAM or disk-backed
// (e.g. after 'next changed').
// With only two samples any changed address fits SOME line, so establish
// additionally requires the slope a to look like a real encoding multiplier
// (integer or 1/integer). Each refine pass then kills random survivors fast.

type relParams struct {
	A, B float64
}

// relNice reports whether slope a looks like a plausible encoding multiplier:
// an integer (x2, x8, x100, negated...) or the inverse of one (x0.5, x0.25...).
func relNice(a float64) bool {
	if math.IsNaN(a) || math.IsInf(a, 0) || a == 0 {
		return false
	}
	abs := math.Abs(a)
	if abs < 1e-4 || abs > 1e6 {
		return false
	}
	if r := math.Round(a); r != 0 && math.Abs(a-r) <= 1e-3*math.Max(1, abs) {
		return true
	}
	inv := 1 / a
	if ri := math.Round(inv); ri != 0 && math.Abs(inv-ri) <= 1e-3*math.Max(1, math.Abs(inv)) {
		return true
	}
	return false
}

func relTolerance(dt DataType, expected float64) float64 {
	if dt == TypeFloat32 || dt == TypeFloat64 {
		return math.Max(0.01, 0.001*math.Abs(expected))
	}
	return 0.5
}

func relBadFloat(dt DataType, v float64) bool {
	return (dt == TypeFloat32 || dt == TypeFloat64) && (math.IsNaN(v) || math.IsInf(v, 0))
}

// encodeNumeric converts a float into the raw bytes of dt (rounding integers).
func encodeNumeric(dt DataType, f float64) []byte {
	buf := make([]byte, dataTypeSize(dt))
	switch dt {
	case TypeInt8, TypeUInt8:
		buf[0] = byte(int64(math.Round(f)))
	case TypeInt16, TypeUInt16:
		binary.LittleEndian.PutUint16(buf, uint16(int64(math.Round(f))))
	case TypeInt32, TypeUInt32:
		binary.LittleEndian.PutUint32(buf, uint32(int64(math.Round(f))))
	case TypeInt64, TypeUInt64:
		binary.LittleEndian.PutUint64(buf, uint64(int64(math.Round(f))))
	case TypeFloat32:
		binary.LittleEndian.PutUint32(buf, math.Float32bits(float32(f)))
	case TypeFloat64:
		binary.LittleEndian.PutUint64(buf, math.Float64bits(f))
	}
	return buf
}

// relEstablishFromSnapshot compares the unknown-scan snapshot (real value r1)
// against live memory (real value r2), keeping addresses with a plausible
// linear relation. Consumes the snapshot like nextScanFromSnapshot.
func (ms *MemoryScanner) relEstablishFromSnapshot(dt DataType, r1, r2 float64) int {
	snap := ms.snapshot
	ms.snapshot = nil
	defer snap.close()

	sz := dataTypeSize(dt)
	dr := r2 - r1
	totalChunks := len(snap.chunks)
	fmt.Printf("  comparing snapshot vs live memory (%d chunks)...\n", totalChunks)

	var doneChunks, foundSoFar int64
	doneCh := make(chan struct{})
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-tick.C:
				d := atomic.LoadInt64(&doneChunks)
				f := atomic.LoadInt64(&foundSoFar)
				pct := float64(d) / float64(totalChunks) * 100
				fmt.Printf("\r  ... %d/%d chunks (%.1f%%) | relations=%d   ", d, totalChunks, pct, f)
			}
		}
	}()

	type relHit struct {
		res ScanResult
		p   relParams
	}
	numCPU := runtime.NumCPU()
	resultCh := make(chan []relHit, numCPU*2)
	jobs := make(chan snapshotChunk, totalChunks)
	for _, c := range snap.chunks {
		jobs <- c
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				oldData, err := snap.readChunk(c)
				if err != nil {
					atomic.AddInt64(&doneChunks, 1)
					continue
				}
				newData, err := ReadMemory(ms.handle, c.addr, c.size)
				if err != nil || len(newData) < sz {
					atomic.AddInt64(&doneChunks, 1)
					continue
				}
				limit := len(oldData)
				if len(newData) < limit {
					limit = len(newData)
				}
				startOff := 0
				if sz > 1 {
					if rem := int(c.addr) % sz; rem != 0 {
						startOff = sz - rem
					}
				}
				var local []relHit
				for i := startOff; i <= limit-sz; i += sz {
					v1 := toFloat64(dt, oldData[i:i+sz])
					v2 := toFloat64(dt, newData[i:i+sz])
					if v1 == v2 || relBadFloat(dt, v1) || relBadFloat(dt, v2) {
						continue
					}
					a := (v2 - v1) / dr
					if !relNice(a) {
						continue
					}
					b := v1 - a*r1
					if math.Abs(b) > 1e12 {
						continue
					}
					cp := make([]byte, sz)
					copy(cp, newData[i:i+sz])
					local = append(local, relHit{
						res: ScanResult{Address: c.addr + uintptr(i), Value: cp},
						p:   relParams{a, b},
					})
				}
				atomic.AddInt64(&doneChunks, 1)
				if len(local) > 0 {
					atomic.AddInt64(&foundSoFar, int64(len(local)))
					resultCh <- local
				}
			}
		}()
	}
	go func() { wg.Wait(); close(resultCh) }()

	var results []ScanResult
	relMap := make(map[uintptr]relParams)
	capped := false
	for batch := range resultCh {
		for _, h := range batch {
			if len(results) >= diskResThreshold {
				capped = true
				continue
			}
			results = append(results, h.res)
			relMap[h.res.Address] = h.p
		}
	}
	close(doneCh)
	fmt.Println()
	if capped {
		fmt.Printf("  capped at %d relations; results are partial. Narrow with 'next changed' first.\n", diskResThreshold)
	}
	ms.Results = results
	ms.relMap = relMap
	Log.Info("relEstablishFromSnapshot: %d relations", len(results))
	return len(results)
}

// relEstablishFromResults establishes relations across the in-RAM result set,
// using each result's stored value as the r1-state and live memory as r2.
func (ms *MemoryScanner) relEstablishFromResults(dt DataType, r1, r2 float64) int {
	sz := dataTypeSize(dt)
	dr := r2 - r1
	var kept []ScanResult
	relMap := make(map[uintptr]relParams)
	for _, r := range ms.Results {
		if len(r.Value) < sz {
			continue
		}
		v1 := toFloat64(dt, r.Value)
		buf, err := ReadMemory(ms.handle, r.Address, sz)
		if err != nil || len(buf) < sz {
			continue
		}
		v2 := toFloat64(dt, buf)
		if v1 == v2 || relBadFloat(dt, v1) || relBadFloat(dt, v2) {
			continue
		}
		a := (v2 - v1) / dr
		if !relNice(a) {
			continue
		}
		b := v1 - a*r1
		if math.Abs(b) > 1e12 {
			continue
		}
		nr := r
		nr.Value = buf
		kept = append(kept, nr)
		relMap[r.Address] = relParams{a, b}
	}
	ms.Results = kept
	ms.relMap = relMap
	Log.Info("relEstablishFromResults: %d relations", len(kept))
	return len(kept)
}

// relEstablishFromDisk establishes relations across a disk-backed result set,
// streaming stored addresses/values in chunks and reading live memory in
// gap-grouped spans (same pattern as nextScanDisk). Consumes the disk set;
// survivors (capped at diskResThreshold) become the new in-RAM result set.
func (ms *MemoryScanner) relEstablishFromDisk(dt DataType, r1, r2 float64) int {
	old := ms.diskRes
	sz := dataTypeSize(dt)
	if old.valSize != sz {
		fmt.Printf("  stored results hold %d-byte values but current type is %d bytes; set 'type' back or rescan\n", old.valSize, sz)
		return 0
	}
	ms.diskRes = nil
	defer old.delete()

	dr := r2 - r1
	total := old.count

	const chunkBytes = 20 * 4096
	chunkAddrs := chunkBytes / 8
	if chunkAddrs < 1024 {
		chunkAddrs = 1024
	}
	const maxGap = 64 * 1024
	const maxSpan = 1 * 1024 * 1024

	var processed, found int64
	doneCh := make(chan struct{})
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-tick.C:
				p := atomic.LoadInt64(&processed)
				f := atomic.LoadInt64(&found)
				pct := float64(p) / float64(total) * 100
				fmt.Printf("\r  ... %d/%d (%.1f%%) | relations=%d   ", p, total, pct, f)
			}
		}
	}()

	addrChunk := make([]uintptr, chunkAddrs)
	oldVals := make([]byte, chunkAddrs*sz)
	var results []ScanResult
	relMap := make(map[uintptr]relParams)
	capped := false

	pos := 0
	for pos < old.count {
		n := old.readAddressChunk(pos, chunkAddrs, addrChunk)
		if n == 0 {
			break
		}
		old.readValueChunk(pos, n, oldVals)
		pos += n

		i := 0
		for i < n {
			j := i + 1
			for j < n {
				gap := addrChunk[j] - addrChunk[j-1]
				span := addrChunk[j] + uintptr(sz) - addrChunk[i]
				if gap > maxGap || span > maxSpan {
					break
				}
				j++
			}
			spanStart := addrChunk[i]
			spanEnd := addrChunk[j-1] + uintptr(sz)
			pageData, err := ReadMemory(ms.handle, spanStart, int(spanEnd-spanStart))
			if err != nil || len(pageData) < sz {
				i = j
				continue
			}
			for k := i; k < j; k++ {
				off := int(addrChunk[k] - spanStart)
				if off+sz > len(pageData) {
					continue
				}
				v1 := toFloat64(dt, oldVals[k*sz:k*sz+sz])
				v2 := toFloat64(dt, pageData[off:off+sz])
				if v1 == v2 || relBadFloat(dt, v1) || relBadFloat(dt, v2) {
					continue
				}
				a := (v2 - v1) / dr
				if !relNice(a) {
					continue
				}
				b := v1 - a*r1
				if math.Abs(b) > 1e12 {
					continue
				}
				if len(results) >= diskResThreshold {
					capped = true
					continue
				}
				cp := make([]byte, sz)
				copy(cp, pageData[off:off+sz])
				results = append(results, ScanResult{Address: addrChunk[k], Value: cp})
				relMap[addrChunk[k]] = relParams{a, b}
				atomic.AddInt64(&found, 1)
			}
			i = j
		}
		atomic.AddInt64(&processed, int64(n))
	}
	close(doneCh)
	fmt.Println()
	if capped {
		fmt.Printf("  capped at %d relations; results are partial. Narrow with 'next changed' first.\n", diskResThreshold)
	}
	ms.Results = results
	ms.relMap = relMap
	Log.Info("relEstablishFromDisk: %d relations from %d disk results", len(results), total)
	return len(results)
}

// relVerify keeps only results whose live value still matches their stored
// (a, b) relation at real value r.
func (ms *MemoryScanner) relVerify(dt DataType, r float64) int {
	sz := dataTypeSize(dt)
	var kept []ScanResult
	newMap := make(map[uintptr]relParams)
	for _, res := range ms.Results {
		p, ok := ms.relMap[res.Address]
		if !ok {
			continue
		}
		buf, err := ReadMemory(ms.handle, res.Address, sz)
		if err != nil || len(buf) < sz {
			continue
		}
		v := toFloat64(dt, buf)
		expected := p.A*r + p.B
		if math.Abs(v-expected) > relTolerance(dt, expected) {
			continue
		}
		nr := res
		nr.Value = buf
		kept = append(kept, nr)
		newMap[res.Address] = p
	}
	ms.Results = kept
	ms.relMap = newMap
	Log.Info("relVerify: %d relations remain", len(kept))
	return len(kept)
}

// cmdNextRel handles 'next rel <r1> <r2>' (establish) and 'next rel <r>' (refine).
func cmdNextRel(args []string) {
	if currentDT == TypeString || currentDT == TypeBytes {
		fmt.Println("Relation scan needs a numeric data type (use 'type f32', 'type i32', ...)")
		return
	}
	defer debug.FreeOSMemory()

	switch len(args) {
	case 2:
		r1, e1 := strconv.ParseFloat(args[0], 64)
		r2, e2 := strconv.ParseFloat(args[1], 64)
		if e1 != nil || e2 != nil || r1 == r2 {
			fmt.Println("Usage: next rel <realValueAtScanTime> <realValueNow>  (values must differ)")
			return
		}
		setQuickEdit(false)
		defer setQuickEdit(true)
		start := time.Now()
		var count int
		switch {
		case scanner.snapshot != nil:
			count = scanner.relEstablishFromSnapshot(currentDT, r1, r2)
		case scanner.diskRes != nil:
			fmt.Printf("Establishing linear relations across %d disk-backed results...\n", scanner.diskRes.count)
			count = scanner.relEstablishFromDisk(currentDT, r1, r2)
		case len(scanner.Results) > 0:
			fmt.Printf("Establishing linear relations across %d results...\n", len(scanner.Results))
			count = scanner.relEstablishFromResults(currentDT, r1, r2)
		default:
			fmt.Println("No scan data. Run 'scan unknown' (or a scan) first.")
			return
		}
		fmt.Printf("%d address(es) fit a plausible linear relation (%v)\n", count, time.Since(start))
		relPreview(5)
		if count > 0 {
			fmt.Println("Change the value in game, then refine with: next rel <newRealValue>")
		}
	case 1:
		if scanner == nil || len(scanner.relMap) == 0 {
			fmt.Println("No relation established. Run 'next rel <r1> <r2>' first.")
			return
		}
		r, err := strconv.ParseFloat(args[0], 64)
		if err != nil {
			fmt.Println("Usage: next rel <currentRealValue>")
			return
		}
		count := scanner.relVerify(currentDT, r)
		fmt.Printf("%d relation(s) still consistent\n", count)
		relPreview(5)
	default:
		fmt.Println("Usage: next rel <r1> <r2>   establish (r1 = real value at scan/last state, r2 = now)")
		fmt.Println("       next rel <r>        refine against established relations")
	}
}

func relPreview(n int) {
	if scanner == nil || len(scanner.relMap) == 0 {
		return
	}
	shown := 0
	for i, res := range scanner.Results {
		p, ok := scanner.relMap[res.Address]
		if !ok {
			continue
		}
		v := toFloat64(currentDT, res.Value)
		fmt.Printf("  [%d] 0x%X  stored=%g  a=%g b=%g  decoded=%g\n", i+1, res.Address, v, p.A, p.B, (v-p.B)/p.A)
		shown++
		if shown >= n {
			break
		}
	}
	if len(scanner.Results) > shown {
		fmt.Printf("  ... 'rel %d' to list more\n", len(scanner.Results))
	}
}

// cmdRelList shows surviving relations with decoded real values.
// Indices match the scan set, so iwrite/results add work on them.
func cmdRelList(args []string) {
	if scanner == nil || len(scanner.relMap) == 0 {
		fmt.Println("No relations. Run 'next rel <r1> <r2>' first.")
		return
	}
	n := 20
	if len(args) > 0 {
		if v, err := strconv.Atoi(args[0]); err == nil && v > 0 {
			n = v
		}
	}
	fmt.Printf("%-5s  %-20s  %-14s  %-10s  %-12s  %s\n", "#", "Address", "Stored", "a", "b", "Decoded")
	fmt.Println("---------------------------------------------------------------------------")
	shown := 0
	for i, res := range scanner.Results {
		if shown >= n {
			break
		}
		p, ok := scanner.relMap[res.Address]
		if !ok {
			continue
		}
		v := toFloat64(currentDT, res.Value)
		fmt.Printf("%-5d  0x%-18X  %-14g  %-10g  %-12g  %g\n", i+1, res.Address, v, p.A, p.B, (v-p.B)/p.A)
		shown++
	}
	fmt.Printf("Shown %d of %d relation(s)\n", shown, len(scanner.relMap))
}

// cmdRelWrite writes a REAL value through a relation: stored = a*real + b.
// relwrite <idx|range|list> <realValue>
func cmdRelWrite(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if scanner == nil || len(scanner.relMap) == 0 {
		fmt.Println("No relations. Run 'next rel <r1> <r2>' first.")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: relwrite <idx|range|list> <realValue>")
		return
	}
	real, err := strconv.ParseFloat(args[1], 64)
	if err != nil {
		fmt.Println("Invalid value:", args[1])
		return
	}
	ok, failed := 0, 0
	for _, idx := range parseIndexSpec(args[0]) {
		if idx < 1 || idx > len(scanner.Results) {
			fmt.Printf("  [%d] out of range (total %d)\n", idx, len(scanner.Results))
			failed++
			continue
		}
		res := scanner.Results[idx-1]
		p, has := scanner.relMap[res.Address]
		if !has {
			fmt.Printf("  [%d] 0x%X has no relation\n", idx, res.Address)
			failed++
			continue
		}
		encoded := p.A*real + p.B
		data := encodeNumeric(currentDT, encoded)
		if err := WriteMemory(currentHandle, res.Address, data); err != nil {
			fmt.Printf("  [%d] 0x%X write failed: %v\n", idx, res.Address, err)
			failed++
		} else {
			fmt.Printf("  [%d] 0x%X = %g (real %g via a=%g b=%g)\n", idx, res.Address, encoded, real, p.A, p.B)
			ok++
		}
	}
	fmt.Printf("Written %d/%d\n", ok, ok+failed)
}
