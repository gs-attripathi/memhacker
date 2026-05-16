//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// scanActive / scanCancelFlag — set by Ctrl+C handler in main to cancel FirstScan.
// Ctrl+C during scan: cancel + clear results. Ctrl+C outside scan: exit.
var scanActive     int32 // 1 when FirstScan is running
var scanCancelFlag int32 // set to 1 to cancel current scan

func encodeValue(dt DataType, s string) ([]byte, error) {
	buf := make([]byte, dataTypeSize(dt))
	switch dt {
	case TypeInt8:
		var v int8
		fmt.Sscanf(s, "%d", &v)
		buf[0] = byte(v)
	case TypeInt16:
		var v int16
		fmt.Sscanf(s, "%d", &v)
		binary.LittleEndian.PutUint16(buf, uint16(v))
	case TypeInt32:
		var v int32
		fmt.Sscanf(s, "%d", &v)
		binary.LittleEndian.PutUint32(buf, uint32(v))
	case TypeInt64:
		var v int64
		fmt.Sscanf(s, "%d", &v)
		binary.LittleEndian.PutUint64(buf, uint64(v))
	case TypeUInt8:
		var v uint8
		fmt.Sscanf(s, "%d", &v)
		buf[0] = v
	case TypeUInt16:
		var v uint16
		fmt.Sscanf(s, "%d", &v)
		binary.LittleEndian.PutUint16(buf, v)
	case TypeUInt32:
		var v uint32
		fmt.Sscanf(s, "%d", &v)
		binary.LittleEndian.PutUint32(buf, v)
	case TypeUInt64:
		var v uint64
		fmt.Sscanf(s, "%d", &v)
		binary.LittleEndian.PutUint64(buf, v)
	case TypeFloat32:
		var v float64
		fmt.Sscanf(s, "%f", &v)
		bits := math.Float32bits(float32(v))
		binary.LittleEndian.PutUint32(buf, bits)
	case TypeFloat64:
		var v float64
		fmt.Sscanf(s, "%f", &v)
		bits := math.Float64bits(v)
		binary.LittleEndian.PutUint64(buf, bits)
	case TypeString:
		return []byte(s), nil
	case TypeBytes:
		var out []byte
		for _, tok := range splitHex(s) {
			var b byte
			fmt.Sscanf(tok, "%x", &b)
			out = append(out, b)
		}
		return out, nil
	}
	return buf, nil
}

func decodeValue(dt DataType, buf []byte) string {
	if len(buf) < dataTypeSize(dt) {
		return "?"
	}
	switch dt {
	case TypeInt8:
		return fmt.Sprintf("%d", int8(buf[0]))
	case TypeInt16:
		return fmt.Sprintf("%d", int16(binary.LittleEndian.Uint16(buf)))
	case TypeInt32:
		return fmt.Sprintf("%d", int32(binary.LittleEndian.Uint32(buf)))
	case TypeInt64:
		return fmt.Sprintf("%d", int64(binary.LittleEndian.Uint64(buf)))
	case TypeUInt8:
		return fmt.Sprintf("%d", buf[0])
	case TypeUInt16:
		return fmt.Sprintf("%d", binary.LittleEndian.Uint16(buf))
	case TypeUInt32:
		return fmt.Sprintf("%d", binary.LittleEndian.Uint32(buf))
	case TypeUInt64:
		return fmt.Sprintf("%d", binary.LittleEndian.Uint64(buf))
	case TypeFloat32:
		v := math.Float32frombits(binary.LittleEndian.Uint32(buf))
		return fmt.Sprintf("%g", v)
	case TypeFloat64:
		v := math.Float64frombits(binary.LittleEndian.Uint64(buf))
		return fmt.Sprintf("%g", v)
	case TypeString:
		return string(buf)
	case TypeBytes:
		out := ""
		for i, b := range buf {
			if i > 0 {
				out += " "
			}
			out += fmt.Sprintf("%02X", b)
		}
		return out
	}
	return "?"
}

func toFloat64(dt DataType, buf []byte) float64 {
	switch dt {
	case TypeInt8:
		return float64(int8(buf[0]))
	case TypeInt16:
		return float64(int16(binary.LittleEndian.Uint16(buf)))
	case TypeInt32:
		return float64(int32(binary.LittleEndian.Uint32(buf)))
	case TypeInt64:
		return float64(int64(binary.LittleEndian.Uint64(buf)))
	case TypeUInt8:
		return float64(buf[0])
	case TypeUInt16:
		return float64(binary.LittleEndian.Uint16(buf))
	case TypeUInt32:
		return float64(binary.LittleEndian.Uint32(buf))
	case TypeUInt64:
		return float64(binary.LittleEndian.Uint64(buf))
	case TypeFloat32:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(buf)))
	case TypeFloat64:
		return math.Float64frombits(binary.LittleEndian.Uint64(buf))
	}
	return 0
}

func compareNumeric(dt DataType, a, b []byte) int {
	fa := toFloat64(dt, a)
	fb := toFloat64(dt, b)
	if fa < fb {
		return -1
	}
	if fa > fb {
		return 1
	}
	return 0
}

func numericDiff(dt DataType, a, b []byte) float64 {
	return toFloat64(dt, a) - toFloat64(dt, b)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func compareValues(dt DataType, old, newVal, target, target2 []byte, st ScanType, tolerance float64) bool {
	sz := dataTypeSize(dt)
	if dt == TypeString || dt == TypeBytes {
		sz = len(target)
	}
	if sz == 0 || len(newVal) < sz {
		return false
	}
	// Reject NaN/Inf for float scans — games never store these as real values
	if dt == TypeFloat32 || dt == TypeFloat64 {
		v := toFloat64(dt, newVal)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	switch st {
	case ScanExact:
		if dt == TypeFloat32 || dt == TypeFloat64 {
			tol := tolerance
			if tol == 0 { tol = 1.0 }
			return math.Abs(toFloat64(dt, newVal)-toFloat64(dt, target)) <= tol
		}
		return bytesEqual(newVal[:sz], target[:sz])
	case ScanNotEqual:
		return !bytesEqual(newVal[:sz], target[:sz])
	case ScanUnknown:
		return true
	case ScanChanged:
		return old != nil && !bytesEqual(old[:sz], newVal[:sz])
	case ScanUnchanged:
		return old == nil || bytesEqual(old[:sz], newVal[:sz])
	case ScanBiggerThan:
		return compareNumeric(dt, newVal, target) > 0
	case ScanSmallerThan:
		return compareNumeric(dt, newVal, target) < 0
	case ScanBiggerThanOrEqual:
		return compareNumeric(dt, newVal, target) >= 0
	case ScanSmallerThanOrEqual:
		return compareNumeric(dt, newVal, target) <= 0
	case ScanIncreased:
		return old != nil && compareNumeric(dt, newVal, old) > 0
	case ScanDecreased:
		return old != nil && compareNumeric(dt, newVal, old) < 0
	case ScanIncreasedBy:
		if old == nil {
			return false
		}
		diff := numericDiff(dt, newVal, old)
		expected := toFloat64(dt, target)
		return math.Abs(diff-expected) <= tolerance
	case ScanDecreasedBy:
		if old == nil {
			return false
		}
		diff := numericDiff(dt, old, newVal)
		expected := toFloat64(dt, target)
		return math.Abs(diff-expected) <= tolerance
	case ScanBetween:
		if len(target2) < sz {
			return false
		}
		return compareNumeric(dt, newVal, target) >= 0 && compareNumeric(dt, newVal, target2) <= 0
	}
	return false
}

func splitHex(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ' ' || c == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func pointerSize() int {
	return int(unsafe.Sizeof(uintptr(0)))
}

type MemoryScanner struct {
	handle   windows.Handle
	Results  []ScanResult    // in-memory results (< diskResThreshold)
	diskRes  *diskResultSet  // disk-backed results (>= diskResThreshold)
	snapshot *memSnapshot    // non-nil after ScanUnknown first scan
}

func NewMemoryScanner(handle windows.Handle) *MemoryScanner {
	return &MemoryScanner{handle: handle}
}

func (ms *MemoryScanner) clearSnapshot() {
	if ms.snapshot != nil {
		ms.snapshot.close()
		ms.snapshot = nil
	}
}

func (ms *MemoryScanner) clearDiskRes() {
	if ms.diskRes != nil {
		ms.diskRes.delete()
		ms.diskRes = nil
	}
}

func (ms *MemoryScanner) totalResults() int {
	if ms.diskRes != nil { return ms.diskRes.count }
	return len(ms.Results)
}

// getResult returns a result by 0-based index, from disk or RAM.
func (ms *MemoryScanner) getResult(i int) (uintptr, []byte) {
	if ms.diskRes != nil {
		addr, val := ms.diskRes.get(i)
		return addr, val
	}
	r := ms.Results[i]
	return r.Address, r.Value
}

// nearZeroFast holds pre-computed params for the integer-comparison fast path.
// For symmetric float ranges [-a, a], |v| <= a is equivalent to
// (bits & 0x7FFF...) <= float_bits(a) — no float conversion needed per value.
type nearZeroFast struct {
	enabled bool
	is32    bool
	abits32 uint32
	abits64 uint64
}

func buildNearZeroFast(params ScanParams) nearZeroFast {
	if params.DT != TypeFloat32 && params.DT != TypeFloat64 {
		return nearZeroFast{}
	}
	is32 := params.DT == TypeFloat32

	var lo, hi float64
	switch params.ST {
	case ScanExact:
		v := toFloat64(params.DT, params.Value)
		tol := params.Tolerance
		if tol == 0 { tol = 1.0 }
		lo, hi = v-tol, v+tol
	case ScanBetween:
		lo = toFloat64(params.DT, params.Value)
		hi = toFloat64(params.DT, params.Value2)
	default:
		return nearZeroFast{}
	}

	// Range must cross or touch zero
	if lo > 0 || hi < 0 {
		return nearZeroFast{}
	}
	aLo, aHi := math.Abs(lo), math.Abs(hi)
	aMax := math.Max(aLo, aHi)

	// Only valid for symmetric ranges (lo == -hi): |v| <= aMax is exact.
	// For asymmetric (e.g. between -2 0.5), fall back to general path.
	eps := aMax * 1e-6
	if math.Abs(lo+hi) > eps {
		return nearZeroFast{}
	}

	if is32 {
		return nearZeroFast{enabled: true, is32: true, abits32: math.Float32bits(float32(aMax))}
	}
	return nearZeroFast{enabled: true, abits64: math.Float64bits(aMax)}
}

type scanChunk struct {
	addr uintptr
	size int
}

func (ms *MemoryScanner) FirstScan(params ScanParams) int {
	Log.Info("FirstScan: type=%s scan=%d writable=%v", dataTypeName(params.DT), params.ST, params.Writable)
	atomic.StoreInt32(&scanActive, 1)
	atomic.StoreInt32(&scanCancelFlag, 0)
	defer func() {
		atomic.StoreInt32(&scanActive, 0)
		atomic.StoreInt32(&scanCancelFlag, 0)
	}()

	ms.clearSnapshot()

	// Unknown scan: snapshot entire memory to disk instead of storing per-address results.
	// CE does this via TScanFileWriter with async dual-buffer writes.
	// Avoids GBs of RAM for games with huge writable address spaces.
	if params.ST == ScanUnknown {
		return ms.firstScanUnknown(params)
	}

	regions := EnumMemoryRegions(ms.handle, params.Writable)
	Log.Debug("FirstScan: scanning %d memory regions", len(regions))

	// Split regions into 4MB chunks for parallel work.
	// Skip regions > 128MB when scanning writable-only: those are allocator pools /
	// streaming caches (mostly paged to disk). Game values are never in a single
	// contiguous allocation > 128MB. Use 'scan <type> all' to include them.
	const chunkSize   = 4 * 1024 * 1024
	const maxRegionSz = 128 * 1024 * 1024
	var chunks []scanChunk
	skipped := 0
	for _, r := range regions {
		if params.Writable && r.RegionSize > maxRegionSz {
			skipped++
			continue
		}
		rEnd := r.BaseAddress + r.RegionSize
		// Apply address range filter if set
		lo := r.BaseAddress
		hi := rEnd
		if params.RangeLo > 0 && params.RangeLo > lo { lo = params.RangeLo }
		if params.RangeHi > 0 && params.RangeHi < hi { hi = params.RangeHi }
		if lo >= hi { continue }

		for off := lo - r.BaseAddress; off < hi-r.BaseAddress; off += uintptr(chunkSize) {
			sz := hi - r.BaseAddress - off
			if sz > uintptr(chunkSize) { sz = uintptr(chunkSize) }
			chunks = append(chunks, scanChunk{r.BaseAddress + off, int(sz)})
		}
	}
	total := len(chunks)
	if skipped > 0 {
		fmt.Printf("  scanning %d regions (%d chunks, skipped %d large regions >128MB)...\n", len(regions)-skipped, total, skipped)
	} else {
		fmt.Printf("  scanning %d regions (%d chunks)...\n", len(regions), total)
	}

	nzf := buildNearZeroFast(params)

	jobs := make(chan scanChunk, total)
	for _, c := range chunks {
		jobs <- c
	}
	close(jobs)

	var doneCount int64
	numCPU := runtime.NumCPU()

	isFloat   := params.DT == TypeFloat32 || params.DT == TypeFloat64
	isNumeric := params.DT != TypeString && params.DT != TypeBytes

	sz := dataTypeSize(params.DT)
	if params.DT == TypeString || params.DT == TypeBytes {
		sz = len(params.Value)
	}

	// Pipeline: readers and scanners run concurrently.
	// Readers do ReadProcessMemory (kernel I/O, blocks per call).
	// Scanners process the data CPU-side.
	// While scanners work on chunk N, readers are already fetching chunk N+1.

	type readResult struct {
		addr uintptr
		data []byte
	}

	// numCPU readers — RPM is a blocking kernel call, more goroutines = more concurrent reads
	readCh := make(chan readResult, numCPU*2) // buffer so readers pre-fetch while scanners work
	var readerWg sync.WaitGroup
	for i := 0; i < numCPU; i++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			for chunk := range jobs {
				if atomic.LoadInt32(&scanCancelFlag) != 0 {
					atomic.AddInt64(&doneCount, 1)
					continue
				}
				data, err := ReadMemory(ms.handle, chunk.addr, chunk.size)
				atomic.AddInt64(&doneCount, 1)
				if err != nil || len(data) < sz || sz == 0 {
					continue
				}
				readCh <- readResult{chunk.addr, data}
			}
		}()
	}
	go func() { readerWg.Wait(); close(readCh) }()

	// numCPU scanners — pure CPU work, NumCPU is optimal
	resultChan := make(chan []ScanResult, numCPU*4)
	var scanWg sync.WaitGroup
	for i := 0; i < numCPU; i++ {
		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			for rr := range readCh {
				data, addr := rr.data, rr.addr
				var local []ScanResult

				// Fast path: exact non-float — bytes.Index (SIMD), shared value slice
				if params.ST == ScanExact && !isFloat && len(params.Value) == sz {
					needle := params.Value[:sz]
					sharedVal := make([]byte, sz)
					copy(sharedVal, needle)
					searchIn := data
					offset := 0
					for {
						idx := bytes.Index(searchIn, needle)
						if idx < 0 { break }
						local = append(local, ScanResult{
							Address: addr + uintptr(offset+idx),
							Value:   sharedVal,
						})
						advance := idx + 1
						offset += advance
						searchIn = searchIn[advance:]
					}
				} else {
					step := 1
					if isNumeric { step = sz }

					startOff := 0
					if isNumeric && sz > 1 {
						if rem := int(addr) % sz; rem != 0 {
							startOff = sz - rem
						}
					}

					const arenaBlock = 65536
					arena := make([]byte, arenaBlock*sz)
					arenaOff := 0
					local = make([]ScanResult, 0, 64)

					if nzf.enabled {
						if nzf.is32 {
							abits := nzf.abits32
							for i := startOff; i <= len(data)-4; i += 4 {
								v := binary.LittleEndian.Uint32(data[i:])
								if v&0x7FFFFFFF <= abits {
									if arenaOff+4 > len(arena) { arena = make([]byte, arenaBlock*4); arenaOff = 0 }
									cp := arena[arenaOff : arenaOff+4 : arenaOff+4]
									cp[0], cp[1], cp[2], cp[3] = data[i], data[i+1], data[i+2], data[i+3]
									arenaOff += 4
									local = append(local, ScanResult{Address: addr + uintptr(i), Value: cp})
								}
							}
						} else {
							abits := nzf.abits64
							for i := startOff; i <= len(data)-8; i += 8 {
								v := binary.LittleEndian.Uint64(data[i:])
								if v&0x7FFFFFFFFFFFFFFF <= abits {
									if arenaOff+8 > len(arena) { arena = make([]byte, arenaBlock*8); arenaOff = 0 }
									cp := arena[arenaOff : arenaOff+8 : arenaOff+8]
									copy(cp, data[i:i+8])
									arenaOff += 8
									local = append(local, ScanResult{Address: addr + uintptr(i), Value: cp})
								}
							}
						}
					} else {
						for i := startOff; i <= len(data)-sz; i += step {
							c := data[i : i+sz]
							if compareValues(params.DT, nil, c, params.Value, params.Value2, params.ST, params.Tolerance) {
								if arenaOff+sz > len(arena) { arena = make([]byte, arenaBlock*sz); arenaOff = 0 }
								cp := arena[arenaOff : arenaOff+sz : arenaOff+sz]
								copy(cp, c)
								arenaOff += sz
								local = append(local, ScanResult{Address: addr + uintptr(i), Value: cp})
							}
						}
					}
				}

				if len(local) > 0 {
					resultChan <- local
				}
			}
		}()
	}
	go func() { scanWg.Wait(); close(resultChan) }()

	var foundCount int64

	// Progress ticker
	doneCh := make(chan struct{})
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-tick.C:
				d := atomic.LoadInt64(&doneCount)
				f := atomic.LoadInt64(&foundCount)
				fmt.Printf("\r  ... %d/%d chunks | %d results   ", d, total, f)
			}
		}
	}()

	ms.clearDiskRes()
	var all []ScanResult
	var diskW *diskWriter
	sz2 := sz // capture for closure

	for batch := range resultChan {
		// Switch to disk when threshold exceeded — avoids RAM spike
		if diskW == nil && len(all)+len(batch) > diskResThreshold {
			var werr error
			diskW, werr = newDiskWriter(sz2)
			if werr != nil {
				Log.Warn("disk result fallback failed: %v — staying in RAM", werr)
			} else {
				for _, r := range all { diskW.append(r.Address, r.Value) }
				all = nil
			}
		}
		if diskW != nil {
			for _, r := range batch { diskW.append(r.Address, r.Value) }
		} else {
			all = append(all, batch...)
		}
		atomic.AddInt64(&foundCount, int64(len(batch)))
		if params.ResultCap > 0 {
			total := len(all)
			if diskW != nil { total = diskW.count }
			if total >= params.ResultCap {
				atomic.StoreInt32(&scanCancelFlag, 1)
				if diskW != nil && diskW.count > params.ResultCap {
					// cap is approximate for disk mode
				} else if len(all) > params.ResultCap {
					all = all[:params.ResultCap]
				}
				break
			}
		}
	}
	for range resultChan {}
	close(doneCh)

	fmt.Println()
	if atomic.LoadInt32(&scanCancelFlag) != 0 && params.ResultCap == 0 {
		ms.Results = nil
		if diskW != nil { diskW.flush(); diskW.addrFile.Close(); diskW.valFile.Close()
			os.Remove(diskW.addrPath); os.Remove(diskW.valPath) }
		fmt.Println("  Scan cancelled — results cleared for fresh start.")
		return 0
	}

	if diskW != nil {
		diskW.flush()
		dr, err := diskW.toDiskResultSet()
		if err != nil {
			Log.Error("failed to open disk result set: %v", err)
			ms.Results = nil
			return 0
		}
		ms.diskRes = dr
		ms.Results = nil
		fmt.Printf("  %d results stored in %s + %s\n", dr.count,
			filepath.Base(diskW.addrPath), filepath.Base(diskW.valPath))
		Log.Info("FirstScan: %d results on disk", dr.count)
		return dr.count
	}

	ms.Results = all
	Log.Info("FirstScan: done, found %d results", len(all))
	return len(all)
}

// firstScanUnknown snapshots all scanned memory to disk — no per-address RAM allocation.
// Returns approximate count of aligned addresses available for next scan.
func (ms *MemoryScanner) firstScanUnknown(params ScanParams) int {
	regions := EnumMemoryRegions(ms.handle, params.Writable)

	sz := dataTypeSize(params.DT)
	if sz == 0 { sz = 4 }

	const chunkSize   = 4 * 1024 * 1024
	const maxRegionSz = 128 * 1024 * 1024
	var chunks []scanChunk
	for _, r := range regions {
		if params.Writable && r.RegionSize > maxRegionSz { continue }
		rEnd := r.BaseAddress + r.RegionSize
		lo, hi := r.BaseAddress, rEnd
		if params.RangeLo > 0 && params.RangeLo > lo { lo = params.RangeLo }
		if params.RangeHi > 0 && params.RangeHi < hi { hi = params.RangeHi }
		if lo >= hi { continue }
		for off := lo - r.BaseAddress; off < hi-r.BaseAddress; off += uintptr(chunkSize) {
			csz := hi - r.BaseAddress - off
			if csz > uintptr(chunkSize) { csz = uintptr(chunkSize) }
			chunks = append(chunks, scanChunk{r.BaseAddress + off, int(csz)})
		}
	}
	total := len(chunks)
	fmt.Printf("  snapshotting %d chunks to disk...\n", total)

	snap, err := newMemSnapshot(sz)
	if err != nil {
		fmt.Printf("  snapshot failed (%v) — falling back to in-memory unknown scan\n", err)
		// Fall back: mark all regions as one big result set — not ideal but functional
		ms.Results = nil
		return 0
	}

	jobs := make(chan scanChunk, total)
	for _, c := range chunks { jobs <- c }
	close(jobs)

	var doneCount int64
	numCPU := runtime.NumCPU()

	// Readers send raw data to a single writer goroutine (sequential file writes)
	type rawChunk struct{ addr uintptr; data []byte }
	writeCh := make(chan rawChunk, numCPU*2)

	var readerWg sync.WaitGroup
	for i := 0; i < numCPU; i++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			for chunk := range jobs {
				if atomic.LoadInt32(&scanCancelFlag) != 0 {
					atomic.AddInt64(&doneCount, 1)
					continue
				}
				data, err := ReadMemory(ms.handle, chunk.addr, chunk.size)
				atomic.AddInt64(&doneCount, 1)
				if err != nil || len(data) == 0 { continue }
				writeCh <- rawChunk{chunk.addr, data}
			}
		}()
	}
	go func() { readerWg.Wait(); close(writeCh) }()

	// Single writer goroutine — sequential writes = correct file offsets
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		for rc := range writeCh {
			snap.writeChunk(rc.addr, rc.data)
		}
	}()

	// Progress ticker
	doneCh := make(chan struct{})
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-tick.C:
				d := atomic.LoadInt64(&doneCount)
				fmt.Printf("\r  ... %d/%d chunks | %.1f MB snapshotted   ", d, total, float64(snap.fileOff)/(1024*1024))
			}
		}
	}()

	writerWg.Wait()
	close(doneCh)
	fmt.Println()

	if atomic.LoadInt32(&scanCancelFlag) != 0 {
		snap.close()
		ms.Results = nil
		fmt.Println("  Scan cancelled — results cleared for fresh start.")
		return 0
	}

	ms.snapshot = snap
	ms.Results = nil
	count := snap.countAddresses()
	fmt.Printf("  Snapshot complete: %.1f MB on disk, ~%d addresses ready\n",
		float64(snap.fileOff)/(1024*1024), count)
	Log.Info("firstScanUnknown: %.1fMB snapshotted, ~%d addresses", float64(snap.fileOff)/(1024*1024), count)
	return count
}

// nextScanFromSnapshot compares live memory against the snapshot for the first
// next scan after an unknown first scan. Produces a normal result set.
func (ms *MemoryScanner) nextScanFromSnapshot(params ScanParams) int {
	snap := ms.snapshot
	ms.snapshot = nil
	defer snap.close()

	sz := dataTypeSize(params.DT)
	if params.DT == TypeString || params.DT == TypeBytes { sz = len(params.Value) }
	if sz == 0 { return 0 }

	totalChunks := len(snap.chunks)
	fmt.Printf("  comparing snapshot vs live memory (%d chunks)...\n", totalChunks)

	var doneChunks int64
	var foundSoFar int64
	doneCh2 := make(chan struct{})
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-doneCh2:
				return
			case <-tick.C:
				d := atomic.LoadInt64(&doneChunks)
				f := atomic.LoadInt64(&foundSoFar)
				pct := float64(d) / float64(totalChunks) * 100
				fmt.Printf("\r  ... %d/%d chunks (%.1f%%) | survivors=%d   ", d, totalChunks, pct, f)
			}
		}
	}()

	numCPU := runtime.NumCPU()

	type chunkResult struct{ results []ScanResult }
	resultCh := make(chan chunkResult, numCPU*2)

	jobs := make(chan snapshotChunk, totalChunks)
	for _, c := range snap.chunks { jobs <- c }
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nzf := buildNearZeroFast(params)
			const arenaBlock = 65536
			arena := make([]byte, arenaBlock*sz)
			arenaOff := 0

			for c := range jobs {
				oldData, err := snap.readChunk(c)
				if err != nil { continue }
				newData, err := ReadMemory(ms.handle, c.addr, c.size)
				if err != nil || len(newData) < sz { continue }

				limit := len(oldData)
				if len(newData) < limit { limit = len(newData) }

				startOff := 0
				if sz > 1 {
					if rem := int(c.addr) % sz; rem != 0 { startOff = sz - rem }
				}

				var local []ScanResult
				for i := startOff; i <= limit-sz; i += sz {
					oldVal := oldData[i : i+sz]
					newVal := newData[i : i+sz]

					var keep bool
					if nzf.enabled {
						if nzf.is32 {
							v := binary.LittleEndian.Uint32(newVal)
							keep = v&0x7FFFFFFF <= nzf.abits32
						} else {
							v := binary.LittleEndian.Uint64(newVal)
							keep = v&0x7FFFFFFFFFFFFFFF <= nzf.abits64
						}
					} else {
						keep = compareValues(params.DT, oldVal, newVal, params.Value, params.Value2, params.ST, params.Tolerance)
					}

					if keep {
						if arenaOff+sz > len(arena) { arena = make([]byte, arenaBlock*sz); arenaOff = 0 }
						cp := arena[arenaOff : arenaOff+sz : arenaOff+sz]
						copy(cp, newVal)
						arenaOff += sz
						local = append(local, ScanResult{Address: c.addr + uintptr(i), Value: cp})
					}
				}
				atomic.AddInt64(&doneChunks, 1)
				if len(local) > 0 {
					atomic.AddInt64(&foundSoFar, int64(len(local)))
					resultCh <- chunkResult{local}
				}
			}
		}()
	}
	go func() { wg.Wait(); close(resultCh) }()

	var all []ScanResult
	for r := range resultCh {
		all = append(all, r.results...)
	}
	close(doneCh2)
	fmt.Println()
	ms.Results = all
	Log.Info("nextScanFromSnapshot: %d results", len(all))
	return len(all)
}

// nextScanDisk streams NextScan from disk with gap-based address grouping.
// CE groups by 4KB page boundary. We go further: bridge any gap up to maxGap bytes,
// capped at maxSpan per read. More addresses per RPM call = fewer kernel transitions.
// Two addresses 8 bytes apart but on different pages = 1 call instead of 2.
func (ms *MemoryScanner) nextScanDisk(params ScanParams) int {
	old := ms.diskRes
	ms.diskRes = nil
	defer old.delete()

	sz := old.valSize
	nzf := buildNearZeroFast(params)
	total := old.count

	const chunkBytes = 20 * 4096
	chunkAddrs := chunkBytes / 8
	if chunkAddrs < 1024 { chunkAddrs = 1024 }

	const maxGap  = 64 * 1024
	const maxSpan = 1 * 1024 * 1024

	newW, err := newDiskWriter(sz)
	if err != nil {
		Log.Error("nextScanDisk: can't create output: %v", err)
		return 0
	}

	var processed int64
	var kept     int64
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
				k := atomic.LoadInt64(&kept)
				pct := float64(p) / float64(total) * 100
				fmt.Printf("\r  ... %d/%d (%.1f%%) | survivors=%d   ", p, total, pct, k)
			}
		}
	}()

	addrChunk := make([]uintptr, chunkAddrs)
	oldVals   := make([]byte, chunkAddrs*sz)

	pos := 0
	for pos < old.count {
		n := old.readAddressChunk(pos, chunkAddrs, addrChunk)
		if n == 0 { break }
		old.readValueChunk(pos, n, oldVals)
		pos += n

		// Gap-based grouping: extend group as long as next address is within maxGap
		// AND total span stays under maxSpan. Bridges page boundaries transparently.
		i := 0
		for i < n {
			j := i + 1
			for j < n {
				gap  := addrChunk[j] - addrChunk[j-1]
				span := addrChunk[j] + uintptr(sz) - addrChunk[i]
				if gap > maxGap || span > maxSpan { break }
				j++
			}
			// j is one past last address in this group

			spanStart := addrChunk[i]
			spanEnd   := addrChunk[j-1] + uintptr(sz)
			spanSize  := int(spanEnd - spanStart)

			pageData, err := ReadMemory(ms.handle, spanStart, spanSize)
			if err != nil || len(pageData) < sz {
				i = j
				continue
			}

			// Compare each address in this group
			for k := i; k < j; k++ {
				off := int(addrChunk[k] - spanStart)
				if off+sz > len(pageData) { continue }
				newVal := pageData[off : off+sz]
				oldVal := oldVals[k*sz : k*sz+sz]

				var keep bool
				if nzf.enabled {
					if nzf.is32 {
						v := binary.LittleEndian.Uint32(newVal)
						keep = v&0x7FFFFFFF <= nzf.abits32
					} else {
						v := binary.LittleEndian.Uint64(newVal)
						keep = v&0x7FFFFFFFFFFFFFFF <= nzf.abits64
					}
				} else {
					keep = compareValues(params.DT, oldVal, newVal, params.Value, params.Value2, params.ST, params.Tolerance)
				}
				if keep {
					newW.append(addrChunk[k], newVal)
					atomic.AddInt64(&kept, 1)
				}
			}
			i = j
		}
		atomic.AddInt64(&processed, int64(n)) // once per chunk, after all page groups
	}

	close(doneCh)
	fmt.Println()

	newW.flush()
	count := newW.count

	if count == 0 {
		newW.addrFile.Close(); newW.valFile.Close()
		os.Remove(newW.addrPath); os.Remove(newW.valPath)
		ms.Results = nil
		return 0
	}

	if count < diskResThreshold/10 {
		dr, _ := newW.toDiskResultSet()
		ms.Results = dr.toMemory()
		dr.delete()
		return len(ms.Results)
	}

	dr, _ := newW.toDiskResultSet()
	ms.diskRes = dr
	ms.Results = nil
	return count
}

func (ms *MemoryScanner) NextScan(params ScanParams) int {
	// Route to appropriate NextScan implementation
	if ms.snapshot != nil {
		return ms.nextScanFromSnapshot(params)
	}
	if ms.diskRes != nil {
		return ms.nextScanDisk(params)
	}
	if len(ms.Results) == 0 {
		Log.Warn("NextScan: called with 0 results")
		return 0
	}
	Log.Info("NextScan: filtering %d results, scan=%d", len(ms.Results), params.ST)

	sz := dataTypeSize(params.DT)
	if params.DT == TypeString || params.DT == TypeBytes {
		sz = len(params.Value)
	}

	// Group results by memory region to minimize ReadMemory syscalls
	// Sort by address, then read a whole region at once and check all addresses in it
	sorted := make([]int, len(ms.Results))
	for i := range sorted {
		sorted[i] = i
	}
	sort.Slice(sorted, func(a, b int) bool {
		return ms.Results[sorted[a]].Address < ms.Results[sorted[b]].Address
	})

	numCPU := runtime.NumCPU()
	batchSize := (len(sorted) + numCPU - 1) / numCPU

	type keepEntry struct {
		idx int
		val []byte
	}
	resultChan := make(chan keepEntry, len(ms.Results))

	var wg sync.WaitGroup
	for w := 0; w < numCPU; w++ {
		start := w * batchSize
		end := start + batchSize
		if end > len(sorted) {
			end = len(sorted)
		}
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(indices []int) {
			defer wg.Done()

			nzf := buildNearZeroFast(params)

			const chunkRead = 256 * 1024 // 256KB — more addresses covered per syscall
			const arenaBlock = 65536
			arena := make([]byte, arenaBlock*sz)
			arenaOff := 0

			var regionData []byte
			var regionBase uintptr

			checkAndKeep := func(idx int, newVal []byte) {
				keep := false
				if nzf.enabled {
					// Fast integer comparison for near-zero float range
					if nzf.is32 {
						v := binary.LittleEndian.Uint32(newVal)
						keep = v&0x7FFFFFFF <= nzf.abits32
					} else {
						v := binary.LittleEndian.Uint64(newVal)
						keep = v&0x7FFFFFFFFFFFFFFF <= nzf.abits64
					}
				} else {
					keep = compareValues(params.DT, ms.Results[idx].Value, newVal, params.Value, params.Value2, params.ST, params.Tolerance)
				}
				if keep {
					if arenaOff+sz > len(arena) { arena = make([]byte, arenaBlock*sz); arenaOff = 0 }
					cp := arena[arenaOff : arenaOff+sz : arenaOff+sz]
					copy(cp, newVal)
					arenaOff += sz
					resultChan <- keepEntry{idx: idx, val: cp}
				}
			}

			for _, idx := range indices {
				r := ms.Results[idx]

				// Use cached region if address falls within it
				if regionData != nil && r.Address >= regionBase && int(r.Address-regionBase)+sz <= len(regionData) {
					offset := int(r.Address - regionBase)
					checkAndKeep(idx, regionData[offset:offset+sz])
					continue
				}

				// Read 256KB chunk, clamped to memory region boundary
				readSize := chunkRead
				if mbi, err2 := QueryRegion(ms.handle, r.Address); err2 == nil {
					regionEnd := mbi.BaseAddress + mbi.RegionSize
					if r.Address+uintptr(readSize) > regionEnd {
						readSize = int(regionEnd - r.Address)
					}
				}
				if readSize < sz { readSize = sz }

				data, err := ReadMemory(ms.handle, r.Address, readSize)
				if err != nil || len(data) < sz {
					data, err = ReadMemory(ms.handle, r.Address, sz)
					if err != nil || len(data) < sz { continue }
					regionData = nil
				} else {
					regionData = data
					regionBase = r.Address
				}

				checkAndKeep(idx, data[:sz])
			}
		}(sorted[start:end])
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	keeps := make(map[int][]byte, len(ms.Results))
	for k := range resultChan {
		keeps[k.idx] = k.val
	}

	var filtered []ScanResult
	for i, r := range ms.Results {
		if val, ok := keeps[i]; ok {
			r.Value = val
			filtered = append(filtered, r)
		}
	}
	ms.Results = filtered
	Log.Info("NextScan: done, %d results remaining", len(filtered))
	return len(filtered)
}

func (ms *MemoryScanner) RefreshValues(dt DataType) {
	sz := dataTypeSize(dt)
	for i := range ms.Results {
		val, err := ReadMemory(ms.handle, ms.Results[i].Address, sz)
		if err == nil && len(val) == sz {
			ms.Results[i].Value = val
		}
	}
}

func (ms *MemoryScanner) ReadCurrentValue(addr uintptr, dt DataType) (string, error) {
	sz := dataTypeSize(dt)
	buf, err := ReadMemory(ms.handle, addr, sz)
	if err != nil {
		return "", err
	}
	return decodeValue(dt, buf), nil
}

func (ms *MemoryScanner) WriteValue(addr uintptr, data []byte) error {
	Log.Info("WriteValue: addr=0x%X size=%d", addr, len(data))
	err := WriteMemory(ms.handle, addr, data)
	if err != nil {
		Log.Error("WriteValue: addr=0x%X failed: %v", addr, err)
	}
	return err
}
