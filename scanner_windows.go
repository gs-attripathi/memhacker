//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
	handle  windows.Handle
	Results []ScanResult
}

func NewMemoryScanner(handle windows.Handle) *MemoryScanner {
	return &MemoryScanner{handle: handle}
}

func (ms *MemoryScanner) FirstScan(params ScanParams) int {
	Log.Info("FirstScan: type=%s scan=%d writable=%v", dataTypeName(params.DT), params.ST, params.Writable)
	regions := EnumMemoryRegions(ms.handle, params.Writable)
	total := len(regions)
	Log.Debug("FirstScan: scanning %d memory regions", total)
	fmt.Printf("  scanning %d regions...\n", total)
	numCPU := runtime.NumCPU()

	jobs := make(chan MEMORY_BASIC_INFORMATION, total)
	for _, r := range regions {
		jobs <- r
	}
	close(jobs)

	var doneCount int64
	resultChan := make(chan []ScanResult, numCPU*4)
	var wg sync.WaitGroup

	isFloat    := params.DT == TypeFloat32 || params.DT == TypeFloat64
	isNumeric  := params.DT != TypeString && params.DT != TypeBytes

	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				data, err := ReadMemory(ms.handle, r.BaseAddress, int(r.RegionSize))
				atomic.AddInt64(&doneCount, 1)
				if err != nil || len(data) == 0 {
					continue
				}
				sz := dataTypeSize(params.DT)
				if params.DT == TypeString || params.DT == TypeBytes {
					sz = len(params.Value)
				}
				if sz == 0 {
					continue
				}

				var local []ScanResult

				// Fast path: exact non-float scan — bytes.Index (SIMD), shared value slice
				if params.ST == ScanExact && !isFloat && len(params.Value) == sz {
					needle := params.Value[:sz]
					sharedVal := make([]byte, sz)
					copy(sharedVal, needle)
					searchIn := data
					offset := 0
					for {
						idx := bytes.Index(searchIn, needle)
						if idx < 0 {
							break
						}
						local = append(local, ScanResult{
							Address: r.BaseAddress + uintptr(offset+idx),
							Value:   sharedVal, // all exact matches share one value copy
						})
						advance := idx + 1
						offset += advance
						searchIn = searchIn[advance:]
					}
				} else {
					// General path — aligned scan (CE default: step by value size, not 1 byte)
					// + arena allocation (one large alloc per region, not one per match)
					step := 1
					if isNumeric {
						step = sz
					}
					const arenaBlock = 65536
					arena := make([]byte, arenaBlock*sz)
					arenaOff := 0
					local = make([]ScanResult, 0, 64)
					for i := 0; i <= len(data)-sz; i += step {
						chunk := data[i : i+sz]
						if compareValues(params.DT, nil, chunk, params.Value, params.Value2, params.ST, params.Tolerance) {
							if arenaOff+sz > len(arena) {
								arena = make([]byte, arenaBlock*sz)
								arenaOff = 0
							}
							cp := arena[arenaOff : arenaOff+sz : arenaOff+sz]
							copy(cp, chunk)
							arenaOff += sz
							local = append(local, ScanResult{
								Address: r.BaseAddress + uintptr(i),
								Value:   cp,
							})
						}
					}
				}

				if len(local) > 0 {
					resultChan <- local
				}
			}
		}()
	}

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
				fmt.Printf("  ... %d/%d regions | %d results\n", d, total, len(ms.Results))
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var all []ScanResult
	for batch := range resultChan {
		all = append(all, batch...)
	}
	close(doneCh)

	ms.Results = all
	Log.Info("FirstScan: done, found %d results", len(all))
	return len(all)
}

func (ms *MemoryScanner) NextScan(params ScanParams) int {
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

			// Try to batch-read a region covering consecutive addresses
			var regionData []byte
			var regionBase uintptr

			for _, idx := range indices {
				r := ms.Results[idx]

				// Check if this address is within our cached region
				if regionData != nil && r.Address >= regionBase && int(r.Address-regionBase)+sz <= len(regionData) {
					// Use cached region data
					offset := int(r.Address - regionBase)
					newVal := regionData[offset : offset+sz]
					keep := compareValues(params.DT, r.Value, newVal, params.Value, params.Value2, params.ST, params.Tolerance)
					if keep {
						cp := make([]byte, sz)
						copy(cp, newVal)
						resultChan <- keepEntry{idx: idx, val: cp}
					}
					continue
				}

				// Read a chunk covering this address + next ~64KB to amortize syscall cost
					// But don't cross memory region boundaries — query region size first
					const chunkSize = 64 * 1024
					readSize := chunkSize
					if mbi, err2 := QueryRegion(ms.handle, r.Address); err2 == nil {
						regionEnd := mbi.BaseAddress + mbi.RegionSize
						if r.Address+uintptr(readSize) > regionEnd {
							readSize = int(regionEnd - r.Address)
						}
					}
					if readSize < sz {
						readSize = sz
					}
					data, err := ReadMemory(ms.handle, r.Address, readSize)
					if err != nil || len(data) < sz {
						// Fallback: read just this address
						data, err = ReadMemory(ms.handle, r.Address, sz)
						if err != nil || len(data) < sz {
							continue
						}
						regionData = nil
					} else {
						regionData = data
						regionBase = r.Address
					}

				newVal := data[:sz]
				keep := compareValues(params.DT, r.Value, newVal, params.Value, params.Value2, params.ST, params.Tolerance)
				if keep {
					cp := make([]byte, sz)
					copy(cp, newVal)
					resultChan <- keepEntry{idx: idx, val: cp}
				}
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
