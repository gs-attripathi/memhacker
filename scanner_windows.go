//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync"
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
	switch st {
	case ScanExact:
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
	Log.Debug("FirstScan: scanning %d memory regions", len(regions))
	numCPU := runtime.NumCPU()

	jobs := make(chan MEMORY_BASIC_INFORMATION, len(regions))
	for _, r := range regions {
		jobs <- r
	}
	close(jobs)

	resultChan := make(chan []ScanResult, numCPU*4)
	var wg sync.WaitGroup

	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				data, err := ReadMemory(ms.handle, r.BaseAddress, int(r.RegionSize))
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
				for i := 0; i <= len(data)-sz; i++ {
					chunk := data[i : i+sz]
					if compareValues(params.DT, nil, chunk, params.Value, params.Value2, params.ST, params.Tolerance) {
						cp := make([]byte, sz)
						copy(cp, chunk)
						local = append(local, ScanResult{
							Address: r.BaseAddress + uintptr(i),
							Value:   cp,
						})
					}
				}
				if len(local) > 0 {
					resultChan <- local
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var all []ScanResult
	for batch := range resultChan {
		all = append(all, batch...)
	}
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
	numCPU := runtime.NumCPU()
	batchSize := (len(ms.Results) + numCPU - 1) / numCPU

	type result struct {
		idx  int
		keep bool
		val  []byte
	}
	resultChan := make(chan result, len(ms.Results))

	var wg sync.WaitGroup
	for i := 0; i < numCPU; i++ {
		start := i * batchSize
		end := start + batchSize
		if end > len(ms.Results) {
			end = len(ms.Results)
		}
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			sz := dataTypeSize(params.DT)
			if params.DT == TypeString || params.DT == TypeBytes {
				sz = len(params.Value)
			}
			for idx := start; idx < end; idx++ {
				r := ms.Results[idx]
				newVal, err := ReadMemory(ms.handle, r.Address, sz)
				if err != nil || len(newVal) < sz {
					resultChan <- result{idx: idx, keep: false}
					continue
				}
				keep := compareValues(params.DT, r.Value, newVal, params.Value, params.Value2, params.ST, params.Tolerance)
				cp := make([]byte, len(newVal))
				copy(cp, newVal)
				resultChan <- result{idx: idx, keep: keep, val: cp}
			}
		}(start, end)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	type keepEntry struct {
		val []byte
	}
	keeps := make(map[int]keepEntry, len(ms.Results))
	for r := range resultChan {
		if r.keep {
			keeps[r.idx] = keepEntry{val: r.val}
		}
	}

	var filtered []ScanResult
	for i, r := range ms.Results {
		if k, ok := keeps[i]; ok {
			r.Value = k.val
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
