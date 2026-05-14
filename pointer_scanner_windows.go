//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sort"
	"sync"

	"golang.org/x/sys/windows"
)

// PointerMap: sorted slice of all pointer-like values in the process
// For each address A, if *A looks like a valid heap address, store (value -> addr)
// Then BFS from target backward through this map.

type ptrEntry struct {
	value uintptr // what this address points to
	addr  uintptr // the address itself
}

type PointerMap struct {
	Entries []ptrEntry // sorted by .value
}

// BuildPointerMap scans all writable regions and collects all 8-byte aligned
// values that look like valid process addresses. This is the CE "pointer map" equivalent.
func BuildPointerMap(handle windows.Handle, modules []ModuleInfo) (*PointerMap, error) {
	// Get all readable regions
	regions := EnumMemoryRegions(handle, false)

	// Collect valid address range (union of all committed regions)
	type addrRange struct {
		lo, hi uintptr
	}
	var ranges []addrRange
	for _, r := range regions {
		ranges = append(ranges, addrRange{r.BaseAddress, r.BaseAddress + r.RegionSize})
	}

	isValidAddr := func(v uintptr) bool {
		if v < 0x10000 || v > 0x7FFFFFFFFFFF {
			return false
		}
		for _, r := range ranges {
			if v >= r.lo && v < r.hi {
				return true
			}
		}
		return false
	}

	numCPU := runtime.NumCPU()
	jobs := make(chan MEMORY_BASIC_INFORMATION, len(regions))
	for _, r := range regions {
		jobs <- r
	}
	close(jobs)

	resultChan := make(chan []ptrEntry, numCPU*4)
	var wg sync.WaitGroup

	for i := 0; i < numCPU; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				// Align start to 8 bytes
				start := r.BaseAddress
				if start%8 != 0 {
					start += 8 - (start % 8)
				}
				size := int(r.RegionSize)
				if size < 8 {
					continue
				}

				data, err := ReadMemory(handle, r.BaseAddress, size)
				if err != nil || len(data) < 8 {
					continue
				}

				offset := int(start - r.BaseAddress)
				var local []ptrEntry
				for i := offset; i+8 <= len(data); i += 8 {
					v := uintptr(binary.LittleEndian.Uint64(data[i : i+8]))
					if isValidAddr(v) {
						local = append(local, ptrEntry{
							value: v,
							addr:  r.BaseAddress + uintptr(i),
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

	var all []ptrEntry
	for batch := range resultChan {
		all = append(all, batch...)
	}

	// Sort by value so we can binary-search
	sort.Slice(all, func(i, j int) bool {
		return all[i].value < all[j].value
	})

	fmt.Printf("[*] Pointer map built: %d pointer entries\n", len(all))
	return &PointerMap{Entries: all}, nil
}

// FindPointersTo finds all entries in the map whose value is in [target, target+maxOffset]
func (pm *PointerMap) FindPointersTo(target uintptr, maxOffset uintptr) []ptrEntry {
	lo := sort.Search(len(pm.Entries), func(i int) bool {
		return pm.Entries[i].value >= target
	})
	hi := sort.Search(len(pm.Entries), func(i int) bool {
		return pm.Entries[i].value > target+maxOffset
	})
	return pm.Entries[lo:hi]
}

// BFSPointerScan finds pointer chains from any module base to the target address.
// maxDepth: max chain length (e.g. 7)
// maxOffset: max offset at each level (e.g. 2048)
// Returns up to maxResults chains.
func BFSPointerScan(
	handle windows.Handle,
	pm *PointerMap,
	modules []ModuleInfo,
	target uintptr,
	maxDepth int,
	maxOffset uintptr,
	maxResults int,
) []PointerResult {

	type searchNode struct {
		addr    uintptr
		offsets []uintptr
	}

	// We work backward: find what points to target (with offset), then what points to those, etc.
	var results []PointerResult
	var mu sync.Mutex

	// BFS queue
	type qItem struct {
		targetAddr uintptr
		chain      []uintptr // offsets so far (innermost first)
	}

	queue := []qItem{{targetAddr: target, chain: nil}}

	for depth := 0; depth < maxDepth && len(results) < maxResults; depth++ {
		if len(queue) == 0 {
			break
		}
		var nextQueue []qItem
		var nextMu sync.Mutex

		numCPU := runtime.NumCPU()
		jobs := make(chan qItem, len(queue))
		for _, q := range queue {
			jobs <- q
		}
		close(jobs)

		var wg sync.WaitGroup
		for i := 0; i < numCPU; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for item := range jobs {
					// Find all entries pointing into [item.targetAddr - maxOffset, item.targetAddr]
					baseTarget := item.targetAddr
					if baseTarget > maxOffset {
						baseTarget -= maxOffset
					} else {
						baseTarget = 0
					}
					ptrs := pm.FindPointersTo(baseTarget, maxOffset+(item.targetAddr-baseTarget))

					for _, p := range ptrs {
						offset := item.targetAddr - p.value
						// Build the new chain
						newChain := make([]uintptr, len(item.chain)+1)
						newChain[0] = offset
						copy(newChain[1:], item.chain)

						// Check if this pointer is in a module (static base)
						if mod := findModule(modules, p.addr); mod != nil {
							mu.Lock()
							if len(results) < maxResults {
								results = append(results, PointerResult{
									BaseModule: mod.Name,
									BaseOffset: p.addr - mod.Base,
									Offsets:    newChain,
									FinalAddr:  target,
								})
							}
							mu.Unlock()
						} else {
							// Keep searching backward
							nextMu.Lock()
							nextQueue = append(nextQueue, qItem{
								targetAddr: p.addr,
								chain:      newChain,
							})
							nextMu.Unlock()
						}
					}
				}
			}()
		}
		wg.Wait()
		queue = nextQueue
		_ = nextMu
	}

	_ = searchNode{}
	return results
}

func findModule(modules []ModuleInfo, addr uintptr) *ModuleInfo {
	for i := range modules {
		m := &modules[i]
		if addr >= m.Base && addr < m.Base+uintptr(m.Size) {
			return m
		}
	}
	return nil
}

// VerifyPointerChain verifies a pointer chain is still valid and returns the final address
func VerifyPointerChain(handle windows.Handle, modules []ModuleInfo, result *PointerResult) (uintptr, bool) {
	// Find module base
	var base uintptr
	for _, m := range modules {
		if m.Name == result.BaseModule {
			base = m.Base
			break
		}
	}
	if base == 0 {
		return 0, false
	}

	addr := base + result.BaseOffset
	for i, offset := range result.Offsets {
		ptr, err := ReadPointer(handle, addr)
		if err != nil || ptr == 0 {
			return 0, false
		}
		if i < len(result.Offsets)-1 {
			addr = ptr + offset
		} else {
			addr = ptr + offset
		}
	}
	return addr, true
}

// FormatPointerResult formats a pointer chain as a CE-style string
func FormatPointerResult(r PointerResult) string {
	s := fmt.Sprintf(`"%s"+%X`, r.BaseModule, r.BaseOffset)
	for _, off := range r.Offsets {
		s += fmt.Sprintf(" -> [+%X]", off)
	}
	return s
}
