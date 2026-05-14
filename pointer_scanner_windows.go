//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// -----------------------------------------------------------------------
// PointerMap: sorted (value, addr) pairs — saved to / loaded from a file
// -----------------------------------------------------------------------

const pmapMagic = uint32(0x504D4150) // "PMAP"
const pmapVersion = uint32(1)

type ptrEntry struct {
	value uintptr // what this address points to
	addr  uintptr // the address that holds that value
}

type PointerMap struct {
	Entries    []ptrEntry
	Modules    []ModuleInfo
	CreatedAt  time.Time
	PID        uint32
	TargetAddr uintptr // the address we were scanning for when this pmap was saved
}

// Save writes the pointer map to a binary file.
// Format: magic(4) version(4) pid(4) time_unix(8) mod_count(4) [name_len(2) name mod_base(8) mod_size(4)]...
//         entry_count(8) [value(8) addr(8)]...
func (pm *PointerMap) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create pmap file: %v", err)
	}
	defer f.Close()

	w := func(v interface{}) error {
		return binary.Write(f, binary.LittleEndian, v)
	}

	w(pmapMagic)
	w(pmapVersion)
	w(pm.PID)
	w(pm.CreatedAt.Unix())
	w(uint64(pm.TargetAddr))
	w(uint32(len(pm.Modules)))
	for _, m := range pm.Modules {
		name := []byte(m.Name)
		w(uint16(len(name)))
		f.Write(name)
		w(uint64(m.Base))
		w(m.Size)
	}
	w(uint64(len(pm.Entries)))
	for _, e := range pm.Entries {
		w(uint64(e.value))
		w(uint64(e.addr))
	}
	return nil
}

// LoadPointerMap reads a pmap file from disk.
func LoadPointerMap(path string) (*PointerMap, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open pmap file: %v", err)
	}
	defer f.Close()

	r := func(v interface{}) error {
		return binary.Read(f, binary.LittleEndian, v)
	}

	var magic, version, pid uint32
	var ts int64
	var targetAddr uint64
	r(&magic)
	if magic != pmapMagic {
		return nil, fmt.Errorf("not a valid pmap file (bad magic)")
	}
	r(&version)
	r(&pid)
	r(&ts)
	r(&targetAddr)

	var modCount uint32
	r(&modCount)
	mods := make([]ModuleInfo, modCount)
	for i := range mods {
		var nlen uint16
		r(&nlen)
		nameBuf := make([]byte, nlen)
		io.ReadFull(f, nameBuf)
		var base uint64
		var size uint32
		r(&base)
		r(&size)
		mods[i] = ModuleInfo{Name: string(nameBuf), Base: uintptr(base), Size: size}
	}

	var entryCount uint64
	r(&entryCount)
	entries := make([]ptrEntry, entryCount)
	for i := range entries {
		var v, a uint64
		r(&v)
		r(&a)
		entries[i] = ptrEntry{value: uintptr(v), addr: uintptr(a)}
	}

	return &PointerMap{
		Entries:    entries,
		Modules:    mods,
		CreatedAt:  time.Unix(ts, 0),
		PID:        pid,
		TargetAddr: uintptr(targetAddr),
	}, nil
}

// -----------------------------------------------------------------------
// Building the pointer map
// -----------------------------------------------------------------------

func BuildPointerMap(handle windows.Handle, modules []ModuleInfo, pid uint32) (*PointerMap, error) {
	Log.Info("BuildPointerMap: starting, %d modules", len(modules))
	regions := EnumMemoryRegions(handle, false)
	Log.Debug("BuildPointerMap: %d readable regions", len(regions))

	// build valid address range set for fast lookup
	type addrRange struct{ lo, hi uintptr }
	ranges := make([]addrRange, len(regions))
	for i, r := range regions {
		ranges[i] = addrRange{r.BaseAddress, r.BaseAddress + r.RegionSize}
	}
	// sort ranges for binary search
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })

	isValidAddr := func(v uintptr) bool {
		if v < 0x10000 || v > 0x7FFFFFFFFFFF {
			return false
		}
		// binary search
		lo, hi := 0, len(ranges)-1
		for lo <= hi {
			mid := (lo + hi) / 2
			if v < ranges[mid].lo {
				hi = mid - 1
			} else if v >= ranges[mid].hi {
				lo = mid + 1
			} else {
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
				// align start to 8 bytes
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
	go func() { wg.Wait(); close(resultChan) }()

	var all []ptrEntry
	for batch := range resultChan {
		all = append(all, batch...)
	}

	// sort by value for binary search during scan
	sort.Slice(all, func(i, j int) bool { return all[i].value < all[j].value })

	pm := &PointerMap{
		Entries:   all,
		Modules:   modules,
		CreatedAt: time.Now(),
		PID:       pid,
	}
	Log.Info("BuildPointerMap: done, %d pointer entries", len(all))
	return pm, nil
}

// FindPointersTo returns all entries whose .value is in [target, target+maxOffset].
func (pm *PointerMap) FindPointersTo(target uintptr, maxOffset uintptr) []ptrEntry {
	lo := sort.Search(len(pm.Entries), func(i int) bool {
		return pm.Entries[i].value >= target
	})
	hi := sort.Search(len(pm.Entries), func(i int) bool {
		return pm.Entries[i].value > target+maxOffset
	})
	return pm.Entries[lo:hi]
}

// -----------------------------------------------------------------------
// PointerScanSession: one (target address, pointer map) pair
// -----------------------------------------------------------------------

type PointerScanSession struct {
	TargetAddr uintptr
	PMap       *PointerMap
	Label      string // e.g. "session1.pmap"
}

// -----------------------------------------------------------------------
// PointerChain: the result of a scan — module+offset + slice of offsets
// -----------------------------------------------------------------------

type PointerChain struct {
	BaseModule string
	BaseOffset uintptr
	Offsets    []uintptr
}

func (c PointerChain) Key() string {
	s := fmt.Sprintf("%s+%X", c.BaseModule, c.BaseOffset)
	for _, o := range c.Offsets {
		s += fmt.Sprintf("|%X", o)
	}
	return s
}

func (c PointerChain) String() string {
	s := fmt.Sprintf(`"%s"+%X`, c.BaseModule, c.BaseOffset)
	for _, o := range c.Offsets {
		// treat as signed — if top bit set it's negative
		signed := int64(o)
		if signed < 0 {
			s += fmt.Sprintf(" -> [-%X]", uint64(-signed))
		} else {
			s += fmt.Sprintf(" -> [+%X]", o)
		}
	}
	return s
}

// PointerResult as returned to the user
type PointerResult struct {
	Chain PointerChain
}

// -----------------------------------------------------------------------
// BFS pointer scan — supports multiple sessions (cross-reference)
// -----------------------------------------------------------------------

type PointerScanConfig struct {
	Sessions   []PointerScanSession
	MaxDepth   int
	MaxOffset  uintptr
	MaxResults int
}

// MultiSessionPointerScan finds pointer chains that resolve correctly
// across ALL provided sessions. This is the key insight: a chain that
// works for session1(addr=0xAAA) AND session2(addr=0xBBB) is a real
// static pointer — not a coincidental match.
func MultiSessionPointerScan(cfg PointerScanConfig) []PointerResult {
	if len(cfg.Sessions) == 0 {
		return nil
	}
	Log.Info("MultiSessionPointerScan: %d sessions, depth=%d, maxOffset=0x%X, maxResults=%d",
		len(cfg.Sessions), cfg.MaxDepth, cfg.MaxOffset, cfg.MaxResults)

	// Run BFS for each session independently, collect chain keys
	type sessionChains struct {
		chains map[string]PointerChain // key -> chain
	}

	allSessionChains := make([]sessionChains, len(cfg.Sessions))
	var wg sync.WaitGroup

	for i, sess := range cfg.Sessions {
		wg.Add(1)
		go func(idx int, s PointerScanSession) {
			defer wg.Done()
			Log.Info("  Session[%d] %s: scanning from 0x%X", idx, s.Label, s.TargetAddr)
			chains := bfsSingleSession(s.PMap, s.TargetAddr, cfg.MaxDepth, cfg.MaxOffset, cfg.MaxResults*10)
			m := make(map[string]PointerChain, len(chains))
			for _, c := range chains {
				m[c.Key()] = c
			}
			allSessionChains[idx] = sessionChains{chains: m}
			Log.Info("  Session[%d] %s: found %d chains", idx, s.Label, len(chains))
		}(i, sess)
	}
	wg.Wait()

	// Cross-reference: keep only chains present in ALL sessions
	// Start with session 0's chains, then intersect with rest
	candidates := allSessionChains[0].chains
	for i := 1; i < len(allSessionChains); i++ {
		next := make(map[string]PointerChain)
		for key, chain := range candidates {
			if _, ok := allSessionChains[i].chains[key]; ok {
				next[key] = chain
			}
		}
		candidates = next
	}

	var results []PointerResult
	for _, c := range candidates {
		results = append(results, PointerResult{Chain: c})
		if len(results) >= cfg.MaxResults {
			break
		}
	}

	// Sort by chain length then base offset for deterministic output
	sort.Slice(results, func(i, j int) bool {
		ci, cj := results[i].Chain, results[j].Chain
		if len(ci.Offsets) != len(cj.Offsets) {
			return len(ci.Offsets) < len(cj.Offsets)
		}
		return ci.BaseOffset < cj.BaseOffset
	})

	Log.Info("MultiSessionPointerScan: %d chains survive cross-reference", len(results))
	return results
}

// bfsSingleSession does BFS backward from target using one pmap.
// Returns all PointerChain that start from a module-static address.
func bfsSingleSession(pm *PointerMap, target uintptr, maxDepth int, maxOffset uintptr, maxResults int) []PointerChain {
	type qItem struct {
		targetAddr uintptr
		offsets    []uintptr // chain so far (innermost offset first)
	}

	var results []PointerChain
	var mu sync.Mutex

	queue := []qItem{{targetAddr: target}}

	for depth := 0; depth < maxDepth; depth++ {
		if len(queue) == 0 || len(results) >= maxResults {
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
					// scan range: [targetAddr - maxOffset, targetAddr + maxOffset]
					scanFrom := uintptr(0)
					if item.targetAddr > maxOffset {
						scanFrom = item.targetAddr - maxOffset
					}
					scanRange := (item.targetAddr - scanFrom) + maxOffset // covers both directions
					ptrs := pm.FindPointersTo(scanFrom, scanRange)

					for _, p := range ptrs {
						// compute signed difference
						var offset uintptr
						if p.value <= item.targetAddr {
							offset = item.targetAddr - p.value
						} else {
							diff := p.value - item.targetAddr
							if diff > maxOffset {
								continue // too far in positive direction
							}
							// store as two's-complement negative
							offset = uintptr(^diff + 1)
						}
						// also skip positive offsets beyond maxOffset
						if p.value <= item.targetAddr && offset > maxOffset {
							continue
						}

						newOffsets := make([]uintptr, len(item.offsets)+1)
						newOffsets[0] = offset
						copy(newOffsets[1:], item.offsets)

						// Is this pointer inside a module (static)?
						if mod := findModuleByAddr(pm.Modules, p.addr); mod != nil {
							mu.Lock()
							if len(results) < maxResults {
								results = append(results, PointerChain{
									BaseModule: mod.Name,
									BaseOffset: p.addr - mod.Base,
									Offsets:    newOffsets,
								})
							}
							mu.Unlock()
						} else {
							// Not static yet — keep going deeper
							nextMu.Lock()
							nextQueue = append(nextQueue, qItem{
								targetAddr: p.addr,
								offsets:    newOffsets,
							})
							nextMu.Unlock()
						}
					}
				}
			}()
		}
		wg.Wait()
		queue = nextQueue
	}
	return results
}

func findModuleByAddr(modules []ModuleInfo, addr uintptr) *ModuleInfo {
	for i := range modules {
		m := &modules[i]
		if addr >= m.Base && addr < m.Base+uintptr(m.Size) {
			// skip system DLLs as base — static ptr inside kernel32 etc is useless
			if m.IsSystem {
				return nil
			}
			return m
		}
	}
	return nil
}

// VerifyChain follows a chain and returns the final address.
// modules = current session's modules (to resolve base).
func VerifyChain(handle windows.Handle, modules []ModuleInfo, chain PointerChain) (uintptr, bool) {
	var base uintptr
	for _, m := range modules {
		if m.Name == chain.BaseModule {
			base = m.Base
			break
		}
	}
	if base == 0 {
		return 0, false
	}
	addr := base + chain.BaseOffset
	for _, offset := range chain.Offsets {
		ptr, err := ReadPointer(handle, addr)
		if err != nil || ptr == 0 {
			return 0, false
		}
		// offset stored as two's complement — adding it works correctly
		// whether positive or negative due to unsigned wrap-around
		addr = ptr + offset
	}
	return addr, true
}
