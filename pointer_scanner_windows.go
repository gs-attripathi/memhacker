//go:build windows

package main

import (
	"bufio"
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
	TargetAddr uintptr
	Is32Bit    bool // true if this was built from a 32-bit process
}

// Save writes the pointer map to a binary file.
func (pm *PointerMap) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create pmap file: %v", err)
	}
	defer f.Close()

	// Use a large buffered writer
	bw := bufio.NewWriterSize(f, 8*1024*1024) // 8MB write buffer

	w := func(v interface{}) error {
		return binary.Write(bw, binary.LittleEndian, v)
	}

	w(pmapMagic)
	w(pmapVersion)
	w(pm.PID)
	w(pm.CreatedAt.Unix())
	w(uint64(pm.TargetAddr))
	is32 := uint8(0)
	if pm.Is32Bit {
		is32 = 1
	}
	w(is32)
	w(uint32(len(pm.Modules)))
	for _, m := range pm.Modules {
		name := []byte(m.Name)
		w(uint16(len(name)))
		bw.Write(name)
		w(uint64(m.Base))
		w(m.Size)
	}

	// Write all entries as one big raw block — massively faster than per-entry writes
	w(uint64(len(pm.Entries)))
	entryBuf := make([]byte, len(pm.Entries)*16) // each entry: value(8) + addr(8)
	for i, e := range pm.Entries {
		binary.LittleEndian.PutUint64(entryBuf[i*16:], uint64(e.value))
		binary.LittleEndian.PutUint64(entryBuf[i*16+8:], uint64(e.addr))
	}
	bw.Write(entryBuf)

	return bw.Flush()
}

// LoadPointerMap reads a pmap file from disk.
func LoadPointerMap(path string) (*PointerMap, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open pmap file: %v", err)
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 8*1024*1024) // 8MB read buffer

	r := func(v interface{}) error {
		return binary.Read(br, binary.LittleEndian, v)
	}

	var magic, version, pid uint32
	var ts int64
	var targetAddr uint64
	var is32 uint8
	r(&magic)
	if magic != pmapMagic {
		return nil, fmt.Errorf("not a valid pmap file (bad magic)")
	}
	r(&version)
	r(&pid)
	r(&ts)
	r(&targetAddr)
	r(&is32)

	var modCount uint32
	r(&modCount)
	mods := make([]ModuleInfo, modCount)
	for i := range mods {
		var nlen uint16
		r(&nlen)
		nameBuf := make([]byte, nlen)
		io.ReadFull(br, nameBuf)
		var base uint64
		var size uint32
		r(&base)
		r(&size)
		mods[i] = ModuleInfo{Name: string(nameBuf), Base: uintptr(base), Size: size}
	}

	var entryCount uint64
	r(&entryCount)

	// Read all entries as one raw block
	entryBuf := make([]byte, entryCount*16)
	if _, err := io.ReadFull(br, entryBuf); err != nil {
		return nil, fmt.Errorf("failed to read entries: %v", err)
	}
	entries := make([]ptrEntry, entryCount)
	for i := range entries {
		entries[i].value = uintptr(binary.LittleEndian.Uint64(entryBuf[i*16:]))
		entries[i].addr = uintptr(binary.LittleEndian.Uint64(entryBuf[i*16+8:]))
	}

	return &PointerMap{
		Entries:    entries,
		Modules:    mods,
		CreatedAt:  time.Unix(ts, 0),
		PID:        pid,
		TargetAddr: uintptr(targetAddr),
		Is32Bit:    is32 != 0,
	}, nil
}

// -----------------------------------------------------------------------
// Building the pointer map
// -----------------------------------------------------------------------

func BuildPointerMap(handle windows.Handle, modules []ModuleInfo, pid uint32, is32Bit bool) (*PointerMap, error) {
	Log.Info("BuildPointerMap: starting, %d modules, is32Bit=%v", len(modules), is32Bit)
	ptrSz := 8
	if is32Bit {
		ptrSz = 4
	}
	maxUserAddr := uintptr(0x7FFFFFFFFFFF)
	if is32Bit {
		maxUserAddr = uintptr(0x7FFFFFFF)
	}
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
		if v < 0x10000 || v > maxUserAddr {
			return false
		}
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
					// align start to ptrSz bytes
					start := r.BaseAddress
					if start%uintptr(ptrSz) != 0 {
						start += uintptr(ptrSz) - (start % uintptr(ptrSz))
					}
					size := int(r.RegionSize)
					if size < ptrSz {
						continue
					}
					data, err := ReadMemory(handle, r.BaseAddress, size)
					if err != nil || len(data) < ptrSz {
						continue
					}
					offset := int(start - r.BaseAddress)
					var local []ptrEntry
					for i := offset; i+ptrSz <= len(data); i += ptrSz {
						var v uintptr
						if ptrSz == 4 {
							v = uintptr(binary.LittleEndian.Uint32(data[i : i+4]))
						} else {
							v = uintptr(binary.LittleEndian.Uint64(data[i : i+8]))
						}
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
	total := len(regions)
	done := 0
	for batch := range resultChan {
		all = append(all, batch...)
		done++
		if done%50 == 0 || done == total {
			fmt.Printf("\r  scanning regions... %d/%d (%d pointers found)", done, total, len(all))
		}
	}
	fmt.Println()

	// sort by value for binary search during scan
	sort.Slice(all, func(i, j int) bool { return all[i].value < all[j].value })

	pm := &PointerMap{
		Entries:   all,
		Modules:   modules,
		CreatedAt: time.Now(),
		PID:       pid,
		Is32Bit:   is32Bit,
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
// across ALL provided sessions.
func MultiSessionPointerScan(cfg PointerScanConfig) []PointerResult {
	if len(cfg.Sessions) == 0 {
		return nil
	}

	// Warn about duplicate sessions
	seen := map[string]bool{}
	for _, s := range cfg.Sessions {
		key := fmt.Sprintf("%s_%X", s.Label, s.TargetAddr)
		if seen[key] {
			fmt.Printf("  [WARN] Duplicate session detected: %s target=0x%X — remove it with pmclear and re-add\n", s.Label, s.TargetAddr)
		}
		seen[key] = true
	}

	Log.Info("MultiSessionPointerScan: %d sessions, depth=%d, maxOffset=0x%X, maxResults=%d",
		len(cfg.Sessions), cfg.MaxDepth, cfg.MaxOffset, cfg.MaxResults)

	// Run BFS for each session independently — no per-session cap, collect all chains
	type sessionChains struct {
		chains map[string]PointerChain
	}
	allSessionChains := make([]sessionChains, len(cfg.Sessions))
	var wg sync.WaitGroup

	for i, sess := range cfg.Sessions {
		wg.Add(1)
		go func(idx int, s PointerScanSession) {
			defer wg.Done()
			Log.Info("  Session[%d] %s: scanning from 0x%X", idx, s.Label, s.TargetAddr)
			// No cap on per-session results — collect everything, cross-reference will filter
			chains := bfsSingleSession(s.PMap, s.TargetAddr, cfg.MaxDepth, cfg.MaxOffset, 0)
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
	}

	// Sort by chain length then base offset
	sort.Slice(results, func(i, j int) bool {
		ci, cj := results[i].Chain, results[j].Chain
		if len(ci.Offsets) != len(cj.Offsets) {
			return len(ci.Offsets) < len(cj.Offsets)
		}
		return ci.BaseOffset < cj.BaseOffset
	})

	// Apply maxResults only to final output
	if cfg.MaxResults > 0 && len(results) > cfg.MaxResults {
		results = results[:cfg.MaxResults]
	}

	Log.Info("MultiSessionPointerScan: %d chains survive cross-reference", len(results))
	return results
}

// bfsSingleSession does BFS backward from target using one pmap.
// maxResults=0 means no cap.
const maxQueuePerDepth = 500_000 // prevent BFS explosion

func bfsSingleSession(pm *PointerMap, target uintptr, maxDepth int, maxOffset uintptr, maxResults int) []PointerChain {
	type qItem struct {
		targetAddr uintptr
		offsets    []uintptr // chain so far (innermost offset first)
	}

	var results []PointerChain
	var mu sync.Mutex

	queue := []qItem{{targetAddr: target}}

	for depth := 0; depth < maxDepth; depth++ {
		if len(queue) == 0 {
			break
		}
		// maxResults=0 means no cap
		if maxResults > 0 && len(results) >= maxResults {
			break
		}

		fmt.Printf("  [depth %d/%d] queue=%d found=%d...\n", depth+1, maxDepth, len(queue), len(results))

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
						// maxResults=0 means no cap
						if maxResults == 0 || len(results) < maxResults {
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
		fmt.Printf("  [depth %d/%d] done — found %d chains so far, next queue=%d\n", depth+1, maxDepth, len(results), len(nextQueue))

		// Cap queue to prevent explosion
		if len(nextQueue) > maxQueuePerDepth {
			fmt.Printf("  [WARN] queue capped at %d (was %d) — increase depth or reduce offset for better results\n", maxQueuePerDepth, len(nextQueue))
			nextQueue = nextQueue[:maxQueuePerDepth]
		}
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
func VerifyChain(handle windows.Handle, modules []ModuleInfo, chain PointerChain, is32Bit bool) (uintptr, bool) {
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
		var ptr uintptr
		var err error
		if is32Bit {
			buf, e := ReadMemory(handle, addr, 4)
			if e != nil || len(buf) < 4 {
				return 0, false
			}
			ptr = uintptr(binary.LittleEndian.Uint32(buf))
		} else {
			ptr, err = ReadPointer(handle, addr)
			if err != nil || ptr == 0 {
				return 0, false
			}
		}
		// offset stored as two's complement — works for both signs
		addr = ptr + offset
	}
	return addr, true
}
