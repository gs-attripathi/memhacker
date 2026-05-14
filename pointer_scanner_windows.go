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
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

const pmapMagic   = uint32(0x504D4150) // "PMAP"
const pmapVersion = uint32(3)           // v3: added module path

type ptrEntry struct {
	value uintptr // what is stored at addr (the pointer value)
	addr  uintptr // memory location that holds this value
}

type PointerMap struct {
	Entries    []ptrEntry // sorted ascending by .value
	Modules    []ModuleInfo
	CreatedAt  time.Time
	PID        uint32
	TargetAddr uintptr // address we want to reach via pointer chain
	Is32Bit    bool
}

type PointerScanSession struct {
	PMap        *PointerMap
	Label       string
	TargetAddrs []uintptr // multiple target addresses for same pmap (CE-style)
}

type PointerChain struct {
	BaseModule string
	BaseOffset uintptr   // offset from module base to the static pointer
	Offsets    []uintptr // chain offsets, each stored as two's-complement (handles negative)
}

// Key produces a string that uniquely identifies a chain structure.
// Two chains with the same Key() in different sessions = static pointer found.
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
		signed := int64(o)
		if signed < 0 {
			s += fmt.Sprintf(" -> [-%X]", uint64(-signed))
		} else {
			s += fmt.Sprintf(" -> [+%X]", o)
		}
	}
	return s
}

type PointerResult struct {
	Chain PointerChain
}

type PointerScanConfig struct {
	Sessions   []PointerScanSession
	MaxDepth   int
	MaxOffset  uintptr
	MaxResults int
	BaseFilter string
	ChainCap   int // max chains per session, 0 = default (10M)
}

// ---------------------------------------------------------------------------
// Save / Load
// ---------------------------------------------------------------------------

func (pm *PointerMap) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create pmap file: %v", err)
	}
	defer f.Close()

	bw := bufio.NewWriterSize(f, 8*1024*1024)
	w := func(v interface{}) { binary.Write(bw, binary.LittleEndian, v) }

	w(pmapMagic)
	w(pmapVersion)
	w(pm.PID)
	w(pm.CreatedAt.Unix())
	w(uint64(pm.TargetAddr))
	is32 := uint8(0)
	if pm.Is32Bit { is32 = 1 }
	w(is32)

	w(uint32(len(pm.Modules)))
	for _, m := range pm.Modules {
		name := []byte(m.Name)
		w(uint16(len(name)))
		bw.Write(name)
		// Save path too so IsGameDir can be reconstructed on load
		path := []byte(m.Path)
		w(uint16(len(path)))
		bw.Write(path)
		w(uint64(m.Base))
		w(m.Size)
	}

	w(uint64(len(pm.Entries)))
	buf := make([]byte, len(pm.Entries)*16)
	for i, e := range pm.Entries {
		binary.LittleEndian.PutUint64(buf[i*16:],   uint64(e.value))
		binary.LittleEndian.PutUint64(buf[i*16+8:], uint64(e.addr))
	}
	bw.Write(buf)
	return bw.Flush()
}

func LoadPointerMap(path string) (*PointerMap, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open pmap file: %v", err)
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 8*1024*1024)
	r := func(v interface{}) error { return binary.Read(br, binary.LittleEndian, v) }

	var magic, version, pid uint32
	var ts int64
	var targetAddr uint64
	var is32 uint8

	r(&magic)
	if magic != pmapMagic {
		return nil, fmt.Errorf("not a valid pmap file (bad magic 0x%X)", magic)
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

		// v3+: read module path
		var path string
		if version >= 3 {
			var plen uint16
			r(&plen)
			pathBuf := make([]byte, plen)
			io.ReadFull(br, pathBuf)
			path = string(pathBuf)
		}

		var base uint64
		var size uint32
		r(&base)
		r(&size)
		mods[i] = ModuleInfo{
			Name:     string(nameBuf),
			Base:     uintptr(base),
			Size:     size,
			Path:     path,
			IsSystem: classifyModule(path),
		}
		if path == "" {
			mods[i].IsSystem = isSystemModuleName(mods[i].Name)
		}
	}

	// Derive game root from first module path (first module = main exe)
	gameRoot := ""
	if len(mods) > 0 && mods[0].Path != "" {
		p := strings.ToLower(mods[0].Path)
		for i := len(p) - 1; i >= 0; i-- {
			if p[i] == '\\' || p[i] == '/' {
				gameRoot = p[:i+1]
				break
			}
		}
	}
	// Set IsGameDir for all modules
	for i := range mods {
		if gameRoot != "" {
			mods[i].IsGameDir = strings.HasPrefix(strings.ToLower(mods[i].Path), gameRoot)
		}
	}

	var entryCount uint64
	r(&entryCount)

	entryBuf := make([]byte, entryCount*16)
	if _, err := io.ReadFull(br, entryBuf); err != nil {
		return nil, fmt.Errorf("failed to read entries: %v", err)
	}
	entries := make([]ptrEntry, entryCount)
	for i := range entries {
		entries[i].value = uintptr(binary.LittleEndian.Uint64(entryBuf[i*16:]))
		entries[i].addr  = uintptr(binary.LittleEndian.Uint64(entryBuf[i*16+8:]))
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

// isSystemModuleName checks module name (not path) for known system DLL names.
// Used when loading a pmap where we don't have the full path.
func isSystemModuleName(name string) bool {
	systemNames := []string{
		"ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
		"gdi32.dll", "advapi32.dll", "msvcrt.dll", "ws2_32.dll",
		"rpcrt4.dll", "ole32.dll", "oleaut32.dll", "shell32.dll",
		"shlwapi.dll", "comctl32.dll", "comdlg32.dll", "winmm.dll",
		"imm32.dll", "msctf.dll", "uxtheme.dll", "dwmapi.dll",
		"sechost.dll", "bcryptprimitives.dll", "clbcatq.dll",
		"cfgmgr32.dll", "win32u.dll", "gdi32full.dll", "msvcp_win.dll",
		"ucrtbase.dll", "combase.dll", "shcore.dll", "wintypes.dll",
	}
	// GPU driver DLLs — not system but not game either, skip as base
	driverPrefixes := []string{
		"nvwgf2um", "nvwgf2umx", "nvcuda", "nvopencl", // NVIDIA
		"amdxc",  "atig6pxx", "atidxx",                // AMD
		"igdumdim", "ig75icd",                          // Intel
		"d3d9", "d3d10", "d3d11", "d3d12",             // D3D runtime
		"dxgi", "dxcore",
	}
	lower := strings.ToLower(name)
	for _, s := range systemNames {
		if lower == s {
			return true
		}
	}
	for _, p := range driverPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Build pointer map
// ---------------------------------------------------------------------------

func BuildPointerMap(handle windows.Handle, modules []ModuleInfo, pid uint32, is32Bit bool) (*PointerMap, error) {
	Log.Info("BuildPointerMap: starting, %d modules, is32Bit=%v", len(modules), is32Bit)

	ptrSz := 8
	maxUserAddr := uintptr(0x7FFFFFFFFFFF)
	if is32Bit {
		ptrSz = 4
		maxUserAddr = uintptr(0x7FFFFFFF)
	}

	regions := EnumMemoryRegions(handle, false)
	Log.Debug("BuildPointerMap: %d readable regions", len(regions))

	// Build sorted range list for O(log n) valid-address checks
	type addrRange struct{ lo, hi uintptr }
	ranges := make([]addrRange, len(regions))
	for i, r := range regions {
		ranges[i] = addrRange{r.BaseAddress, r.BaseAddress + r.RegionSize}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })

	isValidAddr := func(v uintptr) bool {
		if v < 0x10000 || v > maxUserAddr {
			return false
		}
		lo, hi := 0, len(ranges)-1
		for lo <= hi {
			mid := (lo + hi) / 2
			switch {
			case v < ranges[mid].lo:
				hi = mid - 1
			case v >= ranges[mid].hi:
				lo = mid + 1
			default:
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
				start := r.BaseAddress
				if rem := start % uintptr(ptrSz); rem != 0 {
					start += uintptr(ptrSz) - rem
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
			fmt.Printf("\r  scanning regions... %d/%d (%d pointers found)  ", done, total, len(all))
		}
	}
	fmt.Println()

	// Sort by value — required for binary-search lookups
	sort.Slice(all, func(i, j int) bool { return all[i].value < all[j].value })

	Log.Info("BuildPointerMap: done, %d entries", len(all))
	return &PointerMap{
		Entries:   all,
		Modules:   modules,
		CreatedAt: time.Now(),
		PID:       pid,
		Is32Bit:   is32Bit,
	}, nil
}

// findInRange returns all entries with value in [lo, hi] using binary search.
func (pm *PointerMap) findInRange(lo, hi uintptr) []ptrEntry {
	if lo > hi {
		return nil
	}
	i := sort.Search(len(pm.Entries), func(k int) bool { return pm.Entries[k].value >= lo })
	j := sort.Search(len(pm.Entries), func(k int) bool { return pm.Entries[k].value > hi })
	return pm.Entries[i:j]
}

// ---------------------------------------------------------------------------
// BFS pointer scan — single session
// ---------------------------------------------------------------------------

// bfsSingleSession performs backward BFS from target through the pointer map.
// It returns all pointer chains anchored at a non-system module (static address).
// hardCap limits how many chains are collected per session to prevent OOM.
const bfsHardCap  = 10_000_000 // max chains per session (CE default is ~10k but we keep more for cross-ref)
const bfsQueueCap = 2_000_000  // max queue per depth level

func bfsSingleSession(pm *PointerMap, target uintptr, maxDepth int, maxOffset uintptr, filter string, hardCap, queueCap int) []PointerChain {
	type qItem struct {
		addr    uintptr   // memory address to look backwards from
		offsets []uintptr // chain offsets built so far (innermost first)
	}

	var (
		results []PointerChain
		mu      sync.Mutex
	)

	queue := []qItem{{addr: target}}

	for depth := 0; depth < maxDepth && len(queue) > 0; depth++ {
		fmt.Printf("    depth %d/%d — queue=%d chains=%d\n", depth+1, maxDepth, len(queue), len(results))

		var nextQueue []qItem
		var nextMu   sync.Mutex

		numCPU := runtime.NumCPU()
		jobs    := make(chan qItem, len(queue))
		for _, q := range queue { jobs <- q }
		close(jobs)

		var wg sync.WaitGroup
		for i := 0; i < numCPU; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for item := range jobs {
					// Search for entries whose value is within maxOffset of item.addr
					// Both directions: item.addr - maxOffset  to  item.addr + maxOffset
					scanLo := uintptr(0)
					if item.addr > maxOffset {
						scanLo = item.addr - maxOffset
					}
					scanHi := item.addr + maxOffset

					ptrs := pm.findInRange(scanLo, scanHi)
					for _, p := range ptrs {
						// Compute offset = item.addr - p.value (may be negative → two's complement)
						offset := item.addr - p.value // works correctly for both signs in uintptr arithmetic

						// Build new chain: prepend this offset
						newOffsets := make([]uintptr, len(item.offsets)+1)
						newOffsets[0] = offset
						copy(newOffsets[1:], item.offsets)

					if mod := findStaticModule(pm.Modules, p.addr, filter); mod != nil {
						mu.Lock()
						if hardCap == 0 || len(results) < hardCap {
							results = append(results, PointerChain{
								BaseModule: mod.Name,
								BaseOffset: p.addr - mod.Base,
								Offsets:    newOffsets,
							})
						}
						mu.Unlock()
					} else {
						nextMu.Lock()
						nextQueue = append(nextQueue, qItem{
							addr:    p.addr,
							offsets: newOffsets,
						})
						nextMu.Unlock()
					}
				} // end for ptrs
			} // end for jobs
			}()
		}
		wg.Wait()

		if len(nextQueue) > 0 && queueCap > 0 && len(nextQueue) > queueCap {
			fmt.Printf("  [WARN] queue capped at %d (was %d)\n", queueCap, len(nextQueue))
			nextQueue = nextQueue[:queueCap]
		}
		queue = nextQueue
	}

	return results
}

// findStaticModule returns the module containing addr based on filter:
// "exe"  = only the main executable (.exe)
// "game" = any module inside the game's root directory (detected from exe path)
// "all"  = any module including GPU/driver/system DLLs
func findStaticModule(modules []ModuleInfo, addr uintptr, filter string) *ModuleInfo {
	for i := range modules {
		m := &modules[i]
		if addr < m.Base || addr >= m.Base+uintptr(m.Size) {
			continue
		}
		switch filter {
		case "exe":
			if strings.HasSuffix(strings.ToLower(m.Name), ".exe") {
				return m
			}
		case "game":
			// Use IsGameDir — set from actual game root directory at attach time
			// Falls back to non-system if IsGameDir not set (e.g. loaded from old pmap)
			if m.IsGameDir {
				return m
			}
		case "all":
			return m
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Multi-session pointer scan
// ---------------------------------------------------------------------------

func MultiSessionPointerScan(cfg PointerScanConfig) []PointerResult {
	if len(cfg.Sessions) == 0 {
		return nil
	}

	maxResults := cfg.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}

	// Default filter: exe only
	filter := cfg.BaseFilter
	if filter == "" {
		filter = "exe"
	}

	// Warn on duplicate sessions
	seen := map[string]bool{}
	for _, s := range cfg.Sessions {
		key := fmt.Sprintf("%s_%X", s.Label, s.PMap.TargetAddr)
		if seen[key] {
			fmt.Printf("  [WARN] Duplicate session: %s target=0x%X\n", s.Label, s.PMap.TargetAddr)
		}
		seen[key] = true
	}

	// Try with current filter only — no auto-widen (causes noise from runtime DLLs)
	fmt.Printf("\nBase filter: %s\n", filterLabel(filter))
	Log.Info("MultiSessionPointerScan: filter=%s depth=%d offset=0x%X maxResults=%d", filter, cfg.MaxDepth, cfg.MaxOffset, maxResults)

	results := runScan(cfg.Sessions, cfg.MaxDepth, cfg.MaxOffset, maxResults, filter, cfg.ChainCap)

	if len(results) > 0 {
		Log.Info("MultiSessionPointerScan: %d results with filter=%s", len(results), filter)
		return results
	}

	// No results — tell user what to try, don't auto-widen
	fmt.Println("  No chains found.")
	if filter == "exe" {
		fmt.Println("  Tip: exe-anchored chains need more depth. Try:")
		fmt.Println("       pscan 9 5000 100        <- more depth")
		fmt.Println("       pscan 7 5000 100 game   <- include game DLLs (may include runtime DLLs)")
	} else if filter == "game" {
		fmt.Println("  Tip: try pscan 7 5000 100 all  (includes GPU/driver DLLs, less reliable)")
	}
	return nil
}

func filterLabel(f string) string {
	switch f {
	case "exe":
		return "main EXE only (most reliable)"
	case "game":
		return "game DLLs + EXE (non-system)"
	case "all":
		return "all modules including GPU/driver DLLs"
	}
	return f
}

func runScan(sessions []PointerScanSession, maxDepth int, maxOffset uintptr, maxResults int, filter string, chainCap int) []PointerResult {
	hCap := chainCap
	if hCap <= 0 {
		hCap = bfsHardCap
	}
	qCap := hCap * 2 // queue cap = 2x chain cap
	allChains := make([]map[string]PointerChain, len(sessions))

	for idx, sess := range sessions {
		// Collect target addresses — from TargetAddrs list if set, else from PMap.TargetAddr
		targets := sess.TargetAddrs
		if len(targets) == 0 {
			targets = []uintptr{sess.PMap.TargetAddr}
		}

		fmt.Printf("  Session [%d/%d] %s (%d entries, %d targets)\n",
			idx+1, len(sessions), sess.Label, len(sess.PMap.Entries), len(targets))
		Log.Info("  Session[%d] %s: BFS start filter=%s targets=%d", idx, sess.Label, filter, len(targets))

		// BFS each target address against this pmap, then intersect results
		var sessionMap map[string]PointerChain
		for ti, target := range targets {
			fmt.Printf("    target [%d/%d] 0x%X\n", ti+1, len(targets), target)
			chains := bfsSingleSession(sess.PMap, target, maxDepth, maxOffset, filter, hCap, qCap)
			m := make(map[string]PointerChain, len(chains))
			for _, c := range chains {
				m[c.Key()] = c
			}
			fmt.Printf("    => %d chains\n", len(chains))
			Log.Info("  Session[%d] target 0x%X: found %d chains", idx, target, len(chains))

			if sessionMap == nil {
				sessionMap = m
			} else {
				// Intersect — only chains present for ALL targets in this session
				filtered := make(map[string]PointerChain)
				for key, chain := range sessionMap {
					if _, ok := m[key]; ok {
						filtered[key] = chain
					}
				}
				sessionMap = filtered
			}
			fmt.Printf("    after intersect: %d candidates\n", len(sessionMap))
		}
		allChains[idx] = sessionMap
		fmt.Printf("    => session total: %d chains\n", len(sessionMap))
	}

	// Cross-reference across sessions
	candidates := allChains[0]
	for i := 1; i < len(allChains); i++ {
		filtered := make(map[string]PointerChain)
		for key, chain := range candidates {
			if _, ok := allChains[i][key]; ok {
				filtered[key] = chain
			}
		}
		candidates = filtered
		fmt.Printf("  After cross-ref with session %d: %d candidates\n", i+1, len(candidates))
	}

	var results []PointerResult
	for _, c := range candidates {
		results = append(results, PointerResult{Chain: c})
	}

	sort.Slice(results, func(i, j int) bool {
		ci, cj := results[i].Chain, results[j].Chain
		if len(ci.Offsets) != len(cj.Offsets) {
			return len(ci.Offsets) < len(cj.Offsets)
		}
		return ci.BaseOffset < cj.BaseOffset
	})

	if len(results) > maxResults {
		results = results[:maxResults]
	}
	return results
}

// ---------------------------------------------------------------------------
// Verify a chain against the live process
// ---------------------------------------------------------------------------

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
		if is32Bit {
			buf, err := ReadMemory(handle, addr, 4)
			if err != nil || len(buf) < 4 {
				return 0, false
			}
			ptr = uintptr(binary.LittleEndian.Uint32(buf))
		} else {
			var err error
			ptr, err = ReadPointer(handle, addr)
			if err != nil {
				return 0, false
			}
		}
		if ptr == 0 {
			return 0, false
		}
		addr = ptr + offset
	}
	return addr, true
}
