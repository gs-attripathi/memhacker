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
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

// ---------------------------------------------------------------------------
// File-format constants (unchanged — existing .pmap files remain compatible)
// ---------------------------------------------------------------------------

const pmapMagic   = uint32(0x504D4150) // "PMAP"
const pmapVersion = uint32(3)          // v3: module path included

// dfsQueueSize is the work-stealing channel buffer.
// When full, workers recurse inline (DFS) — CE-style natural backpressure.
// No OOM possible: inline recursion depth is bounded by maxDepth (7-12 typically).
const dfsQueueSize = 32768

// maxDepthCap is the compile-time max depth that fits in a dfsJob.
const maxDepthCap = 24

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

type ptrEntry struct {
	value uintptr // pointer value stored at addr
	addr  uintptr // memory address that holds this pointer value
}

type PointerMap struct {
	Entries    []ptrEntry // sorted ascending by .value
	Modules    []ModuleInfo
	CreatedAt  time.Time
	PID        uint32
	TargetAddr uintptr
	Is32Bit    bool
}

type PointerScanSession struct {
	PMap        *PointerMap
	Label       string
	TargetAddrs []uintptr // multiple target addrs (CE-style pmadd)
}

type PointerChain struct {
	BaseModule string
	BaseOffset uintptr   // offset from module base to the static pointer
	Offsets    []uintptr // chain offsets, outermost first
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
	ChainCap   int // kept for API compat; DFS no longer needs a cap
}

// ---------------------------------------------------------------------------
// Pmap Save / Load (binary format unchanged)
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
	if pm.Is32Bit {
		is32 = 1
	}
	w(is32)

	w(uint32(len(pm.Modules)))
	for _, m := range pm.Modules {
		name := []byte(m.Name)
		w(uint16(len(name)))
		bw.Write(name)
		mpath := []byte(m.Path)
		w(uint16(len(mpath)))
		bw.Write(mpath)
		w(uint64(m.Base))
		w(m.Size)
	}

	w(uint64(len(pm.Entries)))
	buf := make([]byte, len(pm.Entries)*16)
	for i, e := range pm.Entries {
		binary.LittleEndian.PutUint64(buf[i*16:], uint64(e.value))
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

		var mpath string
		if version >= 3 {
			var plen uint16
			r(&plen)
			pathBuf := make([]byte, plen)
			io.ReadFull(br, pathBuf)
			mpath = string(pathBuf)
		}

		var base uint64
		var size uint32
		r(&base)
		r(&size)
		mods[i] = ModuleInfo{
			Name:     string(nameBuf),
			Base:     uintptr(base),
			Size:     size,
			Path:     mpath,
			IsSystem: classifyModule(mpath),
		}
		if mpath == "" {
			mods[i].IsSystem = isSystemModuleName(mods[i].Name)
		}
	}

	// Derive game root from first module path (main exe)
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
	driverPrefixes := []string{
		"nvwgf2um", "nvwgf2umx", "nvcuda", "nvopencl",
		"amdxc", "atig6pxx", "atidxx",
		"igdumdim", "ig75icd",
		"d3d9", "d3d10", "d3d11", "d3d12",
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

// findInRange returns all entries with value in [lo, hi]. Used externally.
func (pm *PointerMap) findInRange(lo, hi uintptr) []ptrEntry {
	if lo > hi {
		return nil
	}
	i := sort.Search(len(pm.Entries), func(k int) bool { return pm.Entries[k].value >= lo })
	j := sort.Search(len(pm.Entries), func(k int) bool { return pm.Entries[k].value > hi })
	return pm.Entries[i:j]
}

// ---------------------------------------------------------------------------
// CE-style DFS pointer scanner with work-stealing goroutine pool
//
// Algorithm matches Cheat Engine's PointerscanWorker.rscan():
//  - Scan backward from target: find all ptr values in [target-maxOffset, target]
//  - For each value group: compute offset = target - ptrValue
//  - For each address holding that value:
//      static (in module) -> save chain (done!)
//      non-static          -> go deeper (level+1)
//  - "Go deeper" = try to enqueue to goroutine pool; if pool full, recurse inline
//  - Natural backpressure: full pool = inline DFS, stack bounded by maxDepth
//  - No OOM: no BFS queue that grows exponentially
// ---------------------------------------------------------------------------

// dfsJob is a unit of work for the goroutine pool.
// Offsets are stored in a fixed array (no heap alloc per job).
type dfsJob struct {
	addr  uintptr
	level int
	noff  int                   // number of valid offsets in offs
	offs  [maxDepthCap]uintptr  // chain offsets built so far
}

// dfsRunner holds the shared state for one dfsSingleSession call.
type dfsRunner struct {
	pm        *PointerMap
	jobs      chan dfsJob
	wg        sync.WaitGroup
	mu        sync.Mutex
	results   []PointerChain

	maxDepth   int
	maxOffset  uintptr
	filter     string
	resultsCap int    // stop collecting per-session when we hit this many chains
	stopped    int32  // atomic: 1 = stop submitting new work
}

// submit adds a job to the goroutine pool.
// If the pool's channel is full it runs inline — CE's "do it myself" fallback.
func (r *dfsRunner) submit(job dfsJob) {
	if atomic.LoadInt32(&r.stopped) != 0 {
		return
	}
	r.wg.Add(1)
	select {
	case r.jobs <- job:
		// a worker goroutine will pick it up and call r.run()
	default:
		// channel full: run inline on current goroutine (bounded by maxDepth recursion)
		r.run(job)
	}
}

// run processes one job and decrements the WaitGroup when done.
func (r *dfsRunner) run(job dfsJob) {
	defer r.wg.Done()
	r.rscan(job.addr, job.level, job.offs, job.noff)
}

// rscan is the core DFS — mirrors CE's TPointerscanWorker.rscan().
// It scans backward from addr through the pointer map, follows chains,
// and records chains that reach a static (module) address.
func (r *dfsRunner) rscan(addr uintptr, level int, offs [maxDepthCap]uintptr, noff int) {
	if atomic.LoadInt32(&r.stopped) != 0 {
		return
	}

	entries := r.pm.Entries

	startVal := uintptr(0)
	if addr >= r.maxOffset {
		startVal = addr - r.maxOffset
	}

	// Find the rightmost entry with value <= addr (CE: stopvalue = valuetofind initially)
	hi := sort.Search(len(entries), func(i int) bool {
		return entries[i].value > addr
	}) - 1

	// Walk backward through value groups — mirrors CE's "plist = plist.previous" loop
	for hi >= 0 {
		val := entries[hi].value
		if val < startVal {
			break // all remaining values are too small (< addr-maxOffset)
		}

		// CE: tempresults[level] := valuetofind - stopvalue
		offs[noff] = addr - val // offset at this level (always 0..maxOffset)

		// Find the start of this value group (entries with same .value are contiguous)
		lo := hi
		for lo > 0 && entries[lo-1].value == val {
			lo--
		}

		// Process every address that holds this pointer value
		for i := lo; i <= hi; i++ {
			e := entries[i]

			if mod := findStaticModule(r.pm.Modules, e.addr, r.filter); mod != nil {
				// CE: StorePath — found a chain anchored to a static module!
				chain := PointerChain{
					BaseModule: mod.Name,
					BaseOffset: e.addr - mod.Base,
					Offsets:    append([]uintptr(nil), offs[:noff+1]...),
				}
				r.mu.Lock()
				r.results = append(r.results, chain)
				hitCap := r.resultsCap > 0 && len(r.results) >= r.resultsCap
				r.mu.Unlock()
				if hitCap {
					atomic.StoreInt32(&r.stopped, 1)
					return
				}
			} else if level+1 < r.maxDepth {
				// CE: enqueue or recurse inline
				childJob := dfsJob{
					addr:  e.addr,
					level: level + 1,
					offs:  offs,
					noff:  noff + 1,
				}
				r.submit(childJob)
			}
			// If level+1 >= maxDepth and not static: dead end — discard (CE: "end of the line")
		}

		// Step to next lower value group (CE: plist = plist.previous)
		hi = lo - 1
	}
}

// dfsSingleSession runs the CE-style DFS scan on one pointer map for one target address.
// Returns all chains anchored at a static module address, up to resultsCap chains.
func dfsSingleSession(pm *PointerMap, target uintptr, maxDepth int, maxOffset uintptr, filter string, resultsCap int) []PointerChain {
	numWorkers := runtime.NumCPU()

	r := &dfsRunner{
		pm:         pm,
		jobs:       make(chan dfsJob, dfsQueueSize),
		maxDepth:   maxDepth,
		maxOffset:  maxOffset,
		filter:     filter,
		resultsCap: resultsCap,
	}

	// Launch worker goroutines — they block on the jobs channel
	for i := 0; i < numWorkers; i++ {
		go func() {
			for job := range r.jobs {
				r.run(job)
			}
		}()
	}

	// Progress ticker — prints every 5s so user knows scan is alive
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		start := time.Now()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				r.mu.Lock()
				n := len(r.results)
				r.mu.Unlock()
				q := len(r.jobs)
				fmt.Printf("    ... %v elapsed | chains=%d | queue=%d\n",
					time.Since(start).Round(time.Second), n, q)
			}
		}
	}()

	// Seed the initial job
	var initial dfsJob
	initial.addr = target
	r.submit(initial)

	// Block until all DFS work is done
	r.wg.Wait()
	close(done)   // stop progress ticker
	close(r.jobs) // signal all worker goroutines to exit

	return r.results
}

// ---------------------------------------------------------------------------
// findStaticModule — CE's "is this address in a module?" check
// ---------------------------------------------------------------------------

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

	filter := cfg.BaseFilter
	if filter == "" {
		filter = "exe"
	}

	// No cap — DFS stack depth is bounded by maxDepth so OOM is impossible.
	// A cap here caused cross-session intersection to fail (valid chains cut off early).
	perSessionCap := 0

	fmt.Printf("\nBase filter: %s\n", filterLabel(filter))
	Log.Info("MultiSessionPointerScan: filter=%s depth=%d offset=0x%X maxResults=%d sessions=%d",
		filter, cfg.MaxDepth, cfg.MaxOffset, maxResults, len(cfg.Sessions))

	results := runScan(cfg.Sessions, cfg.MaxDepth, cfg.MaxOffset, maxResults, filter, perSessionCap)

	if len(results) > 0 {
		Log.Info("MultiSessionPointerScan: %d results with filter=%s", len(results), filter)
		return results
	}

	fmt.Println("  No chains found.")
	if filter == "exe" {
		fmt.Println("  Tips:")
		fmt.Println("    pscan 9 5000 100          <- more depth")
		fmt.Println("    pscan 7 5000 100 game     <- include game DLLs")
		fmt.Println("    pscan 7 5000 100 all      <- include all modules (noisy)")
	} else if filter == "game" {
		fmt.Println("  Try: pscan 7 5000 100 all")
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

func runScan(sessions []PointerScanSession, maxDepth int, maxOffset uintptr, maxResults int, filter string, perSessionCap int) []PointerResult {
	allChains := make([]map[string]PointerChain, len(sessions))

	for idx, sess := range sessions {
		// Collect target addresses from TargetAddrs or fallback to PMap.TargetAddr
		targets := sess.TargetAddrs
		if len(targets) == 0 {
			targets = []uintptr{sess.PMap.TargetAddr}
		}

		fmt.Printf("  Session [%d/%d] %s (%d entries, %d targets)\n",
			idx+1, len(sessions), sess.Label, len(sess.PMap.Entries), len(targets))
		Log.Info("Session[%d] %s: DFS start filter=%s targets=%d", idx, sess.Label, filter, len(targets))

		// DFS each target address, then intersect results within this session (CE-style pmadd)
		var sessionMap map[string]PointerChain
		for ti, target := range targets {
			fmt.Printf("    target [%d/%d] 0x%X — scanning...\n", ti+1, len(targets), target)
			start := time.Now()
			chains := dfsSingleSession(sess.PMap, target, maxDepth, maxOffset, filter, perSessionCap)
			elapsed := time.Since(start)

			m := make(map[string]PointerChain, len(chains))
			for _, c := range chains {
				m[c.Key()] = c
			}
			fmt.Printf("    => %d chains in %v\n", len(chains), elapsed)
			Log.Info("Session[%d] target 0x%X: found %d chains in %v", idx, target, len(chains), elapsed)

			if sessionMap == nil {
				sessionMap = m
			} else {
				// Intersect — keep only chains present for ALL targets (CE: pmadd behavior)
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
		fmt.Printf("  Session [%d] total: %d chains\n", idx+1, len(sessionMap))
	}

	// Cross-reference across sessions — keep only chains present in ALL sessions
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
// VerifyChain — follow a saved chain in the live process
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
