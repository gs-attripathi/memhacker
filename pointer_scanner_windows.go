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
// File-format constants
// ---------------------------------------------------------------------------

const pmapMagic   = uint32(0x504D4150) // "PMAP"
const pmapVersion = uint32(3)

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

type ptrEntry struct {
	value uintptr // pointer value stored at this memory location
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
	TargetAddrs []uintptr // multiple targets (CE-style pmadd)
}

// PointerChain stores a complete pointer path.
// Offsets are stored STATIC→TARGET order (CE convention):
//   Offsets[0] = first offset after dereferencing the static base ptr
//   Offsets[N] = last offset that reaches the target
// This matches VerifyChain's iteration order exactly.
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
	Label string
}

type PointerScanConfig struct {
	Sessions          []PointerScanSession
	MaxDepth          int
	MaxOffset         uintptr
	MaxResults        int
	BaseFilter        string
	MaxOffsetsPerNode int // CE's LimitToMaxOffsetsPerNode (0 = use default 5)
	ChainCap          int // unused, kept for API compat
}

// ---------------------------------------------------------------------------
// Pmap Save / Load
// ---------------------------------------------------------------------------

func (pm *PointerMap) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create pmap file: %v", err)
	}
	defer f.Close()

	bw := bufio.NewWriterSize(f, 8*1024*1024)
	w := func(v interface{}) { binary.Write(bw, binary.LittleEndian, v) }

	w(pmapMagic); w(pmapVersion); w(pm.PID)
	w(pm.CreatedAt.Unix()); w(uint64(pm.TargetAddr))
	is32 := uint8(0)
	if pm.Is32Bit {
		is32 = 1
	}
	w(is32)

	w(uint32(len(pm.Modules)))
	for _, m := range pm.Modules {
		name := []byte(m.Name)
		w(uint16(len(name))); bw.Write(name)
		mpath := []byte(m.Path)
		w(uint16(len(mpath))); bw.Write(mpath)
		w(uint64(m.Base)); w(m.Size)
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
	r(&version); r(&pid); r(&ts); r(&targetAddr); r(&is32)

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
		r(&base); r(&size)
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

	// Reconstruct game root using the same iterative-strip heuristic as gameRootFromModules.
	// First module in a pmap is always the main exe.
	gameRoot := ""
	if len(mods) > 0 && mods[0].Path != "" {
		p := strings.ToLower(mods[0].Path)
		// Get exe's immediate parent directory
		for i := len(p) - 1; i >= 0; i-- {
			if p[i] == '\\' || p[i] == '/' {
				gameRoot = p[:i+1]
				break
			}
		}
		// Strip recognized bin subdirs from the tail, same as gameRootFromModules
		subDirNames := []string{"bin\\", "bin32\\", "bin64\\", "win32\\", "win64\\", "binaries\\", "x64\\", "x86\\"}
		for {
			stripped := false
			for _, sub := range subDirNames {
				if strings.HasSuffix(gameRoot, sub) {
					candidate := strings.TrimSuffix(gameRoot, sub)
					if candidate != "" {
						gameRoot = candidate
						stripped = true
						break
					}
				}
			}
			if !stripped {
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
		if lower == s { return true }
	}
	for _, p := range driverPrefixes {
		if strings.HasPrefix(lower, p) { return true }
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
		if v < 0x10000 || v > maxUserAddr { return false }
		lo, hi := 0, len(ranges)-1
		for lo <= hi {
			mid := (lo + hi) / 2
			switch {
			case v < ranges[mid].lo:  hi = mid - 1
			case v >= ranges[mid].hi: lo = mid + 1
			default:                  return true
			}
		}
		return false
	}

	numCPU := runtime.NumCPU()
	jobs := make(chan MEMORY_BASIC_INFORMATION, len(regions))
	for _, r := range regions { jobs <- r }
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
				if size < ptrSz { continue }
				data, err := ReadMemory(handle, r.BaseAddress, size)
				if err != nil || len(data) < ptrSz { continue }
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
						local = append(local, ptrEntry{value: v, addr: r.BaseAddress + uintptr(i)})
					}
				}
				if len(local) > 0 { resultChan <- local }
			}
		}()
	}
	go func() { wg.Wait(); close(resultChan) }()

	var all []ptrEntry
	total, done := len(regions), 0
	for batch := range resultChan {
		all = append(all, batch...)
		done++
		if done%50 == 0 || done == total {
			fmt.Printf("\r  scanning regions... %d/%d (%d pointers)  ", done, total, len(all))
		}
	}
	fmt.Println()

	sort.Slice(all, func(i, j int) bool { return all[i].value < all[j].value })
	Log.Info("BuildPointerMap: done, %d entries", len(all))
	return &PointerMap{Entries: all, Modules: modules, CreatedAt: time.Now(), PID: pid, Is32Bit: is32Bit}, nil
}

func (pm *PointerMap) findInRange(lo, hi uintptr) []ptrEntry {
	if lo > hi { return nil }
	i := sort.Search(len(pm.Entries), func(k int) bool { return pm.Entries[k].value >= lo })
	j := sort.Search(len(pm.Entries), func(k int) bool { return pm.Entries[k].value > hi })
	return pm.Entries[i:j]
}

// ---------------------------------------------------------------------------
// CE-style DFS pointer scanner
//
// Mirrors PointerscanWorker.rscan() exactly.
//
// Key correctness features from CE source:
//   1. noLoop — skip address if already visited in current chain (prevents cycles)
//   2. maxOffsetsPerNode — limit distinct pointer value groups per node,
//      but ONLY at level > 0 (CE never limits at level 0 / target level)
//   3. Offsets stored STATIC→TARGET order so VerifyChain works correctly
//
// Key performance features from CE source:
//   4. Queue priority — last 3 levels always inline (CE never enqueues near-leaf work)
//      Prevents queue flooding with cheap shallow work; deep work gets distributed
// ---------------------------------------------------------------------------

const maxDepthCap  = 16   // depth >16 is never useful; smaller = smaller job structs
const dfsQueueSize = 1 << 18 // 262144 — large queue reduces unnecessary inline serialisation

type dfsJob struct {
	addr    uintptr
	level   int
	noff    int                    // offsets accumulated so far
	offs    [maxDepthCap]uintptr   // offs[0]=level0 offset (near target), offs[noff-1]=deepest
	visited [maxDepthCap]uintptr   // addresses in current chain for noLoop
}

type dfsRunner struct {
	pm           *PointerMap
	staticRanges []moduleRange // pre-built, sorted — replaces per-address O(n) module scan
	jobs         chan dfsJob
	resultsCh    chan PointerChain  // lockless: workers send here, collector goroutine drains
	wg           sync.WaitGroup
	found        int64 // atomic, for progress ticker

	maxDepth          int
	maxOffset         uintptr
	maxOffsetsPerNode int
	noLoop            bool
	stopped           int32
}

// submit — CE's queue/inline policy:
// Only enqueue if level+3 < maxDepth (not last 3 levels).
// Last 3 levels are always inlined — avoids flooding queue with near-leaf work.
func (r *dfsRunner) submit(job dfsJob) {
	if atomic.LoadInt32(&r.stopped) != 0 { return }
	r.wg.Add(1)

	// CE: only try to queue for non-leaf work (level+3 < maxlevel)
	if job.level+3 < r.maxDepth {
		select {
		case r.jobs <- job:
			return // worker goroutine will handle it
		default:
			// channel full: fall through to inline
		}
	}
	// inline recursion — CE: "I'll have to do it myself"
	r.run(job)
}

func (r *dfsRunner) run(job dfsJob) {
	defer r.wg.Done()
	r.rscan(job.addr, job.level, job.offs, job.noff, job.visited)
}

// rscan — mirrors CE's TPointerscanWorker.rscan() exactly.
//
// Offset accumulation note:
//   offs[0] is set at level 0 (scanning from target):  offs[0] = target - ptrValue
//   offs[1] is set at level 1:                          offs[1] = level0_addr - ptrValue
//   offs[noff] is set at current level
//
// When a static address is found at level L (noff=L), we store the chain with
// offsets REVERSED so that chain.Offsets[0] is the deepest offset (near static)
// and chain.Offsets[L] is the shallowest (near target).
// VerifyChain applies offsets in slice order (index 0 first), which correctly
// starts from static and walks toward target.
func (r *dfsRunner) rscan(addr uintptr, level int, offs [maxDepthCap]uintptr, noff int, visited [maxDepthCap]uintptr) {
	if atomic.LoadInt32(&r.stopped) != 0 { return }

	// CE: noLoop — exit if this address is already in the current chain
	if r.noLoop {
		for i := 0; i < level; i++ {
			if visited[i] == addr { return }
		}
		visited[level] = addr
	}

	entries := r.pm.Entries

	startVal := uintptr(0)
	if addr >= r.maxOffset {
		startVal = addr - r.maxOffset
	}

	// Binary search: rightmost index with .value <= addr.
	// Inlined to avoid sort.Search closure overhead — this runs millions of times.
	blo, bhi := 0, len(entries)
	for blo < bhi {
		mid := int(uint(blo+bhi) >> 1)
		if entries[mid].value > addr {
			bhi = mid
		} else {
			blo = mid + 1
		}
	}
	hi := blo - 1

	// CE: DifferentOffsetsInThisNode counter
	offsetsAtNode := 0

	// Walk backward through pointer value groups — CE: "plist = plist.previous"
	for hi >= 0 {
		val := entries[hi].value
		if val < startVal { break }

		// CE: tempresults[level] = valuetofind - stopvalue
		offs[noff] = addr - val

		// Find start of this value group (contiguous entries with same .value)
		lo := hi
		for lo > 0 && entries[lo-1].value == val {
			lo--
		}

		// Process every address that holds this pointer value
		for i := lo; i <= hi; i++ {
			e := entries[i]

			if mod := findInRanges(r.staticRanges, e.addr); mod != nil {
				// CE: StorePath — found chain anchored at a static module address.
				//
				// Store offsets in REVERSED order (static→target):
				//   offs[noff] = deepest (nearest to static base)
				//   offs[0]    = shallowest (nearest to target)
				// Reversed so VerifyChain can apply them in index order correctly.
				offLen := noff + 1
				chainOffsets := make([]uintptr, offLen)
				for k := 0; k < offLen; k++ {
					chainOffsets[k] = offs[offLen-1-k]
				}
				chain := PointerChain{
					BaseModule: mod.Name,
					BaseOffset: e.addr - mod.Base,
					Offsets:    chainOffsets,
				}
				r.resultsCh <- chain
				atomic.AddInt64(&r.found, 1)

			} else if level+1 < r.maxDepth {
				// CE: non-static, go deeper — enqueue or inline
				child := dfsJob{
					addr:    e.addr,
					level:   level + 1,
					offs:    offs,
					noff:    noff + 1,
					visited: visited,
				}
				r.submit(child)
			}
			// level+1 >= maxDepth and not static: dead end (CE: "end of the line")
		}

		// CE: LimitToMaxOffsetsPerNode
		// Only counts at level > 0. At level 0 (target), never limit.
		if r.maxOffsetsPerNode > 0 && level > 0 {
			offsetsAtNode++
			if offsetsAtNode >= r.maxOffsetsPerNode {
				break
			}
		}

		hi = lo - 1 // step to previous value group (CE: plist = plist.previous)
	}
}

// dfsSingleSession runs the CE-style DFS for one target address.
func dfsSingleSession(pm *PointerMap, target uintptr, maxDepth int, maxOffset uintptr, filter string, maxOffsetsPerNode int) []PointerChain {
	if maxDepth > maxDepthCap {
		Log.Warn("maxDepth %d exceeds cap %d, clamping", maxDepth, maxDepthCap)
		maxDepth = maxDepthCap
	}

	numWorkers := runtime.NumCPU()

	r := &dfsRunner{
		pm:                pm,
		staticRanges:      buildStaticRanges(pm.Modules, filter),
		jobs:              make(chan dfsJob, dfsQueueSize),
		resultsCh:         make(chan PointerChain, 65536), // collector drains this; workers never block
		maxDepth:          maxDepth,
		maxOffset:         maxOffset,
		maxOffsetsPerNode: maxOffsetsPerNode,
		noLoop:            true,
	}

	// Collector goroutine — drains resultsCh without holding any lock
	var collWg sync.WaitGroup
	var collected []PointerChain
	collWg.Add(1)
	go func() {
		defer collWg.Done()
		for c := range r.resultsCh {
			collected = append(collected, c)
		}
	}()

	// Worker pool
	for i := 0; i < numWorkers; i++ {
		go func() {
			for job := range r.jobs {
				r.run(job)
			}
		}()
	}

	// Progress ticker
	doneCh := make(chan struct{})
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		start := time.Now()
		for {
			select {
			case <-doneCh:
				return
			case <-tick.C:
				n := atomic.LoadInt64(&r.found)
				q := len(r.jobs)
				fmt.Printf("    ... %v | chains=%d | queue=%d\n",
					time.Since(start).Round(time.Second), n, q)
			}
		}
	}()

	var initial dfsJob
	initial.addr = target
	r.submit(initial)

	r.wg.Wait()          // all DFS workers done
	close(doneCh)
	close(r.jobs)
	close(r.resultsCh)   // signal collector to finish
	collWg.Wait()        // wait for collector to drain

	return collected
}

// ---------------------------------------------------------------------------
// Fast static-module lookup — sorted by base address, binary searched.
// Replaces the O(n) linear scan inside the hot DFS loop.
// ---------------------------------------------------------------------------

type moduleRange struct {
	lo, hi uintptr
	mod    *ModuleInfo
}

func buildStaticRanges(modules []ModuleInfo, filter string) []moduleRange {
	var ranges []moduleRange
	for i := range modules {
		m := &modules[i]
		var include bool
		switch filter {
		case "exe":
			include = strings.HasSuffix(strings.ToLower(m.Name), ".exe")
		case "game":
			include = m.IsGameDir
		case "all":
			include = true
		}
		if include {
			ranges = append(ranges, moduleRange{m.Base, m.Base + uintptr(m.Size), m})
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })
	return ranges
}

func findInRanges(ranges []moduleRange, addr uintptr) *ModuleInfo {
	lo, hi := 0, len(ranges)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		r := ranges[mid]
		switch {
		case addr < r.lo:
			hi = mid - 1
		case addr >= r.hi:
			lo = mid + 1
		default:
			return r.mod
		}
	}
	return nil
}

// findStaticModule kept for any external callers; internally DFS uses findInRanges.
func findStaticModule(modules []ModuleInfo, addr uintptr, filter string) *ModuleInfo {
	return findInRanges(buildStaticRanges(modules, filter), addr)
}

// ---------------------------------------------------------------------------
// Multi-session pointer scan
// ---------------------------------------------------------------------------

func MultiSessionPointerScan(cfg PointerScanConfig) []PointerResult {
	if len(cfg.Sessions) == 0 { return nil }

	maxResults := cfg.MaxResults
	if maxResults <= 0 { maxResults = 100 }

	filter := cfg.BaseFilter
	if filter == "" { filter = "exe" }

	maxOffsets := cfg.MaxOffsetsPerNode
	if maxOffsets <= 0 { maxOffsets = 5 } // CE default

	fmt.Printf("\nBase filter: %s | maxOffsetsPerNode=%d | noLoop=true\n", filterLabel(filter), maxOffsets)
	Log.Info("MultiSessionPointerScan: filter=%s depth=%d offset=0x%X maxResults=%d sessions=%d maxOffsets=%d",
		filter, cfg.MaxDepth, cfg.MaxOffset, maxResults, len(cfg.Sessions), maxOffsets)

	results := runScan(cfg.Sessions, cfg.MaxDepth, cfg.MaxOffset, maxResults, filter, maxOffsets)
	if len(results) > 0 {
		Log.Info("MultiSessionPointerScan: %d results", len(results))
		return results
	}

	fmt.Println("  No chains found.")
	fmt.Println("  Tips:")
	fmt.Println("    pscan 5 5000 100            <- more depth")
	fmt.Println("    pscan 5 5000 100 game        <- include game DLLs")
	fmt.Println("    pscan 5 5000 100 exe 10      <- more offsets per node (slower, more thorough)")
	return nil
}

func filterLabel(f string) string {
	switch f {
	case "exe":  return "main EXE only"
	case "game": return "game DLLs + EXE"
	case "all":  return "all modules"
	}
	return f
}

func runScan(sessions []PointerScanSession, maxDepth int, maxOffset uintptr, maxResults int, filter string, maxOffsets int) []PointerResult {
	allChains := make([]map[string]PointerChain, len(sessions))

	for idx, sess := range sessions {
		targets := sess.TargetAddrs
		if len(targets) == 0 {
			targets = []uintptr{sess.PMap.TargetAddr}
		}

		fmt.Printf("  Session [%d/%d] %s (%d entries, %d targets)\n",
			idx+1, len(sessions), sess.Label, len(sess.PMap.Entries), len(targets))

		var sessionMap map[string]PointerChain
		for ti, target := range targets {
			fmt.Printf("    target [%d/%d] 0x%X — scanning...\n", ti+1, len(targets), target)
			start := time.Now()
			chains := dfsSingleSession(sess.PMap, target, maxDepth, maxOffset, filter, maxOffsets)
			elapsed := time.Since(start)

			m := make(map[string]PointerChain, len(chains))
			for _, c := range chains { m[c.Key()] = c }
			fmt.Printf("    => %d chains in %v\n", len(chains), elapsed)
			Log.Info("Session[%d] target 0x%X: %d chains in %v", idx, target, len(chains), elapsed)

			if sessionMap == nil {
				sessionMap = m
			} else {
				filtered := make(map[string]PointerChain)
				for key, chain := range sessionMap {
					if _, ok := m[key]; ok { filtered[key] = chain }
				}
				sessionMap = filtered
			}
			fmt.Printf("    after intersect: %d candidates\n", len(sessionMap))
		}
		allChains[idx] = sessionMap
		fmt.Printf("  Session [%d] total: %d chains\n", idx+1, len(sessionMap))
	}

	// Cross-reference across sessions
	candidates := allChains[0]
	for i := 1; i < len(allChains); i++ {
		filtered := make(map[string]PointerChain)
		for key, chain := range candidates {
			if _, ok := allChains[i][key]; ok { filtered[key] = chain }
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
		if len(ci.Offsets) != len(cj.Offsets) { return len(ci.Offsets) < len(cj.Offsets) }
		return ci.BaseOffset < cj.BaseOffset
	})
	if len(results) > maxResults { results = results[:maxResults] }
	return results
}

// ---------------------------------------------------------------------------
// VerifyChain — follow a saved chain in the live process
//
// chain.Offsets are in STATIC→TARGET order (outermost/deepest offset first).
// We apply them in order: dereference ptr at current addr, add offset, repeat.
// ---------------------------------------------------------------------------

func VerifyChain(handle windows.Handle, modules []ModuleInfo, chain PointerChain, is32Bit bool) (uintptr, bool) {
	var base uintptr
	for _, m := range modules {
		if m.Name == chain.BaseModule { base = m.Base; break }
	}
	if base == 0 { return 0, false }

	addr := base + chain.BaseOffset
	for _, offset := range chain.Offsets {
		var ptr uintptr
		if is32Bit {
			buf, err := ReadMemory(handle, addr, 4)
			if err != nil || len(buf) < 4 { return 0, false }
			ptr = uintptr(binary.LittleEndian.Uint32(buf))
		} else {
			var err error
			ptr, err = ReadPointer(handle, addr)
			if err != nil { return 0, false }
		}
		if ptr == 0 { return 0, false }
		addr = ptr + offset
	}
	return addr, true
}
