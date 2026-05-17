//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

var (
	currentHandle  windows.Handle
	currentPID     uint32
	currentModules []ModuleInfo
	currentIs32Bit bool // true if attached process is 32-bit (WOW64)
	scanner        *MemoryScanner
	freezer        *Freezer
	currentDT      DataType = TypeFloat32
	pointerMap     *PointerMap
	addressList    []addressEntry

	// pointer scan sessions: each is a saved (pmap_file, target_addr) pair
	pscanSessions []PointerScanSession
)

type addressEntry struct {
	Addr  uintptr
	Label string
	DT    DataType
}

func main() {
	// Init logger — writes to memhacker.log next to the exe
	logPath := "memhacker.log"
	if err := InitLogger(logPath, LogDEBUG, true); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not init logger: %v\n", err)
	} else {
		defer Log.Close()
		fmt.Printf("Logging to: %s\n", logPath)
	}

	// Ctrl+C: cancel active scan (clears results) or exit if no scan running
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		for range sigCh {
			if atomic.LoadInt32(&scanActive) != 0 {
				atomic.StoreInt32(&scanCancelFlag, 1)
				fmt.Println("\n  [Ctrl+C] cancelling scan...")
			} else {
				fmt.Println("Bye!")
				if currentHandle != 0 {
					CloseProcessHandle(currentHandle)
					if freezer != nil { freezer.Stop() }
				}
				os.Exit(0)
			}
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	printBanner()

	for {
		fmt.Print("\n> ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])
		args := parts[1:]

		switch cmd {
		case "help", "h", "?":
			printHelp()
		case "alias":
			cmdAlias(args)
		case "unalias":
			cmdUnalias(args)
		case "list", "ps":
			cmdListProcesses()
		case "open", "attach":
			Log.Info("CMD: open %v", args)
			cmdOpen(args)
		case "close", "detach":
			Log.Info("CMD: close")
			cmdClose()
		case "type", "dt":
			Log.Info("CMD: type %v", args)
			cmdSetType(args)
		case "scan", "s":
			Log.Info("CMD: scan %v", args)
			cmdScan(args, reader)
		case "next", "n":
			Log.Info("CMD: next %v", args)
			cmdNext(args, reader)
		case "results", "r":
			cmdResults(args)
		case "write", "w":
			Log.Info("CMD: write %v", args)
			cmdWrite(args)
		case "iwrite", "iw":
			Log.Info("CMD: iwrite %v", args)
			cmdIndexWrite(args)
		case "iread", "ir":
			Log.Info("CMD: iread %v", args)
			cmdIndexRead(args)
		case "add", "a":
			cmdAddToList(args)
		case "addrlist", "al":
			cmdShowAddressList()
		case "freeze", "f":
			Log.Info("CMD: freeze %v", args)
			cmdFreeze(args)
		case "ifreeze", "if":
			Log.Info("CMD: ifreeze %v", args)
			cmdIndexFreeze(args)
		case "unfreeze", "uf":
			Log.Info("CMD: unfreeze %v", args)
			cmdUnfreeze(args)
		case "frozen", "fl":
			cmdFrozenList()
		case "read":
			Log.Info("CMD: read %v", args)
			cmdRead(args)
		case "pmap":
			Log.Info("CMD: pmap")
			cmdBuildPointerMap()
		case "pmsave":
			Log.Info("CMD: pmsave %v", args)
			cmdPmapSave(args)
		case "pmload":
			Log.Info("CMD: pmload %v", args)
			cmdPmapLoad(args)
		case "pmadd":
			Log.Info("CMD: pmadd %v", args)
			cmdPmapAdd(args)
		case "pmsessions":
			cmdPmapSessions()
		case "pmexport":
			Log.Info("CMD: pmexport %v", args)
			cmdPmapExportCE(args)
		case "pmclear":
			Log.Info("CMD: pmclear")
			cmdPmapClear()
		case "pscan":
			Log.Info("CMD: pscan %v", args)
			cmdPointerScan(args, reader)
		case "prsave":
			Log.Info("CMD: prsave %v", args)
			cmdPointerResultsSave(args)
		case "prmerge":
			Log.Info("CMD: prmerge %v", args)
			cmdPointerResultsMerge(args)
		case "prload":
			Log.Info("CMD: prload %v", args)
			cmdPointerResultsLoad(args)
		case "prverify":
			Log.Info("CMD: prverify")
			cmdPointerResultsVerify(args)
		case "prlist":
			cmdPointerResultsList(args)
		case "prwrite":
			Log.Info("CMD: prwrite %v", args)
			cmdPointerResultsWrite(args)
		case "prfreeze":
			Log.Info("CMD: prfreeze %v", args)
			cmdPointerResultsFreeze(args)
		case "modules", "mod":
			cmdModules()
		case "regions", "reg":
			cmdRegions(args)
		case "reset":
			Log.Info("CMD: reset")
			cmdReset()
		case "log":
			if Log != nil {
				fmt.Printf("Log file: %s\n", Log.LogPath())
			}
		case "loglast":
			cmdLogLast(args)
		case "exit", "quit", "q":
			Log.Info("CMD: exit")
			fmt.Println("Bye!")
			if currentHandle != 0 {
				CloseProcessHandle(currentHandle)
				if freezer != nil {
					freezer.Stop()
				}
			}
			os.Exit(0)
		default:
			Log.Warn("Unknown command: %s", cmd)
			fmt.Printf("Unknown command: %s  (type 'help')\n", cmd)
		}
	}
}

func printBanner() {
	fmt.Printf("============================================\n")
	fmt.Printf("   MemHacker v%s - CE-style Memory Tool\n", AppVersion)
	fmt.Printf("   type 'help' for commands\n")
	fmt.Printf("============================================\n")
}

func printHelp() {
	fmt.Println(`
PROCESS
  ps / list                     - list running processes
  open <pid|name>               - attach (partial name ok: open surro -> SurrounDead.exe)
  close                         - detach
  modules                       - list loaded DLLs (GAME/SYSTEM/OTHER)
  regions [all]                 - list scannable memory regions with addresses/sizes

SCANNING                        (default type: f32, default scope: writable private memory)
  type <dt>                     - set data type: i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 str bytes
  scan <type> [value]           - first scan
    types: exact  unknown  bigger  smaller  between <v1> <v2>
           changed  unchanged  increased  decreased  incby  decby  notequal
    keywords (append to any scan):
      all                       - scan all memory including read-only (slower)
      range <lo> <hi>           - limit to address range
      cap <n>                   - stop after N results
    e.g: scan exact 100
         scan unknown
         scan exact 0 cap 50000
         scan exact 100 range 0x1000000 0x2000000
         scan between -0.01 0.01 all
  next <type> [value]           - filter existing results (same types as scan)
  results [n] [addr|val]        - show top N results, optionally sorted by address or value
  results <range|list> [addr|val] - show specific results by index
    e.g: results 20 val         - top 20 sorted by value
         results 1-5            - show results #1 to #5
         results 1,3,5 addr     - show #1,#3,#5 sorted by address
  reset                         - clear scan results (Ctrl+C during scan also clears)

VALUE OPS
  read <addr> [dt]              - read value at address
  write <addr> <value>          - write value at address
  iread <addr> <index>          - read at addr + index * sizeof(type)
                                  e.g: iread 0x1A2B3C 4  reads 4th element of f32 array
  iwrite <idx> <value>          - write to scan result by index
                                  e.g: iwrite 5 100   iwrite 5-7 100   iwrite 1,3,5 100
  add <addr> [label]            - add to address list
  addrlist                      - show address list with live values

FREEZING
  freeze <addr> <value> [label] - freeze address at value (50ms write loop)
  ifreeze <idx> <value>         - freeze scan result by index (range/list ok)
                                  e.g: ifreeze 5 100   ifreeze 5-7 100
  unfreeze <pos|range|0xADDR>   - unfreeze by position in frozen list, range, or address
                                  e.g: unfreeze 1   unfreeze 1-3   unfreeze 0x1A2B3C
  frozen                        - list frozen entries (positions 1,2,3... reset each time)

ALIASES
  alias <name> <addr>           - set alias  e.g: alias hp 0x614DD58
  alias                         - list all aliases
  unalias <name>                - remove alias
  (use alias name anywhere an address is expected: write hp 999  freeze hp 999)

POINTER SCANNING
  pmap                          - build pointer map (in-memory)
  pmsave <file> <addr>          - build pmap + save + register session
  pmadd <addr>                  - add another target to last session
  pmload <f1> [f2] [f3] ...    - load one or more saved pmaps
  pmsessions                    - list sessions
  pmclear                       - clear all sessions

  pscan [depth] [offset] [max] [filter] [maxOffsets]
                                - scan across all sessions (sessions run in parallel)
                                  filter: exe (default), game, all
                                  defaults: depth=5 offset=8192 max=100
                                  e.g: pscan 5 4000 100   pscan 6 8192 100 game
  (results auto-saved to pscan_last_N.json, only verified chains shown)

POINTER RESULTS
  prsave <file.json>            - save chains to file
  prload <file.json> [addr]     - load chains, optionally filter to those resolving to addr
  prverify [addr]               - re-verify chains against current process
  prlist [ok|addr]              - list chains (ok=resolvable only, addr=filter by address)
  prlabel <index> <label>       - label a chain
  prwrite <index> <value>       - follow chain, write value
  prfreeze <index> <value>      - follow chain, freeze value

OTHER
  log                           - show log file path
  loglast [N]                   - copy log to clipboard (paste into GitHub issues)
  exit / quit / q               - exit
`)
}

func cmdListProcesses() {
	procs, err := ListProcesses()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].Name < procs[j].Name })
	fmt.Printf("%-8s  %s\n", "PID", "Name")
	fmt.Println(strings.Repeat("-", 40))
	for _, p := range procs {
		fmt.Printf("%-8d  %s\n", p.PID, p.Name)
	}
}

func cmdOpen(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: open <pid|name>")
		return
	}
	// Try as PID first
	pid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		// Try by name — exact, then strip .exe, then partial substring (case-insensitive)
		procs, _ := ListProcesses()
		name := strings.ToLower(args[0])
		// Pass 1: exact match or exact-minus-.exe
		for _, p := range procs {
			plow := strings.ToLower(p.Name)
			if plow == name || strings.TrimSuffix(plow, ".exe") == name {
				pid = uint64(p.PID)
				break
			}
		}
		// Pass 2: partial substring match (allows "surroundead" to match "SurrounDead.exe")
		if pid == 0 {
			for _, p := range procs {
				if strings.Contains(strings.ToLower(p.Name), name) {
					pid = uint64(p.PID)
					fmt.Printf("Matched '%s' -> %s\n", args[0], p.Name)
					break
				}
			}
		}
		if pid == 0 {
			fmt.Printf("Process '%s' not found\n", args[0])
			return
		}
	}

	if currentHandle != 0 {
		CloseProcessHandle(currentHandle)
		if freezer != nil {
			freezer.Stop()
			freezer = nil
		}
	}

	h, err2 := OpenProcessHandle(uint32(pid))
	if err2 != nil {
		fmt.Println("Error:", err2)
		return
	}
	currentHandle = h
	currentPID = uint32(pid)
	currentIs32Bit = IsProcess32Bit(h)
	scanner = NewMemoryScanner(h)
	freezer = NewFreezer(h)
	pointerMap = nil // invalidate stale pmap from previous session

	mods, _ := GetModules(uint32(pid))
	currentModules = mods

	// Find process name
	name := fmt.Sprintf("PID %d", pid)
	procs, _ := ListProcesses()
	for _, p := range procs {
		if p.PID == uint32(pid) {
			name = p.Name
			break
		}
	}

	arch := "64-bit"
	if currentIs32Bit {
		arch = "32-bit (WOW64)"
	}
	fmt.Printf("Attached to %s (PID %d) [%s], %d modules loaded\n", name, pid, arch, len(mods))
}

func cmdClose() {
	if currentHandle == 0 {
		fmt.Println("Not attached to any process")
		return
	}
	CloseProcessHandle(currentHandle)
	if freezer != nil {
		freezer.Stop()
		freezer = nil
	}
	currentHandle = 0
	currentPID = 0
	if scanner != nil { scanner.clearSnapshot(); scanner.clearDiskRes() }
	scanner = nil
	pointerMap = nil
	fmt.Println("Detached")
}

func cmdSetType(args []string) {
	if len(args) == 0 {
		fmt.Println("Current type:", dataTypeName(currentDT))
		fmt.Println("Usage: type <i8|i16|i32|i64|u8|u16|u32|u64|f32|f64|str|bytes>")
		return
	}
	dt, ok := parseDataType(args[0])
	if !ok {
		fmt.Println("Unknown type:", args[0])
		return
	}
	currentDT = dt
	fmt.Println("Data type set to:", dataTypeName(currentDT))
}

func parseDataType(s string) (DataType, bool) {
	switch strings.ToLower(s) {
	case "i8", "int8":
		return TypeInt8, true
	case "i16", "int16":
		return TypeInt16, true
	case "i32", "int32", "int":
		return TypeInt32, true
	case "i64", "int64":
		return TypeInt64, true
	case "u8", "uint8", "byte":
		return TypeUInt8, true
	case "u16", "uint16":
		return TypeUInt16, true
	case "u32", "uint32":
		return TypeUInt32, true
	case "u64", "uint64":
		return TypeUInt64, true
	case "f32", "float32", "float":
		return TypeFloat32, true
	case "f64", "float64", "double":
		return TypeFloat64, true
	case "str", "string":
		return TypeString, true
	case "bytes", "byte[]", "aob":
		return TypeBytes, true
	}
	return TypeInt32, false
}

func parseScanArgs(scanType string, args []string) (ScanParams, bool) {
	p := ScanParams{
		DT:        currentDT,
		Tolerance: 0,
	}
	switch strings.ToLower(scanType) {
	case "exact", "e":
		if len(args) == 0 {
			fmt.Println("Usage: scan exact <value>")
			return p, false
		}
		v, err := encodeValue(currentDT, args[0])
		if err != nil {
			fmt.Println("Error encoding value:", err)
			return p, false
		}
		p.ST = ScanExact
		p.Value = v
	case "unknown", "u":
		p.ST = ScanUnknown
	case "bigger", "gt", ">":
		if len(args) == 0 {
			fmt.Println("Usage: scan bigger <value>")
			return p, false
		}
		v, _ := encodeValue(currentDT, args[0])
		p.ST = ScanBiggerThan
		p.Value = v
	case "smaller", "lt", "<":
		if len(args) == 0 {
			fmt.Println("Usage: scan smaller <value>")
			return p, false
		}
		v, _ := encodeValue(currentDT, args[0])
		p.ST = ScanSmallerThan
		p.Value = v
	case "biggereq", "gte", ">=":
		if len(args) == 0 {
			return p, false
		}
		v, _ := encodeValue(currentDT, args[0])
		p.ST = ScanBiggerThanOrEqual
		p.Value = v
	case "smallereq", "lte", "<=":
		if len(args) == 0 {
			return p, false
		}
		v, _ := encodeValue(currentDT, args[0])
		p.ST = ScanSmallerThanOrEqual
		p.Value = v
	case "notequal", "ne", "!=":
		if len(args) == 0 {
			return p, false
		}
		v, _ := encodeValue(currentDT, args[0])
		p.ST = ScanNotEqual
		p.Value = v
	case "between", "btw":
		if len(args) < 2 {
			fmt.Println("Usage: scan between <v1> <v2>")
			return p, false
		}
		v1, _ := encodeValue(currentDT, args[0])
		v2, _ := encodeValue(currentDT, args[1])
		p.ST = ScanBetween
		p.Value = v1
		p.Value2 = v2
	case "changed", "c":
		p.ST = ScanChanged
	case "unchanged", "uc":
		p.ST = ScanUnchanged
	case "increased", "inc", "+":
		p.ST = ScanIncreased
	case "decreased", "dec", "-":
		p.ST = ScanDecreased
	case "incby":
		if len(args) == 0 {
			return p, false
		}
		v, _ := encodeValue(currentDT, args[0])
		p.ST = ScanIncreasedBy
		p.Value = v
	case "decby":
		if len(args) == 0 {
			return p, false
		}
		v, _ := encodeValue(currentDT, args[0])
		p.ST = ScanDecreasedBy
		p.Value = v
	default:
		// Try as direct value (exact scan shortcut)
		v, err := encodeValue(currentDT, scanType)
		if err == nil {
			p.ST = ScanExact
			p.Value = v
		} else {
			fmt.Printf("Unknown scan type: %s\n", scanType)
			return p, false
		}
	}
	return p, true
}

func cmdScan(args []string, reader *bufio.Reader) {
	if currentHandle == 0 {
		fmt.Println("Not attached. Use 'open <pid>'")
		return
	}
	if len(args) == 0 {
		fmt.Println("Usage: scan <type> [value]  (e.g.: scan exact 100  or  scan unknown)")
		fmt.Println("       append 'all' to scan all memory: scan exact 100 all")
		return
	}

	// Guard: confirm before wiping existing results
	if scanner != nil && scanner.totalResults() > 0 {
		total := scanner.totalResults()
		fmt.Printf("  You have %d results. Starting a new scan will clear them. Type 'yes' to confirm: ", total)
		line, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(line)) != "yes" {
			fmt.Println("  Cancelled.")
			return
		}
	}

	// Strip optional keywords: "all", "range <lo> <hi>", "cap <n>"
	scanAll := false
	var rangeLo, rangeHi uintptr
	var resultCap int
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "all":
			scanAll = true
		case "range":
			if i+2 < len(args) {
				lo, err1 := resolveAddr(args[i+1])
				hi, err2 := resolveAddr(args[i+2])
				if err1 == nil && err2 == nil {
					rangeLo, rangeHi = lo, hi
					i += 2
				} else {
					fmt.Println("Usage: scan ... range <lo_addr> <hi_addr>")
					return
				}
			}
		case "cap":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &resultCap)
				i++
			}
		default:
			filtered = append(filtered, args[i])
		}
	}
	args = filtered

	p, ok := parseScanArgs(args[0], args[1:])
	if !ok {
		return
	}
	p.Writable = !scanAll
	p.RangeLo = rangeLo
	p.RangeHi = rangeHi
	p.ResultCap = resultCap
	scope := "writable"
	if scanAll { scope = "all" }
	info := fmt.Sprintf("type=%s scope=%s", dataTypeName(currentDT), scope)
	if rangeLo > 0 { info += fmt.Sprintf(" range=0x%X-0x%X", rangeLo, rangeHi) }
	if resultCap > 0 { info += fmt.Sprintf(" cap=%d", resultCap) }
	fmt.Printf("Scanning for %s [%s]...\n", args[0], info)
	start := time.Now()
	count := scanner.FirstScan(p)
	elapsed := time.Since(start)
	fmt.Printf("Found %d results in %v\n", count, elapsed)
	if count > 0 && count <= 20 {
		showResults(20, "")
	} else if count > 20 {
		showResults(10, "")
	}
}

func cmdNext(args []string, reader *bufio.Reader) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if scanner == nil || scanner.totalResults() == 0 {
		fmt.Println("No previous scan. Run 'scan' first")
		return
	}
	if len(args) == 0 {
		fmt.Println("Usage: next <type> [value]")
		return
	}
	p, ok := parseScanArgs(args[0], args[1:])
	if !ok {
		return
	}
	fmt.Printf("Filtering %d results...\n", scanner.totalResults())
	start := time.Now()
	count := scanner.NextScan(p)
	elapsed := time.Since(start)
	fmt.Printf("%d results remaining (%v)\n", count, elapsed)
	if count > 0 && count <= 20 {
		showResults(20, "")
	} else if count > 20 {
		showResults(10, "")
	}
}

func cmdResults(args []string) {
	if scanner == nil || scanner.totalResults() == 0 {
		fmt.Println("No results")
		return
	}

	// Parse args: optional count/range, optional sort keyword
	sortBy := "" // "addr" or "val"
	filtered := args[:0:len(args)]
	for _, a := range args {
		switch strings.ToLower(a) {
		case "addr", "address":
			sortBy = "addr"
		case "val", "value":
			sortBy = "val"
		default:
			filtered = append(filtered, a)
		}
	}
	args = filtered

	// Index range: results 1-5 or results 1,3,5
	if len(args) > 0 && (strings.Contains(args[0], "-") || strings.Contains(args[0], ",")) {
		indices := parseIndexSpec(args[0])
		type row struct{ idx int; addr uintptr; val string }
		var rows []row
		for _, idx := range indices {
			if idx < 1 || idx > scanner.totalResults() { continue }
			addr, _ := scanner.getResult(idx - 1)
			val, err := scanner.ReadCurrentValue(addr, currentDT)
			if err != nil { val = "?" }
			rows = append(rows, row{idx, addr, val})
		}
		if sortBy == "val" {
			sort.Slice(rows, func(i, j int) bool { return rows[i].val < rows[j].val })
		} else if sortBy == "addr" {
			sort.Slice(rows, func(i, j int) bool { return rows[i].addr < rows[j].addr })
		}
		fmt.Printf("%-5s  %-20s  %s\n", "#", "Address", "Value")
		fmt.Println(strings.Repeat("-", 45))
		for _, r := range rows {
			fmt.Printf("%-5d  0x%-18X  %s\n", r.idx, r.addr, r.val)
		}
		return
	}

	n := 20
	if len(args) > 0 { n, _ = strconv.Atoi(args[0]) }
	showResults(n, sortBy)
}


func showResults(n int, sortBy string) {
	if scanner == nil || scanner.totalResults() == 0 {
		fmt.Println("No results")
		return
	}
	total := scanner.totalResults()
	if n > total { n = total }

	type row struct{ idx int; addr uintptr; val string }
	rows := make([]row, n)
	for i := 0; i < n; i++ {
		addr, _ := scanner.getResult(i)
		val, err := scanner.ReadCurrentValue(addr, currentDT)
		if err != nil { val = "?" }
		rows[i] = row{i + 1, addr, val}
	}
	if sortBy == "val" {
		sort.Slice(rows, func(i, j int) bool { return rows[i].val < rows[j].val })
	} else if sortBy == "addr" {
		sort.Slice(rows, func(i, j int) bool { return rows[i].addr < rows[j].addr })
	}

	fmt.Printf("%-5s  %-20s  %s\n", "#", "Address", "Value")
	fmt.Println(strings.Repeat("-", 45))
	for _, r := range rows {
		fmt.Printf("%-5d  0x%-18X  %s\n", r.idx, r.addr, r.val)
	}
	if total > n {
		fmt.Printf("... and %d more (use 'results <N>' to show more)\n", total-n)
	}
}

func cmdWrite(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: write <addr_hex> <value>")
		return
	}
	addr, err := resolveAddr(args[0])
	if err != nil {
		fmt.Println("Invalid address:", err)
		return
	}
	val, err := encodeValue(currentDT, strings.Join(args[1:], " "))
	if err != nil {
		fmt.Println("Invalid value:", err)
		return
	}
	if err := WriteMemory(currentHandle, addr, val); err != nil {
		fmt.Println("Write failed:", err)
		return
	}
	fmt.Printf("Written %s to 0x%X\n", decodeValue(currentDT, val), addr)
}

// iwrite <index|range> <value> — write value to scan results by 1-based index or range
// e.g: iwrite 5 100       -> write to result #5
//      iwrite 5-7 100     -> write to results #5, #6, #7
//      iwrite 1,3,5 100   -> write to results #1, #3, #5
// iread <base_addr> <index> — reads at base_addr + index * sizeof(currentDT)
// e.g: iread 0x1A2B3C4D 4  with f32 reads at 0x1A2B3C4D + 4*4 = 0x1A2B3C4D + 16
func cmdIndexRead(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: iread <base_addr> <index>")
		fmt.Println("  Reads at base_addr + index * sizeof(type)")
		fmt.Println("  e.g: iread 0x1A2B3C4D 4   <- reads 4th element in array")
		return
	}
	base, err := resolveAddr(args[0])
	if err != nil {
		fmt.Println("Invalid address:", err)
		return
	}
	var idx int
	fmt.Sscanf(args[1], "%d", &idx)
	sz := dataTypeSize(currentDT)
	addr := base + uintptr(idx)*uintptr(sz)
	val, err := scanner.ReadCurrentValue(addr, currentDT)
	if err != nil {
		fmt.Println("Read failed:", err)
		return
	}
	fmt.Printf("0x%X [%d] = %s  (base=0x%X + %d * %d bytes)\n", addr, idx, val, base, idx, sz)
}

func cmdIndexWrite(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: iwrite <index|range|list> <value>")
		fmt.Println("  e.g: iwrite 5 100       <- write to result #5")
		fmt.Println("       iwrite 5-7 100     <- write to results #5 to #7")
		fmt.Println("       iwrite 1,3,5 100   <- write to results #1, #3, #5")
		return
	}
	if scanner == nil || scanner.totalResults() == 0 {
		fmt.Println("No scan results. Run scan first.")
		return
	}

	val, err := encodeValue(currentDT, args[1])
	if err != nil {
		fmt.Println("Invalid value:", err)
		return
	}

	indices := parseIndexSpec(args[0])

	ok, failed := 0, 0
	for _, idx := range indices {
		if idx < 1 || idx > scanner.totalResults() {
			fmt.Printf("  [%d] out of range (total %d)\n", idx, len(scanner.Results))
			failed++
			continue
		}
		addr := func() uintptr { a, _ := scanner.getResult(idx-1); return a }()
		if err := WriteMemory(currentHandle, addr, val); err != nil {
			fmt.Printf("  [%d] 0x%X skipped: %v\n", idx, addr, err)
			failed++
		} else {
			fmt.Printf("  [%d] 0x%X = %s\n", idx, addr, args[1])
			ok++
		}
	}
	fmt.Printf("Written to %d/%d addresses\n", ok, ok+failed)
}

// parseIndexSpec parses "5", "5-7", or "1,3,5-7" into a list of 1-based indices
func parseIndexSpec(spec string) []int {
	var indices []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			var lo, hi int
			fmt.Sscanf(bounds[0], "%d", &lo)
			fmt.Sscanf(bounds[1], "%d", &hi)
			for i := lo; i <= hi; i++ {
				indices = append(indices, i)
			}
		} else {
			var idx int
			fmt.Sscanf(part, "%d", &idx)
			indices = append(indices, idx)
		}
	}
	return indices
}

// ifreeze <index|range|list> <value> — freeze scan results by index
func cmdIndexFreeze(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: ifreeze <index|range|list> <value>")
		fmt.Println("  e.g: ifreeze 5 100       <- freeze result #5")
		fmt.Println("       ifreeze 5-7 100     <- freeze results #5 to #7")
		fmt.Println("       ifreeze 1,3,5 100   <- freeze results #1, #3, #5")
		return
	}
	if scanner == nil || scanner.totalResults() == 0 {
		fmt.Println("No scan results. Run scan first.")
		return
	}
	val, err := encodeValue(currentDT, args[1])
	if err != nil {
		fmt.Println("Invalid value:", err)
		return
	}
	indices := parseIndexSpec(args[0])
	ok, failed := 0, 0
	for _, idx := range indices {
		if idx < 1 || idx > scanner.totalResults() {
			fmt.Printf("  [%d] out of range (total %d)\n", idx, len(scanner.Results))
			failed++
			continue
		}
		addr := func() uintptr { a, _ := scanner.getResult(idx-1); return a }()
		id := freezer.Add(addr, val, fmt.Sprintf("scan[%d]", idx))
		fmt.Printf("  [%d] 0x%X = %s (freeze #%d)\n", idx, addr, args[1], id)
		ok++
	}
	fmt.Printf("Freezing %d/%d addresses\n", ok, ok+failed)
}

func cmdAddToList(args []string) {
	if len(args) == 0 {
		// Add all current results
		if scanner == nil {
			fmt.Println("No results to add")
			return
		}
		for _, r := range scanner.Results {
			addressList = append(addressList, addressEntry{Addr: r.Address, DT: currentDT})
		}
		fmt.Printf("Added %d addresses to list\n", scanner.totalResults())
		return
	}
	addr, err := resolveAddr(args[0])
	if err != nil {
		fmt.Println("Invalid address:", err)
		return
	}
	label := ""
	if len(args) > 1 {
		label = strings.Join(args[1:], " ")
	}
	addressList = append(addressList, addressEntry{Addr: addr, Label: label, DT: currentDT})
	fmt.Printf("Added 0x%X to address list\n", addr)
}

func cmdShowAddressList() {
	if len(addressList) == 0 {
		fmt.Println("Address list is empty")
		return
	}
	fmt.Printf("%-5s  %-20s  %-8s  %-20s  %s\n", "ID", "Address", "Type", "Value", "Label")
	fmt.Println(strings.Repeat("-", 70))
	for i, e := range addressList {
		val := "?"
		if currentHandle != 0 {
			v, err := scanner.ReadCurrentValue(e.Addr, e.DT)
			if err == nil {
				val = v
			}
		}
		fmt.Printf("%-5d  0x%-18X  %-8s  %-20s  %s\n", i, e.Addr, dataTypeName(e.DT), val, e.Label)
	}
}

func cmdRead(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if len(args) == 0 {
		fmt.Println("Usage: read <addr_hex> [type]")
		return
	}
	addr, err := resolveAddr(args[0])
	if err != nil {
		fmt.Println("Invalid address:", err)
		return
	}
	dt := currentDT
	if len(args) > 1 {
		dt2, ok := parseDataType(args[1])
		if ok {
			dt = dt2
		}
	}
	val, err := scanner.ReadCurrentValue(addr, dt)
	if err != nil {
		fmt.Println("Read failed:", err)
		return
	}
	fmt.Printf("0x%X = %s (%s)\n", addr, val, dataTypeName(dt))
}

func cmdFreeze(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: freeze <addr_hex> <value> [label]")
		return
	}
	addr, err := resolveAddr(args[0])
	if err != nil {
		fmt.Println("Invalid address:", err)
		return
	}
	val, err := encodeValue(currentDT, args[1])
	if err != nil {
		fmt.Println("Invalid value:", err)
		return
	}
	label := ""
	if len(args) > 2 {
		label = strings.Join(args[2:], " ")
	}
	id := freezer.Add(addr, val, label)
	fmt.Printf("Freezing 0x%X = %s (freeze #%d)\n", addr, args[1], id)
}

func cmdUnfreeze(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: unfreeze <id|range|list|0xADDR>")
		fmt.Println("  e.g: unfreeze 3        <- by ID")
		fmt.Println("       unfreeze 1-5      <- range of IDs")
		fmt.Println("       unfreeze 0x1A2B   <- by address")
		return
	}
	// If argument looks like an address (0x prefix or alias), unfreeze by address
	arg := args[0]
	if strings.HasPrefix(strings.ToLower(arg), "0x") || (!strings.Contains(arg, "-") && !strings.Contains(arg, ",")) {
		if addr, err := resolveAddr(arg); err == nil && addr > 0xFFFF {
			if freezer.RemoveByAddr(addr) {
				fmt.Printf("Unfroze 0x%X\n", addr)
			} else {
				fmt.Printf("No frozen entry at 0x%X\n", addr)
			}
			return
		}
	}
	// "all" — clear everything
	if strings.ToLower(arg) == "all" {
		n := freezer.RemoveAll()
		fmt.Printf("Unfroze all %d entries\n", n)
		return
	}
	// Position-based removal — sort DESCENDING so removing high positions first
	// doesn't shift lower positions, allowing ranges like 1-100 to work correctly.
	indices := parseIndexSpec(arg)
	sort.Sort(sort.Reverse(sort.IntSlice(indices)))
	ok := 0
	for _, pos := range indices {
		if freezer.RemoveByPosition(pos) {
			ok++
		} else {
			fmt.Printf("Position %d not found\n", pos)
		}
	}
	fmt.Printf("Unfroze %d entries\n", ok)
}

func cmdFrozenList() {
	if freezer == nil {
		fmt.Println("Not attached")
		return
	}
	list := freezer.List()
	if len(list) == 0 {
		fmt.Println("No frozen entries")
		return
	}
	fmt.Printf("%-5s  %-22s  %-8s  %-12s  %s\n", "#", "Address", "Active", "Value", "Label")
	fmt.Println(strings.Repeat("-", 75))
	for i, e := range list {
		active := "YES"
		if !e.Entry.Active { active = "NO" }
		fmt.Printf("%-5d  0x%-20X  %-8s  %-12s  %s\n",
			i+1, e.Entry.Address, active,
			decodeValue(currentDT, e.Entry.Value),
			e.Entry.Label)
	}
	fmt.Println("\nTip: unfreeze 1   unfreeze 1-3   unfreeze 0xADDR")
}

func cmdBuildPointerMap() {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	fmt.Println("Building pointer map (this may take a while)...")
	start := time.Now()
	pm, err := BuildPointerMap(currentHandle, currentModules, currentPID, currentIs32Bit)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	pointerMap = pm
	fmt.Printf("Pointer map ready in %v (%d entries)\n", time.Since(start), len(pm.Entries))
}

// pmsave <file> <target_addr_hex>
// Saves current pmap to disk and registers it as a session with the given target address.
func cmdPmapSave(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: pmsave <file.pmap> <target_addr_hex>")
		fmt.Println("  Builds pmap if needed, saves to file, registers as a pscan session")
		return
	}
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}

	targetAddr, err := resolveAddr(args[1])
	if err != nil {
		fmt.Println("Invalid address:", err)
		return
	}

	// Build pmap if not already built
	if pointerMap == nil {
		fmt.Println("Building pointer map first...")
		cmdBuildPointerMap()
		if pointerMap == nil {
			fmt.Println("Failed to build pointer map")
			return
		}
	}

	// Embed target address into the map itself before saving
	pointerMap.TargetAddr = targetAddr

	path := args[0]
	if err := pointerMap.Save(path); err != nil {
		fmt.Println("Save failed:", err)
		return
	}

	// Register as session — store a reference to current pmap
	// Then nil out pointerMap so next pmsave builds a fresh one
	savedPmap := pointerMap
	pscanSessions = append(pscanSessions, PointerScanSession{
		PMap:  savedPmap,
		Label: path,
	})
	pointerMap = nil // force fresh pmap on next pmsave

	Log.Info("pmsave: saved %s, target=0x%X, session count=%d", path, targetAddr, len(pscanSessions))
	fmt.Printf("Saved %s (%d entries) | target=0x%X | session #%d registered\n",
		path, len(savedPmap.Entries), targetAddr, len(pscanSessions))
}

// pmload <file>
// Loads a pmap file — target address is read from the file itself, no need to specify.
func cmdPmapLoad(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: pmload <file.pmap>")
		return
	}
	pm, err := LoadPointerMap(args[0])
	if err != nil {
		fmt.Println("Load failed:", err)
		return
	}
	if pm.TargetAddr == 0 {
		fmt.Println("Warning: this pmap has no target address saved (old format?)")
		fmt.Println("Use: pmload <file.pmap> <addr_hex>  to specify it manually")
		if len(args) >= 2 {
			addr, err := resolveAddr(args[1])
			if err != nil {
				fmt.Println("Invalid address:", err)
				return
			}
			pm.TargetAddr = addr
		} else {
			return
		}
	}
	pscanSessions = append(pscanSessions, PointerScanSession{
		
		PMap:       pm,
		Label:      args[0],
	})
	Log.Info("pmload: loaded %s, target=0x%X, session count=%d", args[0], pm.TargetAddr, len(pscanSessions))
	fmt.Printf("Loaded %s | pid=%d | saved=%s | target=0x%X | session #%d registered\n",
		args[0], pm.PID,
		pm.CreatedAt.Format("2006-01-02 15:04:05"),
		pm.TargetAddr, len(pscanSessions))
}

// pmadd <addr> — add another target address to the last registered session (same pmap)
func cmdPmapAdd(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: pmadd <addr>")
		fmt.Println("  Adds another target address to the last pmsave session (same pmap)")
		fmt.Println("  e.g: pmsave a1.pmap 0xAAA  <- first address")
		fmt.Println("       pmadd 0xBBB            <- second address, same pmap")
		fmt.Println("       pmadd 0xCCC            <- third address, same pmap")
		fmt.Println("       pscan                  <- CE-style: one pmap, multiple addresses")
		return
	}
	if len(pscanSessions) == 0 {
		fmt.Println("No session registered yet. Run pmsave first.")
		return
	}
	addr, err := resolveAddr(args[0])
	if err != nil {
		fmt.Println("Invalid address:", err)
		return
	}
	// Add to last session
	last := &pscanSessions[len(pscanSessions)-1]
	// First pmadd on this session: also include the original pmsave address
	if len(last.TargetAddrs) == 0 {
		last.TargetAddrs = append(last.TargetAddrs, last.PMap.TargetAddr)
	}
	last.TargetAddrs = append(last.TargetAddrs, addr)
	fmt.Printf("Added 0x%X to session '%s' (now %d targets: ",
		addr, last.Label, len(last.TargetAddrs))
	for i, a := range last.TargetAddrs {
		if i > 0 {
			fmt.Printf(", ")
		}
		fmt.Printf("0x%X", a)
	}
	fmt.Println(")")
	Log.Info("pmadd: added 0x%X to session %s, total targets=%d", addr, last.Label, len(last.TargetAddrs))
}
// pmsessions — list registered sessions
func cmdPmapSessions() {
	if len(pscanSessions) == 0 {
		fmt.Println("No sessions registered. Use 'pmsave' or 'pmload' to add sessions.")
		return
	}
	for i, s := range pscanSessions {
		targets := s.TargetAddrs
		if len(targets) == 0 {
			targets = []uintptr{s.PMap.TargetAddr}
		}
		fmt.Printf("[%d] %s (%d entries)\n", i+1, s.Label, len(s.PMap.Entries))
		for j, a := range targets {
			fmt.Printf("     target %d: 0x%X\n", j+1, a)
		}
	}
}

// pmclear — clear all sessions
// pmexport <file.scandata> — export current pmap to CE-compatible .scandata format
// CE can load this directly: Pointer Scanner → File → Load pointer map
func cmdPmapExportCE(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: pmexport <file.scandata>")
		fmt.Println("  Exports current pmap to Cheat Engine compatible format")
		fmt.Println("  In CE: Pointer Scanner → File → Load pointer map → select file")
		return
	}
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if pointerMap == nil {
		fmt.Println("No pmap in memory. Run 'pmap' first.")
		return
	}
	path := args[0]
	fmt.Printf("Exporting pmap to CE format: %s (%d entries)...\n", path, len(pointerMap.Entries))
	if err := ExportPmapToCE(pointerMap, path, 0); err != nil {
		fmt.Println("Export failed:", err)
		return
	}
	fmt.Printf("Done. Load in CE: Pointer Scanner → File → Load pointer map → %s\n", path)
}

func cmdPmapClear() {
	pscanSessions = nil
	pointerMap = nil
	fmt.Println("All sessions cleared")
}

// pscan [depth] [max_offset] [max_results]
// Runs multi-session pointer scan using all registered sessions.
func cmdPointerScan(args []string, reader *bufio.Reader) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}

	// Need at least one session
	if len(pscanSessions) == 0 {
		fmt.Println("No sessions registered.")
		fmt.Println("Workflow:")
		fmt.Println("  1. Find target address (e.g. scan exact 100)")
		fmt.Println("  2. pmsave session1.pmap 0xYOURADDR   <- saves pmap + registers session")
		fmt.Println("  3. Restart game / change state so address moves")
		fmt.Println("  4. Find new address of same value")
		fmt.Println("  5. pmsave session2.pmap 0xNEWADDR    <- second session")
		fmt.Println("  6. pscan [depth] [max_offset] [max_results]")
		return
	}

	depth := 5
	maxOffset := uintptr(8192)
	maxResults := 100
	baseFilter := ""
	maxOffsetsPerNode := 0 // 0 = use default (5)

	if len(args) > 0 {
		depth, _ = strconv.Atoi(args[0])
	}
	if len(args) > 1 {
		v, _ := strconv.ParseUint(args[1], 0, 64)
		maxOffset = uintptr(v)
	}
	if len(args) > 2 {
		maxResults, _ = strconv.Atoi(args[2])
	}
	if len(args) > 3 {
		baseFilter = strings.ToLower(args[3])
	}
	if len(args) > 4 {
		maxOffsetsPerNode, _ = strconv.Atoi(args[4])
	}

	fmt.Printf("Running pointer scan across %d session(s): depth=%d maxOffset=0x%X maxResults=%d\n",
		len(pscanSessions), depth, maxOffset, maxResults)
	for i, s := range pscanSessions {
		fmt.Printf("  [%d] %s -> target=0x%X (%d pmap entries)\n", i+1, s.Label, s.PMap.TargetAddr, len(s.PMap.Entries))
	}

	start := time.Now()
	results := MultiSessionPointerScan(PointerScanConfig{
		Sessions:          pscanSessions,
		MaxDepth:          depth,
		MaxOffset:         maxOffset,
		MaxResults:        maxResults,
		BaseFilter:        baseFilter,
		MaxOffsetsPerNode: maxOffsetsPerNode,
		DT:                currentDT,
	})
	elapsed := time.Since(start)

	fmt.Printf("\nFound %d pointer chain(s) in %v\n", len(results), elapsed)
	if len(results) == 0 {
		fmt.Println("No chains found. Try: more sessions, bigger depth/offset, or check target addresses.")
		return
	}
	storeAndPrintResults(results, currentHandle, maxResults)
}

func cmdRegions(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	// Optional filter: "all" shows all readable, default shows writable private only
	showAll := len(args) > 0 && strings.ToLower(args[0]) == "all"
	regions := EnumMemoryRegions(currentHandle, !showAll)
	fmt.Printf("%-20s  %-20s  %-10s  %s\n", "Base", "End", "Size(MB)", "Type")
	fmt.Println(strings.Repeat("-", 65))
	for _, r := range regions {
		end := r.BaseAddress + r.RegionSize
		sizeMB := float64(r.RegionSize) / (1024 * 1024)
		typ := "PRIVATE"
		if r.Type == 0x40000 { typ = "MAPPED" }
		if r.Type == 0x1000000 { typ = "IMAGE" }
		fmt.Printf("0x%-18X  0x%-18X  %-10.1f  %s\n", r.BaseAddress, end, sizeMB, typ)
	}
	fmt.Printf("\nTotal: %d regions  (use: scan exact 100 range 0xBASE 0xEND)\n", len(regions))
}

func cmdModules() {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	fmt.Printf("%-40s  %-8s  %-10s  %s\n", "Module", "Size(KB)", "Type", "Path")
	fmt.Println(strings.Repeat("-", 100))
	for _, m := range currentModules {
		kind := "OTHER"
		if m.IsGameDir {
			kind = "GAME"
		} else if m.IsSystem {
			kind = "SYSTEM"
		}
		fmt.Printf("%-40s  %-8d  %-10s  %s\n", m.Name, m.Size/1024, kind, m.Path)
	}
	sys, game, other := 0, 0, 0
	for _, m := range currentModules {
		if m.IsGameDir {
			game++
		} else if m.IsSystem {
			sys++
		} else {
			other++
		}
	}
	fmt.Printf("\nTotal: %d modules (%d game dir, %d system, %d other)\n", len(currentModules), game, sys, other)
}

func cmdReset() {
	if scanner != nil {
		scanner.clearSnapshot()
		scanner.clearDiskRes()
		scanner.Results = nil
	}
	fmt.Println("Scan results cleared")
}

// cmdLogLast reads the full log file and copies it to Windows clipboard via clip.exe
// Usage: loglast [N]  — optionally last N lines only
func cmdLogLast(args []string) {
	if Log == nil || Log.LogPath() == "" {
		fmt.Println("No log file active")
		return
	}

	data, err := os.ReadFile(Log.LogPath())
	if err != nil {
		fmt.Println("Cannot read log file:", err)
		return
	}

	content := string(data)

	// If N specified, take only last N lines
	if len(args) > 0 {
		n, _ := strconv.Atoi(args[0])
		if n > 0 {
			lines := strings.Split(content, "\n")
			if n < len(lines) {
				lines = lines[len(lines)-n:]
			}
			content = strings.Join(lines, "\n")
		}
	}

	// Prepend version header so issue comments always have version info
	header := fmt.Sprintf("MemHacker v%s log\n%s\n\n", AppVersion, strings.Repeat("=", 40))
	content = header + content

	// Copy to clipboard using clip.exe (built into Windows, no deps)
	cmd := exec.Command("clip")
	cmd.Stdin = strings.NewReader(content)
	if err := cmd.Run(); err != nil {
		fmt.Println("clipboard copy failed:", err)
		fmt.Println("(Make sure you're running on Windows)")
		return
	}

	lineCount := strings.Count(content, "\n")
	fmt.Printf("Copied %d lines to clipboard — paste directly into GitHub issue\n", lineCount)
}

func parseAddr(s string) (uintptr, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, err
	}
	return uintptr(v), nil
}
