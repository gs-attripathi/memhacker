//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
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
	currentDT      DataType = TypeInt32
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
		case "add", "a":
			cmdAddToList(args)
		case "addrlist", "al":
			cmdShowAddressList()
		case "freeze", "f":
			Log.Info("CMD: freeze %v", args)
			cmdFreeze(args)
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
		case "pmsessions":
			cmdPmapSessions()
		case "pmclear":
			Log.Info("CMD: pmclear")
			cmdPmapClear()
		case "pscan":
			Log.Info("CMD: pscan %v", args)
			cmdPointerScan(args, reader)
		case "prsave":
			Log.Info("CMD: prsave %v", args)
			cmdPointerResultsSave(args)
		case "prload":
			Log.Info("CMD: prload %v", args)
			cmdPointerResultsLoad(args)
		case "prverify":
			Log.Info("CMD: prverify")
			cmdPointerResultsVerify(args)
		case "prlist":
			cmdPointerResultsList()
		case "prwrite":
			Log.Info("CMD: prwrite %v", args)
			cmdPointerResultsWrite(args)
		case "prfreeze":
			Log.Info("CMD: prfreeze %v", args)
			cmdPointerResultsFreeze(args)
		case "modules", "mod":
			cmdModules()
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
  ps / list              - list all running processes
  open <pid|name>        - attach to a process
  close                  - detach
  modules                - list loaded modules

SCANNING
  type <dt>              - set data type (i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 str bytes)
  scan <type> [value]    - first scan
    types: exact <v>  unknown  bigger <v>  smaller <v>  between <v1> <v2>
           changed  unchanged  increased  decreased  incby <v>  decby <v>  notequal <v>
  next <type> [value]    - filter scan (same types as scan)
  results [n]            - show top N results (default 20)
  reset                  - clear scan results

VALUE OPS
  read <addr> [dt]       - read value at address
  write <addr> <value>   - write value at address
  add <addr> [label]     - add to address list
  addrlist               - show address list

FREEZING
  freeze <addr> <value> [label]  - freeze address to value
  unfreeze <id>                  - unfreeze by ID
  frozen                         - show frozen entries

POINTER SCANNING (CE-style multi-session)
  pmap                          - build pointer map for current process (in-memory)
  pmsave <file> <addr>          - save pmap to file + register as session
                                  (target addr saved inside the file)
                                  e.g: pmsave s1.pmap 0x1A2B3C4D
  pmload <file>                 - load saved pmap (target addr read from file)
                                  e.g: pmload s1.pmap
  pmsessions                    - list all registered sessions
  pmclear                       - clear all sessions + pmap

  pscan [depth] [offset] [max] [filter]
                                - run pointer scan across ALL registered sessions
                                  filter: exe (default), game, all
                                  auto-widens: exe -> game -> all if no results
                                  defaults: depth=7 offset=5000 max=100

POINTER RESULTS (save/load/verify chains)
  prsave <file.json>            - save last pscan results to JSON file
  prload <file.json> [addr]     - load saved chains
                                  addr = current session address (chain must resolve to it)
                                  e.g: prload hp.json 0x614DD58
  prverify [addr]               - re-verify chains, optional addr = must resolve to this
                                  e.g: prverify 0x614DD58  or  prverify hp (alias)
  prlist                        - list current in-memory chains
  prwrite <index> <value>       - follow chain, write value once  (e.g: prwrite 1 999)
  prfreeze <index> <value>      - follow chain, freeze value      (e.g: prfreeze 1 999)

  WORKFLOW (persistent pointers across restarts):
    pscan                       <- find chains
    prsave hp.json              <- save them
    --- game restart ---
    open game.exe
    prload hp.json              <- load + auto-verify
    prwrite 1 999               <- write to chain 1
    prfreeze 1 999              <- or freeze it
                                  e.g: pscan 7 4096 200 game

  WORKFLOW:
    1. open game.exe
    2. scan exact 100           <- find HP address
    3. pmsave s1.pmap 0xADDR    <- snapshot pmap + register
    4. restart game (address changes)
    5. scan exact 100           <- find new HP address
    6. pmsave s2.pmap 0xNEWADDR <- second snapshot
    7. pscan 6 2048 50          <- cross-reference both sessions

OTHER
  alias [name] [addr]  - set/list address aliases (use name instead of hex anywhere)
                         e.g: alias hp 0x614DD58  then: write hp 999  freeze hp 999
  unalias <name>       - remove an alias
  log                  - show log file path
  loglast [N]          - copy full log to clipboard (last N lines if specified)
                         includes version header — paste directly into GitHub issue
  exit / quit          - exit
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
		// Try by name
		procs, _ := ListProcesses()
		name := strings.ToLower(args[0])
		for _, p := range procs {
			if strings.ToLower(p.Name) == name || strings.ToLower(strings.TrimSuffix(p.Name, ".exe")) == name {
				pid = uint64(p.PID)
				break
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
		return
	}
	p, ok := parseScanArgs(args[0], args[1:])
	if !ok {
		return
	}
	fmt.Printf("Scanning for %s [type=%s]...\n", args[0], dataTypeName(currentDT))
	start := time.Now()
	count := scanner.FirstScan(p)
	elapsed := time.Since(start)
	fmt.Printf("Found %d results in %v\n", count, elapsed)
	if count > 0 && count <= 20 {
		showResults(20)
	}
}

func cmdNext(args []string, reader *bufio.Reader) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if scanner == nil || len(scanner.Results) == 0 {
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
	fmt.Printf("Filtering %d results...\n", len(scanner.Results))
	start := time.Now()
	count := scanner.NextScan(p)
	elapsed := time.Since(start)
	fmt.Printf("%d results remaining (%v)\n", count, elapsed)
	if count > 0 && count <= 20 {
		showResults(20)
	}
}

func cmdResults(args []string) {
	n := 20
	if len(args) > 0 {
		n, _ = strconv.Atoi(args[0])
	}
	showResults(n)
}

func showResults(n int) {
	if scanner == nil || len(scanner.Results) == 0 {
		fmt.Println("No results")
		return
	}
	// Refresh values
	scanner.RefreshValues(currentDT)
	total := len(scanner.Results)
	if n > total {
		n = total
	}
	fmt.Printf("%-20s  %s\n", "Address", "Value")
	fmt.Println(strings.Repeat("-", 40))
	for i := 0; i < n; i++ {
		r := scanner.Results[i]
		fmt.Printf("0x%-18X  %s\n", r.Address, decodeValue(currentDT, r.Value))
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
		fmt.Printf("Added %d addresses to list\n", len(scanner.Results))
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
	fmt.Printf("Freezing 0x%X = %s (id=%d)\n", addr, args[1], id)
}

func cmdUnfreeze(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: unfreeze <id>")
		return
	}
	id, _ := strconv.Atoi(args[0])
	freezer.Remove(id)
	fmt.Printf("Unfroze id=%d\n", id)
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
	fmt.Printf("%-5s  %-6s  %-20s  %-20s  %s\n", "ID", "Active", "Address", "Value", "Label")
	fmt.Println(strings.Repeat("-", 70))
	for _, e := range list {
		active := "YES"
		if !e.Entry.Active {
			active = "NO"
		}
		fmt.Printf("%-5d  %-6s  0x%-18X  %-20s  %s\n",
			e.ID, active, e.Entry.Address,
			decodeValue(currentDT, e.Entry.Value),
			e.Entry.Label)
	}
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

	// Register as session
	pscanSessions = append(pscanSessions, PointerScanSession{
		
		PMap:       pointerMap,
		Label:      path,
	})

	Log.Info("pmsave: saved %s, target=0x%X, session count=%d", path, targetAddr, len(pscanSessions))
	fmt.Printf("Saved %s (%d entries) | target=0x%X | session #%d registered\n",
		path, len(pointerMap.Entries), targetAddr, len(pscanSessions))
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

// pmsessions — list registered sessions
func cmdPmapSessions() {
	if len(pscanSessions) == 0 {
		fmt.Println("No sessions registered. Use 'pmsave' or 'pmload' to add sessions.")
		return
	}
	fmt.Printf("%-4s  %-14s  %-40s  %s\n", "#", "Target Addr", "File", "Entries")
	fmt.Println(strings.Repeat("-", 75))
	for i, s := range pscanSessions {
		fmt.Printf("%-4d  0x%-12X  %-40s  %d\n", i+1, s.PMap.TargetAddr, s.Label, len(s.PMap.Entries))
	}
}

// pmclear — clear all sessions
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

	depth := 7
	maxOffset := uintptr(5000)
	maxResults := 100
	baseFilter := "" // default = "exe", auto-widens if needed

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
		baseFilter = strings.ToLower(args[3]) // "exe", "game", "all"
	}

	fmt.Printf("Running pointer scan across %d session(s): depth=%d maxOffset=0x%X maxResults=%d\n",
		len(pscanSessions), depth, maxOffset, maxResults)
	for i, s := range pscanSessions {
		fmt.Printf("  [%d] %s -> target=0x%X (%d pmap entries)\n", i+1, s.Label, s.PMap.TargetAddr, len(s.PMap.Entries))
	}

	start := time.Now()
	results := MultiSessionPointerScan(PointerScanConfig{
		Sessions:   pscanSessions,
		MaxDepth:   depth,
		MaxOffset:  maxOffset,
		MaxResults: maxResults,
		BaseFilter: baseFilter,
	})
	elapsed := time.Since(start)

	fmt.Printf("\nFound %d pointer chain(s) in %v\n", len(results), elapsed)
	if len(results) == 0 {
		fmt.Println("No chains found. Try: more sessions, bigger depth/offset, or check target addresses.")
		return
	}
	storeAndPrintResults(results, currentHandle)
}

func cmdModules() {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	fmt.Printf("%-40s  %-8s  %-10s  %s\n", "Module", "Size(KB)", "Type", "Path")
	fmt.Println(strings.Repeat("-", 100))
	for _, m := range currentModules {
		kind := "GAME"
		if m.IsSystem {
			kind = "SYSTEM"
		}
		fmt.Printf("%-40s  %-8d  %-10s  %s\n", m.Name, m.Size/1024, kind, m.Path)
	}
	// summary
	sys, game := 0, 0
	for _, m := range currentModules {
		if m.IsSystem {
			sys++
		} else {
			game++
		}
	}
	fmt.Printf("\nTotal: %d modules (%d game/unknown, %d system)\n", len(currentModules), game, sys)
}

func cmdReset() {
	if scanner != nil {
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
