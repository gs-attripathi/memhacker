//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
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
	scanner        *MemoryScanner
	freezer        *Freezer
	currentDT      DataType = TypeInt32
	pointerMap     *PointerMap
	addressList    []addressEntry
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
		case "pscan":
			Log.Info("CMD: pscan %v", args)
			cmdPointerScan(args, reader)
		case "modules", "mod":
			cmdModules()
		case "reset":
			Log.Info("CMD: reset")
			cmdReset()
		case "log":
			if Log != nil {
				fmt.Printf("Log file: %s\n", Log.LogPath())
			}
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
	fmt.Println("============================================")
	fmt.Println("   MemHacker - CE-style Memory Tool")
	fmt.Println("   type 'help' for commands")
	fmt.Println("============================================")
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

POINTER SCANNING
  pmap                   - build pointer map (required before pscan)
  pscan <addr> [depth] [offset] [max_results]
                         - pointer scan for address
                           defaults: depth=5 offset=2048 max=100
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
	scanner = NewMemoryScanner(h)
	freezer = NewFreezer(h)

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
	fmt.Printf("Attached to %s (PID %d), %d modules loaded\n", name, pid, len(mods))
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
	addr, err := parseAddr(args[0])
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
	addr, err := parseAddr(args[0])
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
	addr, err := parseAddr(args[0])
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
	addr, err := parseAddr(args[0])
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
	pm, err := BuildPointerMap(currentHandle, currentModules)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	pointerMap = pm
	fmt.Printf("Pointer map ready in %v (%d entries)\n", time.Since(start), len(pm.Entries))
}

func cmdPointerScan(args []string, reader *bufio.Reader) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if pointerMap == nil {
		fmt.Println("No pointer map. Run 'pmap' first")
		return
	}
	if len(args) == 0 {
		fmt.Println("Usage: pscan <addr_hex> [depth] [max_offset] [max_results]")
		return
	}
	addr, err := parseAddr(args[0])
	if err != nil {
		fmt.Println("Invalid address:", err)
		return
	}
	depth := 5
	maxOffset := uintptr(2048)
	maxResults := 100
	if len(args) > 1 {
		depth, _ = strconv.Atoi(args[1])
	}
	if len(args) > 2 {
		v, _ := strconv.ParseUint(args[2], 0, 64)
		maxOffset = uintptr(v)
	}
	if len(args) > 3 {
		maxResults, _ = strconv.Atoi(args[3])
	}

	fmt.Printf("Pointer scanning for 0x%X (depth=%d, maxOffset=0x%X, max=%d)...\n",
		addr, depth, maxOffset, maxResults)
	start := time.Now()
	results := BFSPointerScan(currentHandle, pointerMap, currentModules, addr, depth, maxOffset, maxResults)
	fmt.Printf("Found %d pointer chains in %v\n", len(results), time.Since(start))
	for i, r := range results {
		fmt.Printf("[%d] %s\n", i+1, FormatPointerResult(r))
	}
}

func cmdModules() {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	fmt.Printf("%-40s  %-18s  %s\n", "Module", "Base", "Size")
	fmt.Println(strings.Repeat("-", 70))
	for _, m := range currentModules {
		fmt.Printf("%-40s  0x%-16X  %d KB\n", m.Name, m.Base, m.Size/1024)
	}
}

func cmdReset() {
	if scanner != nil {
		scanner.Results = nil
	}
	fmt.Println("Scan results cleared")
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
