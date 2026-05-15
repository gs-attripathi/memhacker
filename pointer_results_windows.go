//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// PointerResultsFile — saved pointer scan results
type PointerResultsFile struct {
	Version    string         `json:"version"`
	SavedAt    time.Time      `json:"saved_at"`
	GameExe    string         `json:"game_exe"`
	Is32Bit    bool           `json:"is_32bit"`
	DataType   string         `json:"data_type"`
	Chains     []SavedChain   `json:"chains"`
}

type SavedChain struct {
	BaseModule    string   `json:"base_module"`
	BaseOffset    string   `json:"base_offset"`
	Offsets       []string `json:"offsets"`
	Label         string   `json:"label"`
	Notes         string   `json:"notes"`
	ExpectedValue string   `json:"expected_value"` // value at time of prsave
}

func chainToSaved(c PointerChain, label string) SavedChain {
	offsets := make([]string, len(c.Offsets))
	for i, o := range c.Offsets {
		signed := int64(o)
		if signed < 0 {
			offsets[i] = fmt.Sprintf("-%X", uint64(-signed))
		} else {
			offsets[i] = fmt.Sprintf("+%X", o)
		}
	}
	return SavedChain{
		BaseModule: c.BaseModule,
		BaseOffset: fmt.Sprintf("%X", c.BaseOffset),
		Offsets:    offsets,
		Label:      label,
	}
}

func savedToChain(s SavedChain) (PointerChain, error) {
	var baseOffset uint64
	fmt.Sscanf(s.BaseOffset, "%X", &baseOffset)

	offsets := make([]uintptr, len(s.Offsets))
	for i, o := range s.Offsets {
		o = strings.TrimSpace(o)
		negative := strings.HasPrefix(o, "-")
		o = strings.TrimPrefix(o, "-")
		o = strings.TrimPrefix(o, "+")
		var v uint64
		fmt.Sscanf(o, "%X", &v)
		if negative {
			offsets[i] = uintptr(^v + 1) // two's complement
		} else {
			offsets[i] = uintptr(v)
		}
	}
	return PointerChain{
		BaseModule: s.BaseModule,
		BaseOffset: uintptr(baseOffset),
		Offsets:    offsets,
	}, nil
}

// SavePointerResults saves pscan results to a JSON file
func SavePointerResults(path string, results []PointerResult, gameExe string, is32Bit bool, dt DataType, handle windows.Handle, modules []ModuleInfo) error {
	chains := make([]SavedChain, len(results))
	for i, r := range results {
		sc := chainToSaved(r.Chain, r.Label)
		// Read current value at this chain's address so we can verify later
		if handle != 0 {
			addr, ok := VerifyChain(handle, modules, r.Chain, is32Bit)
			if ok {
				val, err := ReadMemory(handle, addr, dataTypeSize(dt))
				if err == nil {
					sc.ExpectedValue = decodeValue(dt, val)
				}
			}
		}
		chains[i] = sc
	}
	prf := PointerResultsFile{
		Version:  AppVersion,
		SavedAt:  time.Now(),
		GameExe:  gameExe,
		Is32Bit:  is32Bit,
		DataType: dataTypeName(dt),
		Chains:   chains,
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(prf)
}

// LoadPointerResults loads saved pscan results from a JSON file
func LoadPointerResults(path string) (*PointerResultsFile, []PointerChain, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var prf PointerResultsFile
	if err := json.NewDecoder(f).Decode(&prf); err != nil {
		return nil, nil, fmt.Errorf("invalid results file: %v", err)
	}

	chains := make([]PointerChain, len(prf.Chains))
	for i, s := range prf.Chains {
		c, err := savedToChain(s)
		if err != nil {
			return nil, nil, err
		}
		chains[i] = c
	}
	return &prf, chains, nil
}

// --- Commands ---

var lastPscanResults []PointerResult     // in-memory last pscan output
var lastLoadedFile   *PointerResultsFile // last prload file, for expected value comparison

// prsave <file> — save last pscan results to file
func cmdPointerResultsSave(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: prsave <file.json>")
		fmt.Println("  Saves the last pscan results to a JSON file")
		return
	}
	if len(lastPscanResults) == 0 {
		fmt.Println("No pscan results in memory. Run pscan first.")
		return
	}
	gameExe := ""
	for _, m := range currentModules {
		if strings.HasSuffix(strings.ToLower(m.Name), ".exe") {
			gameExe = m.Name
			break
		}
	}
	if err := SavePointerResults(args[0], lastPscanResults, gameExe, currentIs32Bit, currentDT, currentHandle, currentModules); err != nil {
		fmt.Println("Save failed:", err)
		return
	}
	fmt.Printf("Saved %d chains to %s\n", len(lastPscanResults), args[0])
	Log.Info("prsave: saved %d chains to %s", len(lastPscanResults), args[0])
}

// prload <file> [expected_addr_hex]
// Loads saved chains. If expected_addr given, verifies each chain resolves to that address.
func cmdPointerResultsLoad(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: prload <file.json> [expected_addr_hex]")
		fmt.Println("  expected_addr: the address you found this session (e.g. 0x614DD58)")
		fmt.Println("  Chain must resolve to this address to be considered valid")
		return
	}
	prf, chains, err := LoadPointerResults(args[0])
	if err != nil {
		fmt.Println("Load failed:", err)
		return
	}

	fmt.Printf("Loaded %s\n", args[0])
	fmt.Printf("  Saved:    %s\n", prf.SavedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Version:  %s\n", prf.Version)
	fmt.Printf("  Game:     %s (%s)\n", prf.GameExe, map[bool]string{true: "32-bit", false: "64-bit"}[prf.Is32Bit])
	fmt.Printf("  DataType: %s\n", prf.DataType)
	fmt.Printf("  Chains:   %d\n\n", len(chains))

	lastLoadedFile = prf
	lastPscanResults = make([]PointerResult, len(chains))
	for i, c := range chains {
		lastPscanResults[i] = PointerResult{Chain: c, Label: prf.Chains[i].Label}
	}

	// If expected address given, verify chains resolve to it
	if len(args) >= 2 && currentHandle != 0 {
		expectedAddr, err := resolveAddr(args[1])
		if err != nil {
			fmt.Println("Invalid address:", err)
			return
		}
		fmt.Printf("Verifying chains resolve to 0x%X...\n", expectedAddr)
		fmt.Printf("%-5s  %-10s  %-20s  %s\n", "#", "Status", "Resolved To", "Chain")
		fmt.Println(strings.Repeat("-", 90))

		var matchedResults []PointerResult
		invalid := 0
		for i, r := range lastPscanResults {
			addr, ok := VerifyChain(currentHandle, currentModules, r.Chain, currentIs32Bit)
			if ok && addr == expectedAddr {
				fmt.Printf("%-5d  %-10s  0x%-18X  %s\n", i+1, "MATCH", addr, r.Chain.String())
				matchedResults = append(matchedResults, r)
			} else if ok {
				fmt.Printf("%-5d  %-10s  0x%-18X  %s\n", i+1, "WRONG ADDR", addr, r.Chain.String())
				invalid++
			} else {
				fmt.Printf("%-5d  %-10s  %-20s  %s\n", i+1, "BROKEN", "-", r.Chain.String())
				invalid++
			}
		}
		fmt.Printf("\n%d chains match 0x%X, %d don't\n", len(matchedResults), expectedAddr, invalid)

		// Replace in-memory results with only matched ones
		lastPscanResults = matchedResults
		if len(matchedResults) > 0 {
			fmt.Printf("\nIn-memory results updated to %d matched chains only\n", len(matchedResults))
			fmt.Println("Tip: prsave <file.json>  <- overwrite file with only working chains")
		}
		Log.Info("prload verify: %d match 0x%X, %d invalid", len(matchedResults), expectedAddr, invalid)
	} else if len(args) >= 2 && currentHandle == 0 {
		fmt.Println("Not attached to process — skipping address verification")
		fmt.Println("Use 'open <game>' first, then run: prload", args[0], args[1])
		for i, c := range chains {
			fmt.Printf("  [%d] %s\n", i+1, c.String())
		}
	} else {
		if currentHandle != 0 {
			cmdPointerResultsVerify(nil)
		} else {
			fmt.Println("Tip: prload <file> <current_addr>  to verify chains match a specific address")
			for i, c := range chains {
				fmt.Printf("  [%d] %s\n", i+1, c.String())
			}
		}
	}
	Log.Info("prload: loaded %d chains from %s", len(chains), args[0])
}

// prverify [addr] — verify chains against current process
// If addr given, only chains resolving to that address are OK
func cmdPointerResultsVerify(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached. Use 'open <game>' first.")
		return
	}
	if len(lastPscanResults) == 0 {
		fmt.Println("No chains loaded. Run pscan or prload first.")
		return
	}

	// Optional: expected address to match against
	var expectedAddr uintptr
	hasExpected := false
	if len(args) > 0 && args[0] != "" {
		addr, err := resolveAddr(args[0])
		if err != nil {
			fmt.Println("Invalid address:", err)
			return
		}
		expectedAddr = addr
		hasExpected = true
		fmt.Printf("Verifying %d chains — must resolve to 0x%X\n", len(lastPscanResults), expectedAddr)
	} else {
		fmt.Printf("Verifying %d chains against current process...\n", len(lastPscanResults))
	}

	// Load expected values from file if available
	expectedVals := make(map[int]string)
	if lastLoadedFile != nil {
		for i, sc := range lastLoadedFile.Chains {
			if sc.ExpectedValue != "" {
				expectedVals[i] = sc.ExpectedValue
			}
		}
	}

	fmt.Printf("%-5s  %-10s  %-20s  %-12s  %-12s  %s\n", "#", "Status", "Address", "Current", "Expected", "Chain")
	fmt.Println(strings.Repeat("-", 100))

	var matchedResults []PointerResult
	ok, broken, mismatch, wrongAddr := 0, 0, 0, 0

	for i, r := range lastPscanResults {
		addr, valid := VerifyChain(currentHandle, currentModules, r.Chain, currentIs32Bit)
		if !valid {
			fmt.Printf("%-5d  %-10s  %-20s  %-12s  %-12s  %s\n", i+1, "BROKEN", "-", "-", "-", r.Chain.String())
			broken++
			continue
		}

		// If expected address given, check it matches
		if hasExpected && addr != expectedAddr {
			fmt.Printf("%-5d  %-10s  0x%-18X  %-12s  %-12s  %s\n", i+1, "WRONG ADDR", addr, "-", "-", r.Chain.String())
			wrongAddr++
			continue
		}

		currentVal, err := scanner.ReadCurrentValue(addr, currentDT)
		if err != nil {
			currentVal = "read err"
		}
		expected := expectedVals[i]
		status := "OK"
		if expected != "" && currentVal != expected {
			status = "MISMATCH"
			mismatch++
		} else {
			ok++
		}
		fmt.Printf("%-5d  %-10s  0x%-18X  %-12s  %-12s  %s\n",
			i+1, status, addr, currentVal, expected, r.Chain.String())
		matchedResults = append(matchedResults, r)
	}

	fmt.Printf("\nResult: %d OK, %d mismatch, %d wrong addr, %d broken\n", ok, mismatch, wrongAddr, broken)

	// If address filter was used, update in-memory to matched only
	if hasExpected && len(matchedResults) > 0 {
		lastPscanResults = matchedResults
		fmt.Printf("In-memory updated to %d matched chains\n", len(matchedResults))
		fmt.Println("Tip: prsave <file.json>  <- save only working chains")
	}
	if mismatch > 0 {
		fmt.Println("MISMATCH = chain valid but value changed (different save/character)")
	}
	if broken > 0 {
		fmt.Println("BROKEN = chain no longer resolves (game updated?)")
	}
	Log.Info("prverify: %d OK, %d mismatch, %d wrongAddr, %d broken", ok, mismatch, wrongAddr, broken)
}

// prlabel <index> <label> — label a chain for easier identification
func cmdPointerResultsLabel(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: prlabel <index> <label>   e.g: prlabel 1 HP")
		return
	}
	var idx int
	fmt.Sscanf(args[0], "%d", &idx)
	idx-- // 1-based to 0-based
	if idx < 0 || idx >= len(lastPscanResults) {
		fmt.Println("Invalid index")
		return
	}
	label := strings.Join(args[1:], " ")
	lastPscanResults[idx].Label = label
	fmt.Printf("Chain %d labeled as '%s'\n", idx+1, label)
}

// prfreeze <index> <value> — freeze a verified chain's address
func cmdPointerResultsFreeze(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: prfreeze <index> <value>   e.g: prfreeze 1 999")
		return
	}
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	var idx int
	fmt.Sscanf(args[0], "%d", &idx)
	idx--
	if idx < 0 || idx >= len(lastPscanResults) {
		fmt.Println("Invalid index")
		return
	}
	addr, ok := VerifyChain(currentHandle, currentModules, lastPscanResults[idx].Chain, currentIs32Bit)
	if !ok {
		fmt.Printf("Chain %d is broken — cannot freeze\n", idx+1)
		return
	}
	val, err := encodeValue(currentDT, args[1])
	if err != nil {
		fmt.Println("Invalid value:", err)
		return
	}
	id := freezer.Add(addr, val, lastPscanResults[idx].Chain.String())
	fmt.Printf("Freezing chain %d -> 0x%X = %s (freeze id=%d)\n", idx+1, addr, args[1], id)
	Log.Info("prfreeze: chain %d addr=0x%X val=%s freeze_id=%d", idx+1, addr, args[1], id)
}

// prwrite <index> <value> — write to a verified chain's address once
func cmdPointerResultsWrite(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: prwrite <index> <value>   e.g: prwrite 1 999")
		return
	}
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	var idx int
	fmt.Sscanf(args[0], "%d", &idx)
	idx--
	if idx < 0 || idx >= len(lastPscanResults) {
		fmt.Println("Invalid index")
		return
	}
	addr, ok := VerifyChain(currentHandle, currentModules, lastPscanResults[idx].Chain, currentIs32Bit)
	if !ok {
		fmt.Printf("Chain %d is broken\n", idx+1)
		return
	}
	val, err := encodeValue(currentDT, args[1])
	if err != nil {
		fmt.Println("Invalid value:", err)
		return
	}
	if err := WriteMemory(currentHandle, addr, val); err != nil {
		fmt.Println("Write failed:", err)
		return
	}
	fmt.Printf("Written %s to chain %d -> 0x%X\n", args[1], idx+1, addr)
	Log.Info("prwrite: chain %d addr=0x%X val=%s", idx+1, addr, args[1])
}

// prlist — list current in-memory pointer results
func cmdPointerResultsList() {
	if len(lastPscanResults) == 0 {
		fmt.Println("No results. Run pscan or prload first.")
		return
	}
	fmt.Printf("%-5s  %-14s  %s\n", "#", "Label", "Chain")
	fmt.Println(strings.Repeat("-", 90))
	for i, r := range lastPscanResults {
		fmt.Printf("%-5d  %-14s  %s\n", i+1, r.Label, r.Chain.String())
	}
	fmt.Printf("\nTotal: %d chains  (use prverify to check against current process)\n", len(lastPscanResults))
}

// --- Wire into cmdPointerScan to auto-store results ---
func storeAndPrintResults(results []PointerResult, handle windows.Handle) {
	lastPscanResults = results

	fmt.Println()
	for i, r := range results {
		fmt.Printf("[%d] %s\n", i+1, r.Chain.String())
	}

	if handle != 0 && len(results) > 0 {
		fmt.Println("\nVerifying chains against current process...")
		ok := 0
		for i, r := range results {
			addr, valid := VerifyChain(handle, currentModules, r.Chain, currentIs32Bit)
			if valid {
				val, err := scanner.ReadCurrentValue(addr, currentDT)
				if err == nil {
					fmt.Printf("  [%d] OK -> 0x%X = %s\n", i+1, addr, val)
				} else {
					fmt.Printf("  [%d] OK -> 0x%X\n", i+1, addr)
				}
				ok++
			} else {
				fmt.Printf("  [%d] BROKEN\n", i+1)
			}
		}
		fmt.Printf("\n%d/%d chains verified OK\n", ok, len(results))
	}
	fmt.Printf("\nTip: prsave results.json  <- save these chains\n")
	fmt.Printf("     prverify             <- re-verify after game restart\n")
}
