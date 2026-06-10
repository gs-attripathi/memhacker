//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Disk-backed result set: the user's curated working set, fully separate from
// the scan set. `results add <selection>` copies scan rows in (deduped by
// address); `results view/write/freeze/remove/clear` operate on it directly.
// Nothing is held in RAM: appends stream to the file, views read back a window
// on demand. Lives next to the exe (NOT in the swept memhacker_scans dir) so it
// survives app restarts; entries go stale when the game restarts.
//
// Record layout (16 bytes): addr u64 | conf f32 | guessCode u8 | dt u8 | 2 pad
// guessCode indexes rsTypeNames when the row came from a guess; 255 = not
// guessed, in which case dt (a DataType) says how to decode the value.

const rsRecSize = 16
const rsNoGuess = 255

var rsTypeNames = []string{"f32", "f64", "i32", "i64", "i8", "ptr", "zero", "?"}

func rsTypeByte(name string) byte {
	for i, n := range rsTypeNames {
		if n == name {
			return byte(i)
		}
	}
	return rsNoGuess
}

func rsTypeName(b byte) string {
	if int(b) < len(rsTypeNames) {
		return rsTypeNames[b]
	}
	return ""
}

// guessNameDT maps a guess label to the DataType used to decode the value.
func guessNameDT(name string) DataType {
	switch name {
	case "f32":
		return TypeFloat32
	case "f64":
		return TypeFloat64
	case "i32":
		return TypeInt32
	case "i64":
		return TypeInt64
	case "i8":
		return TypeInt8
	case "ptr":
		return TypeUInt64
	}
	return currentDT
}

func rsPath() string {
	return filepath.Join(exeDir(), "memhacker_results.bin")
}

func rsCount() int {
	fi, err := os.Stat(rsPath())
	if err != nil {
		return 0
	}
	return int(fi.Size()) / rsRecSize
}

type rsRec struct {
	addr  uintptr
	conf  float64
	gname string   // guess label, "" if the row wasn't guessed
	dt    DataType // how to decode the value
}

// rsAddrSet streams every stored address into a transient set for dedupe.
func rsAddrSet() map[uintptr]bool {
	set := make(map[uintptr]bool)
	f, err := os.Open(rsPath())
	if err != nil {
		return set
	}
	defer f.Close()
	buf := make([]byte, rsRecSize*4096)
	for {
		n, err := f.Read(buf)
		for off := 0; off+rsRecSize <= n; off += rsRecSize {
			set[uintptr(binary.LittleEndian.Uint64(buf[off:]))] = true
		}
		if err != nil {
			break
		}
	}
	return set
}

// rsAppend appends rows to the store, skipping already-stored addresses.
// Guessed rows record their guess label + confidence; plain rows record the
// data type that was active when they were added.
func rsAppend(rows []resultRow) (added, dupes int) {
	if len(rows) == 0 {
		return 0, 0
	}
	seen := rsAddrSet()
	f, err := os.OpenFile(rsPath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("  cannot open result set file:", err)
		return 0, 0
	}
	defer f.Close()
	var rec [rsRecSize]byte
	for _, r := range rows {
		if seen[r.addr] {
			dupes++
			continue
		}
		seen[r.addr] = true
		binary.LittleEndian.PutUint64(rec[0:], uint64(r.addr))
		binary.LittleEndian.PutUint32(rec[8:], math.Float32bits(float32(r.conf)))
		if r.gname != "" {
			rec[12] = rsTypeByte(r.gname)
			rec[13] = byte(guessNameDT(r.gname))
		} else {
			rec[12] = rsNoGuess
			rec[13] = byte(currentDT)
		}
		rec[14], rec[15] = 0, 0
		f.Write(rec[:])
		added++
	}
	return added, dupes
}

// rsRead returns up to n records starting at 0-based index start.
func rsRead(start, n int) []rsRec {
	f, err := os.Open(rsPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n*rsRecSize)
	nr, _ := f.ReadAt(buf, int64(start)*rsRecSize)
	recs := make([]rsRec, 0, nr/rsRecSize)
	for off := 0; off+rsRecSize <= nr; off += rsRecSize {
		recs = append(recs, rsRec{
			addr:  uintptr(binary.LittleEndian.Uint64(buf[off:])),
			conf:  float64(math.Float32frombits(binary.LittleEndian.Uint32(buf[off+8:]))),
			gname: rsTypeName(buf[off+12]),
			dt:    DataType(buf[off+13]),
		})
	}
	return recs
}

// rsRemove rewrites the store without the given 1-based indices.
func rsRemove(rm map[int]bool) {
	src, err := os.Open(rsPath())
	if err != nil {
		return
	}
	tmp := rsPath() + ".tmp"
	dst, err := os.Create(tmp)
	if err != nil {
		src.Close()
		return
	}
	buf := make([]byte, rsRecSize)
	idx := 0
	for {
		if _, err := io.ReadFull(src, buf); err != nil {
			break
		}
		idx++
		if rm[idx] {
			continue
		}
		dst.Write(buf)
	}
	src.Close()
	dst.Close()
	os.Remove(rsPath())
	os.Rename(tmp, rsPath())
}

func rsClear() {
	if err := os.Remove(rsPath()); err != nil && !os.IsNotExist(err) {
		fmt.Println("  cannot clear result set:", err)
	}
}

// rsValueString reads the live value at the record's address, decoded as the
// type it was captured with (guessed type or the data type active at capture).
func rsValueString(r rsRec) string {
	if currentHandle == 0 {
		return "?"
	}
	if r.gname == "ptr" {
		buf, err := ReadMemory(currentHandle, r.addr, 8)
		if err != nil || len(buf) < 8 {
			return "?"
		}
		return fmt.Sprintf("0x%X", binary.LittleEndian.Uint64(buf))
	}
	sz := dataTypeSize(r.dt)
	buf, err := ReadMemory(currentHandle, r.addr, sz)
	if err != nil || len(buf) < sz {
		return "?"
	}
	return decodeValue(r.dt, buf)
}

// ---------------------------------------------------------------------------
// result set commands (dispatched from cmdResults)
// ---------------------------------------------------------------------------

// resolveSelection turns a selection token into 1-based indices against total.
// A plain number means "top n"; ranges/lists are explicit indices.
func resolveSelection(sel string, total int) []int {
	if strings.Contains(sel, "-") || strings.Contains(sel, ",") {
		var idxs []int
		for _, idx := range parseIndexSpec(sel) {
			if idx >= 1 && idx <= total {
				idxs = append(idxs, idx)
			}
		}
		return idxs
	}
	n, err := strconv.Atoi(sel)
	if err != nil || n <= 0 {
		return nil
	}
	if n > total {
		n = total
	}
	idxs := make([]int, n)
	for i := range idxs {
		idxs[i] = i + 1
	}
	return idxs
}

// cmdResultsAdd copies selected scan-set rows into the result set.
// results add <count|range|list> [guess|g <type> [minconf]]
func cmdResultsAdd(args []string) {
	if scanner == nil || scanner.totalResults() == 0 {
		fmt.Println("No scan results. Run scan first")
		return
	}
	if len(args) == 0 {
		fmt.Println("Usage: results add <count|range|list> [guess|g <type> [minconf]]")
		fmt.Println("  e.g: results add 50             <- top 50 scan rows")
		fmt.Println("       results add 100-200        <- scan rows #100-200")
		fmt.Println("       results add 1-400 g i8 0.7 <- only i8-guessed rows from #1-400")
		return
	}

	gFilter := ""
	gThresh := 0.5
	sel := ""
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "guess", "g":
			if i+1 < len(args) && validGuessTypes[strings.ToLower(args[i+1])] {
				gFilter = strings.ToLower(args[i+1])
				i++
				if i+1 < len(args) {
					if t, err := strconv.ParseFloat(args[i+1], 64); err == nil && t > 0 && t <= 1 {
						gThresh = t
						i++
					}
				}
			} else {
				fmt.Println("guess filter needs a type: f32 f64 i32 i64 i8 ptr zero")
				return
			}
		default:
			if sel == "" {
				sel = args[i]
			}
		}
	}
	if sel == "" {
		fmt.Println("Missing selection (count, range, or list)")
		return
	}

	total := scanner.totalResults()
	var rows []resultRow
	tryRow := func(idx int) bool {
		addr, _ := scanner.getResult(idx - 1)
		var gl, name string
		var conf float64
		if gFilter != "" {
			gl, name, conf = guessAt(addr)
			if name != gFilter || conf < gThresh {
				return false
			}
		}
		rows = append(rows, resultRow{idx, addr, "", gl, name, conf})
		return true
	}

	isCount := !strings.Contains(sel, "-") && !strings.Contains(sel, ",")
	if isCount && gFilter != "" {
		// Count + filter: collect the first n MATCHES, walking from the top.
		// Each row costs 1-2 process reads, so cap how far we walk.
		n, err := strconv.Atoi(sel)
		if err != nil || n <= 0 {
			fmt.Println("Invalid selection:", sel)
			return
		}
		const examineCap = 100_000
		limit := total
		if limit > examineCap {
			limit = examineCap
		}
		matched := 0
		for i := 1; i <= limit && matched < n; i++ {
			if tryRow(i) {
				matched++
			}
		}
	} else {
		idxs := resolveSelection(sel, total)
		if idxs == nil {
			fmt.Println("Invalid selection:", sel)
			return
		}
		for _, idx := range idxs {
			tryRow(idx)
		}
	}

	added, dupes := rsAppend(rows)
	fmt.Printf("result set: +%d added", added)
	if dupes > 0 {
		fmt.Printf(" (%d already present)", dupes)
	}
	fmt.Printf(", total %d ('results view' to inspect)\n", rsCount())
}

// cmdResultsView shows result-set entries with live values.
// results view [count|range|list] [addr|val|conf] [guess|g [type] [minconf]]
// guess re-runs the live type heuristic on each entry; with a type it filters.
func cmdResultsView(args []string) {
	total := rsCount()
	if total == 0 {
		fmt.Println("Result set is empty. Use 'results add <count|range>' to copy scan rows in.")
		return
	}
	sortBy := ""
	sel := ""
	guess := false
	gFilter := ""
	gThresh := 0.5
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "addr", "address":
			sortBy = "addr"
		case "val", "value":
			sortBy = "val"
		case "conf", "confidence":
			sortBy = "conf"
		case "guess", "g":
			guess = true
			if i+1 < len(args) && validGuessTypes[strings.ToLower(args[i+1])] {
				gFilter = strings.ToLower(args[i+1])
				i++
				if i+1 < len(args) {
					if t, err := strconv.ParseFloat(args[i+1], 64); err == nil && t > 0 && t <= 1 {
						gThresh = t
						i++
					}
				}
			}
		default:
			if sel == "" {
				sel = args[i]
			}
		}
	}
	if sel == "" {
		// Default: first 20; with a guess filter, examine the whole set since
		// the result set is curated and the user wants all matches.
		if gFilter != "" {
			sel = strconv.Itoa(total)
		} else {
			sel = "20"
		}
	}
	idxs := resolveSelection(sel, total)
	if idxs == nil {
		fmt.Println("Invalid selection:", sel)
		return
	}

	type disp struct {
		idx   int
		rec   rsRec
		val   string
		gl    string
		gconf float64
	}
	var rows []disp
	for _, idx := range idxs {
		recs := rsRead(idx-1, 1)
		if len(recs) == 0 {
			continue
		}
		r := recs[0]
		var gl, name string
		var gconf float64
		if guess {
			gl, name, gconf = guessAt(r.addr)
			if gFilter != "" && (name != gFilter || gconf < gThresh) {
				continue
			}
		}
		rows = append(rows, disp{idx, r, rsValueString(r), gl, gconf})
	}
	switch {
	case sortBy == "addr":
		sort.Slice(rows, func(i, j int) bool { return rows[i].rec.addr < rows[j].rec.addr })
	case sortBy == "val":
		sort.Slice(rows, func(i, j int) bool { return rows[i].val < rows[j].val })
	case sortBy == "conf":
		sort.Slice(rows, func(i, j int) bool { return rows[i].rec.conf > rows[j].rec.conf })
	case gFilter != "":
		sort.Slice(rows, func(i, j int) bool { return rows[i].gconf > rows[j].gconf })
	}

	if guess {
		fmt.Printf("%-5s  %-20s  %-18s  %-8s  %-6s  %-12s  %s\n", "#", "Address", "Value", "Type", "Conf.", "Guess", "GConf.")
		fmt.Println(strings.Repeat("-", 85))
	} else {
		fmt.Printf("%-5s  %-20s  %-18s  %-8s  %s\n", "#", "Address", "Value", "Type", "Conf.")
		fmt.Println(strings.Repeat("-", 65))
	}
	for _, d := range rows {
		typ := d.rec.gname
		conf := fmt.Sprintf("%.2f", d.rec.conf)
		if typ == "" {
			typ = dataTypeName(d.rec.dt)
			conf = "-"
		}
		if guess {
			fmt.Printf("%-5d  0x%-18X  %-18s  %-8s  %-6s  %-12s  %.2f\n", d.idx, d.rec.addr, d.val, typ, conf, d.gl, d.gconf)
		} else {
			fmt.Printf("%-5d  0x%-18X  %-18s  %-8s  %s\n", d.idx, d.rec.addr, d.val, typ, conf)
		}
	}
	if gFilter != "" {
		fmt.Printf("%d match(es) live-guessed as %s with conf >= %.2f, of %d examined\n", len(rows), gFilter, gThresh, len(idxs))
	}
	fmt.Printf("Shown %d of result set total %d\n", len(rows), total)
}

// cmdResultsWrite writes a value to result-set entries by index, encoded with
// each entry's captured type. results write <idx|range|list> <value>
func cmdResultsWrite(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: results write <idx|range|list> <value>")
		return
	}
	total := rsCount()
	if total == 0 {
		fmt.Println("Result set is empty")
		return
	}
	valStr := strings.Join(args[1:], " ")
	ok, failed := 0, 0
	for _, idx := range parseIndexSpec(args[0]) {
		if idx < 1 || idx > total {
			fmt.Printf("  [%d] out of range (total %d)\n", idx, total)
			failed++
			continue
		}
		recs := rsRead(idx-1, 1)
		if len(recs) == 0 {
			failed++
			continue
		}
		r := recs[0]
		data, err := encodeValue(r.dt, valStr)
		if err != nil {
			fmt.Println("Invalid value:", err)
			return
		}
		if err := WriteMemory(currentHandle, r.addr, data); err != nil {
			fmt.Printf("  [%d] 0x%X write failed: %v\n", idx, r.addr, err)
			failed++
		} else {
			fmt.Printf("  [%d] 0x%X = %s\n", idx, r.addr, decodeValue(r.dt, data))
			ok++
		}
	}
	fmt.Printf("Written %d/%d entries\n", ok, ok+failed)
}

// cmdResultsFreeze freezes result-set entries by index.
// results freeze <idx|range|list> <value>
func cmdResultsFreeze(args []string) {
	if currentHandle == 0 {
		fmt.Println("Not attached")
		return
	}
	if len(args) < 2 {
		fmt.Println("Usage: results freeze <idx|range|list> <value>")
		return
	}
	total := rsCount()
	if total == 0 {
		fmt.Println("Result set is empty")
		return
	}
	valStr := strings.Join(args[1:], " ")
	ok, failed := 0, 0
	for _, idx := range parseIndexSpec(args[0]) {
		if idx < 1 || idx > total {
			fmt.Printf("  [%d] out of range (total %d)\n", idx, total)
			failed++
			continue
		}
		recs := rsRead(idx-1, 1)
		if len(recs) == 0 {
			failed++
			continue
		}
		r := recs[0]
		data, err := encodeValue(r.dt, valStr)
		if err != nil {
			fmt.Println("Invalid value:", err)
			return
		}
		id := freezer.Add(r.addr, data, fmt.Sprintf("rs[%d]", idx))
		fmt.Printf("  [%d] 0x%X = %s (freeze #%d)\n", idx, r.addr, valStr, id)
		ok++
	}
	fmt.Printf("Freezing %d/%d entries\n", ok, ok+failed)
}

// cmdResultsRemove deletes result-set entries by index.
// results remove <idx|range|list>
func cmdResultsRemove(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: results remove <idx|range|list>")
		return
	}
	total := rsCount()
	if total == 0 {
		fmt.Println("Result set is empty")
		return
	}
	rm := make(map[int]bool)
	for _, idx := range parseIndexSpec(args[0]) {
		if idx >= 1 && idx <= total {
			rm[idx] = true
		}
	}
	if len(rm) == 0 {
		fmt.Println("No valid indices")
		return
	}
	rsRemove(rm)
	fmt.Printf("Removed %d entries, %d remain\n", len(rm), rsCount())
}
