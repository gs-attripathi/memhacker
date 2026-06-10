//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// Disk-backed kept-results store: the user's curated working set.
// Every explicit `results <selection>` invocation appends the rows it displayed
// (after any guess filter), deduped by address. Nothing is held in RAM: appends
// stream to the file, views read back a window on demand.
// Bare `results` and `results kept [n]` view it; `results clear` is the ONLY
// thing that clears it. Lives next to the exe (NOT in the swept memhacker_scans
// dir) so it survives app restarts; entries go stale when the game restarts.
//
// Record layout (16 bytes): addr u64 | conf f32 | guessCode u8 | dt u8 | 2 pad
// guessCode indexes keptTypeNames when the row came from a guess; 255 = not
// guessed, in which case dt (a DataType) says how to decode the value.

const keptRecSize = 16
const keptNoGuess = 255

var keptTypeNames = []string{"f32", "f64", "i32", "i64", "i8", "ptr", "zero", "?"}

func keptTypeByte(name string) byte {
	for i, n := range keptTypeNames {
		if n == name {
			return byte(i)
		}
	}
	return keptNoGuess
}

func keptTypeName(b byte) string {
	if int(b) < len(keptTypeNames) {
		return keptTypeNames[b]
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

func keptPath() string {
	return filepath.Join(exeDir(), "memhacker_results.bin")
}

func keptCount() int {
	fi, err := os.Stat(keptPath())
	if err != nil {
		return 0
	}
	return int(fi.Size()) / keptRecSize
}

type keptRec struct {
	addr  uintptr
	conf  float64
	gname string   // guess label, "" if the row wasn't guessed
	dt    DataType // how to decode the value
}

// keptAddrSet streams every stored address into a transient set for dedupe.
func keptAddrSet() map[uintptr]bool {
	set := make(map[uintptr]bool)
	f, err := os.Open(keptPath())
	if err != nil {
		return set
	}
	defer f.Close()
	buf := make([]byte, keptRecSize*4096)
	for {
		n, err := f.Read(buf)
		for off := 0; off+keptRecSize <= n; off += keptRecSize {
			set[uintptr(binary.LittleEndian.Uint64(buf[off:]))] = true
		}
		if err != nil {
			break
		}
	}
	return set
}

// keptAppend appends rows to the store, skipping already-stored addresses.
// Guessed rows record their guess label + confidence; plain rows record the
// data type that was active when they were displayed.
func keptAppend(rows []resultRow) (added, dupes int) {
	if len(rows) == 0 {
		return 0, 0
	}
	seen := keptAddrSet()
	f, err := os.OpenFile(keptPath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("  cannot open kept results file:", err)
		return 0, 0
	}
	defer f.Close()
	var rec [keptRecSize]byte
	for _, r := range rows {
		if seen[r.addr] {
			dupes++
			continue
		}
		seen[r.addr] = true
		binary.LittleEndian.PutUint64(rec[0:], uint64(r.addr))
		binary.LittleEndian.PutUint32(rec[8:], math.Float32bits(float32(r.conf)))
		if r.gname != "" {
			rec[12] = keptTypeByte(r.gname)
			rec[13] = byte(guessNameDT(r.gname))
		} else {
			rec[12] = keptNoGuess
			rec[13] = byte(currentDT)
		}
		rec[14], rec[15] = 0, 0
		f.Write(rec[:])
		added++
	}
	return added, dupes
}

// keptRead returns up to n records starting at 0-based index start.
func keptRead(start, n int) []keptRec {
	f, err := os.Open(keptPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, n*keptRecSize)
	nr, _ := f.ReadAt(buf, int64(start)*keptRecSize)
	recs := make([]keptRec, 0, nr/keptRecSize)
	for off := 0; off+keptRecSize <= nr; off += keptRecSize {
		recs = append(recs, keptRec{
			addr:  uintptr(binary.LittleEndian.Uint64(buf[off:])),
			conf:  float64(math.Float32frombits(binary.LittleEndian.Uint32(buf[off+8:]))),
			gname: keptTypeName(buf[off+12]),
			dt:    DataType(buf[off+13]),
		})
	}
	return recs
}

func keptClear() {
	if err := os.Remove(keptPath()); err != nil && !os.IsNotExist(err) {
		fmt.Println("  cannot clear kept results:", err)
	}
}

// keptValueString reads the live value at the record's address, decoded as the
// type it was captured with (guessed type or the data type active at capture).
func keptValueString(r keptRec) string {
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

func keptHeader() {
	fmt.Printf("%-5s  %-20s  %-18s  %-8s  %s\n", "#", "Address", "Value", "Type", "Conf.")
	fmt.Println(strings.Repeat("-", 65))
}

func printKeptRow(idx int, r keptRec) {
	typ := r.gname
	conf := fmt.Sprintf("%.2f", r.conf)
	if typ == "" {
		typ = dataTypeName(r.dt)
		conf = "-"
	}
	fmt.Printf("%-5d  0x%-18X  %-18s  %-8s  %s\n", idx, r.addr, keptValueString(r), typ, conf)
}

func keptEmptyMsg() {
	fmt.Println("Kept results list is empty.")
	fmt.Println("Any 'results <n|range>' selection appends its rows here; 'results clear' empties it.")
}

func showKeptResults(n int) {
	total := keptCount()
	if total == 0 {
		keptEmptyMsg()
		return
	}
	if n > total {
		n = total
	}
	recs := keptRead(0, n)
	keptHeader()
	for i, r := range recs {
		printKeptRow(i+1, r)
	}
	fmt.Printf("Kept total: %d", total)
	if total > n {
		fmt.Printf(" (showing %d, use 'results kept <N>' for more)", n)
	}
	fmt.Println()
}

// showKeptIndices shows specific kept entries by 1-based index (range/list form).
func showKeptIndices(indices []int) {
	total := keptCount()
	if total == 0 {
		keptEmptyMsg()
		return
	}
	keptHeader()
	shown := 0
	for _, idx := range indices {
		if idx < 1 || idx > total {
			continue
		}
		recs := keptRead(idx-1, 1)
		if len(recs) == 0 {
			continue
		}
		printKeptRow(idx, recs[0])
		shown++
	}
	fmt.Printf("Shown %d of kept total %d\n", shown, total)
}
