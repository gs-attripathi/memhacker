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

// Disk-backed kept-results store. Every guess-filtered `results` invocation
// appends its matches here, accumulating across scans. Nothing is held in RAM:
// appends stream to the file, views read back a window on demand.
// Cleared only by `results clear`. Lives next to the exe (NOT in the swept
// memhacker_scans dir) so it survives app restarts; entries go stale when the
// game restarts, so clear it then.
//
// Record layout (16 bytes): addr u64 | conf f32 | type byte | 3 pad

const keptRecSize = 16

var keptTypeNames = []string{"f32", "f64", "i32", "i64", "i8", "ptr", "zero", "?"}

func keptTypeByte(name string) byte {
	for i, n := range keptTypeNames {
		if n == name {
			return byte(i)
		}
	}
	return byte(len(keptTypeNames) - 1)
}

func keptTypeName(b byte) string {
	if int(b) < len(keptTypeNames) {
		return keptTypeNames[b]
	}
	return "?"
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
	addr uintptr
	conf float64
	typ  string
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
func keptAppend(rows []resultRow, typeName string) (added, dupes int) {
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
		rec[12] = keptTypeByte(typeName)
		rec[13], rec[14], rec[15] = 0, 0, 0
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
			addr: uintptr(binary.LittleEndian.Uint64(buf[off:])),
			conf: float64(math.Float32frombits(binary.LittleEndian.Uint32(buf[off+8:]))),
			typ:  keptTypeName(buf[off+12]),
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
// type it was guessed as when kept (not the current `type` setting).
func keptValueString(r keptRec) string {
	if currentHandle == 0 {
		return "?"
	}
	if r.typ == "ptr" {
		buf, err := ReadMemory(currentHandle, r.addr, 8)
		if err != nil || len(buf) < 8 {
			return "?"
		}
		return fmt.Sprintf("0x%X", binary.LittleEndian.Uint64(buf))
	}
	dt := currentDT
	switch r.typ {
	case "f32":
		dt = TypeFloat32
	case "f64":
		dt = TypeFloat64
	case "i32":
		dt = TypeInt32
	case "i64":
		dt = TypeInt64
	case "i8":
		dt = TypeInt8
	}
	sz := dataTypeSize(dt)
	buf, err := ReadMemory(currentHandle, r.addr, sz)
	if err != nil || len(buf) < sz {
		return "?"
	}
	return decodeValue(dt, buf)
}

func showKeptResults(n int) {
	total := keptCount()
	if total == 0 {
		fmt.Println("No kept results. Use 'results <n|range> guess <type> [minconf]' to collect some.")
		return
	}
	if n > total {
		n = total
	}
	recs := keptRead(0, n)
	fmt.Printf("%-5s  %-20s  %-18s  %-6s  %s\n", "#", "Address", "Value", "Type", "Conf.")
	fmt.Println(strings.Repeat("-", 65))
	for i, r := range recs {
		fmt.Printf("%-5d  0x%-18X  %-18s  %-6s  %.2f\n", i+1, r.addr, keptValueString(r), r.typ, r.conf)
	}
	if total > n {
		fmt.Printf("... and %d more (use 'results kept <N>')\n", total-n)
	}
}
