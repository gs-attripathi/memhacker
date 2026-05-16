//go:build windows

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// CE-compatible disk result storage.
// Addresses file: raw uint64 array.
// Values file:    raw bytes (valSize bytes per entry).
// Simple binary — no complex headers, fast sequential I/O.

const (
	diskResThreshold = 1_000_000 // switch to disk above this many results
	diskWriteBufSize = 4 * 1024 * 1024 // 4MB write buffer
)

// generation counter ensures new scan files don't clobber old ones that are
// still being read. Each call to newDiskWriter gets a unique generation number.
var diskResGen int32

// exeDir returns the directory of the running executable.
func exeDir() string {
	exe, err := os.Executable()
	if err != nil { return "." }
	return filepath.Dir(exe)
}

// ---------------------------------------------------------------------------
// diskWriter — write-time handle (buffered sequential writes)
// ---------------------------------------------------------------------------

type diskWriter struct {
	addrPath string
	valPath  string
	addrFile *os.File
	valFile  *os.File
	addrBuf  *bufio.Writer
	valBuf   *bufio.Writer
	count    int
	valSize  int
}

func scanDir() string {
	dir := filepath.Join(exeDir(), "memhacker_scans")
	os.MkdirAll(dir, 0755)
	return dir
}

func newDiskWriter(valSize int) (*diskWriter, error) {
	gen := atomic.AddInt32(&diskResGen, 1)
	dir := scanDir()
	addrPath := filepath.Join(dir, fmt.Sprintf("scan_%d.addr", gen))
	valPath  := filepath.Join(dir, fmt.Sprintf("scan_%d.vals", gen))

	af, err := os.Create(addrPath)
	if err != nil { return nil, fmt.Errorf("addr file: %v", err) }
	vf, err := os.Create(valPath)
	if err != nil { af.Close(); os.Remove(addrPath); return nil, fmt.Errorf("val file: %v", err) }

	return &diskWriter{
		addrPath: addrPath, valPath: valPath,
		addrFile: af, valFile: vf,
		addrBuf:  bufio.NewWriterSize(af, diskWriteBufSize),
		valBuf:   bufio.NewWriterSize(vf, diskWriteBufSize),
		valSize:  valSize,
	}, nil
}

func (w *diskWriter) append(addr uintptr, val []byte) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(addr))
	w.addrBuf.Write(buf[:])
	w.valBuf.Write(val[:w.valSize])
	w.count++
}

func (w *diskWriter) flush() {
	w.addrBuf.Flush()
	w.valBuf.Flush()
}

// toDiskResultSet flushes, closes write handles, opens read handles.
func (w *diskWriter) toDiskResultSet() (*diskResultSet, error) {
	w.flush()
	w.addrFile.Close()
	w.valFile.Close()

	af, err := os.Open(w.addrPath)
	if err != nil { return nil, err }
	vf, err := os.Open(w.valPath)
	if err != nil { af.Close(); return nil, err }

	return &diskResultSet{
		addrPath: w.addrPath, valPath: w.valPath,
		addrFile: af, valFile: vf,
		count: w.count, valSize: w.valSize,
	}, nil
}

// ---------------------------------------------------------------------------
// diskResultSet — read-time handle
// ---------------------------------------------------------------------------

type diskResultSet struct {
	addrPath string
	valPath  string
	addrFile *os.File
	valFile  *os.File
	count    int
	valSize  int
}

// get reads the result at index i.
func (d *diskResultSet) get(i int) (uintptr, []byte) {
	var abuf [8]byte
	d.addrFile.ReadAt(abuf[:], int64(i)*8)
	vbuf := make([]byte, d.valSize)
	d.valFile.ReadAt(vbuf, int64(i)*int64(d.valSize))
	return uintptr(binary.LittleEndian.Uint64(abuf[:])), vbuf
}

// readAddressChunk reads up to n addresses starting at index start into dst.
// Returns number of addresses actually read.
func (d *diskResultSet) readAddressChunk(start, n int, dst []uintptr) int {
	if start >= d.count { return 0 }
	if start+n > d.count { n = d.count - start }
	buf := make([]byte, n*8)
	nr, _ := d.addrFile.ReadAt(buf, int64(start)*8)
	read := nr / 8
	for i := 0; i < read; i++ {
		dst[i] = uintptr(binary.LittleEndian.Uint64(buf[i*8:]))
	}
	return read
}

// readValueChunk reads up to n values starting at index start into dst.
func (d *diskResultSet) readValueChunk(start, n int, dst []byte) int {
	if start >= d.count { return 0 }
	if start+n > d.count { n = d.count - start }
	nr, _ := d.valFile.ReadAt(dst[:n*d.valSize], int64(start)*int64(d.valSize))
	return nr / d.valSize
}

func (d *diskResultSet) close() {
	if d.addrFile != nil { d.addrFile.Close(); d.addrFile = nil }
	if d.valFile != nil  { d.valFile.Close();  d.valFile = nil  }
}

// delete removes the disk files.
func (d *diskResultSet) delete() {
	d.close()
	os.Remove(d.addrPath)
	os.Remove(d.valPath)
}

// toMemory loads all results into []ScanResult (only call for small sets).
func (d *diskResultSet) toMemory() []ScanResult {
	results := make([]ScanResult, d.count)
	addrBuf := make([]uintptr, d.count)
	d.readAddressChunk(0, d.count, addrBuf)
	valBuf := make([]byte, d.count*d.valSize)
	d.readValueChunk(0, d.count, valBuf)
	for i := range results {
		v := make([]byte, d.valSize)
		copy(v, valBuf[i*d.valSize:])
		results[i] = ScanResult{Address: addrBuf[i], Value: v}
	}
	return results
}
