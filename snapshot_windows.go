//go:build windows

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// snapshotChunk records where one chunk's raw bytes were written in the
// snapshot file. offset == -1 means the chunk was entirely zero bytes and
// nothing was written; readChunk synthesizes zeros for it.
type snapshotChunk struct {
	addr   uintptr
	size   int
	offset int64
}

// memSnapshot writes all scanned memory to a temp file instead of RAM.
// CE does the same via TScanFileWriter + dual buffers.
// Allows unknown scan on multi-GB games without eating RAM.
// All-zero runs (very common: calloc'd pools, reserved arenas) are recorded
// as metadata only, skipping the disk write AND the later read-back.
type memSnapshot struct {
	mu        sync.Mutex
	file      *os.File
	w         *bufio.Writer
	path      string
	fileOff   int64 // current sequential write position
	chunks    []snapshotChunk
	valSize   int
	zeroBytes int64 // bytes recorded as zero runs (not written to disk)
}

func newMemSnapshot(valSize int) (*memSnapshot, error) {
	path := filepath.Join(scanDir(), "snapshot.snap")
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("cannot create snapshot file: %v", err)
	}
	return &memSnapshot{
		file:    f,
		w:       bufio.NewWriterSize(f, 4*1024*1024),
		path:    path,
		valSize: valSize,
	}, nil
}

// isAllZero reports whether b contains only zero bytes (8-byte fast path).
func isAllZero(b []byte) bool {
	n := len(b) &^ 7
	for i := 0; i < n; i += 8 {
		if binary.LittleEndian.Uint64(b[i:]) != 0 {
			return false
		}
	}
	for i := n; i < len(b); i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}

// writeChunk appends raw bytes to the snapshot file and records the chunk location.
// Safe for concurrent calls — file writes are serialised via mutex.
func (s *memSnapshot) writeChunk(addr uintptr, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write(data); err != nil {
		return err
	}
	s.chunks = append(s.chunks, snapshotChunk{addr: addr, size: len(data), offset: s.fileOff})
	s.fileOff += int64(len(data))
	return nil
}

// recordZero records an all-zero run as metadata only (no disk write).
func (s *memSnapshot) recordZero(addr uintptr, size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chunks = append(s.chunks, snapshotChunk{addr: addr, size: size, offset: -1})
	s.zeroBytes += int64(size)
}

// flush must be called after all writes and before any readChunk.
func (s *memSnapshot) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w != nil {
		s.w.Flush()
	}
}

// readChunk reads back a previously written chunk from disk.
// Zero chunks are synthesized without touching the file.
func (s *memSnapshot) readChunk(c snapshotChunk) ([]byte, error) {
	if c.offset < 0 {
		return make([]byte, c.size), nil
	}
	buf := make([]byte, c.size)
	_, err := s.file.ReadAt(buf, c.offset)
	return buf, err
}

// countAddresses returns the total number of value-aligned addresses snapshotted.
func (s *memSnapshot) countAddresses() int {
	n := 0
	for _, c := range s.chunks {
		n += c.size / s.valSize
	}
	return n
}

// close deletes the temp file from disk.
func (s *memSnapshot) close() {
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}
	os.Remove(s.path)
}
