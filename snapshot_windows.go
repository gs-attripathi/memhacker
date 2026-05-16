//go:build windows

package main

import (
	"fmt"
	"os"
	"sync"
)

// snapshotChunk records where one chunk's raw bytes were written in the snapshot file.
type snapshotChunk struct {
	addr   uintptr
	size   int
	offset int64
}

// memSnapshot writes all scanned memory to a temp file instead of RAM.
// CE does the same via TScanFileWriter + dual buffers.
// Allows unknown scan on multi-GB games without eating RAM.
type memSnapshot struct {
	mu      sync.Mutex
	file    *os.File
	path    string
	fileOff int64 // current sequential write position
	chunks  []snapshotChunk
	valSize int
}

func newMemSnapshot(valSize int) (*memSnapshot, error) {
	f, err := os.CreateTemp("", "memhacker_*.snap")
	if err != nil {
		return nil, fmt.Errorf("cannot create snapshot file: %v", err)
	}
	return &memSnapshot{file: f, path: f.Name(), valSize: valSize}, nil
}

// writeChunk appends raw bytes to the snapshot file and records the chunk location.
// Safe for concurrent calls — file writes are serialised via mutex.
func (s *memSnapshot) writeChunk(addr uintptr, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.file.Write(data); err != nil {
		return err
	}
	s.chunks = append(s.chunks, snapshotChunk{addr: addr, size: len(data), offset: s.fileOff})
	s.fileOff += int64(len(data))
	return nil
}

// readChunk reads back a previously written chunk from disk.
func (s *memSnapshot) readChunk(c snapshotChunk) ([]byte, error) {
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
