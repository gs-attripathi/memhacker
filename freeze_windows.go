//go:build windows

package main

import (
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

type Freezer struct {
	handle  windows.Handle
	entries map[int]*FrozenEntry
	nextID  int
	mu      sync.Mutex
	stop    chan struct{}
}

func NewFreezer(handle windows.Handle) *Freezer {
	f := &Freezer{
		handle:  handle,
		entries: make(map[int]*FrozenEntry),
		stop:    make(chan struct{}),
	}
	go f.loop()
	return f
}

func (f *Freezer) Add(addr uintptr, value []byte, label string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextID
	f.nextID++
	cp := make([]byte, len(value))
	copy(cp, value)
	f.entries[id] = &FrozenEntry{
		Address: addr,
		Value:   cp,
		Label:   label,
		Active:  true,
	}
	return id
}

func (f *Freezer) Remove(id int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, id)
}

func (f *Freezer) Toggle(id int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.entries[id]; ok {
		e.Active = !e.Active
		return e.Active
	}
	return false
}

func (f *Freezer) List() []struct {
	ID    int
	Entry FrozenEntry
} {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []struct {
		ID    int
		Entry FrozenEntry
	}
	for id, e := range f.entries {
		out = append(out, struct {
			ID    int
			Entry FrozenEntry
		}{id, *e})
	}
	return out
}

func (f *Freezer) Stop() {
	close(f.stop)
}

func (f *Freezer) loop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-f.stop:
			return
		case <-ticker.C:
			f.mu.Lock()
			for _, e := range f.entries {
				if e.Active {
					WriteMemory(f.handle, e.Address, e.Value)
				}
			}
			f.mu.Unlock()
		}
	}
}
