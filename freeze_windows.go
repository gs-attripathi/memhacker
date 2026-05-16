//go:build windows

package main

import (
	"fmt"
	"sort"
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
	Log.Info("Freeze: id=%d addr=0x%X label=%q", id, addr, label)
	return id
}

func (f *Freezer) Remove(id int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.entries[id]; ok {
		Log.Info("Unfreeze: id=%d", id)
		delete(f.entries, id)
	} else {
		Log.Warn("Unfreeze: id=%d not found", id)
	}
}

// RemoveByPosition removes the entry at 1-based position in the sorted frozen list.
func (f *Freezer) RemoveByPosition(pos int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]int, 0, len(f.entries))
	for id := range f.entries { ids = append(ids, id) }
	sort.Ints(ids)
	if pos < 1 || pos > len(ids) { return false }
	id := ids[pos-1]
	Log.Info("Unfreeze: pos=%d id=%d addr=0x%X", pos, id, f.entries[id].Address)
	delete(f.entries, id)
	return true
}

func (f *Freezer) RemoveAll() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.entries)
	f.entries = make(map[int]*FrozenEntry)
	Log.Info("Unfreeze all: removed %d entries", n)
	return n
}

func (f *Freezer) RemoveByAddr(addr uintptr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, e := range f.entries {
		if e.Address == addr {
			Log.Info("Unfreeze: addr=0x%X id=%d", addr, id)
			delete(f.entries, id)
			return true
		}
	}
	return false
}

func (f *Freezer) Toggle(id int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.entries[id]; ok {
		e.Active = !e.Active
		Log.Info("Freeze toggle: id=%d active=%v", id, e.Active)
		return e.Active
	}
	Log.Warn("Freeze toggle: id=%d not found", id)
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
	Log.Info("Freezer: stopping")
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
			for id, e := range f.entries {
				if !e.Active { continue }
				err := WriteMemory(f.handle, e.Address, e.Value)
				if err != nil {
					// Not writable — say it once, deactivate, never mention again
					e.Active = false
					fmt.Printf("\n  [freeze] 0x%X not writable — deactivated\n> ", e.Address)
					Log.Warn("Freeze deactivated: id=%d addr=0x%X err=%v", id, e.Address, err)
				}
			}
			f.mu.Unlock()
		}
	}
}
