//go:build windows

package main

import (
	"fmt"
	"sort"
	"strings"
)

// Global alias store: name -> address
var aliases = map[string]uintptr{}

// resolveAddr resolves either an alias name OR a hex address string.
// Use this everywhere an address argument is expected.
func resolveAddr(s string) (uintptr, error) {
	s = strings.TrimSpace(s)
	// Check alias first
	if addr, ok := aliases[strings.ToLower(s)]; ok {
		return addr, nil
	}
	// Fall back to hex parse
	return parseAddr(s)
}

// --- Commands ---

// alias [name [addr]] — set, list, or show aliases
func cmdAlias(args []string) {
	switch len(args) {
	case 0:
		// List all aliases
		if len(aliases) == 0 {
			fmt.Println("No aliases set. Usage: alias <name> <addr_hex>")
			return
		}
		names := make([]string, 0, len(aliases))
		for n := range aliases {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Printf("%-20s  %s\n", "Alias", "Address")
		fmt.Println(strings.Repeat("-", 35))
		for _, n := range names {
			fmt.Printf("%-20s  0x%X\n", n, aliases[n])
		}
	case 1:
		// Show single alias
		name := strings.ToLower(args[0])
		if addr, ok := aliases[name]; ok {
			fmt.Printf("%s = 0x%X\n", name, addr)
		} else {
			fmt.Printf("Alias '%s' not found\n", name)
		}
	default:
		// Set alias: alias <name> <addr>
		name := strings.ToLower(args[0])
		addr, err := parseAddr(args[1])
		if err != nil {
			fmt.Println("Invalid address:", err)
			return
		}
		aliases[name] = addr
		fmt.Printf("Alias set: %s = 0x%X\n", name, addr)
		Log.Info("alias set: %s = 0x%X", name, addr)
	}
}

// unalias <name> — remove an alias
func cmdUnalias(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: unalias <name>")
		return
	}
	name := strings.ToLower(args[0])
	if _, ok := aliases[name]; ok {
		delete(aliases, name)
		fmt.Printf("Alias '%s' removed\n", name)
		Log.Info("alias removed: %s", name)
	} else {
		fmt.Printf("Alias '%s' not found\n", name)
	}
}
