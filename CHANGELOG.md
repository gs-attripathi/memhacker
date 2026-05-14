# MemHacker Changelog

## v1.7.0 — End-to-end working release ✅
Verified on: Mount & Blade Warband (32-bit WOW64)

### Memory Scanning
- Scan types: exact, unknown, bigger, smaller, between, changed, unchanged, increased, decreased, incby, decby, notequal
- Data types: i8, i16, i32 (default), i64, u8, u16, u32, u64, f32, f64, string, bytes
- Multi-threaded — uses all CPU cores

### Value Operations
- read, write, freeze/unfreeze (50ms interval), addrlist

### Pointer Scanning (CE-style multi-session)
- pmsave FILE ADDR — build pmap + save to disk + register session (addr embedded in file)
- pmload FILE — load saved pmap, target address read from file automatically
- pscan [depth] [offset] [max] [filter] — BFS cross-reference across all sessions
  - filter: exe (default, most reliable) — auto-widens to game — then all — if no results
  - Negative offsets supported, displayed as [-X]
  - Queue cap: 300K per depth level to prevent explosion
  - Per-session hard cap: 2M chains
- pmsessions — list registered sessions
- pmclear — clear all sessions

### Process and Module Info
- open auto-detects 32-bit WOW64 vs 64-bit on attach
- modules shows GAME vs SYSTEM tag + full path for every DLL
- System DLLs (kernel32, ntdll etc) skipped as base pointers
- GPU/driver DLLs (nvwgf2um, amdxc, d3d* etc) skipped as base pointers

### Logging
- Full structured log to memhacker.log with version in every session header
- Colored WARN/ERROR output on console
- loglast [N] — copies log to Windows clipboard (clip.exe) with version header

### Workflow
```
open game.exe
scan exact 100          <- find target address
pmsave s1.pmap 0xADDR   <- snapshot 1
restart game
scan exact 100          <- find new address
pmsave s2.pmap 0xADDR2  <- snapshot 2
pmsave s3.pmap 0xADDR3  <- snapshot 3
pscan                   <- cross-reference all sessions
```

### Build
```
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o memhacker.exe .
```
Single .exe, zero runtime dependencies, runs on any Windows 64-bit machine.
