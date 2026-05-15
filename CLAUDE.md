# MemHacker — CLAUDE.md

Complete context for AI agents working on this codebase. Read this before touching anything.

---

## What This Is

A Cheat Engine clone in Go — single Windows `.exe`, zero deps, cross-compiled from macOS.
Repo: https://github.com/gs-attripathi/memhacker

**Build command (always use this exact command):**
```
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 /opt/homebrew/bin/go build -ldflags="-s -w" -o memhacker.exe .
```

**Never use `go run`, never use CGO, never add external deps beyond `golang.org/x/sys/windows`.**

---

## File Structure

| File | Purpose |
|------|---------|
| `main_windows.go` | CLI loop, all commands, arg parsing |
| `pointer_scanner_windows.go` | Pmap build, DFS scan, VerifyChain, save/load |
| `pointer_results_windows.go` | prsave/prload/prverify/prwrite/prfreeze |
| `process_memory_windows.go` | OpenProcess, ReadMemory, GetModules, EnumMemoryRegions |
| `scanner_windows.go` | Value scan (FirstScan/NextScan), encode/decode values |
| `freeze_windows.go` | 50ms freeze loop |
| `alias_windows.go` | Address aliases (resolveAddr) |
| `types.go` | ScanType, DataType enums, ScanParams, ScanResult, FrozenEntry |
| `logger.go` | Logger + AppVersion constant |

---

## Algorithm — Pointer Scanner (CRITICAL)

Mirrors Cheat Engine's `PointerscanWorker.rscan()` exactly. Read CE source before changing anything:
- `Cheat Engine/pointerscanworker.pas` — rscan(), StorePath()
- `Cheat Engine/pointervaluelist.pas` — findPointerValue(), fillLinkedList()
- `Cheat Engine/pointerscancontroller.pas` — reversescan(), queue management

### How it works

1. **Pmap** = sorted `[]ptrEntry{value, addr}`. Built by scanning all readable memory regions, collecting every aligned pointer-sized value that points into valid memory. Sorted by `.value` for binary search.

2. **DFS scan** (`dfsSingleSession`):
   - Goroutine pool (channel size 65536) + worker goroutines
   - Seed: one job `{addr: target, level: 0}`
   - Each job calls `rscan(addr, level, offs, noff, visited)`
   - `rscan` binary-searches pmap for all entries with value in `[addr-maxOffset, addr]`
   - For each value group: computes `offset = addr - val`
   - For each address holding that value:
     - If address is in a static module → save chain (done)
     - Else if level+1 < maxDepth → enqueue child job (or inline if channel full)
   - Channel full → inline recursion (CE: "I'll have to do it myself")
   - Last 3 levels always inline (CE's queue priority policy)

3. **CE pruning features (both required, both implemented):**
   - `noLoop=true` — if addr already in current chain's `visited[]`, skip (prevents cycles)
   - `maxOffsetsPerNode=5` (default) — limit distinct value groups explored per node, **but ONLY at level > 0**. At level 0 (target) never limit. Without this, exponential blowup → infinite runtime.

4. **Offset order (CRITICAL — do not change):**
   - During scan: `offs[0]` = offset at level 0 (near target), `offs[N]` = near static
   - On chain save: **REVERSED** → `chain.Offsets[0]` = deepest (near static), `chain.Offsets[N]` = shallowest (near target)
   - `VerifyChain` applies offsets in index order: `static base → deref+offset[0] → deref+offset[1] → ... → target`
   - This is correct. Do NOT change the reversal.

5. **Multi-session cross-reference:**
   - Each session = one pmap + one or more target addresses
   - DFS each target → intersect chains within session (pmadd behavior)
   - Cross-ref all sessions → keep only chains present in ALL sessions
   - Result = stable pointer chain that survives game restarts

### Key constants
```go
const maxDepthCap  = 24     // compile-time max depth for fixed arrays
const dfsQueueSize = 65536  // goroutine pool channel capacity
```

### Default pscan params
- depth=7, maxOffset=5000, maxResults=100, filter=exe, maxOffsetsPerNode=5

---

## Pmap File Format (v3, binary)

```
uint32  magic = 0x504D4150 ("PMAP")
uint32  version = 3
uint32  pid
int64   created_at (unix timestamp)
uint64  target_addr
uint8   is_32bit
uint32  module_count
  for each module:
    uint16  name_len
    []byte  name
    uint16  path_len
    []byte  path          <- v3 addition, used for IsGameDir reconstruction
    uint64  base_addr
    uint32  size
uint64  entry_count
  for each entry (16 bytes each):
    uint64  value         <- pointer value stored at addr
    uint64  addr          <- memory address holding this value
```

Entries are sorted ascending by `.value`. v1/v2 pmaps lack the path field — LoadPointerMap handles this.

---

## Commands

```
open <pid|name>           attach to process
close                     detach
scan <type> [value]       first scan (exact/unknown/bigger/smaller/between/changed/unchanged/increased/decreased/incby/decby/notequal)
next <type> [value]       filter scan
results [n]               show results
write <addr> <value>      write memory
read <addr> [type]        read memory
type <dt>                 set data type (i8/i16/i32/i64/u8/u16/u32/u64/f32/f64/str/bytes)
freeze <addr> <val>       freeze value at addr (50ms write loop)
unfreeze <id>             stop freeze
frozen                    list frozen entries
modules                   list loaded modules (shows GAME/SYSTEM/OTHER)

pmap                      build pointer map (in-memory only)
pmsave <file> <addr>      build pmap + save + register session with target address
pmadd <addr>              add another target to last session (CE-style)
pmload <file>             load saved pmap, register as session (target embedded in file)
pmsessions                list sessions
pmclear                   clear all sessions

pscan [depth] [offset] [max] [filter] [maxOffsets]
                          run pointer scan across all sessions
                          filter: exe (default), game, all
                          maxOffsets: 0=use default(5), higher=more thorough/slower

prsave <file.json>        save last pscan results to JSON
prload <file.json> [addr] load chains, optionally verify against current address
prverify [addr]           re-verify chains against live process
prlist                    list in-memory chains
prwrite <idx> <val>       follow chain, write value once
prfreeze <idx> <val>      follow chain, freeze value

alias <name> <addr>       set address alias
unalias <name>            remove alias
loglast [n]               copy last n log lines to Windows clipboard
```

---

## Game Support

### 32-bit WOW64 (e.g. Mount & Blade Warband)
- IsProcess32Bit() detects via IsWow64Process
- pmap uses 4-byte ptr reads, maxUserAddr=0x7FFFFFFF
- filter=exe works well, depth=7 offset=4096

### 64-bit UE5/Unity (e.g. SurrounDead)
- pmap has 30-36M entries (takes ~13s to build)
- filter=exe, depth=5 (default), offset=8192 (default)
- depth=5 finishes in ~1s, depth=6 in ~27s (exponential), depth=7 = minutes
- Multiple sessions run in parallel — total time = slowest session, not sum

### Game root detection (IsGameDir)
`gameRootFromModules()` finds main exe path, iteratively strips known subdirs from the tail:
`bin\`, `bin32\`, `bin64\`, `win32\`, `win64\`, `binaries\`, `x64\`, `x86\`
Repeats until no more known subdirs remain. Handles both `game\bin\` (1 level) and
`game\Binaries\Win64\` (2 levels, UE5) correctly. Same logic applied in `LoadPointerMap`.

---

## Module Filter (filter arg in pscan)

| Filter | What counts as static base |
|--------|---------------------------|
| `exe` | Only the main .exe module (most reliable, fewer results) |
| `game` | Any module with IsGameDir=true (includes game DLLs) |
| `all` | Any module including GPU drivers, system DLLs (noisy) |

---

## Known Bugs Fixed (do not re-introduce)

1. **BFS → DFS** — BFS caused exponential queue growth → OOM on UE5. DFS with goroutine pool has no queue growth.

2. **perSessionCap** — was cutting off chains at 50K, valid chains were beyond cutoff. Removed entirely. DFS is naturally bounded by maxDepth.

3. **maxOffsetsPerNode at level 0** — was limiting to 5 even at target level. CE never limits at level 0. Fixed: `if level > 0`.

4. **Offset reversal missing** — chains were stored in wrong order (target→static instead of static→target). VerifyChain was following chain backward. Fixed.

5. **pmadd dropping original address** — pmsave address wasn't added to TargetAddrs on first pmadd. Fixed: prepend PMap.TargetAddr when TargetAddrs is empty.

6. **pmsave shared pointer bug** — fixed by nil-ing pointerMap after each pmsave, forcing fresh pmap per session.

7. **NextScan partial read** — 64KB batch reads now clamped to memory region boundary via QueryRegion.

---

## Workflow (user perspective)

### Finding a stable pointer (standard, 2-3 sessions)
```
open game.exe
scan exact 100         <- find HP address
pmsave s1.pmap 0xADDR  <- save pmap + register session 1
--- game restart ---
open game.exe
scan exact 100         <- find new HP address
pmsave s2.pmap 0xNEWADDR
--- restart again ---
pmsave s3.pmap 0xADDR3
pscan 5 4000 100       <- cross-reference all sessions
prsave hp.json         <- save results
```

### Using saved results after restart
```
open game.exe
prload hp.json         <- load chains + auto-verify
prwrite 1 999          <- write to chain #1
prfreeze 1 999         <- or freeze it
```

### pmadd (same session, multiple addresses)
```
pmsave s1.pmap 0xADDR1  <- first address
pmadd 0xADDR2            <- adds addr2 AND keeps addr1 (both scanned, intersected)
pscan                    <- single session, intersect-filtered
```

---

## Versioning

Uses **semver** (MAJOR.MINOR.PATCH). AppVersion is in `logger.go`.

**Rules (always bump before committing a user-facing change):**
- PATCH: bug fix, no new commands or behavior changes
- MINOR: new feature, new command, behavior change, perf improvement
- MAJOR: breaking change — new pmap file format, incompatible command changes

**Always bump the version and update the table below before pushing.**

## Version History

| Version | Key changes |
|---------|------------|
| v1.7.0 | Initial release |
| v1.8.0 | pmap v3 format (module paths), game root detection |
| v1.9.0 | NextScan batch reads, loglast, AppVersion in logs |
| v2.0.0 | Full DFS rewrite (CE-style), noLoop, maxOffsetsPerNode, offset reversal fix, pmadd fix |
| v2.1.0 | Game root detection fix (iterative strip, UE5 + simple bin dirs), LoadPointerMap game root fix, fast module lookup (binary search), partial case-insensitive attach, prlabel fix, DFS speed (lockless channel, inlined binary search, smaller job structs, larger queue), default depth=5 offset=8192, prlist filter (ok/addr), parallel sessions, auto-save pscan_last_N.json (no overwrite), verify-then-cap in pscan output, pmload multiple files, float scan ±0.1 tolerance, NaN/Inf filter, session labels on progress ticker, pscan JSON data type fix |

Current: **v2.1.0** (AppVersion in `logger.go`)

---

## Do Not

- Do not add CGO
- Do not add new external packages
- Do not auto-widen filter (was causing GPU driver DLL noise)
- Do not add caps/limits to DFS (was causing cross-session intersection to fail)
- Do not change pmap file format without bumping pmapVersion and updating LoadPointerMap
- Do not change offset order in chain storage without updating VerifyChain simultaneously
- Do not use `gh` CLI or `git` for GitHub operations — use GitHub MCP tools
- Do not add `Co-Authored-By` to git commits
- Do not produce bulleted recap summaries after implementing features — just say done
