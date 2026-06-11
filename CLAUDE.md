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
| `resultset_windows.go` | Disk-backed result set (`results add/view/write/freeze/remove/clear`) |
| `relscan_windows.go` | Linear-relation scan for obfuscated values (`next rel`, `rel`, `relwrite`) |
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

8. **firstScanUnknown leaking disk results** (fixed v2.15.0): clearDiskRes only ran on the non-unknown FirstScan path, so repeated `scan unknown` leaked GB-scale scan_N.addr/.vals files AND left a stale diskRes that misrouted a later `next` to the old result files. FirstScan now clears snapshot, diskRes, and Results up front for every scan type.

9. **nextScanFromSnapshot unbounded RAM** (fixed v2.15.0): survivors of the first `next` after `scan unknown` were collected into one RAM slice with no disk spill, causing multi-GB spikes and system-wide lag. Now spills to disk above diskResThreshold exactly like FirstScan. Also: FirstScan/NextScan now call debug.FreeOSMemory() on exit so the heap high-water mark is returned to Windows, and main() sweeps memhacker_scans/ at startup to remove temp files left by crashed sessions.

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

**Pre-release suffix rule (IMPORTANT):**
- During active development: use `-alpha` or `-beta` suffix — e.g. `2.3.0-alpha`, `2.3.0-beta`
- Only use a clean version number (e.g. `2.3.0`) when the user explicitly asks to create a GitHub release
- Example flow: `2.3.0-alpha` during dev → user says "create release" → bump to `2.3.0` → release

**Always bump the version and update the table below before pushing.**

## Version History

| Version | Key changes |
|---------|------------|
| v1.7.0 | Initial release |
| v1.8.0 | pmap v3 format (module paths), game root detection |
| v1.9.0 | NextScan batch reads, loglast, AppVersion in logs |
| v2.0.0 | Full DFS rewrite (CE-style), noLoop, maxOffsetsPerNode, offset reversal fix, pmadd fix |
| v2.1.0 | Game root detection fix (iterative strip, UE5 + simple bin dirs), LoadPointerMap game root fix, fast module lookup (binary search), partial case-insensitive attach, prlabel fix, DFS speed (lockless channel, inlined binary search, smaller job structs, larger queue), default depth=5 offset=8192, prlist filter (ok/addr), parallel sessions, auto-save pscan_last_N.json (no overwrite), verify-then-cap in pscan output, pmload multiple files, float scan ±0.1 tolerance, NaN/Inf filter, session labels on progress ticker, pscan JSON data type fix |
| v2.2.0 | Disk-backed scan results (unknown scan snapshot + all results >1M to disk), CE page-grouping NextScan, gap-based address grouping, scan progress output, writable-only scan default, region filter, scan range/cap/all keywords, iread/iwrite/ifreeze commands, sortable results, position-based unfreeze, unfreeze all/by-address, scan confirmation guard, Ctrl+C cancel, results index display, regions command, CHANGED status in prverify, no VirtualProtectEx (direct write only), freeze silently handles failures. Verified on a popular racing game (open world, 64-bit). |

| v2.3.0 | pmexport CE-compatible .scandata format, prmerge offline cross-session intersection, parallel pscan session fix (skip 0-chain sessions), game scripts folder (car speed rotator + drift), iread command, prlist shows live values, disk-backed scan results improvements |
| v2.4.0-alpha | pscan `neg` keyword — CE's NegativeOffsets flag (also scans pointers whose value lands past the target). Use when normal scans return zero chains even with high offset. QuickEdit auto-toggle: disabled during long ops (scan/next/pmap/pscan), restored after — copy/paste still works at the prompt. pmload now loads ALL files passed (was only loading first arg). Car rotator script tuned for Forza H6 (20Hz, exponential decay, anti-windup clamp). |
| v2.4.1-alpha | Negative offsets now default ON (was opt-in via `neg`). Use `noneg` to disable for ~2× speed. Real-world testing showed neg consistently finds chains that survive game updates — making it default avoids the "forgot the flag, got 0 chains" footgun. `neg` keyword still accepted as no-op for backward compat. |
| v2.4.2-alpha | Car rotator: hybrid steer reversal (exp-then-linear). Pressing the opposite arrow now damps existing steer toward 0 exponentially while \|steer\| > threshold, then linear-steps into the new direction once near 0 — much snappier direction changes. Configurable via STEER_REVERSAL_{ENABLED,DAMP,THRESHOLD}. |
| v2.4.3-alpha | prsave JSON: addresses now stored as hex-prefix strings (`"0x1A0"`, `"-0x1A0"`) instead of plain hex without prefix (`"1A0"`, `"+1A0"`). Strip quotes to paste straight into Python tuples. File stays strict-JSON valid. Loader also accepts the legacy format AND raw (unquoted) hex literals via a quote-wrapping preprocessor. |
| v2.4.4-alpha | Car rotator: additive steer mode (default). New STEER_WRITE_MODE="add" reads game's current steer and writes (game+script), so your wheel/controller still works — script just nudges on top. When script is idle (|steer|<0.001) it doesn't write at all. Set to "set" for old override behavior. Velocity rotation always uses script-only steer regardless of mode. |
| v2.4.5-alpha | Car rotator: clamp the combined (game_steer + script_steer) value to ±STEER_MAX before writing in "add" mode, so saturated controller input + script keys can't push the written value past the cap. |
| v2.5.0-alpha | New `look <addr> [count]` command — dumps `count` entries on each side of an address as the current data type, with offset, address, decoded value, and raw bytes. Default count=8 (17 rows). Bytes/string types are rejected (no fixed size). Alias `l`. |
| v2.5.1-alpha | `look` gains asymmetric arg parsing: `look <addr> before <n>`, `look <addr> after <n>`, or both. Plain `look <addr> <n>` still means symmetric. Default unchanged (8 each side). |
| v2.5.2-alpha | `look` short keywords: `b` = before, `a` = after. e.g. `look hp b 4 a 16`. |
| v2.5.3-alpha | `look` drops the raw-bytes column. The decoded value column was carrying the info; the hex bytes were noise next to it. |
| v2.6.0-alpha | `look` adds Guess + Confidence columns. Per-row heuristic that picks the most likely type: f32 / f64 / i32 / i64 / i8 / ptr / zero. Pointer detection uses the live process (ReadMemory at the candidate addr) so it's reliable for real pointers. Reads 8 extra bytes past the end so small-type rows (f32, i32) can still sniff for f64/i64/ptr in the overlapping window. |
| v2.7.0-alpha | Address list gets index ops: `aread` / `awrite` / `afreeze` / `aremove` / `aclear` (aliases `ar` / `aw` / `af` / `arm`). Each entry retains its captured data type. `addrlist` now displays 1-based indices to match the rest of the tool. |
| v2.7.1-alpha | `alist` added as a third alias for `addrlist` — slots neatly with the rest of the `a*` family. |
| v2.8.0-alpha | New ways to populate the address list: `iadd <idx>` adds scan results by index (alias `ia`); `ladd <offset>` adds offsets from the last `look` (alias `la`, accepts +/- decimal and hex, multiple in one go, optional `-- label` for a shared label). Removes the need to paste hex addresses by hand. |
| v2.9.0-alpha | Tab-completion for file arguments at the main prompt. Pressing Tab on a partial filename auto-completes if there is exactly one match, or lists all matches if there are multiple. Only activates for commands that take file args: `pmload`, `pmsave`, `pmexport`, `prsave`, `prload`, `prmerge`. Case-sensitive. Implemented via Windows `ReadConsoleInputW` in raw mode — no external deps. |
| v2.9.1-alpha | Fix: `next` after `scan unknown` printed "No previous scan" because `totalResults()` only counted RAM/disk results, not the snapshot. `next` and `scan`'s overwrite-confirmation now use a new `hasScanData()` check that also sees the snapshot. `scan unknown` → `next changed` now actually filters against the snapshot as documented. |
| v2.10.0-alpha | Up/Down arrow command history at the main prompt. Last 200 commands kept in-session (not persisted to disk). Bash-style draft preservation: pressing Up saves the in-progress line; Down past the newest history entry restores it. Duplicates of the most recent entry are skipped. Escape resets history nav along with clearing the line. |
| v2.11.0-alpha | `results` accepts optional `guess` / `g` keyword to add Guess + Confidence columns (same heuristic as `look`). One 8-byte read per displayed row, so it scales with how many you ask for (default n=20). Works with the existing range/list and sort modes. |
| v2.12.0-alpha | Ctrl+C during `pscan` now cancels the scan and returns to the prompt with partial results, instead of killing the process. Cancellation is checked in the hot DFS path (`submit` and `rscan`) via a global `pscanStopFlag` and propagates across all sessions. `pscanWasCancelled` is sticky so `cmdPointerScan` can label the summary `[CANCELLED]`. The previous Ctrl+C exit semantics still apply when nothing is running. |
| v2.13.0-alpha | New `pscan` 6th positional arg `maxAddrsPerHop` — caps non-static recursions per shared hop value. Targets the UE5/Unity case where one hop value has hundreds of addresses (pool arrays). Static-base hits remain uncapped — they're the actual chain endpoints. Default 0 = unlimited (no behaviour change). Try 16-32 on depth 6/7 scans. Applied symmetrically in positive and negative offset passes. |
| v2.14.0-alpha | `pscan` now prints the resolved settings and asks y/n before running. `n` walks each field one-by-one with the current value in `[brackets]` — blank input keeps current. Loops until y is given so corrections can be made iteratively. Solves the "what does `pscan 6 8192 100 exe 5 16` even mean" problem without forcing named-arg syntax. |

| v2.15.0-alpha | Memory/lag fix for repeated `scan unknown` in one session. FirstScan clears diskRes and Results up front (unknown path was leaking GB-scale result files and misrouting later `next` scans via stale diskRes). nextScanFromSnapshot spills survivors to disk above 1M like FirstScan (was unbounded RAM, multi-GB spikes). FirstScan/NextScan release freed heap to the OS via debug.FreeOSMemory. Startup sweep of memhacker_scans/ removes temp files left by crashed sessions. |

| v2.16.0-alpha | `results` guess type filter: `results [n] guess <type> [minconf]` keeps only rows guessed as that type (f32/f64/i32/i64/i8/ptr/zero) with confidence >= minconf (default 0.5), sorted by confidence descending. Walks results until n matches or 100K rows examined. Works in range/list mode too. |

| v2.17.0-alpha | Disk-backed kept-results store (`keptresults_windows.go`). Every guess-filtered `results` invocation appends its matches to `memhacker_results.bin` (16-byte records: addr/conf/type), deduped by address, never held in RAM. `results kept [n]` views it with live values decoded per entry's guessed type; `results clear` is the only thing that clears it (survives new scans, `reset`, and app restarts). |

| v2.18.0-alpha | `results` semantics revamp: bare `results` now shows the kept list (the curated set), not the scan set. EVERY explicit selection (`results 50`, `results 100-200`, `results 1,3,5`, with or without guess filters) displays scan-set rows AND appends them to the kept list (deduped). Plain rows are kept with the active data type, guessed rows with their guessed type (record format: addr/conf/guessCode/dt). Auto-display after scan/next stays display-only. |

| v2.19.0-alpha | `results kept` accepts range/list index specs (`results kept 40-50`, `results kept 1,5,9`) in addition to a count. Bad count args no longer collapse to 0 rows. |

| v2.20.0-alpha | Result set becomes a first-class second set with explicit verbs. Bare `results` is back to a pure scan-set view (no side effects, no auto-ingestion). New subcommands: `results add <n|range|list> [g type [conf]]` copies scan rows in (deduped), `results view` (alias `v`) inspects with sort, `results write`/`freeze` (aliases `w`/`f`) act on entries via their captured type, `results remove` (alias `rm`) prunes, `results clear` empties. `kept` keyword removed. |

| v2.21.0-alpha | `results view` gains guess-based filtering and richer sorting. `guess`/`g [type] [minconf]` live-guesses each entry (Guess + GConf columns); with a type it filters to matches, examining the whole set by default, sorted by live confidence. New `conf` sort keyword (captured confidence, descending) alongside `addr`/`val`. |

| v2.21.1-alpha | Cleanup after the result-set design churn: `keptresults_windows.go` renamed to `resultset_windows.go`, all `kept*` identifiers renamed to `rs*`, stale file-table row fixed, vet nit (redundant trailing newline in help) fixed. No behavior change. |

| v2.22.0-alpha | Linear-relation scan for obfuscated values (`relscan_windows.go`). `next rel <r1> <r2>` establishes per-address relations stored = a*real + b (after `scan unknown` vs snapshot, or on an in-RAM result set); slope must be integer or 1/integer to kill coincidences. `next rel <r>` refines against recorded (a, b). `rel [n]` lists relations with decoded real values; `relwrite <idx|range> <real>` writes a real value through the relation. relMap cleared on new scan/reset; establish capped at 1M survivors (RAM-only, disk sets must be narrowed first). |

| v2.22.1-alpha | Doc clarifications for the relation scan in help + README: argument order is chronological (old real value first, current second), the two-arg form is used once to establish and the one-arg refine is stronger than re-establishing, and relwrite takes the REAL value while writing the encoded bytes. No behavior change. |

| v2.23.0-alpha | `next rel` establish now works on disk-backed result sets (relEstablishFromDisk: streams addr/val chunks with gap-grouped live reads, same pattern as nextScanDisk; consumes the disk set, survivors capped at 1M become the in-RAM result set + relMap). Removes the "too many results for a relation pass" refusal after scan unknown -> next changed left >100K survivors on disk. Errors cleanly if the stored value size doesn't match the current data type. |

| v2.24.0-alpha | `scan unknown` zero-run optimization. Readers split each 4MB chunk into zero/non-zero runs at 64KB granularity (parallel, not under writer lock); all-zero runs are recorded as metadata only (snapshotChunk.offset = -1), skipping both the disk write and the read-back in later snapshot passes (readChunk synthesizes zeros). Lossless, no semantics change. Snapshot file writes now buffered (4MB bufio, flushed before reads). Summary prints zero MB skipped. Typically cuts snapshot I/O 30-60%. |

| v2.24.1-alpha | Strict value parsing. encodeValue now uses strconv and ERRORS on garbage instead of silently encoding 0 (the killer case: `scan exact unknown` was a scan for f32 0.0 with ±1.0 tolerance, matching half the game's memory and grinding for minutes; users thought it was THE unknown scan). All parseScanArgs value paths check the error; an unknown-like value prints a hint pointing at `scan unknown`. Bonus: integer types now accept 0x hex values (base-0 parsing). Affects scan/next/write/freeze value parsing everywhere. |

| v2.24.2-alpha | `scan unknown` no longer prints a trailing "No results" line (cmdScan tried to auto-display results, but unknown scans produce a snapshot, not listable results). Prints "Snapshotted ~N addresses" plus next-step guidance instead of "Found N results". |

| v2.24.3-alpha | rel/relPreview number formatting: whole numbers print plainly (5479620) instead of %g scientific notation (5.47962e+06); fractional values keep %g. |

Current: **v2.24.3-alpha** (AppVersion in `logger.go`)

---

## Documentation Rules

**User-facing documentation lives in exactly TWO places — keep them in sync, IN THE SAME COMMIT, every time:**

1. **`README.md`** — the user-facing contract.
2. **`printHelp()` in `main_windows.go`** — the in-tool reference (`help` command).

**Do NOT document commands or features in this CLAUDE.md.** This file is context for the AI agent, not user docs. The only command-related thing that lives here is the Version History table, where each release gets a one-line summary.

**Update README + help whenever any of these change** (and yes, this list includes aliases — if `ia` works, `ia` is documented in both):
- A new command is added, or an existing one changes behaviour or arguments
- A command or feature is removed or renamed — remove from both
- A new alias is added to an existing command
- Default values change (scan type, depth, offset, etc.)
- A new temp file or folder is introduced
- A workflow changes
- New keywords/flags are added to existing commands (e.g. `range`, `cap`, `all` on scan)

If you only touch one of README / help, you have an incomplete commit. Stop and update the other.

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
