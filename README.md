# MemHacker v2.13.0-alpha

A Cheat Engine alternative written in Go — memory scanner, CE-style multi-session pointer scan, value freeze.

**Single `.exe`, zero dependencies. Drop and run on any Windows machine.**

---

## Download

Get the latest `memhacker.exe` from [Releases](https://github.com/gs-attripathi/memhacker/releases/latest).

Run as **Administrator** (required to read/write other process memory).

---

## Build from source

Requirements: [Go 1.21+](https://go.dev/dl/)

```
git clone https://github.com/gs-attripathi/memhacker.git
cd memhacker
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o memhacker.exe .
```

Cross-compile from macOS/Linux works fine.

---

## Commands

### Process

| Command | Description |
|---------|-------------|
| `ps` / `list` | List all running processes |
| `open <pid\|name>` (alias `attach`) | Attach to process. Supports partial name match — `open surro` matches `SurrounDead.exe`. Auto-detects 32-bit WOW64 vs 64-bit |
| `close` (alias `detach`) | Detach |
| `modules` (alias `mod`) | List loaded DLLs — shows `GAME` / `SYSTEM` / `OTHER` tag |
| `regions [all]` (alias `reg`) | List scannable memory regions with base/end/size. Default: writable private only. `regions all` shows everything |

---

### Data Type

| Command | Description |
|---------|-------------|
| `type <dt>` (alias `dt`) | Set scan data type. Default: `f32` |

Types: `i8` `i16` `i32` `i64` `u8` `u16` `u32` `u64` `f32` `f64` `str` `bytes`

---

### Scanning

Scans **writable private memory only** by default (game values are always here). Append `all` to scan everything including textures/assets (slower).

| Command | Description |
|---------|-------------|
| `scan exact <val>` (alias `s`) | Exact match. For f32/f64 uses ±1.0 tolerance automatically |
| `scan unknown` | Snapshot all memory to disk — use `next changed/increased/decreased` to filter |
| `scan bigger <val>` | Greater than |
| `scan smaller <val>` | Less than |
| `scan between <v1> <v2>` | In range |
| `scan changed` | Changed since last scan |
| `scan unchanged` | Unchanged since last scan |
| `scan increased` | Any increase |
| `scan decreased` | Any decrease |
| `scan incby <val>` | Increased by exactly this amount |
| `scan decby <val>` | Decreased by exactly this amount |
| `scan notequal <val>` | Not equal to value |
| `next <type> [val]` (alias `n`) | Filter existing results (same types as scan) |
| `results [N] [addr\|val] [guess\|g]` (alias `r`) | Show top N results with live values (default 20). Optional `addr` / `val` sorts the displayed rows. Optional `guess` (or `g`) adds Guess + Confidence columns — same heuristic as `look`, picks the most likely type per address (f32 / f64 / i32 / i64 / i8 / ptr / zero) regardless of the active `type`. Costs one 8-byte read per displayed row — keep N small for big result sets. Range / list also supported: `results 1-5 guess`, `results 1,3,5 val g`. |
| `reset` | Clear scan results |

**Optional scan keywords** (append to any scan command):
```
scan exact 100 all                       <- scan all memory including read-only
scan exact 100 range 0x1000000 0x2000000 <- scan only within address range
scan exact 0 cap 500000                  <- stop after 500K results
```

**Notes:**
- `scan unknown` writes a memory snapshot to `memhacker_scans\snapshot.snap` on disk — no RAM pressure regardless of game size
- Results > 1M are automatically stored to `memhacker_scans\scan_N.addr` + `.vals` — no RAM pressure
- If existing results are present, `scan` asks for confirmation before clearing them
- Press **Ctrl+C** during any scan to cancel and clear results for a fresh start
- Progress is shown every 2 seconds for both `scan` and `next`

---

### Value Operations

| Command | Description |
|---------|-------------|
| `read <addr> [type]` | Read live value at address |
| `look <addr> [count]` (alias `l`) | Dump neighbors around an address as the current data type. `count` = entries on each side (default 8 → 17 rows). Asymmetric forms: `look <addr> before <n>` (or `b <n>`), `look <addr> after <n>` (or `a <n>`), or both: `look <addr> b 4 a 16`. Output also includes a per-row **Guess** + **Confidence** (heuristic — f32 / f64 / i32 / i64 / i8 / ptr / zero) so you don't have to flip `type` to sniff what each field probably is. Useful for figuring out what fields sit at `+4`, `+8` etc. relative to a found value. |
| `write <addr> <val>` (alias `w`) | Write value to address |
| `iread <addr> <index>` (alias `ir`) | Read at `addr + index × sizeof(type)`. e.g. `iread 0x1A2B3C 4` reads 4th element of array |
| `iwrite <idx> <val>` (alias `iw`) | Write to scan result by index. Supports range/list: `iwrite 5 100` `iwrite 5-7 100` `iwrite 1,3,5 100` |
| `add <addr> [label]` (alias `a`) | Add address to address list (captures the current data type) |
| `iadd <idx\|range\|list> [label]` (alias `ia`) | Add **scan result(s)** to the address list by 1-based index. Each entry captures the current data type. `iadd 1`, `iadd 1-3`, `iadd 1,3,5 hp`. |
| `ladd <off> [<off2> ...]` (alias `la`) | Add offsets from the **last `look`** to the address list. Offset is in bytes, signed. Accepts decimal (`+4`, `-8`) and hex (`0x10`, `+0x20`). Multiple offsets in one command. Optional shared label after `--`: `ladd +4 +8 -- stats`. |
| `addrlist` (aliases `alist`, `al`) | Show address list with live values (1-based indices) |
| `aread <idx\|range\|list>` (alias `ar`) | Read entries from the address list, using each entry's stored type. e.g. `aread 1`, `aread 1-3`, `aread 1,3,5` |
| `awrite <idx\|range\|list> <val>` (alias `aw`) | Write a value to address list entries. e.g. `awrite 1 999`, `awrite 1-3 100` |
| `afreeze <idx\|range\|list> <val>` (alias `af`) | Freeze address list entries at a value. Uses each entry's stored type. |
| `aremove <idx\|range\|list>` (alias `arm`) | Remove entries from the list. Removes from highest to lowest so earlier indices don't shift. |
| `aclear` | Empty the address list. |

---

### Freeze

| Command | Description |
|---------|-------------|
| `freeze <addr> <val> [label]` (alias `f`) | Freeze address at value (50ms write loop) |
| `ifreeze <idx> <val>` (alias `if`) | Freeze scan result by index. Supports range/list: `ifreeze 5 100` `ifreeze 5-7 100` |
| `unfreeze <id\|range\|list>` (alias `uf`) | Unfreeze by ID. e.g. `unfreeze 3` `unfreeze 1-5` `unfreeze 1,3,5` |
| `frozen` (alias `fl`) | List all frozen entries |

---

### Address Aliases

Set a name for any address and use it in every command.

| Command | Description |
|---------|-------------|
| `alias <name> <addr>` | Set alias. e.g. `alias hp 0x614DD58` |
| `alias` | List all aliases |
| `unalias <name>` | Remove alias |

---

### Pointer Scanning

CE-style multi-session pointer scan. Find stable pointer chains that survive game restarts.

**How it works:** attach and save a pointer map snapshot each session. `pscan` cross-references all sessions — only chains resolving correctly in ALL sessions are returned.

#### Sessions

| Command | Description |
|---------|-------------|
| `pmap` | Build pointer map in memory only (no file saved). Use `pmsave` to also save + register. |
| `pmsave <file> <addr>` | Build pointer map + save + register session |
| `pmadd <addr>` | Add another address to the last session (CE-style: one pmap, multiple targets) |
| `pmload <file> [file2] ...` | Load one or more saved pmaps. Multiple files at once: `pmload s1.pmap s2.pmap s3.pmap` |
| `pmsessions` | List registered sessions |
| `pmclear` | Clear all sessions |
| `pmexport <src.pmap> <out.scandata>` | Export pmap to CE-compatible `.scandata` format. CE: Pointer Scanner → File → Load pointer map |

#### Running pscan

```
pscan [depth] [offset] [max] [filter] [maxOffsets] [maxAddrsPerHop] [noneg]
```

| Arg | Default | Description |
|-----|---------|-------------|
| `depth` | `5` | DFS depth. depth=5 ~1s, depth=6 ~27s, depth=7 = minutes |
| `offset` | `8192` | Max offset per pointer hop |
| `max` | `100` | Max chains to return |
| `filter` | `exe` | `exe` = main exe only, `game` = all game DLLs, `all` = everything |
| `maxOffsets` | `5` | Max **distinct hop sizes** tried per node (CE's `LimitToMaxOffsetsPerNode`) |
| `maxAddrsPerHop` | `0` (unlimited) | Max non-static recursions per **shared hop value**. Caps the UE5/Unity case where one hop value (e.g. `+0x4`) has hundreds of candidate addresses all in the same actor/object pool. Static-base hits (terminal chains) are **never** capped — they're the chains you actually want. Try `16` or `32` on deep scans (depth 6/7) for large speedups on heavy fan-out games. |
| `noneg` | off | **Disable** negative offsets. By default both positive and negative offsets are scanned (CE's NegativeOffsets, ON). Pass `noneg` to skip the negative pass for ~2× speed. |

**Multiple sessions run in parallel** — total time = slowest session, not sum.

**Press `Ctrl+C` during a `pscan` to cancel it.** Workers wind down within a fraction of a second and you're returned to the prompt with whatever partial chains were already collected (no process exit, unlike scan-cancel). Useful for deep scans (depth=6/7) that run longer than you want to wait.

After pscan, results are **automatically saved** to `pscan_last_N.json` (never overwrites). Only chains that currently resolve in the live process are shown.

**Negative offsets** (default ON since v2.4.1-alpha): pointer scans consider pointers whose value lands either at/before *or* past the target — required for game layouts where struct fields sit before the parent pointer. The `neg` keyword (still accepted as a no-op) is now the default. Use `noneg` to opt out for speed.

---

### Pointer Results

| Command | Description |
|---------|-------------|
| `prsave <file.json>` | Save current chains to JSON |
| `prload <file.json> [addr]` | Load chains. If addr given, keeps only chains resolving to that address |
| `prverify [addr]` | Re-verify chains. Status: `OK` = resolves + value matches, `CHANGED` = resolves but value differs (new game/save), `BROKEN` = dead |
| `prlist [ok\|addr]` | List chains with live address + value. `prlist ok` = only resolvable. `prlist 0xADDR` = filter by address |
| `prlabel <index> <label>` | Label a chain (saved with prsave) |
| `prwrite <index> <val>` | Follow chain, write value once |
| `prfreeze <index> <val>` | Follow chain, freeze value |
| `prmerge <f1.json> <f2.json> ...` | Offline cross-session intersection — keeps only chains appearing in ALL files. No game needed. |

---

### Logging

| Command | Description |
|---------|-------------|
| `log` | Show log file path |
| `loglast [N]` | Copy log (or last N lines) to Windows clipboard — paste into GitHub issues |

---

## Temp Files

All scan temp files go into `memhacker_scans\` folder next to the exe:

```
memhacker_scans\
  snapshot.snap      <- unknown scan snapshot (deleted after first next)
  scan_1.addr        <- addresses from last scan
  scan_1.vals        <- values from last scan
  scan_2.addr        <- addresses after first next
  scan_2.vals
  ...
```

Safe to delete the whole `memhacker_scans\` folder manually at any time.

---

## Workflow

### Find a value (standard scan)

```
open game.exe
scan exact 100        <- find HP (default type is f32)
next decreased        <- take damage in game, filter
next decreased        <- take more damage
results               <- narrow down to 1-2 addresses
write 0xADDR 999      <- or use iwrite 1 999
```

### Unknown scan (when you don't know the value)

```
open game.exe
scan unknown          <- snapshots all memory to disk
                      <- do something in game (take damage, gain gold, etc.)
next changed          <- filter to addresses that changed
next changed          <- filter again
results
```

### Find a stable pointer chain (do once per game)

```
open game.exe
scan exact 100
next exact 85
alias hp 0x614DD58
pmsave s1.pmap hp         <- session 1

restart game
scan exact 100
next exact 85
alias hp 0x72419D0
pmsave s2.pmap hp         <- session 2

restart game
pmsave s3.pmap 0xNEWADDR  <- session 3

pscan                     <- cross-reference all sessions
prsave hp_chains.json
```

### Use the pointer chain every session

```
open game.exe
prload hp_chains.json     <- load + auto-verify
prwrite 1 999             <- write via chain
prfreeze 1 999            <- or freeze
```

---

## Game Scripts

The `scripts/` folder contains Python scripts for game manipulation using found pointer chains.

### `car_speed_rotator.py`
Reads car velocity (X/Y/Z) and steering via pointer chain, modifies velocity in real-time at 60Hz.

```
python scripts/car_speed_rotator.py          # ROTATE mode (default)
python scripts/car_speed_rotator.py drift    # DRIFT mode
```

**Keyboard controls:**
- `LEFT` / `RIGHT` arrow — steer
- `UP` arrow — boost speed
- `DOWN` arrow — reduce speed

Fill in your pointer chain values in the `CONFIG` section at the top. Requires Python + Administrator.

Download commands in `scripts/commands.txt`.

---

## Notes

- Requires Administrator privileges
- Supports 32-bit (WOW64) and 64-bit processes — auto-detected on attach
- Default scan type: `f32` (most games store floats for HP, speed etc.)
- Float `scan exact` uses ±1.0 tolerance automatically — catches imprecise game values
- Scan defaults to writable private memory — append `all` for full scan (much slower)
- Log file: `memhacker.log` next to the exe
- Verified working: SurrounDead (UE5 64-bit), Mount & Blade Warband (32-bit WOW64), a popular open-world racing game (64-bit) — pointer chains survived restarts
