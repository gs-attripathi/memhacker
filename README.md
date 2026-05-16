# MemHacker v2.2.0

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
| `open <pid\|name>` | Attach to process. Supports partial name match — `open surro` matches `SurrounDead.exe`. Auto-detects 32-bit WOW64 vs 64-bit |
| `close` | Detach |
| `modules` | List loaded DLLs — shows `GAME` / `SYSTEM` / `OTHER` tag |
| `regions [all]` | List scannable memory regions with base/end/size. Default: writable private only. `regions all` shows everything |

---

### Data Type

| Command | Description |
|---------|-------------|
| `type <dt>` | Set scan data type. Default: `f32` |

Types: `i8` `i16` `i32` `i64` `u8` `u16` `u32` `u64` `f32` `f64` `str` `bytes`

---

### Scanning

Scans **writable private memory only** by default (game values are always here). Append `all` to scan everything including textures/assets (slower).

| Command | Description |
|---------|-------------|
| `scan exact <val>` | Exact match. For f32/f64 uses ±1.0 tolerance automatically |
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
| `next <type> [val]` | Filter existing results (same types as scan) |
| `results [N]` | Show top N results with live values (default 20) |
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
| `write <addr> <val>` | Write value to address |
| `iwrite <idx> <val>` | Write to scan result by index. Supports range/list: `iwrite 5 100` `iwrite 5-7 100` `iwrite 1,3,5 100` |
| `add <addr> [label]` | Add address to address list |
| `addrlist` | Show address list with live values |

---

### Freeze

| Command | Description |
|---------|-------------|
| `freeze <addr> <val> [label]` | Freeze address at value (50ms write loop) |
| `ifreeze <idx> <val>` | Freeze scan result by index. Supports range/list: `ifreeze 5 100` `ifreeze 5-7 100` |
| `unfreeze <id\|range\|list>` | Unfreeze by ID. e.g. `unfreeze 3` `unfreeze 1-5` `unfreeze 1,3,5` |
| `frozen` | List all frozen entries |

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
| `pmsave <file> <addr>` | Build pointer map + save + register session |
| `pmadd <addr>` | Add another address to the last session (CE-style: one pmap, multiple targets) |
| `pmload <file> [file2] ...` | Load one or more saved pmaps. Multiple files at once: `pmload s1.pmap s2.pmap s3.pmap` |
| `pmsessions` | List registered sessions |
| `pmclear` | Clear all sessions |

#### Running pscan

```
pscan [depth] [offset] [max] [filter] [maxOffsets]
```

| Arg | Default | Description |
|-----|---------|-------------|
| `depth` | `5` | DFS depth. depth=5 ~1s, depth=6 ~27s, depth=7 = minutes |
| `offset` | `8192` | Max offset per pointer hop |
| `max` | `100` | Max chains to return |
| `filter` | `exe` | `exe` = main exe only, `game` = all game DLLs, `all` = everything |
| `maxOffsets` | `5` | Max offset groups per node (CE default) |

**Multiple sessions run in parallel** — total time = slowest session, not sum.

After pscan, results are **automatically saved** to `pscan_last_N.json` (never overwrites). Only chains that currently resolve in the live process are shown.

---

### Pointer Results

| Command | Description |
|---------|-------------|
| `prsave <file.json>` | Save current chains to JSON |
| `prload <file.json> [addr]` | Load chains. If addr given, keeps only chains resolving to that address |
| `prverify [addr]` | Re-verify chains against current process |
| `prlist [ok\|addr]` | List chains. `prlist ok` = only resolvable. `prlist 0xADDR` = only those resolving to addr |
| `prlabel <index> <label>` | Label a chain (saved with prsave) |
| `prwrite <index> <val>` | Follow chain, write value once |
| `prfreeze <index> <val>` | Follow chain, freeze value |

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

## Notes

- Requires Administrator privileges
- Supports 32-bit (WOW64) and 64-bit processes — auto-detected on attach
- Default scan type: `f32` (most games store floats for HP, speed etc.)
- Float `scan exact` uses ±1.0 tolerance automatically — catches imprecise game values
- Scan defaults to writable private memory — append `all` for full scan (much slower)
- Log file: `memhacker.log` next to the exe
- Verified working: SurrounDead (UE5 64-bit), Mount & Blade Warband (32-bit WOW64), a popular open-world racing game (64-bit) — pointer chains survived restarts
