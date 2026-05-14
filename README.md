# MemHacker v1.8.0

A Cheat Engine alternative written in Go — memory scanner, CE-style multi-session pointer scan, value freeze.

**Single `.exe`, zero dependencies. Drop and run on any Windows machine.**

---

## Download

Get the latest `memhacker.exe` from the repo or [Releases](https://github.com/gs-attripathi/memhacker/releases/latest).

Run as **Administrator** (required to read/write other process memory).

---

## Build from source

Requirements: [Go 1.21+](https://go.dev/dl/)

```
git clone https://github.com/gs-attripathi/memhacker.git
cd memhacker
go mod tidy
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o memhacker.exe .
```

Cross-compile from macOS/Linux works fine — produces a single Windows `.exe`.

---

## Commands

### Process
| Command | Args | Description |
|---------|------|-------------|
| `ps` / `list` | — | List all running processes |
| `open <target>` | `pid` or `name` | Attach to process. Auto-detects 32-bit WOW64 vs 64-bit |
| `close` | — | Detach from current process |
| `modules` | — | List loaded DLLs — shows `GAME` (in game dir) / `SYSTEM` / `OTHER` tag + full path |

### Data Type
| Command | Args | Description |
|---------|------|-------------|
| `type <dt>` | `i8` `i16` `i32` `i64` `u8` `u16` `u32` `u64` `f32` `f64` `str` `bytes` | Set scan data type. Default: `i32` |

### Scanning
| Command | Args | Description |
|---------|------|-------------|
| `scan exact <val>` | value | First scan — exact match |
| `scan unknown` | — | First scan — unknown initial value |
| `scan bigger <val>` | value | Greater than |
| `scan smaller <val>` | value | Less than |
| `scan between <v1> <v2>` | two values | In range |
| `scan changed` | — | Changed since last scan |
| `scan unchanged` | — | Unchanged since last scan |
| `scan increased` | — | Any increase |
| `scan decreased` | — | Any decrease |
| `scan incby <val>` | value | Increased by exactly this amount |
| `scan decby <val>` | value | Decreased by exactly this amount |
| `scan notequal <val>` | value | Not equal to value |
| `next <type> [val]` | same as scan | Filter existing results |
| `results [N]` | optional count | Show top N results (default 20) |
| `reset` | — | Clear scan results |

### Address Aliases
Set a name for any address and use it in every command that takes an address.

| Command | Args | Description |
|---------|------|-------------|
| `alias <name> <addr>` | name, hex addr | Set alias. e.g. `alias hp 0x614DD58` |
| `alias <name>` | name | Show single alias value |
| `alias` | — | List all aliases |
| `unalias <name>` | name | Remove alias |

Once set, use alias name anywhere an address is expected:
```
alias hp 0x614DD58
write hp 999
freeze hp 999 MyHP
pmsave s1.pmap hp
read hp
prverify hp
```

### Value Operations
| Command | Args | Description |
|---------|------|-------------|
| `read <addr> [type]` | addr (alias ok), optional type | Read live value. Type defaults to current scan type |
| `write <addr> <val>` | addr (alias ok), value | Write value to address |
| `add <addr> [label]` | addr (alias ok), optional label | Add to address list |
| `addrlist` | — | Show address list with live values |

### Freeze
| Command | Args | Description |
|---------|------|-------------|
| `freeze <addr> <val> [label]` | addr (alias ok), value, optional label | Freeze address at 50ms interval |
| `unfreeze <id>` | freeze ID | Unfreeze by ID |
| `frozen` | — | List all frozen entries |

---

### Pointer Scanning (CE-style multi-session)

**How it works:** scan the same value across multiple game restarts. Each run has a different address for the same data. Only pointer chains that resolve correctly in ALL sessions are returned — these are real static pointers that survive restarts.

#### Session management
| Command | Args | Description |
|---------|------|-------------|
| `pmsave <file> <addr>` | filename, addr (alias ok) | Build pointer map + save to file + register session. Addr is embedded in the file |
| `pmload <file>` | filename | Load a saved pmap and register as session. No need to re-specify address |
| `pmsessions` | — | List all registered sessions |
| `pmclear` | — | Clear all sessions and pointer map |

#### Running the scan
```
pscan [depth] [offset] [max] [filter]
```

| Arg | Default | Description |
|-----|---------|-------------|
| `depth` | `7` | Max BFS depth. Increase if no results (try 9) |
| `offset` | `5000` | Max offset at each pointer hop |
| `max` | `100` | Max results to return |
| `filter` | `exe` | Where to anchor chains (see below) |

**Filters:**
| Filter | Description |
|--------|-------------|
| `exe` | Main executable only — most reliable, use this first |
| `game` | Any DLL/EXE inside the game's root directory — detected automatically from exe path, no hardcoded list |
| `all` | All modules including GPU drivers, runtime DLLs — use as last resort |

**If `exe` returns 0 results**, the tool suggests:
```
pscan 9 5000 100          <- try more depth first
pscan 7 5000 100 game     <- then try game DLLs
pscan 7 5000 100 all      <- last resort
```

---

### Pointer Results (save/load/verify across restarts)

After pscan, save chains to a JSON file. Load and verify them every session. Over time the file gets cleaner as broken chains get filtered out.

| Command | Args | Description |
|---------|------|-------------|
| `prsave <file.json>` | filename | Save current in-memory chains to JSON. Also records current value at each chain address |
| `prload <file.json> [addr]` | filename, optional addr (alias ok) | Load chains from file. If addr given, only chains resolving to that address are kept in memory |
| `prverify [addr]` | optional addr (alias ok) | Verify in-memory chains against current process. If addr given, filters to only chains resolving to it |
| `prlist` | — | List current in-memory chains with index numbers |
| `prwrite <index> <val>` | 1-based index, value | Follow chain by index, write value once |
| `prfreeze <index> <val>` | 1-based index, value | Follow chain by index, freeze value |

**prverify output:**
| Status | Meaning |
|--------|---------|
| `OK` | Chain resolves correctly, value matches what was saved |
| `MISMATCH` | Chain resolves but value changed (different save slot / character) |
| `WRONG ADDR` | Chain resolves but to a different address than expected |
| `BROKEN` | Chain doesn't resolve at all (game updated? wrong version?) |

---

### Logging
| Command | Args | Description |
|---------|------|-------------|
| `log` | — | Show current log file path |
| `loglast [N]` | optional line count | Copy full log (or last N lines) to Windows clipboard. Includes version header — paste directly into GitHub issues |

---

## Full Workflow

### Step 1 — Find the pointer chain (do once per game)

```
open game.exe
type i32
scan exact 100           <- find HP value
next exact 85            <- take damage, scan new value
                         <- repeat until 1-2 results remain
alias hp 0x614DD58       <- name the address
pmsave s1.pmap hp        <- save snapshot 1

restart game
scan exact 100
next exact 85
alias hp 0x72419D0       <- new address this run
pmsave s2.pmap hp        <- snapshot 2

restart game again
scan exact 100
next exact 85
alias hp 0x710E770
pmsave s3.pmap hp        <- snapshot 3

pscan                    <- cross-reference all 3, returns chains valid in all sessions
prsave hp_chains.json    <- save found chains to file
```

### Step 2 — Use every session (no pscan needed again)

```
open game.exe
scan exact 100
next exact 85            <- find current HP address
alias hp 0x8C3D4E0

prload hp_chains.json hp <- load chains, keep only ones resolving to 0x8C3D4E0
                         <- in-memory updated to matched chains only
prsave hp_chains.json    <- overwrite — file gets cleaner each session

prwrite 1 999            <- set HP via chain 1
prfreeze 1 999           <- or freeze it permanently
```

Or use `prverify` after loading:
```
prload hp_chains.json    <- load all chains
prverify hp              <- verify + filter to matched only
prsave hp_chains.json    <- save clean version
```

---

## Notes

- Needs Administrator / elevated privileges
- Supports 32-bit (WOW64) and 64-bit processes — auto-detected on attach
- `game` filter uses actual game directory (from exe path) — works regardless of where game is installed, works with shortcuts
- System DLLs (kernel32, ntdll etc) always skipped as pointer base
- Log file: `memhacker.log` in same folder as the exe
- pmap files are binary — large for 32-bit games (~500MB), keep them safe
- Pointer result `.json` files are small and human-readable
