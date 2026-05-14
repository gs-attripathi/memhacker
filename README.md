# MemHacker v1.7.0

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
| Command | Description |
|---------|-------------|
| `ps` / `list` | List all running processes |
| `open <pid\|name>` | Attach (auto-detects 32-bit WOW64 vs 64-bit) |
| `close` | Detach |
| `modules` | Show loaded DLLs with GAME / SYSTEM tag and full path |

### Data Type
| Command | Description |
|---------|-------------|
| `type <dt>` | Set scan type: `i8` `i16` `i32` `i64` `u8` `u16` `u32` `u64` `f32` `f64` `str` `bytes` |

Default type is `i32`.

### Scanning
| Command | Description |
|---------|-------------|
| `scan exact 100` | First scan — exact value |
| `scan unknown` | First scan — unknown initial value |
| `scan bigger 50` | Greater than |
| `scan smaller 200` | Less than |
| `scan between 10 100` | In range |
| `scan changed` | Changed since last scan |
| `scan unchanged` | Unchanged |
| `scan increased` | Any increase |
| `scan decreased` | Any decrease |
| `scan incby 5` | Increased by exactly 5 |
| `scan decby 3` | Decreased by exactly 3 |
| `scan notequal 0` | Not equal |
| `next <type> [val]` | Filter existing results |
| `results [N]` | Show top N results |
| `reset` | Clear scan results |

### Address Aliases
Instead of typing hex addresses every time, set a name once and use it everywhere.

| Command | Description |
|---------|-------------|
| `alias hp 0x614DD58` | Set alias `hp` for address `0x614DD58` |
| `alias` | List all aliases |
| `alias hp` | Show single alias |
| `unalias hp` | Remove alias |

Once set, use the alias name in any command that takes an address:
```
alias hp 0x614DD58
write hp 999
freeze hp 999 MyHP
pmsave s1.pmap hp
read hp
```

### Value Operations
| Command | Description |
|---------|-------------|
| `read <addr>` | Read live value at address (supports aliases) |
| `write <addr> <val>` | Write value (supports aliases) |
| `add <addr> [label]` | Add to address list |
| `addrlist` | Show address list with live values |

### Freeze
| Command | Description |
|---------|-------------|
| `freeze <addr> <val> [label]` | Freeze address to value at 50ms interval (supports aliases) |
| `unfreeze <id>` | Unfreeze by ID |
| `frozen` | List frozen entries |

### Pointer Scanning (CE-style multi-session)

The idea: scan the same value across multiple game sessions. Each session has a different address for the same data. Chains that resolve correctly in ALL sessions are real static pointers.

| Command | Description |
|---------|-------------|
| `pmsave <file> <addr>` | Build pmap + save to file + register session (addr supports aliases) |
| `pmload <file>` | Load saved pmap (target addr read from file) |
| `pmsessions` | List registered sessions |
| `pmclear` | Clear all sessions |
| `pscan [depth] [offset] [max] [filter]` | Run pointer scan across all sessions |

**pscan filters:**
- `exe` — main executable only (default, most reliable)
- `game` — all non-system DLLs + exe
- `all` — everything including GPU/driver DLLs

Auto-widens: if `exe` finds nothing → tries `game` → tries `all`.

**Defaults:** depth=7, offset=5000, max=100

### Pointer Results (save/load/verify)

After finding pointer chains, save them to a file so you can use them across game restarts without running pscan again.

| Command | Description |
|---------|-------------|
| `prsave <file.json>` | Save last pscan results to JSON file |
| `prload <file.json> [addr]` | Load chains — if addr given, only MATCH chains kept in memory |
| `prverify` | Re-verify chains against current process (shows current vs expected value) |
| `prlist` | List current in-memory chains |
| `prwrite <index> <val>` | Follow chain, write value once |
| `prfreeze <index> <val>` | Follow chain, freeze value |

### Logging
| Command | Description |
|---------|-------------|
| `log` | Show log file path |
| `loglast [N]` | Copy full log (or last N lines) to clipboard — paste into GitHub issues |

---

## Full Workflow

### Step 1 — Find the pointer chain (do once)

```
open game.exe
type i32
scan exact 100           <- your HP value
next exact 85            <- take damage, scan new value
                         <- repeat until 1-2 results
alias hp 0x614DD58       <- give the address a name
pmsave s1.pmap hp        <- save snapshot 1

restart game
scan exact 100
next exact 85
alias hp 0x72419D0
pmsave s2.pmap hp        <- snapshot 2

restart game again
scan exact 100
next exact 85
alias hp 0x710E770
pmsave s3.pmap hp        <- snapshot 3

pscan                    <- cross-reference all 3 sessions
prsave hp_chains.json    <- save the found chains
```

### Step 2 — Use chains every session

```
open game.exe
scan exact 100
next exact 85            <- find current HP address
alias hp 0x8C3D4E0

prload hp_chains.json hp <- loads chains, keeps only ones resolving to 0x8C3D4E0
prsave hp_chains.json    <- overwrite with only working chains (gets cleaner each time)

prwrite 1 999            <- set HP via chain 1
prfreeze 1 999           <- or freeze it
```

---

## Notes

- Needs Administrator / elevated privileges
- Supports 32-bit (WOW64) and 64-bit processes
- System DLLs (kernel32, ntdll etc) and GPU driver DLLs (nvwgf2um, d3d* etc) are skipped as pointer base
- Log file: `memhacker.log` in same folder as the exe
- pmap files are binary (~500MB for 32-bit games) — keep them somewhere safe
- Pointer result files (`.json`) are small and human-readable
