# MemHacker v1.7.0

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
| `type <dt>` | Set scan type: i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 str bytes |

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

### Value Operations
| Command | Description |
|---------|-------------|
| `read 0xADDR` | Read live value at address |
| `write 0xADDR 999` | Write value |
| `add 0xADDR label` | Add to address list |
| `addrlist` | Show address list with live values |

### Freeze
| Command | Description |
|---------|-------------|
| `freeze 0xADDR 999 HP` | Freeze address to value (50ms interval) |
| `unfreeze <id>` | Unfreeze by ID |
| `frozen` | List frozen entries |

### Pointer Scanning (CE-style multi-session)

| Command | Description |
|---------|-------------|
| `pmsave <file> <addr>` | Build pmap + save to file + register session |
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

### Logging
| Command | Description |
|---------|-------------|
| `log` | Show log file path |
| `loglast [N]` | Copy full log (or last N lines) to clipboard — paste into GitHub issues |

---

## Pointer Scan Workflow

```
1. open game.exe
2. scan exact 100           <- find target value (e.g. HP = 100)
3. pmsave s1.pmap 0xADDR    <- save pmap + register session
4. restart game (address will change)
5. scan exact 100           <- find new address
6. pmsave s2.pmap 0xADDR2   <- second session
7. pmsave s3.pmap 0xADDR3   <- third session (more = fewer false positives)
8. pscan                    <- cross-reference all sessions
```

Output:
```
[1] "mb_warband.exe"+3A8C0 -> [+18] -> [+C] -> [+4]
```

This chain will resolve to the correct address on every game restart.

---

## Notes

- Needs Administrator / elevated privileges
- Supports 32-bit (WOW64) and 64-bit processes
- System DLLs (kernel32, ntdll etc) and GPU driver DLLs (nvwgf2um, d3d* etc) are skipped as pointer base — game EXE/DLLs only
- Log file: `memhacker.log` in same folder as the exe
