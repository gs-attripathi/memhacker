# MemHacker - Cheat Engine alternative in Go

Single `.exe`, zero dependencies. Drop and run on any Windows 64-bit machine.

## Build (from macOS/Linux)
```
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o memhacker.exe .
```

## Usage
Run as Administrator (required to read/write other process memory).

```
memhacker.exe
```

---

## Commands

### Process
| Command | Description |
|---------|-------------|
| `ps` / `list` | List all processes |
| `open <pid or name>` | Attach to process (e.g. `open notepad.exe`) |
| `close` | Detach |
| `modules` | Show loaded modules |

### Data Type
| Command | Description |
|---------|-------------|
| `type i32` | Set scan type (i8/i16/i32/i64/u8/u16/u32/u64/f32/f64/str/bytes) |

### Scanning
| Command | Description |
|---------|-------------|
| `scan exact 100` | First scan - exact value |
| `scan unknown` | First scan - unknown initial value |
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

### Value Ops
| Command | Description |
|---------|-------------|
| `read 0x1A2B3C4D` | Read value at address |
| `write 0x1A2B3C4D 999` | Write value |
| `add 0x1A2B3C4D myHP` | Add to address list |
| `addrlist` | Show address list with live values |

### Freeze
| Command | Description |
|---------|-------------|
| `freeze 0x1A2B3C4D 999 HP` | Freeze address to value (50ms interval) |
| `unfreeze 0` | Unfreeze by ID |
| `frozen` | List frozen entries |

### Pointer Scanning (CE-style)
| Command | Description |
|---------|-------------|
| `pmap` | Build pointer map (all pointer-like values in process memory, sorted) |
| `pscan 0xDEADBEEF` | BFS pointer scan for address |
| `pscan 0xDEADBEEF 7 4096 200` | depth=7, maxOffset=0x1000, max 200 results |

Output looks like:
```
[1] "game.exe"+3A8C0 -> [+18] -> [+C] -> [+4]
```
Paste that into CE pointer scanner or follow manually.

---

## Workflow (typical game hack)
1. `open game.exe`
2. `type i32`
3. `scan exact 100`      ← your current HP
4. Take damage in game
5. `next exact 85`       ← new HP value  
6. Keep repeating until 1-2 results left
7. `write 0xADDR 9999`   ← set HP
8. `freeze 0xADDR 9999 HP`  ← keep it frozen
9. `pmap` + `pscan 0xADDR` ← find static pointer chain

## Notes
- Needs Admin / elevated privileges
- Only works on 64-bit processes (x86-64)
- Pointer scan speed: similar to CE because it uses sorted slice + binary search (O(log n) per lookup)
