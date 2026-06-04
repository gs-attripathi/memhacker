//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	rlEnableLineInput      = 0x0002
	rlEnableEchoInput      = 0x0004
	rlEnableProcessedInput = 0x0001
	rlKeyEvent             = 0x0001
	rlVkBack               = 0x08
	rlVkTab                = 0x09
	rlVkReturn             = 0x0D
	rlVkEscape             = 0x1B
	rlVkUp                 = 0x26
	rlVkDown               = 0x28
	rlHistoryMax           = 200
)

var commandHistory []string

// addHistory appends a line to in-session history. Skips empty lines and exact
// duplicates of the most recent entry. Caps at rlHistoryMax.
func addHistory(line string) {
	if line == "" {
		return
	}
	if len(commandHistory) > 0 && commandHistory[len(commandHistory)-1] == line {
		return
	}
	commandHistory = append(commandHistory, line)
	if len(commandHistory) > rlHistoryMax {
		commandHistory = commandHistory[len(commandHistory)-rlHistoryMax:]
	}
}

// replaceLine erases the currently-displayed buf and prints `next` in its place.
// Updates *buf to a copy of next.
func replaceLine(buf *[]rune, next []rune) {
	for range *buf {
		fmt.Print("\b \b")
	}
	fmt.Print(string(next))
	*buf = append([]rune(nil), next...)
}

// Windows INPUT_RECORD layout:
//   EventType uint16  (offset 0)
//   padding   [2]byte (offset 2)
//   Event     [16]byte (offset 4)  ← union, largest member is KEY_EVENT_RECORD (16 bytes)
type rlInputRecord struct {
	EventType uint16
	_         [2]byte
	Event     [16]byte
}

// Windows KEY_EVENT_RECORD layout (16 bytes):
//   bKeyDown          uint32  (4)
//   wRepeatCount      uint16  (2)
//   wVirtualKeyCode   uint16  (2)
//   wVirtualScanCode  uint16  (2)
//   UnicodeChar       uint16  (2, from uChar union)
//   dwControlKeyState uint32  (4)
type rlKeyEventRecord struct {
	KeyDown          uint32
	RepeatCount      uint16
	VirtualKeyCode   uint16
	VirtualScanCode  uint16
	UnicodeChar      uint16
	ControlKeyState  uint32
}

var procReadConsoleInputW = syscall.NewLazyDLL("kernel32.dll").NewProc("ReadConsoleInputW")

// fileArgCommands lists commands whose arguments are file paths.
var fileArgCommands = map[string]bool{
	"pmload":  true,
	"pmsave":  true,
	"pmexport": true,
	"prsave":  true,
	"prload":  true,
	"prmerge": true,
}

// fileCompletions returns files in the current directory whose names start
// with partial. Case-sensitive. Handles sub-paths (partial may contain /\).
func fileCompletions(partial string) []string {
	dir, prefix := ".", partial
	if i := strings.LastIndexAny(partial, `/\`); i >= 0 {
		dir = partial[:i]
		prefix = partial[i+1:]
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var matches []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			name := e.Name()
			if e.IsDir() {
				name += string(os.PathSeparator)
			}
			if dir == "." {
				matches = append(matches, name)
			} else {
				matches = append(matches, filepath.Join(dir, name))
			}
		}
	}
	sort.Strings(matches)
	return matches
}

// readKey reads one key event from the console input handle.
func readKey(handle windows.Handle) (rlKeyEventRecord, bool) {
	var rec rlInputRecord
	var nRead uint32
	ret, _, _ := procReadConsoleInputW.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&rec)),
		1,
		uintptr(unsafe.Pointer(&nRead)),
	)
	if ret == 0 || nRead == 0 {
		return rlKeyEventRecord{}, false
	}
	if rec.EventType != rlKeyEvent {
		return rlKeyEventRecord{}, false
	}
	ke := *(*rlKeyEventRecord)(unsafe.Pointer(&rec.Event[0]))
	if ke.KeyDown == 0 {
		return rlKeyEventRecord{}, false // key release, skip
	}
	return ke, true
}

// ReadLine reads a line from the console with Tab-completion for file arguments.
// Falls back to plain bufio read if the console handle is unavailable.
func ReadLine(prompt string) string {
	handle, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		fmt.Print(prompt)
		var line string
		fmt.Scanln(&line)
		return line
	}

	var origMode uint32
	windows.GetConsoleMode(handle, &origMode)
	// Raw mode: disable line buffering and echo; keep Ctrl+C processing.
	rawMode := (origMode &^ uint32(rlEnableLineInput) &^ uint32(rlEnableEchoInput)) | rlEnableProcessedInput
	windows.SetConsoleMode(handle, rawMode)
	defer windows.SetConsoleMode(handle, origMode)

	fmt.Print(prompt)

	var buf []rune
	histIdx := len(commandHistory) // points "past last" = viewing the live draft
	var savedDraft []rune          // snapshot of draft when first Up is pressed

	for {
		ke, ok := readKey(handle)
		if !ok {
			continue
		}

		vk := ke.VirtualKeyCode
		ch := rune(ke.UnicodeChar)

		switch vk {

		case rlVkReturn:
			line := string(buf)
			fmt.Println()
			addHistory(line)
			return line

		case rlVkUp:
			if len(commandHistory) == 0 || histIdx == 0 {
				continue
			}
			if histIdx == len(commandHistory) {
				savedDraft = append([]rune(nil), buf...)
			}
			histIdx--
			replaceLine(&buf, []rune(commandHistory[histIdx]))

		case rlVkDown:
			if histIdx >= len(commandHistory) {
				continue
			}
			histIdx++
			if histIdx == len(commandHistory) {
				replaceLine(&buf, savedDraft)
			} else {
				replaceLine(&buf, []rune(commandHistory[histIdx]))
			}

		case rlVkBack:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				fmt.Print("\b \b")
			}

		case rlVkEscape:
			// Clear current line
			for range buf {
				fmt.Print("\b \b")
			}
			buf = nil
			histIdx = len(commandHistory)
			savedDraft = nil

		case rlVkTab:
			line := string(buf)
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			cmd := strings.ToLower(parts[0])
			if !fileArgCommands[cmd] {
				continue
			}
			// Only complete when we're past the command (typing a file arg).
			if len(parts) < 2 && !strings.HasSuffix(line, " ") {
				continue
			}

			lastSpace := strings.LastIndex(line, " ")
			partial := ""
			linePrefix := line
			if lastSpace >= 0 {
				partial = line[lastSpace+1:]
				linePrefix = line[:lastSpace+1]
			}

			matches := fileCompletions(partial)
			switch len(matches) {
			case 0:
				// No match — do nothing (could beep here)
			case 1:
				// Erase partial, write the single completion
				for range []rune(partial) {
					fmt.Print("\b \b")
				}
				fmt.Print(matches[0])
				buf = []rune(linePrefix + matches[0])
			default:
				// Show all matches below, redisplay the line
				fmt.Println()
				fmt.Println(strings.Join(matches, "   "))
				fmt.Print(prompt + string(buf))
			}

		default:
			if ch >= 32 { // printable character
				buf = append(buf, ch)
				fmt.Print(string(ch))
			}
		}
	}
}
