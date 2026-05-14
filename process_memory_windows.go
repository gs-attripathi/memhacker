//go:build windows

package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS  = 0x1F0FFF
	MEM_COMMIT          = 0x1000
	PAGE_NOACCESS       = 0x01
	PAGE_GUARD          = 0x100
	TH32CS_SNAPPROCESS  = 0x2
	TH32CS_SNAPMODULE   = 0x8
	TH32CS_SNAPMODULE32 = 0x10
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	_                 [2]byte
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 [4]byte
}

type PROCESSENTRY32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [windows.MAX_PATH]uint16
}

type MODULEENTRY32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	ModuleHandle uintptr
	Module       [256]uint16
	ExePath      [windows.MAX_PATH]uint16
}

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx   = modKernel32.NewProc("VirtualQueryEx")
	procVirtualProtectEx = modKernel32.NewProc("VirtualProtectEx")
	procModule32First    = modKernel32.NewProc("Module32FirstW")
	procModule32Next     = modKernel32.NewProc("Module32NextW")
	procProcess32First   = modKernel32.NewProc("Process32FirstW")
	procProcess32Next    = modKernel32.NewProc("Process32NextW")
	procIsWow64Process   = modKernel32.NewProc("IsWow64Process")
)

// IsProcess32Bit returns true if the process is a 32-bit process running under WOW64
func IsProcess32Bit(handle windows.Handle) bool {
	var wow64 uint32
	ret, _, _ := procIsWow64Process.Call(uintptr(handle), uintptr(unsafe.Pointer(&wow64)))
	if ret == 0 {
		return false
	}
	return wow64 != 0
}

type ProcessInfo struct {
	PID  uint32
	Name string
}

type ModuleInfo struct {
	Name     string
	Base     uintptr
	Size     uint32
	Path     string // full path to the DLL/EXE
	IsSystem bool   // true if it's a Windows system DLL
}

// known system DLL paths (lowercased substrings)
var systemPaths = []string{
	`\windows\system32\`,
	`\windows\syswow64\`,
	`\windows\sysnative\`,
	`\windows\winsxs\`,
	`\windows\microsoft.net\`,
}

func classifyModule(path string) bool {
	lower := strings.ToLower(path)
	for _, sp := range systemPaths {
		if strings.Contains(lower, sp) {
			return true
		}
	}
	return false
}

func ListProcesses() ([]ProcessInfo, error) {
	Log.Debug("ListProcesses: creating snapshot")
	snap, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		Log.Error("ListProcesses: snapshot failed: %v", err)
		return nil, fmt.Errorf("snapshot failed: %v", err)
	}
	defer windows.CloseHandle(snap)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var procs []ProcessInfo

	r1, _, _ := procProcess32First.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
	for r1 != 0 {
		procs = append(procs, ProcessInfo{
			PID:  entry.ProcessID,
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		})
		entry.Size = uint32(unsafe.Sizeof(entry))
		r1, _, _ = procProcess32Next.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
	}
	Log.Debug("ListProcesses: found %d processes", len(procs))
	return procs, nil
}

func OpenProcessHandle(pid uint32) (windows.Handle, error) {
	Log.Info("OpenProcess: PID=%d", pid)
	handle, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		Log.Error("OpenProcess: PID=%d failed: %v", pid, err)
		return 0, fmt.Errorf("OpenProcess failed: %v", err)
	}
	Log.Info("OpenProcess: PID=%d OK, handle=0x%X", pid, handle)
	return handle, nil
}

func CloseProcessHandle(handle windows.Handle) {
	Log.Info("CloseProcessHandle: handle=0x%X", handle)
	windows.CloseHandle(handle)
}

func ReadMemory(handle windows.Handle, addr uintptr, size int) ([]byte, error) {
	buf := make([]byte, size)
	var read uintptr
	err := windows.ReadProcessMemory(handle, addr, &buf[0], uintptr(size), &read)
	if err != nil {
		Log.Debug("ReadMemory: addr=0x%X size=%d failed: %v", addr, size, err)
		return nil, err
	}
	return buf[:read], nil
}

func WriteMemory(handle windows.Handle, addr uintptr, data []byte) error {
	var oldProt uint32
	Log.Debug("WriteMemory: addr=0x%X size=%d", addr, len(data))
	procVirtualProtectEx.Call(uintptr(handle), addr, uintptr(len(data)), 0x40, uintptr(unsafe.Pointer(&oldProt)))
	var written uintptr
	err := windows.WriteProcessMemory(handle, addr, &data[0], uintptr(len(data)), &written)
	procVirtualProtectEx.Call(uintptr(handle), addr, uintptr(len(data)), uintptr(oldProt), uintptr(unsafe.Pointer(&oldProt)))
	if err != nil {
		Log.Error("WriteMemory: addr=0x%X failed: %v", addr, err)
		return err
	}
	Log.Debug("WriteMemory: addr=0x%X wrote %d bytes OK", addr, written)
	return nil
}

func QueryRegion(handle windows.Handle, addr uintptr) (*MEMORY_BASIC_INFORMATION, error) {
	var mbi MEMORY_BASIC_INFORMATION
	ret, _, err := procVirtualQueryEx.Call(
		uintptr(handle),
		addr,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
	)
	if ret == 0 {
		return nil, err
	}
	return &mbi, nil
}

func isReadable(mbi *MEMORY_BASIC_INFORMATION) bool {
	if mbi.State != MEM_COMMIT {
		return false
	}
	if mbi.Protect&PAGE_NOACCESS != 0 {
		return false
	}
	if mbi.Protect&PAGE_GUARD != 0 {
		return false
	}
	return mbi.Protect&uint32(0x02|0x04|0x20|0x40|0x80|0x10) != 0
}

func isWritable(mbi *MEMORY_BASIC_INFORMATION) bool {
	return mbi.Protect&uint32(0x04|0x08|0x40|0x80) != 0
}

func EnumMemoryRegions(handle windows.Handle, writableOnly bool) []MEMORY_BASIC_INFORMATION {
	var regions []MEMORY_BASIC_INFORMATION
	addr := uintptr(0x10000)
	// Use IsProcess32Bit to determine max address
	maxAddr := uintptr(0x7FFFFFFFFFFF)
	if IsProcess32Bit(handle) {
		maxAddr = uintptr(0x7FFFFFFF)
	}

	for addr < maxAddr {
		mbi, err := QueryRegion(handle, addr)
		if err != nil {
			addr += 0x1000
			continue
		}
		if isReadable(mbi) {
			if !writableOnly || isWritable(mbi) {
				regions = append(regions, *mbi)
			}
		}
		if mbi.RegionSize == 0 {
			break
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}
	Log.Debug("EnumMemoryRegions: found %d regions (writableOnly=%v)", len(regions), writableOnly)
	return regions
}

func GetModules(pid uint32) ([]ModuleInfo, error) {
	Log.Debug("GetModules: PID=%d", pid)
	snap, err := windows.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid)
	if err != nil {
		Log.Error("GetModules: PID=%d snapshot failed: %v", pid, err)
		return nil, fmt.Errorf("module snapshot failed: %v", err)
	}
	defer windows.CloseHandle(snap)

	var entry MODULEENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var mods []ModuleInfo

	r1, _, _ := procModule32First.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
	for r1 != 0 {
		path := windows.UTF16ToString(entry.ExePath[:])
		mods = append(mods, ModuleInfo{
			Name:     windows.UTF16ToString(entry.Module[:]),
			Base:     entry.ModBaseAddr,
			Size:     entry.ModBaseSize,
			Path:     path,
			IsSystem: classifyModule(path),
		})
		entry.Size = uint32(unsafe.Sizeof(entry))
		r1, _, _ = procModule32Next.Call(uintptr(snap), uintptr(unsafe.Pointer(&entry)))
	}
	Log.Debug("GetModules: PID=%d found %d modules", pid, len(mods))
	return mods, nil
}

func ReadPointer(handle windows.Handle, addr uintptr) (uintptr, error) {
	buf, err := ReadMemory(handle, addr, 8)
	if err != nil || len(buf) < 8 {
		return 0, err
	}
	val := *(*uint64)(unsafe.Pointer(&buf[0]))
	return uintptr(val), nil
}
