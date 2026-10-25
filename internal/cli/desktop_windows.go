//go:build windows

package cli

import (
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcLst = kernel32.NewProc("GetConsoleProcessList")
)

// isStandaloneDesktopLaunch detects whether sentinel-net.exe was double-clicked
// directly from Windows Explorer (transient console owned solely by this process)
// rather than invoked from an existing shell (cmd, PowerShell, CI, or tests).
func isStandaloneDesktopLaunch(ioCfg IO) bool {
	if !ioCfg.StdoutTTY {
		return false
	}
	var pids [2]uint32
	r1, _, _ := procGetConsoleProcLst.Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	return r1 == 1
}

func openBrowser(url string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}
