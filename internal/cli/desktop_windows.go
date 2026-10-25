//go:build windows

package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	user32                = syscall.NewLazyDLL("user32.dll")
	procGetConsoleProcLst = kernel32.NewProc("GetConsoleProcessList")
	procGetConsoleWindow  = kernel32.NewProc("GetConsoleWindow")
	procShowWindow        = user32.NewProc("ShowWindow")
)

// isStandaloneDesktopLaunch detects whether sentinel-net.exe was double-clicked
// directly from Windows Explorer (transient console owned solely by this process).
func isStandaloneDesktopLaunch(ioCfg IO) bool {
	if !ioCfg.StdoutTTY {
		return false
	}
	var pids [2]uint32
	r1, _, _ := procGetConsoleProcLst.Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	return r1 == 1
}

func hideConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		_, _, _ = procShowWindow.Call(hwnd, 0) // SW_HIDE = 0
	}
}

func findAppBrowserWindows() string {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("LocalAppData"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("LocalAppData"), "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
	}
	for _, p := range candidates {
		if p != "" {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	for _, name := range []string{"msedge", "chrome", "brave"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func launchDesktopWindow(ctx context.Context, url string) (func(), error) {
	browserBin := findAppBrowserWindows()
	if browserBin != "" {
		tmpProfile, err := os.MkdirTemp("", "sentinel-net-gui-*")
		if err == nil {
			cmd := exec.CommandContext(
				ctx,
				browserBin,
				"--app="+url,
				"--window-size=1360,860",
				"--user-data-dir="+tmpProfile,
				"--no-first-run",
				"--no-default-browser-check",
				"--disable-extensions",
			)
			if startErr := cmd.Start(); startErr == nil {
				done := make(chan struct{})
				go func() {
					_ = cmd.Wait()
					_ = os.RemoveAll(tmpProfile)
					close(done)
				}()
				return func() { <-done }, nil
			}
			_ = os.RemoveAll(tmpProfile)
		}
	}
	err := exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	return nil, err
}
