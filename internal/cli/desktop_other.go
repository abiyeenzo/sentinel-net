//go:build !windows

package cli

import (
	"os/exec"
	"runtime"
)

func isStandaloneDesktopLaunch(_ IO) bool {
	return false
}

func openBrowser(url string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", url).Start()
	}
	return exec.Command("xdg-open", url).Start()
}
