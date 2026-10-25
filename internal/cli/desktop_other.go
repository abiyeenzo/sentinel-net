//go:build !windows

package cli

import (
	"context"
	"os"
	"os/exec"
	"runtime"
)

func isStandaloneDesktopLaunch(_ IO) bool {
	return false
}

func hideConsoleWindow() {}

func findAppBrowserUnix() string {
	if runtime.GOOS == "darwin" {
		macApps := []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
		for _, p := range macApps {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
		return ""
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave-browser", "microsoft-edge"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func launchDesktopWindow(ctx context.Context, url string) (func(), error) {
	browserBin := findAppBrowserUnix()
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
	if runtime.GOOS == "darwin" {
		return nil, exec.Command("open", url).Start()
	}
	return nil, exec.Command("xdg-open", url).Start()
}
