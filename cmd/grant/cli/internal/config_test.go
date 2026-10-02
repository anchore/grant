package internal

import (
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestDefaultConfigLocations_SystemConfigDir(t *testing.T) {
	// empty is treated the same as unset
	t.Setenv("XDG_CONFIG_DIRS", "")
	// pin XDG_CONFIG_HOME so the runner's environment cannot produce a stray etc/xdg match
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	hasEtcXDG := false
	for _, loc := range DefaultConfigLocations() {
		if strings.Contains(filepath.ToSlash(loc), "etc/xdg/grant/") {
			hasEtcXDG = true
		}
	}

	// on windows "/etc/xdg" lands at a drive root any user can create, so there must be no default there
	want := runtime.GOOS != "windows"
	if hasEtcXDG != want {
		t.Errorf("etc/xdg in default config locations = %v, want %v (GOOS=%s)", hasEtcXDG, want, runtime.GOOS)
	}
}

func TestDefaultConfigLocations_ExplicitConfigDirs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_DIRS", dir)

	want := filepath.Join(dir, "grant", "grant.yaml")
	if !slices.Contains(DefaultConfigLocations(), want) {
		t.Errorf("explicit XDG_CONFIG_DIRS entry %q missing from default config locations", want)
	}
}
