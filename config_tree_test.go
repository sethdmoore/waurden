package main

// Tests for the tree-scan config additions (config.go): expandHome and the
// TreeScan/TreePauseSeconds/CloneDir defaults + overrides. Reuses writeUserConfig
// and clearEnv from config_test.go.

import (
	"path/filepath"
	"testing"
)

func TestExpandHome(t *testing.T) {
	home := "/home/tester"
	cases := []struct {
		in, want string
	}{
		{"~/x/y", filepath.Join(home, "x/y")},
		{"/abs/path", "/abs/path"},
		{"relative", "relative"},
		{"~", "~"}, // only a leading "~/" is expanded
		{"", ""},
	}
	for _, c := range cases {
		if got := expandHome(c.in, home); got != c.want {
			t.Errorf("expandHome(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// An empty home leaves ~/ untouched.
	if got := expandHome("~/x", ""); got != "~/x" {
		t.Errorf("expandHome with empty home = %q, want ~/x", got)
	}
}

func TestLoadConfig_TreeDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearEnv(t)

	cfg, _, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.TreeScan {
		t.Error("TreeScan default = false, want true")
	}
	if cfg.TreePauseSeconds != 1 {
		t.Errorf("TreePauseSeconds default = %d, want 1", cfg.TreePauseSeconds)
	}
	wantClone := filepath.Join(home, ".cache", "waurden", "aur")
	if cfg.CloneDir != wantClone {
		t.Errorf("CloneDir default = %q, want %q", cfg.CloneDir, wantClone)
	}
}

func TestLoadConfig_TreeScanOptOut_File(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearEnv(t)
	writeUserConfig(t, home, "provider = \"static\"\ntree_scan = false\ntree_pause_seconds = 0\n")

	cfg, found, err := loadConfig()
	if err != nil || !found {
		t.Fatalf("loadConfig: found=%v err=%v", found, err)
	}
	if cfg.TreeScan {
		t.Error("tree_scan = false in the file was not honoured")
	}
	if cfg.TreePauseSeconds != 0 {
		t.Errorf("tree_pause_seconds = %d, want 0", cfg.TreePauseSeconds)
	}
}

func TestLoadConfig_TreeScanEnvOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearEnv(t)
	t.Setenv("WAURDEN_TREE_SCAN", "false")

	cfg, _, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.TreeScan {
		t.Error("WAURDEN_TREE_SCAN=false did not override the default")
	}
}

func TestLoadConfig_CloneDirTildeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearEnv(t)
	writeUserConfig(t, home, "provider = \"static\"\nclone_dir = \"~/custom/clones\"\n")

	cfg, _, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	want := filepath.Join(home, "custom", "clones")
	if cfg.CloneDir != want {
		t.Errorf("CloneDir = %q, want %q (tilde expanded)", cfg.CloneDir, want)
	}
}
