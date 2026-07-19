package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeUserConfig writes a config.toml under $HOME/.config/waurden and returns
// its path. HOME must already point at a temp dir for the calling test.
func writeUserConfig(t *testing.T, home, content string) string {
	t.Helper()
	dir := filepath.Join(home, ".config", "waurden")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// clearEnv UNSETS every WAURDEN_* override this test suite asserts on, so a value
// leaking in from the developer's shell cannot poison a case. It must unset (not
// set to ""): envconfig treats a present-but-empty typed var (e.g. WAURDEN_TIMEOUT)
// as a value and fails to parse "" as an int. The original values are restored on
// cleanup.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"WAURDEN_PROVIDER", "WAURDEN_MODEL", "WAURDEN_BASE_URL",
		"WAURDEN_SCAN_MODE", "WAURDEN_API_KEY", "WAURDEN_API_KEY_ENV",
		"WAURDEN_TIMEOUT", "WAURDEN_DB_PATH", "WAURDEN_DB_BUSY_TIMEOUT",
		"WAURDEN_ON_ERROR", "WAURDEN_INTERACTIVE", "WAURDEN_DEEP_SOURCE",
		"WAURDEN_VIRUSTOTAL", "WAURDEN_VT_API_KEY_ENV", "WAURDEN_WARN_ON",
		"WAURDEN_BLOCK_ON",
	} {
		if v, ok := os.LookupEnv(k); ok {
			t.Cleanup(func() { os.Setenv(k, v) })
		}
		os.Unsetenv(k)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearEnv(t)

	cfg, found, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if found {
		t.Errorf("configFound = true, want false (no config file present)")
	}
	if cfg.Provider != "mock" {
		t.Errorf("Provider = %q, want %q", cfg.Provider, "mock")
	}
	if cfg.Timeout != 60 {
		t.Errorf("Timeout = %d, want 60", cfg.Timeout)
	}
	if cfg.DBBusyTimeout != 7 {
		t.Errorf("DBBusyTimeout = %d, want 7", cfg.DBBusyTimeout)
	}
	if len(cfg.BlockOn) != 1 || cfg.BlockOn[0] != "malicious" {
		t.Errorf("BlockOn = %v, want [malicious]", cfg.BlockOn)
	}
	if len(cfg.WarnOn) != 1 || cfg.WarnOn[0] != "suspicious" {
		t.Errorf("WarnOn = %v, want [suspicious]", cfg.WarnOn)
	}
	if cfg.OnError != "warn" {
		t.Errorf("OnError = %q, want %q", cfg.OnError, "warn")
	}
	wantDB := filepath.Join(home, ".local", "share", "waurden", "waurden.db")
	if cfg.DBPath != wantDB {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, wantDB)
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearEnv(t)

	writeUserConfig(t, home, `provider = "openai"
model = "gpt-4o-mini"
base_url = "https://openrouter.ai/api/v1"
timeout_seconds = 30
on_error = "block"
`)

	cfg, found, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !found {
		t.Errorf("configFound = false, want true")
	}
	if cfg.Provider != "openai" {
		t.Errorf("Provider = %q, want %q", cfg.Provider, "openai")
	}
	if cfg.Model != "gpt-4o-mini" {
		t.Errorf("Model = %q, want %q", cfg.Model, "gpt-4o-mini")
	}
	if cfg.BaseURL != "https://openrouter.ai/api/v1" {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, "https://openrouter.ai/api/v1")
	}
	if cfg.Timeout != 30 {
		t.Errorf("Timeout = %d, want 30", cfg.Timeout)
	}
	if cfg.OnError != "block" {
		t.Errorf("OnError = %q, want %q", cfg.OnError, "block")
	}
	// Fields not present in the file keep their coded defaults.
	if len(cfg.BlockOn) != 1 || cfg.BlockOn[0] != "malicious" {
		t.Errorf("BlockOn = %v, want [malicious] (default preserved)", cfg.BlockOn)
	}
	if cfg.DBBusyTimeout != 7 {
		t.Errorf("DBBusyTimeout = %d, want 7 (default preserved)", cfg.DBBusyTimeout)
	}
}

func TestLoadConfigEnvOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearEnv(t)

	writeUserConfig(t, home, `provider = "openai"
model = "gpt-4o-mini"
base_url = "https://openrouter.ai/api/v1"
timeout_seconds = 30
on_error = "block"
`)

	// Env overrides win over the file values.
	t.Setenv("WAURDEN_PROVIDER", "anthropic")
	t.Setenv("WAURDEN_MODEL", "claude-haiku-4-5")

	cfg, found, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !found {
		t.Errorf("configFound = false, want true")
	}
	if cfg.Provider != "anthropic" {
		t.Errorf("Provider = %q, want %q (env override)", cfg.Provider, "anthropic")
	}
	if cfg.Model != "claude-haiku-4-5" {
		t.Errorf("Model = %q, want %q (env override)", cfg.Model, "claude-haiku-4-5")
	}
	// Unoverridden file value survives.
	if cfg.BaseURL != "https://openrouter.ai/api/v1" {
		t.Errorf("BaseURL = %q, want file value preserved", cfg.BaseURL)
	}
	if cfg.OnError != "block" {
		t.Errorf("OnError = %q, want %q (file value preserved)", cfg.OnError, "block")
	}
}

func TestLoadConfigDBPathTildeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearEnv(t)

	writeUserConfig(t, home, `provider = "static"
db_path = "~/custom/x.db"
`)

	cfg, _, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	want := filepath.Join(home, "custom", "x.db")
	if cfg.DBPath != want {
		t.Errorf("DBPath = %q, want %q (tilde expanded)", cfg.DBPath, want)
	}
}

func TestLoadConfigMalformedTOML(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearEnv(t)

	// Unterminated string / invalid syntax.
	writeUserConfig(t, home, "provider = \nthis is not = valid toml [[[\n")

	_, _, err := loadConfig()
	if err == nil {
		t.Fatalf("loadConfig returned nil error for malformed TOML, want non-nil")
	}
}
