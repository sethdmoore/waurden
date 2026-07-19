package main

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Provider  string `toml:"provider"        envconfig:"PROVIDER"`
	Model     string `toml:"model"           envconfig:"MODEL"`
	BaseURL   string `toml:"base_url"        envconfig:"BASE_URL"`
	ScanMode  string `toml:"scan_mode"       envconfig:"SCAN_MODE"` // full|heuristics|llm (default full)
	APIKey    string `toml:"api_key"         envconfig:"API_KEY"`
	APIKeyEnv string `toml:"api_key_env"     envconfig:"API_KEY_ENV"` // fallback: read key from this env var
	Timeout   int    `toml:"timeout_seconds" envconfig:"TIMEOUT"`
	DBPath    string `toml:"db_path"         envconfig:"DB_PATH"`
	// DBBusyTimeout is how long (seconds) a gate waits for a locked DB before
	// giving up with SQLITE_BUSY. yay runs the makepkg.conf.d hook once per
	// package concurrently, so gates contend for the write lock; this bounds the
	// wait. 0 = fail fast (no wait); negative is clamped to 0.
	DBBusyTimeout int `toml:"db_busy_timeout_seconds" envconfig:"DB_BUSY_TIMEOUT"`
	// TreeScan front-loads a gate by discovering the whole recursive AUR
	// dependency closure of $PWD (via .SRCINFO depends + pacman classification),
	// scanning every AUR package before the helper compiles anything. Default on;
	// false = the legacy single-$PWD gate.
	TreeScan bool `toml:"tree_scan" envconfig:"TREE_SCAN"`
	// TreePauseSeconds holds a clean tree render on screen this long before the
	// gate returns, so the block of results is readable before the helper's build
	// output scrolls it away. 0 = no pause.
	TreePauseSeconds int `toml:"tree_pause_seconds" envconfig:"TREE_PAUSE_SECONDS"`
	// CloneDir is where wAURden keeps its own inert AUR clones (never built), used
	// to discover/pre-scan/diff dependency PKGBUILDs. Default ~/.cache/waurden/aur.
	CloneDir    string   `toml:"clone_dir"       envconfig:"CLONE_DIR"`
	BlockOn     []string `toml:"block_on"        envconfig:"BLOCK_ON"`
	WarnOn      []string `toml:"warn_on"         envconfig:"WARN_ON"`
	OnError     string   `toml:"on_error"        envconfig:"ON_ERROR"`
	Interactive bool     `toml:"interactive"     envconfig:"INTERACTIVE"`
	DeepSource  bool     `toml:"deep_source"     envconfig:"DEEP_SOURCE"`
	VirusTotal  bool     `toml:"virustotal"      envconfig:"VIRUSTOTAL"`
	VTKeyEnv    string   `toml:"vt_api_key_env"  envconfig:"VT_API_KEY_ENV"`
}

// loadConfig returns the merged config, whether any config file was found, and any error.
func loadConfig() (Config, bool, error) {
	cfg := Config{
		Provider:         "mock",
		Timeout:          60,
		DBBusyTimeout:    7,
		TreeScan:         true,
		TreePauseSeconds: 1,
		BlockOn:          []string{"malicious"},
		WarnOn:           []string{"suspicious"},
		OnError:          "warn",
	}

	home, err := os.UserHomeDir()
	if err == nil {
		cfg.DBPath = filepath.Join(home, ".local", "share", "waurden", "waurden.db")
		cfg.CloneDir = filepath.Join(home, ".cache", "waurden", "aur")
	}

	paths := []string{
		"/etc/waurden/config.toml",
	}
	if home != "" {
		paths = append(paths, filepath.Join(home, ".config", "waurden", "config.toml"))
	}

	configFound := false
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return cfg, false, err
		}
		if _, err := toml.Decode(string(data), &cfg); err != nil {
			return cfg, false, err
		}
		configFound = true
	}

	// Environment variables override config file values.
	// WAURDEN_PROVIDER, WAURDEN_MODEL, WAURDEN_BASE_URL, etc.
	// Unset vars are left unchanged (no required fields).
	if err := envconfig.Process("WAURDEN", &cfg); err != nil {
		return cfg, configFound, err
	}

	// Expand ~ in DBPath and CloneDir (from config file or env var).
	cfg.DBPath = expandHome(cfg.DBPath, home)
	cfg.CloneDir = expandHome(cfg.CloneDir, home)

	return cfg, configFound, nil
}

// expandHome rewrites a leading ~/ to the given home directory. An empty home or
// a path that does not start with ~/ is returned unchanged.
func expandHome(path, home string) string {
	if home != "" && len(path) >= 2 && path[:2] == "~/" {
		return filepath.Join(home, path[2:])
	}
	return path
}
