package main

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Provider    string   `toml:"provider"        envconfig:"PROVIDER"`
	Model       string   `toml:"model"           envconfig:"MODEL"`
	BaseURL     string   `toml:"base_url"        envconfig:"BASE_URL"`
	ScanMode    string   `toml:"scan_mode"       envconfig:"SCAN_MODE"` // full|heuristics|llm (default full)
	APIKey      string   `toml:"api_key"         envconfig:"API_KEY"`
	APIKeyEnv   string   `toml:"api_key_env"     envconfig:"API_KEY_ENV"` // fallback: read key from this env var
	Timeout     int      `toml:"timeout_seconds" envconfig:"TIMEOUT"`
	DBPath      string   `toml:"db_path"         envconfig:"DB_PATH"`
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
		Provider: "mock",
		Timeout:  60,
		BlockOn:  []string{"malicious"},
		WarnOn:   []string{"suspicious"},
		OnError:  "warn",
	}

	home, err := os.UserHomeDir()
	if err == nil {
		cfg.DBPath = filepath.Join(home, ".local", "share", "waurden", "waurden.db")
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

	// Expand ~ in DBPath (from config file or env var).
	if len(cfg.DBPath) >= 2 && cfg.DBPath[:2] == "~/" {
		if home != "" {
			cfg.DBPath = filepath.Join(home, cfg.DBPath[2:])
		}
	}

	return cfg, configFound, nil
}
