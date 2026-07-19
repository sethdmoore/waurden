package main

import (
	"bufio"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// setStdin points the package-global stdinReader at a canned input string and
// registers cleanup so the next test starts from a clean slate.
func setStdin(t *testing.T, input string) {
	t.Helper()
	stdinReader = bufio.NewReader(strings.NewReader(input))
	t.Cleanup(func() { stdinReader = nil })
}

func TestRedact(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"short", "*****"},       // len 5 <= 8 → all asterisks
		{"exactly8", "********"}, // len 8 <= 8 → all asterisks
		{"sk-1234567890abcd", "sk-12345" + "*********"}, // len 17: 8 shown + 9 stars
	}
	for _, tc := range cases {
		got := redact(tc.in)
		if got != tc.want {
			t.Errorf("redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Explicitly assert the asterisk count for the long-key case.
	long := "sk-1234567890abcd"
	got := redact(long)
	if got[:8] != "sk-12345" {
		t.Errorf("redact prefix = %q, want %q", got[:8], "sk-12345")
	}
	stars := strings.Count(got, "*")
	if stars != len(long)-8 {
		t.Errorf("redact star count = %d, want %d", stars, len(long)-8)
	}
}

func TestBuildConfigTOMLOpenAI(t *testing.T) {
	out := buildConfigTOML("openai", "gpt-4o-mini", "https://openrouter.ai/api/v1", "sk-secret", "block", "llm")

	wantSubstrings := []string{
		`provider = "openai"`,
		`model = "gpt-4o-mini"`,
		`base_url = "https://openrouter.ai/api/v1"`,
		`api_key = "sk-secret"`,
		`on_error = "block"`,
		`scan_mode = "llm"`,
		`block_on = ["malicious"]`,
		`timeout_seconds = 60`,
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(out, s) {
			t.Errorf("buildConfigTOML output missing %q\n---\n%s", s, out)
		}
	}

	// Prove the generated text is real, valid TOML that decodes into a Config.
	var cfg Config
	if _, err := toml.Decode(out, &cfg); err != nil {
		t.Fatalf("generated TOML did not parse: %v\n---\n%s", err, out)
	}
	if cfg.Provider != "openai" {
		t.Errorf("decoded Provider = %q, want openai", cfg.Provider)
	}
	if cfg.Model != "gpt-4o-mini" {
		t.Errorf("decoded Model = %q, want gpt-4o-mini", cfg.Model)
	}
	if cfg.BaseURL != "https://openrouter.ai/api/v1" {
		t.Errorf("decoded BaseURL = %q", cfg.BaseURL)
	}
	if cfg.APIKey != "sk-secret" {
		t.Errorf("decoded APIKey = %q, want sk-secret", cfg.APIKey)
	}
	if cfg.OnError != "block" {
		t.Errorf("decoded OnError = %q, want block", cfg.OnError)
	}
	if cfg.ScanMode != "llm" {
		t.Errorf("decoded ScanMode = %q, want llm", cfg.ScanMode)
	}
	if cfg.Timeout != 60 {
		t.Errorf("decoded Timeout = %d, want 60", cfg.Timeout)
	}
	if len(cfg.BlockOn) != 1 || cfg.BlockOn[0] != "malicious" {
		t.Errorf("decoded BlockOn = %v, want [malicious]", cfg.BlockOn)
	}
}

func TestBuildConfigTOMLFullOmitsScanMode(t *testing.T) {
	out := buildConfigTOML("anthropic", "claude-haiku-4-5", "", "sk-x", "warn", "full")
	if strings.Contains(out, "scan_mode") {
		t.Errorf("scan_mode line should be omitted when mode=full\n---\n%s", out)
	}
	var cfg Config
	if _, err := toml.Decode(out, &cfg); err != nil {
		t.Fatalf("generated TOML did not parse: %v", err)
	}
	if cfg.ScanMode != "" {
		t.Errorf("decoded ScanMode = %q, want empty (full omitted)", cfg.ScanMode)
	}
	if cfg.Provider != "anthropic" {
		t.Errorf("decoded Provider = %q, want anthropic", cfg.Provider)
	}
}

func TestBuildConfigTOMLOmitsEmptyFields(t *testing.T) {
	// static provider: no model, no base_url, no api_key.
	out := buildConfigTOML("static", "", "", "", "warn", "full")
	for _, s := range []string{"model =", "base_url =", "api_key =", "scan_mode ="} {
		if strings.Contains(out, s) {
			t.Errorf("expected %q to be omitted for empty/full inputs\n---\n%s", s, out)
		}
	}
	var cfg Config
	if _, err := toml.Decode(out, &cfg); err != nil {
		t.Fatalf("generated TOML did not parse: %v", err)
	}
	if cfg.Provider != "static" {
		t.Errorf("decoded Provider = %q, want static", cfg.Provider)
	}
	if cfg.Model != "" || cfg.BaseURL != "" || cfg.APIKey != "" {
		t.Errorf("expected empty model/base_url/api_key, got %q/%q/%q", cfg.Model, cfg.BaseURL, cfg.APIKey)
	}
}

func TestPromptString(t *testing.T) {
	cases := []struct {
		input, def, want string
	}{
		{"hello\n", "def", "hello"},
		{"\n", "def", "def"},              // empty → default
		{"  spaced  \n", "def", "spaced"}, // trimmed
	}
	for _, tc := range cases {
		setStdin(t, tc.input)
		var res string
		captureStdout(t, func() { res = promptString("Label", tc.def) })
		if res != tc.want {
			t.Errorf("promptString(input=%q, def=%q) = %q, want %q", tc.input, tc.def, res, tc.want)
		}
	}
}

func TestPromptSecret(t *testing.T) {
	setStdin(t, "sk-abc\n")
	var res string
	captureStdout(t, func() { res = promptSecret("API key") })
	if res != "sk-abc" {
		t.Errorf("promptSecret = %q, want %q", res, "sk-abc")
	}
}

func TestPromptChoice(t *testing.T) {
	choices := []string{"a", "b", "c"}

	cases := []struct {
		input, want string
	}{
		{"b\n", "b"},    // valid pick
		{"\n", "a"},     // empty → default
		{"X\nb\n", "b"}, // invalid then valid → loops
		{"B\n", "b"},    // case-insensitive
	}
	for _, tc := range cases {
		setStdin(t, tc.input)
		var res string
		captureStdout(t, func() { res = promptChoice("Choose", choices, "a") })
		if res != tc.want {
			t.Errorf("promptChoice(input=%q) = %q, want %q", tc.input, res, tc.want)
		}
	}
}

func TestPromptYN(t *testing.T) {
	cases := []struct {
		input      string
		defaultYes bool
		want       bool
	}{
		{"y\n", false, true},
		{"n\n", true, false},
		{"\n", true, true},   // empty → default (yes)
		{"\n", false, false}, // empty → default (no)
		{"yes\n", false, true},
		{"no\n", true, false},
	}
	for _, tc := range cases {
		setStdin(t, tc.input)
		var res bool
		captureStdout(t, func() { res = promptYN("Sure?", tc.defaultYes) })
		if res != tc.want {
			t.Errorf("promptYN(input=%q, defaultYes=%v) = %v, want %v", tc.input, tc.defaultYes, res, tc.want)
		}
	}
}

func TestStdin(t *testing.T) {
	// After setting stdinReader, stdin() returns that exact reader.
	r := bufio.NewReader(strings.NewReader("data\n"))
	stdinReader = r
	t.Cleanup(func() { stdinReader = nil })
	got := stdin()
	if got == nil {
		t.Fatal("stdin() returned nil")
	}
	if got != r {
		t.Errorf("stdin() returned a different reader than the one set")
	}
}
