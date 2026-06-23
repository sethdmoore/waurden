package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runConfigureCmd() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "wAURden: cannot determine home directory")
		os.Exit(1)
	}

	configPath := filepath.Join(home, ".config", "waurden", "config.toml")

	fmt.Println("wAURden configuration wizard")
	fmt.Println()

	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config file already exists: %s\n", configPath)
		if !promptYN("Overwrite it?", false) {
			fmt.Println("Aborted.")
			return
		}
		fmt.Println()
	}

	fmt.Println("wAURden needs an LLM provider to analyze PKGBUILDs.")
	fmt.Println("Choose a provider:")
	fmt.Println("  1) OpenRouter       — one API key, hundreds of models (recommended)")
	fmt.Println("  2) Ollama           — local models, free, no API key needed")
	fmt.Println("  3) Anthropic Claude — if you have an Anthropic API key")
	fmt.Println("  4) OpenAI           — if you have an OpenAI API key")
	fmt.Println("  5) Other OpenAI-compatible endpoint (Gemini, LM Studio, etc.)")
	fmt.Println("  6) Static           — heuristics only, no LLM, no API key needed")
	fmt.Println()

	choice := promptChoice("Provider", []string{"1", "2", "3", "4", "5", "6"}, "1")

	var provider, model, baseURL, apiKey string

	switch choice {
	case "1":
		provider = "openai"
		baseURL = "https://openrouter.ai/api/v1"
		fmt.Println()
		fmt.Println("OpenRouter gives you access to Claude, GPT, Llama, Mistral and more")
		fmt.Println("through a single API key. Free-tier models are available at no cost.")
		fmt.Println()
		fmt.Println("Get your API key at: https://openrouter.ai/keys")
		fmt.Println()
		fmt.Println("Suggested models:")
		fmt.Println("  meta-llama/llama-3.3-70b-instruct:free  (free, strong)")
		fmt.Println("  anthropic/claude-haiku-4-5               (cheap, fast)")
		fmt.Println("  google/gemini-flash-1.5                  (cheap, fast)")
		model = promptString("Model", "meta-llama/llama-3.3-70b-instruct:free")
		fmt.Println()
		apiKey = promptSecret("OpenRouter API key")
	case "2":
		provider = "openai"
		baseURL = "http://localhost:11434/v1"
		fmt.Println()
		fmt.Println("Ollama runs models locally — no API key, no cost, fully private.")
		fmt.Println("Make sure Ollama is running: ollama serve")
		fmt.Println()
		fmt.Println("Suggested models (pull first with 'ollama pull <model>'):")
		fmt.Println("  llama3.2   mistral   gemma3")
		model = promptString("Model", "llama3.2")
		apiKey = ""
	case "3":
		provider = "anthropic"
		model = promptString("Model", "claude-haiku-4-5")
		fmt.Println()
		fmt.Println("Get your API key at: https://console.anthropic.com/settings/keys")
		apiKey = promptSecret("Anthropic API key")
	case "4":
		provider = "openai"
		model = promptString("Model", "gpt-4o-mini")
		fmt.Println()
		fmt.Println("Get your API key at: https://platform.openai.com/api-keys")
		apiKey = promptSecret("OpenAI API key")
	case "5":
		provider = "openai"
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  Gemini:    https://generativelanguage.googleapis.com/v1beta/openai")
		fmt.Println("  LM Studio: http://localhost:1234/v1")
		baseURL = promptString("Base URL", "")
		model = promptString("Model name", "")
		fmt.Println()
		apiKey = promptSecret("API key (leave blank if none)")
	case "6":
		provider = "static"
		fmt.Println()
		fmt.Println("Static mode: heuristic pattern matching only, no LLM calls.")
		fmt.Println("This catches known-bad patterns (curl|bash, ssh exfiltration, etc.) but")
		fmt.Println("cannot reason about novel or obfuscated attacks. Consider using an LLM")
		fmt.Println("provider for stronger protection.")
	}

	fmt.Println()
	fmt.Println("Policy settings (press Enter to accept defaults):")

	onError := promptChoice(
		"When LLM scan fails: warn (allow build), block (abort build), allow (silent)",
		[]string{"warn", "block", "allow"},
		"warn",
	)

	// Scan mode only matters when an LLM is available; static is heuristics-only
	// by definition, so don't ask.
	scanMode := "full"
	if provider != "static" {
		fmt.Println()
		fmt.Println("Scan mode:")
		fmt.Println("  full       — built-in heuristics first, then the LLM (recommended)")
		fmt.Println("  heuristics — heuristic patterns only, never call the LLM (fast, offline)")
		fmt.Println("  llm        — skip the built-in heuristics, use the LLM only")
		scanMode = promptChoice("Mode", []string{"full", "heuristics", "llm"}, "full")
	}

	fmt.Println()
	fmt.Println("Summary:")
	fmt.Printf("  Provider:    %s\n", provider)
	if model != "" {
		fmt.Printf("  Model:       %s\n", model)
	}
	if baseURL != "" {
		fmt.Printf("  Base URL:    %s\n", baseURL)
	}
	if apiKey != "" {
		fmt.Printf("  API key:     %s (stored in config file, mode 0600)\n", redact(apiKey))
	}
	fmt.Printf("  On error:    %s\n", onError)
	if provider != "static" {
		fmt.Printf("  Scan mode:   %s\n", scanMode)
	}
	fmt.Printf("  Config file: %s\n", configPath)
	fmt.Println()

	if !promptYN("Write this configuration?", true) {
		fmt.Println("Aborted.")
		return
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: cannot create config directory: %v\n", err)
		os.Exit(1)
	}

	content := buildConfigTOML(provider, model, baseURL, apiKey, onError, scanMode)
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: cannot write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Configuration written to %s\n", configPath)
	if provider == "static" {
		fmt.Println("NOTE: static mode uses heuristics only. Run 'waurden configure' again to set up an LLM provider.")
	}
}

func buildConfigTOML(provider, model, baseURL, apiKey, onError, scanMode string) string {
	var sb strings.Builder
	sb.WriteString("# wAURden configuration\n")
	sb.WriteString("# Generated by 'waurden configure'\n")
	sb.WriteString("# Run 'waurden configure' again to change settings.\n\n")

	sb.WriteString("# LLM provider to use for PKGBUILD analysis.\n")
	sb.WriteString("# Values: anthropic, openai, static\n")
	sb.WriteString("#   anthropic — Anthropic Claude API\n")
	sb.WriteString("#   openai    — OpenAI or any OpenAI-compatible endpoint (OpenRouter, Ollama,\n")
	sb.WriteString("#               Gemini, LM Studio, etc.) — set base_url accordingly\n")
	sb.WriteString("#   static    — heuristic pattern matching only, no LLM, no API key needed\n")
	sb.WriteString(fmt.Sprintf("provider = %q\n", provider))

	if model != "" {
		sb.WriteString("\n# Model name (provider-specific).\n")
		sb.WriteString(fmt.Sprintf("model = %q\n", model))
	}

	if baseURL != "" {
		sb.WriteString("\n# Base URL for OpenAI-compatible endpoints.\n")
		sb.WriteString("# Examples:\n")
		sb.WriteString("#   OpenRouter: https://openrouter.ai/api/v1\n")
		sb.WriteString("#   Ollama:     http://localhost:11434/v1\n")
		sb.WriteString("#   Gemini:     https://generativelanguage.googleapis.com/v1beta/openai\n")
		sb.WriteString(fmt.Sprintf("base_url = %q\n", baseURL))
	}

	if apiKey != "" {
		sb.WriteString("\n# API key (stored here; file is mode 0600).\n")
		sb.WriteString("# Alternatively, set api_key_env to the name of an environment variable.\n")
		sb.WriteString(fmt.Sprintf("api_key = %q\n", apiKey))
	}

	if scanMode != "" && scanMode != "full" {
		sb.WriteString("\n# Which analysis engines run.\n")
		sb.WriteString("# full       — built-in heuristics first, then the LLM (default)\n")
		sb.WriteString("# heuristics — heuristic patterns only, never call the LLM (fast, offline)\n")
		sb.WriteString("# llm        — skip the built-in heuristics, use the LLM only\n")
		sb.WriteString(fmt.Sprintf("scan_mode = %q\n", scanMode))
	}

	sb.WriteString("\n# Request timeout in seconds.\n")
	sb.WriteString("timeout_seconds = 60\n")

	sb.WriteString("\n# Verdicts that abort the build (used by 'waurden gate' / the makepkg hook).\n")
	sb.WriteString("# Possible verdict values: ok, suspicious, malicious\n")
	sb.WriteString("block_on = [\"malicious\"]\n")

	sb.WriteString("\n# Verdicts that print a warning but allow the build to continue.\n")
	sb.WriteString("warn_on = [\"suspicious\"]\n")

	sb.WriteString("\n# What to do when the scan itself fails (LLM unreachable, parse error, etc.).\n")
	sb.WriteString("# warn  — allow the build but print a warning (default; recommended)\n")
	sb.WriteString("# block — abort the build on any scan failure (strict / high-security mode)\n")
	sb.WriteString("# allow — silently allow the build on failure\n")
	sb.WriteString(fmt.Sprintf("on_error = %q\n", onError))

	sb.WriteString("\n# On a TTY, prompt the user to override a block verdict before aborting.\n")
	sb.WriteString("# Set to true if you want to manually review and accept flagged packages.\n")
	sb.WriteString("interactive = false\n")

	return sb.String()
}

// redact shows only the first 8 chars of a key with the rest replaced by asterisks.
func redact(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:8] + strings.Repeat("*", len(key)-8)
}

var stdinReader *bufio.Reader

func stdin() *bufio.Reader {
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	return stdinReader
}

func promptString(label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := stdin().ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

// promptSecret reads a value without echoing it if the terminal supports it,
// falling back to plain readline. The key is stored in the config file (mode 0600).
func promptSecret(label string) string {
	fmt.Printf("%s: ", label)
	line, _ := stdin().ReadString('\n')
	return strings.TrimSpace(line)
}

func promptChoice(label string, choices []string, defaultVal string) string {
	fmt.Printf("%s [%s]: ", label, defaultVal)
	for {
		line, _ := stdin().ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return defaultVal
		}
		for _, c := range choices {
			if strings.EqualFold(line, c) {
				return c
			}
		}
		fmt.Printf("Please enter one of %s [%s]: ", strings.Join(choices, "/"), defaultVal)
	}
}

func promptYN(label string, defaultYes bool) bool {
	hint := "y/N"
	if defaultYes {
		hint = "Y/n"
	}
	fmt.Printf("%s [%s]: ", label, hint)
	line, _ := stdin().ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return defaultYes
	}
	return line == "y" || line == "yes"
}
