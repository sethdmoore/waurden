package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Providers: anthropic, openai (+ base_url for Ollama/OpenRouter/any compat endpoint), static.
// Gemini users: set provider="openai", base_url="https://generativelanguage.googleapis.com/v1beta/openai".
// Ollama users: set provider="openai", base_url="http://localhost:11434/v1".
// "static" (alias "mock") runs heuristics only — no LLM, no network calls.
func callProvider(cfg Config, systemPrompt, userContent string) (string, error) {
	switch cfg.Provider {
	case "anthropic":
		return callAnthropic(cfg, systemPrompt, userContent)
	case "openai":
		return callOpenAI(cfg, systemPrompt, userContent)
	case "static", "mock":
		return callMock(cfg, userContent)
	default:
		return "", fmt.Errorf("unknown provider %q (valid: anthropic, openai, static)", cfg.Provider)
	}
}

// providerLabel renders the active backend for the scan/gate report. The
// OpenAI-compatible path (provider="openai") fronts many services via base_url —
// OpenRouter, Ollama, Gemini, a local server — so "openai" alone is misleading.
// Infer the service from the base_url host and append the model, e.g.
// "openrouter: deepseek/deepseek-chat".
func providerLabel(cfg Config) string {
	if scanMode(cfg) == scanModeHeuristics {
		return "static (heuristics, no LLM)"
	}
	switch cfg.Provider {
	case "static", "mock":
		return "static (heuristics)"
	}
	service := cfg.Provider
	if cfg.BaseURL != "" {
		service = serviceFromBaseURL(cfg.BaseURL)
	}
	if cfg.Model != "" {
		return service + ": " + cfg.Model
	}
	return service
}

// serviceFromBaseURL maps a base_url to a friendly service name for display.
// Known hosts get a recognizable label; anything else falls back to the host
// itself (including port, e.g. "localhost:11434") so the user can still tell
// what they hit.
func serviceFromBaseURL(baseURL string) string {
	host := baseURL
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		host = u.Host
	}
	h := strings.ToLower(host)
	switch {
	case strings.Contains(h, "openrouter.ai"):
		return "openrouter"
	case strings.Contains(h, "generativelanguage.googleapis.com"):
		return "gemini"
	case strings.Contains(h, "api.openai.com"):
		return "openai"
	case strings.Contains(h, "api.anthropic.com"):
		return "anthropic"
	default:
		return host
	}
}

func httpClient(cfg Config) *http.Client {
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	return &http.Client{Timeout: timeout}
}

func postJSON(client *http.Client, url string, headers map[string]string, body interface{}) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	// Rate limits (429) and temporary unavailability (503) are transient — common
	// on free/shared endpoints like OpenRouter's :free models. Retry a few times,
	// honoring the provider's Retry-After, before surfacing an error.
	const maxAttempts = 3
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequest("POST", url, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode < 400 {
			return respBody, nil
		}
		if (resp.StatusCode == 429 || resp.StatusCode == 503) && attempt < maxAttempts {
			wait := retryAfter(resp.Header.Get("Retry-After"))
			fmt.Fprintf(os.Stderr, "wAURden: provider rate-limited (HTTP %d), retrying in %s (attempt %d/%d)\n",
				resp.StatusCode, wait, attempt, maxAttempts)
			time.Sleep(wait)
			continue
		}
		return nil, httpError(resp.StatusCode, respBody)
	}
}

// retryAfter derives a sleep duration from the Retry-After header, falling back
// to a short default and capping the wait so a build gate never stalls for long.
func retryAfter(header string) time.Duration {
	const fallback = 3 * time.Second
	const maxWait = 20 * time.Second
	if secs, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && secs >= 0 {
		d := time.Duration(secs) * time.Second
		if d > maxWait {
			return maxWait
		}
		return d
	}
	return fallback
}

// httpError condenses a provider error response to a single readable line,
// extracting the human-readable message and discarding the raw JSON blob
// (which can carry account identifiers and other noise).
func httpError(status int, body []byte) error {
	var parsed struct {
		Error struct {
			Message  string `json:"message"`
			Metadata struct {
				Raw string `json:"raw"`
			} `json:"metadata"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		// metadata.raw is usually the most specific (e.g. which upstream provider
		// rate-limited and for how long); prefer it over the generic message.
		if msg := parsed.Error.Metadata.Raw; msg != "" {
			return fmt.Errorf("HTTP %d: %s", status, msg)
		}
		if msg := parsed.Error.Message; msg != "" {
			return fmt.Errorf("HTTP %d: %s", status, msg)
		}
	}
	// Fallback: collapse whitespace and truncate so we never dump a full blob.
	s := strings.Join(strings.Fields(string(body)), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	if s == "" {
		return fmt.Errorf("HTTP %d", status)
	}
	return fmt.Errorf("HTTP %d: %s", status, s)
}

func resolveAPIKey(cfg Config) (string, error) {
	if cfg.APIKey != "" {
		return cfg.APIKey, nil
	}
	if cfg.APIKeyEnv != "" {
		if v := os.Getenv(cfg.APIKeyEnv); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("api_key not set in config and env var %q is empty", cfg.APIKeyEnv)
	}
	return "", fmt.Errorf("no api_key in config and no api_key_env specified")
}

func callAnthropic(cfg Config, systemPrompt, userContent string) (string, error) {
	apiKey, err := resolveAPIKey(cfg)
	if err != nil {
		return "", err
	}
	base := "https://api.anthropic.com"
	if cfg.BaseURL != "" {
		base = cfg.BaseURL
	}
	url := base + "/v1/messages"

	model := cfg.Model
	if model == "" {
		model = "claude-haiku-4-5"
	}

	body := map[string]interface{}{
		"model":      model,
		"max_tokens": 4096,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": userContent},
		},
	}

	headers := map[string]string{
		"x-api-key":         apiKey,
		"anthropic-version": "2023-06-01",
	}

	respBody, err := postJSON(httpClient(cfg), url, headers, body)
	if err != nil {
		return "", err
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse anthropic response: %w", err)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty anthropic response")
	}
	return result.Content[0].Text, nil
}

func callOpenAI(cfg Config, systemPrompt, userContent string) (string, error) {
	apiKey, err := resolveAPIKey(cfg)
	if err != nil {
		return "", err
	}
	base := "https://api.openai.com/v1"
	if cfg.BaseURL != "" {
		base = cfg.BaseURL
	}
	url := base + "/chat/completions"

	model := cfg.Model
	if model == "" {
		model = "gpt-4o-mini"
	}

	body := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userContent},
		},
	}

	headers := map[string]string{
		"Authorization": "Bearer " + apiKey,
	}

	respBody, err := postJSON(httpClient(cfg), url, headers, body)
	if err != nil {
		return "", err
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse openai response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty openai response")
	}
	return result.Choices[0].Message.Content, nil
}

func callMock(cfg Config, userContent string) (string, error) {
	// The mock provider stands in for the LLM. It must scan the *package* payload,
	// not the fully-assembled prompt: the prompt carries wAURden's own <pkgbuild>
	// wrapper tags and <heuristic_notes> block, and re-scanning those would false-
	// match the injection detector (our own delimiters) and the malware patterns
	// (the note text quotes flagged lines). Injection detection is the pre-filter's
	// job (heuristicCheck runs on raw content before we ever get here); the mock,
	// like a real LLM, only judges the code itself for malware patterns.
	block, advisory := splitVerdict(scanPatterns(mockPayload(userContent), "PKGBUILD"))
	var v *Verdict
	switch {
	case block != nil:
		v = block
	case len(advisory) > 0:
		v = &Verdict{
			Verdict:        "suspicious",
			Confidence:     0.6,
			Summary:        "Mock heuristics flagged patterns worth review; no hard-block pattern matched.",
			Findings:       advisory,
			SourceAnalyzed: "pkgbuild-only",
		}
	default:
		v = &Verdict{
			Verdict:        "ok",
			Confidence:     0.85,
			Summary:        "No suspicious patterns detected by mock heuristics.",
			Findings:       []Finding{},
			SourceAnalyzed: "pkgbuild-only",
		}
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// mockPayload extracts the untrusted package sections (<pkgbuild>, <diff>,
// <helper_files>) from the assembled prompt, dropping wAURden's own framing and
// the trusted <heuristic_notes> block, so the mock provider scans package code
// rather than the scanner's wrapper. Falls back to the whole string if no wrapper
// tags are present (e.g. a caller that passed raw content).
func mockPayload(userContent string) string {
	var b strings.Builder
	for _, tag := range []string{"pkgbuild", "diff", "helper_files"} {
		open, closing := "<"+tag+">", "</"+tag+">"
		s := strings.Index(userContent, open)
		e := strings.Index(userContent, closing)
		if s >= 0 && e > s {
			b.WriteString(userContent[s+len(open) : e])
			b.WriteByte('\n')
		}
	}
	if b.Len() == 0 {
		return userContent
	}
	return b.String()
}
