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
func callProvider(cfg Config, systemPrompt, userContent string) (string, TokenUsage, error) {
	switch cfg.Provider {
	case "anthropic":
		return callAnthropic(cfg, systemPrompt, userContent)
	case "openai":
		return callOpenAI(cfg, systemPrompt, userContent)
	case "static", "mock":
		// The static engine runs local heuristics — no network, no tokens.
		content, err := callMock(cfg, userContent)
		return content, TokenUsage{}, err
	default:
		return "", TokenUsage{}, fmt.Errorf("unknown provider %q (valid: anthropic, openai, static)", cfg.Provider)
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

// transientError marks a provider failure that is worth a fresh attempt from the
// top: a transport error (timeout, connection reset, EOF mid-body) or an HTTP 200
// whose body carried no usable completion (empty choices, empty content). analyze()
// retries these; errors NOT wrapped in it — a config problem (missing API key), an
// unknown provider, or an HTTP status postJSON already retried to exhaustion — are
// surfaced immediately, so the retry budget is never spent on a deterministic failure.
type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

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

	// Rate limits (429), temporary unavailability (503), and gateway flakes
	// (500/502/504) are transient — common on free/shared endpoints like
	// OpenRouter's :free models, and on Bedrock under concurrent gate bursts.
	// Retry a few times, honoring the provider's Retry-After, before surfacing
	// an error. Transport errors (timeout, reset, EOF mid-body) are returned as
	// transientError so the caller's outer retry loop gets them instead — they
	// need a fresh connection, not a Retry-After sleep.
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
			return nil, &transientError{err}
		}
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, &transientError{readErr}
		}
		if resp.StatusCode < 400 {
			return respBody, nil
		}
		if retryableStatus(resp.StatusCode) && attempt < maxAttempts {
			wait := retryAfter(resp.Header.Get("Retry-After"))
			fmt.Fprintf(os.Stderr, "wAURden: transient provider error (HTTP %d), retrying in %s (attempt %d/%d)\n",
				resp.StatusCode, wait, attempt, maxAttempts)
			time.Sleep(wait)
			continue
		}
		return nil, httpError(resp.StatusCode, respBody)
	}
}

// retryableStatus reports whether an HTTP status is worth an in-place retry:
// rate limits and transient server/gateway failures. 4xx client errors (bad key,
// bad model name) are deterministic and never retried.
func retryableStatus(code int) bool {
	switch code {
	case 429, 500, 502, 503, 504:
		return true
	}
	return false
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

func callAnthropic(cfg Config, systemPrompt, userContent string) (string, TokenUsage, error) {
	apiKey, err := resolveAPIKey(cfg)
	if err != nil {
		return "", TokenUsage{}, err
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
		return "", TokenUsage{}, err
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", TokenUsage{}, &transientError{fmt.Errorf("parse anthropic response: %w", err)}
	}
	if len(result.Content) == 0 {
		return "", TokenUsage{}, &transientError{fmt.Errorf("empty anthropic response")}
	}
	text := result.Content[0].Text
	if strings.TrimSpace(text) == "" {
		// HTTP 200 with a blank completion — seen as provider flake under load.
		return "", TokenUsage{}, &transientError{fmt.Errorf("empty content in anthropic response")}
	}
	usage := usageOrEstimate(result.Usage.InputTokens, result.Usage.OutputTokens, systemPrompt+userContent, text)
	return text, usage, nil
}

func callOpenAI(cfg Config, systemPrompt, userContent string) (string, TokenUsage, error) {
	apiKey, err := resolveAPIKey(cfg)
	if err != nil {
		return "", TokenUsage{}, err
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
		return "", TokenUsage{}, err
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", TokenUsage{}, &transientError{fmt.Errorf("parse openai response: %w", err)}
	}
	if len(result.Choices) == 0 {
		return "", TokenUsage{}, &transientError{fmt.Errorf("empty openai response")}
	}
	content := result.Choices[0].Message.Content
	if strings.TrimSpace(content) == "" {
		// HTTP 200, choices present, but a blank completion — the exact failure
		// seen from OpenRouter/Bedrock under a concurrent gate burst. Previously
		// this was returned as success and died later in parseVerdict with "no
		// JSON object found in response", which is not retried the same way.
		return "", TokenUsage{}, &transientError{fmt.Errorf("empty content in openai response")}
	}
	usage := usageOrEstimate(result.Usage.PromptTokens, result.Usage.CompletionTokens, systemPrompt+userContent, content)
	return content, usage, nil
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
