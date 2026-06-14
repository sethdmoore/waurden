package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
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
	v := heuristicCheck(userContent)
	if v == nil {
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
