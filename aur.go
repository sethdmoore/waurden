package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type AURInfo struct {
	Maintainer     *string
	LastModified   int64
	MaintainerInfo *MaintainerInfo
}

type MaintainerInfo struct {
	Username     string
	AccountType  string
	Status       string
	RegisteredAt time.Time
	LastLogin    time.Time
}

func fetchAURInfo(pkgbase string, timeout int) AURInfo {
	var info AURInfo
	if pkgbase == "" || pkgbase == "unknown" {
		return info
	}
	if timeout <= 0 {
		timeout = 10
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	rpcURL := "https://aur.archlinux.org/rpc/v5/info?arg[]=" + url.QueryEscape(pkgbase)
	resp, err := client.Get(rpcURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: AUR RPC unavailable: %v\n", err)
		return info
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wAURden: AUR RPC read error: %v\n", err)
		return info
	}

	var rpcResp struct {
		Results []struct {
			Maintainer   *string `json:"Maintainer"`
			LastModified int64   `json:"LastModified"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil || len(rpcResp.Results) == 0 {
		return info
	}

	result := rpcResp.Results[0]
	info.Maintainer = result.Maintainer
	info.LastModified = result.LastModified

	if info.Maintainer != nil {
		info.MaintainerInfo = fetchMaintainerInfo(client, *info.Maintainer)
	}
	return info
}

func fetchMaintainerInfo(client *http.Client, username string) *MaintainerInfo {
	profileURL := "https://aur.archlinux.org/account/" + url.PathEscape(username)
	resp, err := client.Get(profileURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return parseMaintainerHTML(string(body), username)
}

func parseMaintainerHTML(html, username string) *MaintainerInfo {
	mi := &MaintainerInfo{Username: username}
	for _, row := range strings.Split(html, "</tr>") {
		th := extractTag(row, "th")
		td := extractTag(row, "td")
		if th == "" || td == "" {
			continue
		}
		switch strings.TrimSpace(th) {
		case "Account Type:":
			mi.AccountType = strings.TrimSpace(td)
		case "Status:":
			mi.Status = strings.TrimSpace(td)
		case "Registration date:":
			if t, err := time.Parse("2006-01-02 (UTC)", strings.TrimSpace(td)); err == nil {
				mi.RegisteredAt = t
			}
		case "Last Login:":
			if t, err := time.Parse("2006-01-02 (UTC)", strings.TrimSpace(td)); err == nil {
				mi.LastLogin = t
			}
		}
	}
	return mi
}

func extractTag(s, tag string) string {
	lower := strings.ToLower(s)
	open := "<" + tag
	closeTag := "</" + tag + ">"

	start := strings.Index(lower, open)
	if start < 0 {
		return ""
	}
	end := strings.Index(lower[start:], ">")
	if end < 0 {
		return ""
	}
	content := s[start+end+1:]
	closeIdx := strings.Index(strings.ToLower(content), closeTag)
	if closeIdx < 0 {
		return ""
	}
	return innerText(content[:closeIdx])
}

func innerText(s string) string {
	var sb strings.Builder
	inTag := false
	for _, c := range s {
		switch {
		case c == '<':
			inTag = true
		case c == '>':
			inTag = false
		case !inTag:
			sb.WriteRune(c)
		}
	}
	return strings.TrimSpace(sb.String())
}

// printAURWarnings emits orphan / new-account / inactive-account warnings from
// AUR metadata. Maintainer-change detection has been removed in favour of git
// committer tracking (see trackNewCommitters), which avoids the false positives
// caused by legitimate co-maintainers temporarily holding the primary slot.
func printAURWarnings(pkgname string, info AURInfo) {
	if info.LastModified == 0 {
		// No AUR data — network failure or package not in AUR; skip warnings.
		return
	}

	if info.Maintainer == nil {
		fmt.Fprintf(os.Stderr, "wAURden WARNING: %s is an ORPHAN PACKAGE (no maintainer).\n", pkgname)
		return
	}

	maintainer := *info.Maintainer

	if mi := info.MaintainerInfo; mi != nil {
		if !mi.RegisteredAt.IsZero() {
			age := time.Since(mi.RegisteredAt)
			if age < 30*24*time.Hour {
				days := int(age.Hours() / 24)
				fmt.Fprintf(os.Stderr, "wAURden WARNING: maintainer %q registered %d days ago (%s).\n",
					maintainer, days, mi.RegisteredAt.Format("2006-01-02"))
			}
		}
		if strings.EqualFold(mi.Status, "Inactive") {
			fmt.Fprintf(os.Stderr, "wAURden WARNING: maintainer %q account status is Inactive.\n", maintainer)
		}
	}
}
