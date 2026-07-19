package main

// Tests for aur.go: HTML parsing helpers, AUR account-page parsing, warning
// emission, and the deterministic (no-network) branches of fetchAURInfo.
//
// NOTE: fetchMaintainerInfo is a thin network wrapper — it does a GET against a
// hardcoded https://aur.archlinux.org/account/<user> URL and hands the response
// body to parseMaintainerHTML. Its host is not injectable, so it cannot be
// exercised against an httptest server without a live network. Its entire
// non-network logic lives in parseMaintainerHTML, which is fully tested below,
// so no direct test is written for fetchMaintainerInfo.

import (
	"strings"
	"testing"
	"time"
)

func TestInnerText(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"simple bold", "<b>Active</b>", "Active"},
		{"anchor with attr", `<a href=x>User</a>`, "User"},
		{"leading/trailing space stripped", "  spaced  ", "spaced"},
		{"plain passthrough", "just text", "just text"},
		{"multiple tags", "<span><i>Trusted User</i></span>", "Trusted User"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := innerText(tc.in); got != tc.want {
				t.Fatalf("innerText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestExtractTag(t *testing.T) {
	row := `<tr><th>Account Type:</th><td>Trusted User</td></tr>`

	if got := extractTag(row, "th"); got != "Account Type:" {
		t.Fatalf("extractTag(row,\"th\") = %q, want %q", got, "Account Type:")
	}
	if got := extractTag(row, "td"); got != "Trusted User" {
		t.Fatalf("extractTag(row,\"td\") = %q, want %q", got, "Trusted User")
	}
	// Missing tag → "".
	if got := extractTag(row, "span"); got != "" {
		t.Fatalf("extractTag(row,\"span\") = %q, want empty", got)
	}
	// Case-insensitive matching of the tag name.
	upper := `<TR><TH>Status:</TH><TD>Active</TD></TR>`
	if got := extractTag(upper, "th"); got != "Status:" {
		t.Fatalf("extractTag(UPPER,\"th\") = %q, want %q", got, "Status:")
	}
	if got := extractTag(upper, "td"); got != "Active" {
		t.Fatalf("extractTag(UPPER,\"td\") = %q, want %q", got, "Active")
	}
	// Attributes on the opening tag are skipped up to '>'.
	withAttr := `<td class="foo" id="bar">Developer</td>`
	if got := extractTag(withAttr, "td"); got != "Developer" {
		t.Fatalf("extractTag(withAttr,\"td\") = %q, want %q", got, "Developer")
	}
	// No closing tag → "".
	if got := extractTag("<td>unterminated", "td"); got != "" {
		t.Fatalf("extractTag(unterminated) = %q, want empty", got)
	}
}

// realisticAccountHTML builds an AUR-style account page. The account page renders
// its bio table with <tr><th>Label:</th><td>value</td></tr> rows; parseMaintainerHTML
// splits on </tr> and pulls the th/td from each fragment.
func realisticAccountHTML(regDate, lastLogin string) string {
	return `<!DOCTYPE html>
<html>
<body>
<h2>Account eve</h2>
<table class="results">
  <tr><th>Username:</th><td>eve</td></tr>
  <tr><th>Account Type:</th><td>Trusted User</td></tr>
  <tr><th>Status:</th><td>Active</td></tr>
  <tr><th>Registration date:</th><td>` + regDate + `</td></tr>
  <tr><th>Last Login:</th><td>` + lastLogin + `</td></tr>
</table>
</body>
</html>`
}

func TestParseMaintainerHTML(t *testing.T) {
	html := realisticAccountHTML("2019-04-11 (UTC)", "2026-06-14 (UTC)")

	mi := parseMaintainerHTML(html, "eve")
	if mi == nil {
		t.Fatal("parseMaintainerHTML returned nil")
	}
	if mi.Username != "eve" {
		t.Fatalf("Username = %q, want %q", mi.Username, "eve")
	}
	if mi.AccountType != "Trusted User" {
		t.Fatalf("AccountType = %q, want %q", mi.AccountType, "Trusted User")
	}
	if mi.Status != "Active" {
		t.Fatalf("Status = %q, want %q", mi.Status, "Active")
	}

	wantReg := time.Date(2019, time.April, 11, 0, 0, 0, 0, time.UTC)
	if !mi.RegisteredAt.Equal(wantReg) {
		t.Fatalf("RegisteredAt = %v, want %v", mi.RegisteredAt, wantReg)
	}
	if mi.RegisteredAt.Year() != 2019 || mi.RegisteredAt.Month() != time.April || mi.RegisteredAt.Day() != 11 {
		t.Fatalf("RegisteredAt Y/M/D = %d/%d/%d, want 2019/4/11",
			mi.RegisteredAt.Year(), mi.RegisteredAt.Month(), mi.RegisteredAt.Day())
	}

	wantLogin := time.Date(2026, time.June, 14, 0, 0, 0, 0, time.UTC)
	if !mi.LastLogin.Equal(wantLogin) {
		t.Fatalf("LastLogin = %v, want %v", mi.LastLogin, wantLogin)
	}
}

func TestParseMaintainerHTML_MissingDateRows(t *testing.T) {
	// A page with type/status but no date rows: RegisteredAt and LastLogin must
	// stay zero (the time.Parse never runs / never assigns).
	html := `<table class="results">
  <tr><th>Account Type:</th><td>User</td></tr>
  <tr><th>Status:</th><td>Active</td></tr>
</table>`
	mi := parseMaintainerHTML(html, "bob")
	if mi == nil {
		t.Fatal("parseMaintainerHTML returned nil")
	}
	if mi.AccountType != "User" {
		t.Fatalf("AccountType = %q, want %q", mi.AccountType, "User")
	}
	if mi.Status != "Active" {
		t.Fatalf("Status = %q, want %q", mi.Status, "Active")
	}
	if !mi.RegisteredAt.IsZero() {
		t.Fatalf("RegisteredAt = %v, want zero", mi.RegisteredAt)
	}
	if !mi.LastLogin.IsZero() {
		t.Fatalf("LastLogin = %v, want zero", mi.LastLogin)
	}
}

func TestParseMaintainerHTML_MalformedDateStaysZero(t *testing.T) {
	// A registration date that doesn't match "2006-01-02 (UTC)" fails time.Parse
	// and leaves RegisteredAt zero, while the other fields still parse.
	html := `<table class="results">
  <tr><th>Account Type:</th><td>Developer</td></tr>
  <tr><th>Registration date:</th><td>unknown</td></tr>
</table>`
	mi := parseMaintainerHTML(html, "carol")
	if mi.AccountType != "Developer" {
		t.Fatalf("AccountType = %q, want %q", mi.AccountType, "Developer")
	}
	if !mi.RegisteredAt.IsZero() {
		t.Fatalf("RegisteredAt = %v, want zero (malformed date)", mi.RegisteredAt)
	}
}

// strptr is a small local helper so the *string Maintainer field can be built
// inline from a literal.
func strptr(s string) *string { return &s }

func TestPrintAURWarnings_NoData(t *testing.T) {
	// LastModified == 0 means no AUR data (network failure or not in AUR) → silent.
	out := captureStderr(t, func() {
		printAURWarnings("foo", AURInfo{LastModified: 0})
	})
	if out != "" {
		t.Fatalf("expected no output for zero LastModified, got %q", out)
	}
}

func TestPrintAURWarnings_Orphan(t *testing.T) {
	// LastModified set + nil Maintainer → orphan warning.
	out := captureStderr(t, func() {
		printAURWarnings("orphan-pkg", AURInfo{LastModified: 1700000000, Maintainer: nil})
	})
	if !strings.Contains(out, "ORPHAN PACKAGE") {
		t.Fatalf("expected ORPHAN PACKAGE warning, got %q", out)
	}
	if !strings.Contains(out, "orphan-pkg") {
		t.Fatalf("expected package name in output, got %q", out)
	}
}

func TestPrintAURWarnings_NewMaintainer(t *testing.T) {
	// Registered 3 days + 1 hour ago → int(age.Hours()/24) == 3, no rounding ambiguity.
	reg := time.Now().Add(-(3*24 + 1) * time.Hour)
	info := AURInfo{
		LastModified: 1700000000,
		Maintainer:   strptr("alice"),
		MaintainerInfo: &MaintainerInfo{
			Username:     "alice",
			Status:       "Active",
			RegisteredAt: reg,
		},
	}
	out := captureStderr(t, func() { printAURWarnings("newpkg", info) })

	if !strings.Contains(out, "registered") {
		t.Fatalf("expected 'registered' in output, got %q", out)
	}
	if !strings.Contains(out, "3 days ago") {
		t.Fatalf("expected '3 days ago' in output, got %q", out)
	}
	if !strings.Contains(out, "alice") {
		t.Fatalf("expected maintainer name 'alice' in output, got %q", out)
	}
}

func TestPrintAURWarnings_Inactive(t *testing.T) {
	// Old registration (2 years) + Inactive status → Inactive warning, and NOT a
	// "registered N days ago" line (account is well past the 30-day threshold).
	reg := time.Now().Add(-2 * 365 * 24 * time.Hour)
	info := AURInfo{
		LastModified: 1700000000,
		Maintainer:   strptr("eve"),
		MaintainerInfo: &MaintainerInfo{
			Username:     "eve",
			Status:       "Inactive",
			RegisteredAt: reg,
		},
	}
	out := captureStderr(t, func() { printAURWarnings("inactivepkg", info) })

	if !strings.Contains(out, "Inactive") {
		t.Fatalf("expected 'Inactive' in output, got %q", out)
	}
	if strings.Contains(out, "registered") {
		t.Fatalf("did not expect 'registered' for an old account, got %q", out)
	}
	if !strings.Contains(out, "eve") {
		t.Fatalf("expected maintainer name 'eve' in output, got %q", out)
	}
}

func TestPrintAURWarnings_EstablishedActive_NoWarning(t *testing.T) {
	// Registered > 30 days ago and Active → no warning lines at all.
	reg := time.Now().Add(-90 * 24 * time.Hour)
	info := AURInfo{
		LastModified: 1700000000,
		Maintainer:   strptr("trusted"),
		MaintainerInfo: &MaintainerInfo{
			Username:     "trusted",
			Status:       "Active",
			RegisteredAt: reg,
		},
	}
	out := captureStderr(t, func() { printAURWarnings("goodpkg", info) })

	if strings.Contains(out, "WARNING") {
		t.Fatalf("expected no WARNING for established active maintainer, got %q", out)
	}
	if out != "" {
		t.Fatalf("expected empty output, got %q", out)
	}
}

func TestFetchAURInfo_NoNetworkPaths(t *testing.T) {
	// Both "" and "unknown" short-circuit before any HTTP call and return a zero
	// AURInfo. These are the only deterministic, network-free branches.
	for _, pkgbase := range []string{"", "unknown"} {
		info := fetchAURInfo(pkgbase, 5)
		if info.Maintainer != nil {
			t.Fatalf("fetchAURInfo(%q): Maintainer = %v, want nil", pkgbase, *info.Maintainer)
		}
		if info.LastModified != 0 {
			t.Fatalf("fetchAURInfo(%q): LastModified = %d, want 0", pkgbase, info.LastModified)
		}
		if info.MaintainerInfo != nil {
			t.Fatalf("fetchAURInfo(%q): MaintainerInfo = %+v, want nil", pkgbase, info.MaintainerInfo)
		}
	}
}
