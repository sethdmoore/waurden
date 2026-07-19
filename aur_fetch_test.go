package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rewriteTransport redirects every outbound request to base (an httptest server),
// preserving the original path. This lets us drive fetchMaintainerInfo — whose
// aur.archlinux.org host is hardcoded — against a local server, exercising the
// real HTTP fetch + body read + parseMaintainerHTML wiring without live network.
type rewriteTransport struct {
	base string // e.g. http://127.0.0.1:PORT
}

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := rt.base + req.URL.Path
	proxied, err := http.NewRequest(req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	proxied.Header = req.Header
	return http.DefaultTransport.RoundTrip(proxied)
}

func TestFetchMaintainerInfo(t *testing.T) {
	// A realistic AUR account page for the requested user.
	const page = `<html><body>
<table class="results">
<tr><th>Username:</th><td>arojas</td></tr>
<tr><th>Account Type:</th><td>Developer</td></tr>
<tr><th>Status:</th><td>Active</td></tr>
<tr><th>Registration date:</th><td>2012-03-14 (UTC)</td></tr>
<tr><th>Last Login:</th><td>2026-06-30 (UTC)</td></tr>
</table></body></html>`

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		io.WriteString(w, page)
	}))
	defer srv.Close()

	client := &http.Client{Transport: rewriteTransport{base: srv.URL}}
	mi := fetchMaintainerInfo(client, "arojas")
	if mi == nil {
		t.Fatal("fetchMaintainerInfo returned nil")
	}
	// The correct account path was requested (url.PathEscape of the username).
	if gotPath != "/account/arojas" {
		t.Errorf("requested path = %q, want /account/arojas", gotPath)
	}
	if mi.Username != "arojas" || mi.AccountType != "Developer" || mi.Status != "Active" {
		t.Errorf("parsed maintainer = %+v", mi)
	}
	if mi.RegisteredAt.Year() != 2012 || mi.RegisteredAt.Month() != 3 || mi.RegisteredAt.Day() != 14 {
		t.Errorf("RegisteredAt = %v, want 2012-03-14", mi.RegisteredAt)
	}
	if mi.LastLogin.Year() != 2026 {
		t.Errorf("LastLogin = %v, want 2026", mi.LastLogin)
	}
}

func TestFetchMaintainerInfoTransportError(t *testing.T) {
	// A client whose transport always fails → fetchMaintainerInfo returns nil, no panic.
	client := &http.Client{Transport: errTransport{}}
	if mi := fetchMaintainerInfo(client, "whoever"); mi != nil {
		t.Errorf("expected nil on transport error, got %+v", mi)
	}
}

type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}
