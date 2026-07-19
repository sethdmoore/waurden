package main

// Tests for aurPackageBases (aur.go), driven against an httptest server via the
// aurRPCInfoURL seam so no live AUR call is made.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func withAURRPC(t *testing.T, url string) {
	t.Helper()
	old := aurRPCInfoURL
	aurRPCInfoURL = url
	t.Cleanup(func() { aurRPCInfoURL = old })
}

func TestAURPackageBases_Success(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		io.WriteString(w, `{"resultcount":2,"results":[
			{"Name":"libaur","PackageBase":"libaur"},
			{"Name":"tool","PackageBase":"tool-suite"}
		]}`)
	}))
	defer srv.Close()
	withAURRPC(t, srv.URL)

	bases, ok := aurPackageBases([]string{"libaur", "tool", "ghost"}, 5)
	if !ok {
		t.Fatal("ok = false, want true on a successful call")
	}
	if bases["libaur"] != "libaur" || bases["tool"] != "tool-suite" {
		t.Errorf("bases = %v, want libaur→libaur, tool→tool-suite", bases)
	}
	if _, present := bases["ghost"]; present {
		t.Error("a name absent from the results must not appear in the map")
	}
	// All three names were sent as arg[] params.
	for _, n := range []string{"libaur", "tool", "ghost"} {
		if !strings.Contains(gotQuery, "arg%5B%5D="+n) && !strings.Contains(gotQuery, "arg[]="+n) {
			t.Errorf("query %q missing arg for %q", gotQuery, n)
		}
	}
}

func TestAURPackageBases_Empty(t *testing.T) {
	// No names → no HTTP call, empty map, ok true.
	bases, ok := aurPackageBases(nil, 5)
	if !ok || len(bases) != 0 {
		t.Errorf("aurPackageBases(nil) = %v, %v; want empty map, true", bases, ok)
	}
}

func TestAURPackageBases_TransportError(t *testing.T) {
	// Point at a closed server → the call fails → ok=false (so the resolver falls
	// back to clone-by-name rather than dropping the dep).
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now refusing connections
	withAURRPC(t, url)

	_, ok := aurPackageBases([]string{"x"}, 2)
	if ok {
		t.Error("ok = true on a transport error, want false")
	}
}

func TestAURPackageBases_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "not json")
	}))
	defer srv.Close()
	withAURRPC(t, srv.URL)

	_, ok := aurPackageBases([]string{"x"}, 5)
	if ok {
		t.Error("ok = true on unparseable JSON, want false")
	}
}
