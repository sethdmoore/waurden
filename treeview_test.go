package main

// Tests for treeview.go: per-node line formatting and the in-place renderer.

import (
	"bytes"
	"strings"
	"testing"
)

func TestNodeRenderLine_Markers(t *testing.T) {
	root := &AURNode{Name: "app", Depth: 0, Status: statusOK,
		Verdict: Verdict{Verdict: "ok", Confidence: 0.98, Summary: "clean"}}
	child := &AURNode{Name: "libapp", Depth: 1, Status: statusPending}

	rl := nodeRenderLine(root)
	if !strings.HasPrefix(rl, "  - app: ") {
		t.Errorf("root line = %q, want it to start with '  - app: '", rl)
	}
	cl := nodeRenderLine(child)
	if !strings.HasPrefix(cl, "   |- libapp: ") {
		t.Errorf("child line = %q, want it to start with '   |- libapp: '", cl)
	}
}

func TestNodeStatusText(t *testing.T) {
	// treeColor off → no ANSI in repo/skipped labels, deterministic assertions.
	treeColor = false
	cases := []struct {
		n    *AURNode
		want string
	}{
		{&AURNode{Status: statusRepo}, "repo"},
		{&AURNode{Status: statusSkipped}, "skipped"},
		{&AURNode{Status: statusPending}, "aur: pending"},
		{&AURNode{Status: statusScanning}, "aur: scanning…"},
		{&AURNode{Status: statusError}, "aur: could not scan"},
		{&AURNode{Status: statusOK, Verdict: Verdict{Verdict: "ok", Confidence: 1.0}}, "aur: OK (1.00)"},
		{&AURNode{Status: statusSuspicious, Verdict: Verdict{Verdict: "suspicious", Confidence: 0.62}}, "aur: SUSPICIOUS (0.62)"},
		{&AURNode{Status: statusMalicious, Verdict: Verdict{Verdict: "malicious", Confidence: 0.95}}, "aur: MALICIOUS (0.95)"},
	}
	for _, c := range cases {
		if got := nodeStatusText(c.n); !strings.HasPrefix(got, c.want) {
			t.Errorf("nodeStatusText(%q) = %q, want prefix %q", c.n.Status, got, c.want)
		}
	}
}

func TestVerdictTail(t *testing.T) {
	got := verdictTail(Verdict{Confidence: 0.80, Summary: "curl piped to sh"})
	if !strings.Contains(got, "(0.80)") || !strings.Contains(got, "curl piped to sh") {
		t.Errorf("verdictTail = %q, want confidence + summary", got)
	}
	if !strings.Contains(verdictTail(Verdict{Confidence: 1, Cached: true}), "(cached)") {
		t.Error("verdictTail should append (cached) for a cached verdict")
	}
	if strings.Contains(verdictTail(Verdict{Confidence: 1}), "—") {
		t.Error("verdictTail with an empty summary should not add a dash separator")
	}
}

func TestDim(t *testing.T) {
	treeColor = false
	if got := dim("x"); got != "x" {
		t.Errorf("dim with color off = %q, want plain x", got)
	}
	treeColor = true
	if got := dim("x"); !strings.Contains(got, "x") || !strings.Contains(got, "\033[2m") {
		t.Errorf("dim with color on = %q, want ANSI-wrapped x", got)
	}
	treeColor = false // restore
}

func TestVisibleTreeNodes(t *testing.T) {
	// A realistic flattened tree: an AUR root, a pile of repo leaves, one AUR
	// child, and one unresolvable "skipped" leaf. Only repo leaves are dropped.
	nodes := []*AURNode{
		{Name: "app", Status: statusOK},
		{Name: "cmake", Depth: 1, Status: statusRepo},
		{Name: "glibc", Depth: 1, Status: statusRepo},
		{Name: "libapp-git", Depth: 1, Status: statusOK},
		{Name: "opengl-driver", Depth: 1, Status: statusSkipped},
	}
	got := visibleTreeNodes(nodes)
	if len(got) != 3 {
		t.Fatalf("visibleTreeNodes kept %d nodes, want 3", len(got))
	}
	for _, n := range got {
		if n.Status == statusRepo {
			t.Errorf("repo node %q leaked into the render list", n.Name)
		}
	}
	// Order and the non-repo statuses are preserved.
	if got[0].Name != "app" || got[1].Name != "libapp-git" || got[2].Name != "opengl-driver" {
		t.Errorf("visibleTreeNodes order = [%s %s %s], want [app libapp-git opengl-driver]",
			got[0].Name, got[1].Name, got[2].Name)
	}
	// Nothing to filter is a no-op that still returns a usable slice.
	if len(visibleTreeNodes(nil)) != 0 {
		t.Error("visibleTreeNodes(nil) should be empty")
	}
}

func TestRenderTree_LineCountAndCursor(t *testing.T) {
	nodes := []*AURNode{
		{Name: "app", Status: statusOK, Verdict: Verdict{Verdict: "ok", Confidence: 1}},
		{Name: "lib", Depth: 1, Status: statusPending},
	}
	var buf bytes.Buffer

	// First render: no cursor-up escape, returns the node count.
	n := renderTree(&buf, nodes, 0)
	if n != len(nodes) {
		t.Fatalf("renderTree returned %d, want %d", n, len(nodes))
	}
	first := buf.String()
	if strings.Contains(first, "\033[") && strings.Contains(first, "A") == false {
		// clear-line escapes are expected; a cursor-up (…A) is not on the first call.
	}
	if strings.Contains(first, "2A") {
		t.Error("first render should not emit a cursor-up escape")
	}
	if !strings.Contains(first, "app:") || !strings.Contains(first, "lib:") {
		t.Errorf("render missing node lines: %q", first)
	}

	// Second render with prevLines>0 moves the cursor up that many lines.
	buf.Reset()
	renderTree(&buf, nodes, n)
	if !strings.Contains(buf.String(), "\033[2A") {
		t.Errorf("repeat render should move cursor up 2 lines, got %q", buf.String())
	}
}
