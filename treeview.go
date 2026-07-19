package main

import (
	"fmt"
	"io"
	"strings"
)

// treeColor enables ANSI dimming of pruned (repo/skipped) leaves. Set true only
// on a TTY; the non-TTY (build-log) path leaves lines plain.
var treeColor bool

// renderTree draws every node's current status, rewriting in place. prevLines is
// the number of node lines the previous call printed; on a repeat call the cursor
// is moved up that many lines and each is cleared and reprinted, so the tree
// animates without scrolling. Returns the number of node lines printed (constant
// for a given tree — only statuses change), to feed the next call.
//
// The header ("scanning package tree …") is printed by the caller once, above the
// first render, and is never overwritten. This path is used only on a TTY; the
// non-TTY renderer emits one plain nodeRenderLine per node as it resolves.
func renderTree(w io.Writer, nodes []*AURNode, prevLines int) int {
	var sb strings.Builder
	if prevLines > 0 {
		fmt.Fprintf(&sb, "\033[%dA", prevLines) // cursor up prevLines
	}
	for _, n := range nodes {
		sb.WriteString("\033[2K") // clear the whole line
		sb.WriteString(nodeRenderLine(n))
		sb.WriteByte('\n')
	}
	io.WriteString(w, sb.String())
	return len(nodes)
}

// nodeRenderLine formats one tree row: indentation by depth, a branch marker, the
// package name, and its status text. Used by both the animated TTY renderer and
// the plain non-TTY per-node lines, so the content is identical either way.
func nodeRenderLine(n *AURNode) string {
	marker := "- "
	if n.Depth > 0 {
		marker = "|- "
	}
	return strings.Repeat(" ", n.Depth+2) + marker + n.Name + ": " + nodeStatusText(n)
}

// nodeStatusText renders the trailing status field for a node. Scanned AUR nodes
// carry an "aur:" prefix and their verdict/confidence/summary; pruned official
// deps and unresolvable names show a dimmed label and no verdict.
func nodeStatusText(n *AURNode) string {
	switch n.Status {
	case statusRepo:
		return dim("repo")
	case statusSkipped:
		return dim("skipped")
	case statusPending:
		return "aur: pending"
	case statusScanning:
		return "aur: scanning…"
	case statusError:
		return "aur: could not scan"
	case statusOK:
		return "aur: OK" + verdictTail(n.Verdict)
	case statusSuspicious:
		return "aur: SUSPICIOUS" + verdictTail(n.Verdict)
	case statusMalicious:
		return "aur: MALICIOUS" + verdictTail(n.Verdict)
	default:
		return n.Status
	}
}

// verdictTail appends the confidence, a truncated summary, and a (cached) tag.
func verdictTail(v Verdict) string {
	tail := fmt.Sprintf(" (%.2f)", v.Confidence)
	if s := truncate(v.Summary); s != "" {
		tail += " — " + s
	}
	return tail + cachedTag(v)
}

// dim wraps s in ANSI dim when treeColor is on, else returns it unchanged.
func dim(s string) string {
	if !treeColor {
		return s
	}
	return "\033[2m" + s + "\033[22m"
}
