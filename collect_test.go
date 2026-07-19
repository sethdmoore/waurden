package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripComments(t *testing.T) {
	src := "" +
		"# a leading comment\n" +
		"pkgname=foo\n" +
		"   # indented comment\n" +
		"build() {\n" +
		"\techo hi   # trailing comment kept (not a full-line comment)\n" +
		"}\n"
	got := stripComments(src)
	// Full-line comments (first non-ws char is #) are removed; the trailing
	// inline comment stays because the line does not START with #.
	want := "" +
		"pkgname=foo\n" +
		"build() {\n" +
		"\techo hi   # trailing comment kept (not a full-line comment)\n" +
		"}\n"
	// stripComments joins with \n and does not add a trailing newline for the
	// final (empty) element, so reconstruct exactly.
	if got != want {
		t.Errorf("stripComments mismatch:\n got=%q\nwant=%q", got, want)
	}
	// The injected comment content must be gone.
	if strings.Contains(got, "leading comment") || strings.Contains(got, "indented comment") {
		t.Errorf("full-line comments not stripped: %q", got)
	}
}

func TestExtractPkgname(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"plain", "pkgname=hello-world\n", "hello-world"},
		{"quoted", `pkgname="my-pkg"`, "my-pkg"},
		{"single-quoted", "pkgname='my-pkg'", "my-pkg"},
		{"array-single", "pkgname=('foo')", "foo"},
		{"array-single-double", `pkgname=("foo")`, "foo"},
		// KNOWN LIMITATION: extractPkgname trims parens/quotes but does NOT split a
		// multi-element inline array on whitespace, despite the code comment claiming
		// it "takes first". For split packages the .SRCINFO pkgname is preferred
		// (extractPkgnameFromSrcinfo), so this raw-array path is a rare fallback.
		// Asserting the actual behavior documents the gap rather than hiding it.
		{"array-multi-not-split", "pkgname=('foo' 'bar')", "foo' 'bar"},
		{"with-surrounding-lines", "pkgver=1.0\npkgname=zsh\npkgrel=1", "zsh"},
		{"none", "pkgver=1.0\n", "unknown"},
		{"empty-value", "pkgname=\n", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractPkgname(tc.src); got != tc.want {
				t.Errorf("extractPkgname(%q) = %q, want %q", tc.src, got, tc.want)
			}
		})
	}
}

func TestExtractPkgbase(t *testing.T) {
	srcinfo := "pkgbase = hyprland\n\tpkgdesc = a tiling WM\npkgname = hyprland\n"
	if got := extractPkgbase(srcinfo); got != "hyprland" {
		t.Errorf("extractPkgbase = %q, want hyprland", got)
	}
	if got := extractPkgbase("pkgname = foo\n"); got != "" {
		t.Errorf("extractPkgbase with no pkgbase = %q, want empty", got)
	}
}

func TestExtractPkgnameFromSrcinfo(t *testing.T) {
	// .SRCINFO carries the shell-expanded name — this is preferred over the raw
	// PKGBUILD pkgname= which may contain $variables.
	srcinfo := "pkgbase = hyprland-git\n\npkgname = hyprland-git\n"
	if got := extractPkgnameFromSrcinfo(srcinfo); got != "hyprland-git" {
		t.Errorf("extractPkgnameFromSrcinfo = %q, want hyprland-git", got)
	}
	if got := extractPkgnameFromSrcinfo("pkgbase = x\n"); got != "" {
		t.Errorf("extractPkgnameFromSrcinfo with no pkgname = %q, want empty", got)
	}
}

func TestExpandShellVars(t *testing.T) {
	pkgbuild := "" +
		"_pkgname=hyprland\n" +
		"pkgname=${_pkgname}-git\n" +
		"pkgver=1.0\n"
	if got := expandShellVars(pkgbuild, "${_pkgname}-git"); got != "hyprland-git" {
		t.Errorf("expandShellVars ${_pkgname}-git = %q, want hyprland-git", got)
	}
	if got := expandShellVars(pkgbuild, "$_pkgname"); got != "hyprland" {
		t.Errorf("expandShellVars $_pkgname = %q, want hyprland", got)
	}
	// An undefined variable is left as-is.
	if got := expandShellVars(pkgbuild, "${undefined}"); got != "${undefined}" {
		t.Errorf("expandShellVars undefined = %q, want unchanged", got)
	}
	// Values that themselves reference variables are skipped (one pass only), so
	// _b references _a but is not resolved transitively.
	pb2 := "_a=foo\n_b=$_a\n"
	if got := expandShellVars(pb2, "$_b"); got != "$_b" {
		t.Errorf("expandShellVars transitive = %q, want unchanged ($_b not indexed)", got)
	}
	// Comment lines are ignored when harvesting assignments.
	pb3 := "#_x=commented\n_x=real\n"
	if got := expandShellVars(pb3, "$_x"); got != "real" {
		t.Errorf("expandShellVars with commented assignment = %q, want real", got)
	}
}

func TestCollectFilesBenignSample(t *testing.T) {
	pf, err := collectFiles(sampleDir("benign"))
	if err != nil {
		t.Fatalf("collectFiles(benign): %v", err)
	}
	if pf.Name != "hello-world" {
		t.Errorf("Name = %q, want hello-world", pf.Name)
	}
	// No .SRCINFO in this sample → PkgBase falls back to Name.
	if pf.PkgBase != "hello-world" {
		t.Errorf("PkgBase = %q, want hello-world (fallback to Name)", pf.PkgBase)
	}
	// Hash is the sha256 of the raw PKGBUILD bytes.
	raw, _ := os.ReadFile(filepath.Join(sampleDir("benign"), "PKGBUILD"))
	wantHash := fmt.Sprintf("%x", sha256.Sum256(raw))
	if pf.Hash != wantHash {
		t.Errorf("Hash = %q, want %q", pf.Hash, wantHash)
	}
	if pf.PKGBUILDRaw != string(raw) {
		t.Errorf("PKGBUILDRaw does not match file bytes")
	}
	// The maintainer comment line must be stripped from the src view.
	if strings.Contains(pf.PKGBUILDSrc, "Maintainer: Test User") {
		t.Errorf("comment not stripped from PKGBUILDSrc")
	}
}

func TestCollectFilesMissingPKGBUILD(t *testing.T) {
	_, err := collectFiles(t.TempDir())
	if err == nil {
		t.Fatal("collectFiles on a dir with no PKGBUILD should error")
	}
}

func TestCollectFilesHelpersAndSrcinfo(t *testing.T) {
	dir := t.TempDir()
	// A PKGBUILD whose pkgname contains a variable; .SRCINFO carries the real name.
	pkgbuild := "" +
		"# Maintainer: eve\n" +
		"_pkg=cooltool\n" +
		"pkgname=${_pkg}\n" +
		"pkgver=2.0\n" +
		"build() { make; }\n"
	writeSampleFile(t, dir, "PKGBUILD", pkgbuild)
	writeSampleFile(t, dir, ".SRCINFO", "pkgbase = cooltool\npkgname = cooltool\n")
	writeSampleFile(t, dir, "foo.install", "post_install() { echo hi; }\n")
	writeSampleFile(t, dir, "fix.patch", "--- a\n+++ b\n")

	pf, err := collectFiles(dir)
	if err != nil {
		t.Fatalf("collectFiles: %v", err)
	}
	// .SRCINFO pkgname wins over the raw ${_pkg} form.
	if pf.Name != "cooltool" {
		t.Errorf("Name = %q, want cooltool (from .SRCINFO)", pf.Name)
	}
	if pf.PkgBase != "cooltool" {
		t.Errorf("PkgBase = %q, want cooltool", pf.PkgBase)
	}
	// Helper files are keyed by base name and include .install, .patch and .SRCINFO.
	for _, want := range []string{"foo.install", "fix.patch", ".SRCINFO"} {
		if _, ok := pf.HelperFiles[want]; !ok {
			t.Errorf("HelperFiles missing %q; have %v", want, keysOf(pf.HelperFiles))
		}
	}
	if pf.HelperFiles["foo.install"] != "post_install() { echo hi; }\n" {
		t.Errorf("install helper content wrong: %q", pf.HelperFiles["foo.install"])
	}
}

func TestCollectFilesExpandsVarNameWithoutSrcinfo(t *testing.T) {
	dir := t.TempDir()
	// No .SRCINFO → the last-resort expandShellVars path must resolve the name.
	pkgbuild := "_pkgname=widget\npkgname=${_pkgname}-git\npkgver=1\n"
	writeSampleFile(t, dir, "PKGBUILD", pkgbuild)
	pf, err := collectFiles(dir)
	if err != nil {
		t.Fatalf("collectFiles: %v", err)
	}
	if pf.Name != "widget-git" {
		t.Errorf("Name = %q, want widget-git (expanded)", pf.Name)
	}
}

// --- local helpers (unique names, not shared) ---

func writeSampleFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func keysOf(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
