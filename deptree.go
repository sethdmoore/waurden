package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// treeScanActive is set for the duration of a tree gate so analyze() suppresses
// its per-package "scanning …" stderr line: the live tree already shows each
// node's status, and an extra line mid-render would corrupt the in-place cursor
// math (and just be noise in a non-TTY build log).
var treeScanActive bool

// AURNode is one package in the resolved scan tree. The root is the package whose
// gate fired (scanned authoritatively from its on-disk $PWD); every other node is
// an AUR dependency discovered from .SRCINFO and scanned from wAURden's own inert
// clone. Pruned official-repo deps and unresolvable names are shown as leaves for
// context but never scanned.
type AURNode struct {
	Name     string // pkgname (display + DB key); for a scanned node this is what the clone reports
	PkgBase  string // AUR pkgbase (the clone target); "" for repo/skipped leaves
	Dir      string // on-disk dir scanned: $PWD for the root, else the clone
	Hash     string // pf.Hash of the scanned PKGBUILD (for the ack short-circuit)
	IsRoot   bool   // true for the package whose gate fired (authoritative $PWD scan)
	Depth    int    // 0 = root
	Children []*AURNode
	Verdict  Verdict  // filled in as scanning proceeds
	Status   string   // one of the status* constants below
	Warnings []string // per-node committer notes, buffered so they don't corrupt the live render
}

// Node lifecycle / classification states. The three verdict states deliberately
// equal the Verdict.Verdict strings so a scanned node's Status is just its verdict.
const (
	statusPending    = "pending"    // an AUR node not yet scanned
	statusScanning   = "scanning"   // scan in flight (transient, for the live render)
	statusOK         = "ok"         // == Verdict "ok"
	statusSuspicious = "suspicious" // == Verdict "suspicious"
	statusMalicious  = "malicious"  // == Verdict "malicious"
	statusError      = "error"      // clone/scan failed — advisory, never a block
	statusRepo       = "repo"       // official-repo dep, pruned (never scanned)
	statusSkipped    = "skipped"    // not on the AUR and not official — unresolvable leaf
)

// treeResolver is the set of side-effecting operations resolveTree depends on,
// pulled behind function fields so a test can inject fakes (no pacman, no network,
// no clones). defaultResolver wires the real implementations.
type treeResolver struct {
	isOfficial func(name string) bool                         // satisfiable from an official sync repo?
	aurBases   func(names []string) (map[string]string, bool) // name→pkgbase; bool=false if the lookup call failed
	clone      func(pkgbase string) (dir string, err error)   // ensure a local clone, return its dir
	deps       func(dir string) []string                      // parse depends of a clone dir
	maxDepth   int
	maxNodes   int
}

func defaultResolver(cfg Config) treeResolver {
	officialCache := map[string]bool{}
	baseCache := map[string]string{}
	return treeResolver{
		isOfficial: func(name string) bool {
			if v, ok := officialCache[name]; ok {
				return v
			}
			v := pacmanHasSync(name)
			officialCache[name] = v
			return v
		},
		aurBases: func(names []string) (map[string]string, bool) {
			out := map[string]string{}
			var need []string
			for _, n := range names {
				if b, cached := baseCache[n]; cached {
					if b != "" {
						out[n] = b
					}
				} else {
					need = append(need, n)
				}
			}
			ok := true
			if len(need) > 0 {
				res, callOK := aurPackageBases(need, cfg.Timeout)
				if !callOK {
					ok = false
				} else {
					for _, n := range need {
						b := res[n] // "" when the name isn't on the AUR
						baseCache[n] = b
						if b != "" {
							out[n] = b
						}
					}
				}
			}
			return out, ok
		},
		clone: func(pkgbase string) (string, error) { return ensureClone(cfg, pkgbase) },
		deps: func(dir string) []string {
			return parseDeps(readFileString(filepath.Join(dir, ".SRCINFO")),
				readFileString(filepath.Join(dir, "PKGBUILD")))
		},
		maxDepth: 25,
		maxNodes: 300,
	}
}

// pacmanHasSync reports whether name is satisfiable from an official sync repo
// (`pacman -Si <name>` exits 0). A missing pacman (non-Arch dev box) or any error
// yields false, so the name is treated as an AUR candidate and the clone step
// sorts it out — pacman classification is a pruning optimisation, never a gate.
func pacmanHasSync(name string) bool {
	cmd := exec.Command("pacman", "-Si", name)
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Run() == nil
}

func readFileString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// resolveTree builds the AUR dependency closure rooted at pf, using the real
// (pacman + AUR RPC + git clone) resolver. The root is scanned later from pf's
// on-disk $PWD; children are cloned inert for discovery/pre-scan/diff.
func resolveTree(cfg Config, pf PackageFiles) *AURNode {
	return resolveTreeWith(defaultResolver(cfg), pf)
}

func resolveTreeWith(r treeResolver, pf PackageFiles) *AURNode {
	root := &AURNode{
		Name:    pf.Name,
		PkgBase: pf.PkgBase,
		Dir:     pf.Dir,
		IsRoot:  true,
		Depth:   0,
		Status:  statusPending,
	}
	// No stable identity, or tree scanning disabled by a resolver with no depth:
	// hand back a bare root so the caller takes the single-package fast path.
	if pf.Name == "unknown" || r.maxDepth <= 0 {
		return root
	}
	visited := map[string]bool{}
	if pf.PkgBase != "" {
		visited[pf.PkgBase] = true
	}
	count := 1
	buildChildren(r, root, parseDeps(pf.HelperFiles[".SRCINFO"], pf.PKGBUILDRaw), visited, &count)
	return root
}

// buildChildren classifies parent's deps and appends child nodes: official-repo
// deps become pruned "repo" leaves; AUR deps are cloned and recursed into; names
// that are neither become "skipped" leaves. A visited set keyed on pkgbase guards
// cycles and diamond dependencies, and a node cap bounds a pathological closure.
func buildChildren(r treeResolver, parent *AURNode, deps []string, visited map[string]bool, count *int) {
	if parent.Depth >= r.maxDepth {
		return
	}
	depth := parent.Depth + 1

	var candidates []string
	for _, name := range deps {
		if *count >= r.maxNodes {
			return
		}
		if r.isOfficial(name) {
			parent.Children = append(parent.Children, &AURNode{Name: name, Depth: depth, Status: statusRepo})
			*count++
			continue
		}
		candidates = append(candidates, name)
	}
	if len(candidates) == 0 {
		return
	}

	bases, ok := r.aurBases(candidates)
	for _, name := range candidates {
		if *count >= r.maxNodes {
			return
		}
		base := bases[name]
		if base == "" {
			if ok {
				// The RPC call succeeded and this name isn't on the AUR (and it isn't
				// official) → an unresolvable leaf. Show it, don't scan it.
				parent.Children = append(parent.Children, &AURNode{Name: name, Depth: depth, Status: statusSkipped})
				*count++
				continue
			}
			// RPC unavailable: fall back to trying the name itself as a pkgbase and
			// let the clone step be the arbiter.
			base = name
		}
		if visited[base] {
			continue // already placed elsewhere in the tree
		}
		visited[base] = true

		child := &AURNode{Name: name, PkgBase: base, Depth: depth, Status: statusPending}
		*count++
		dir, err := r.clone(base)
		if err != nil {
			// Advisory: a clone/fetch failure marks the node and we keep going.
			child.Status = statusError
			child.Dir = dir
			parent.Children = append(parent.Children, child)
			continue
		}
		child.Dir = dir
		parent.Children = append(parent.Children, child)
		buildChildren(r, child, r.deps(dir), visited, count)
	}
}

// --- dependency parsing -----------------------------------------------------

// parseDeps returns the deduplicated depends+makedepends+checkdepends names of a
// package, preferring the shell-expanded .SRCINFO and falling back to grepping the
// PKGBUILD arrays. Version constraints and .so suffixes are stripped. optdepends
// are intentionally excluded (optional — not part of the build closure).
func parseDeps(srcinfo, pkgbuild string) []string {
	if strings.TrimSpace(srcinfo) != "" {
		if deps := parseSrcinfoDeps(srcinfo); len(deps) > 0 {
			return deps
		}
	}
	return parsePkgbuildDeps(pkgbuild)
}

func parseSrcinfoDeps(srcinfo string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(srcinfo, "\n") {
		line = strings.TrimSpace(line)
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		if val == "" || !isDependsKey(key) {
			continue
		}
		if name := stripDepName(val); name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// isDependsKey matches depends / makedepends / checkdepends and their
// architecture-specific variants (e.g. depends_x86_64), but not optdepends.
func isDependsKey(key string) bool {
	for _, base := range []string{"depends", "makedepends", "checkdepends"} {
		if key == base || strings.HasPrefix(key, base+"_") {
			return true
		}
	}
	return false
}

var reDepArray = func() map[string]*regexp.Regexp {
	m := map[string]*regexp.Regexp{}
	for _, key := range []string{"depends", "makedepends", "checkdepends"} {
		m[key] = regexp.MustCompile(`(?m)^[ \t]*` + key + `(?:_[a-zA-Z0-9_]+)?[ \t]*=[ \t]*\(([^)]*)\)`)
	}
	return m
}()

func parsePkgbuildDeps(pkgbuild string) []string {
	seen := map[string]bool{}
	var out []string
	for _, key := range []string{"depends", "makedepends", "checkdepends"} {
		for _, m := range reDepArray[key].FindAllStringSubmatch(pkgbuild, -1) {
			for _, tok := range strings.Fields(m[1]) {
				if name := stripDepName(tok); name != "" && !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
		}
	}
	return out
}

// stripDepName reduces a raw dependency atom to a bare package name: it drops an
// optdepends "name: desc" tail, any version constraint (>=, <=, =, >, <), a .so
// provider suffix, and surrounding quotes.
func stripDepName(val string) string {
	val = strings.Trim(strings.TrimSpace(val), `'"`)
	if i := strings.IndexByte(val, ':'); i >= 0 {
		val = val[:i]
	}
	for _, op := range []string{">=", "<=", "=", ">", "<"} {
		if i := strings.Index(val, op); i >= 0 {
			val = val[:i]
		}
	}
	if i := strings.Index(val, ".so"); i >= 0 {
		val = val[:i]
	}
	return strings.Trim(strings.TrimSpace(val), `'"`)
}

// --- tree helpers -----------------------------------------------------------

// walkTree visits every node in DFS pre-order.
func walkTree(n *AURNode, fn func(*AURNode)) {
	fn(n)
	for _, c := range n.Children {
		walkTree(c, fn)
	}
}

// flattenTree returns all nodes in DFS pre-order (root first). The order and
// count are fixed once resolveTree returns — only statuses change — which is what
// lets the live renderer rewrite the same lines in place.
func flattenTree(root *AURNode) []*AURNode {
	var out []*AURNode
	walkTree(root, func(n *AURNode) { out = append(out, n) })
	return out
}

// hasScannableChildren reports whether the tree holds at least one AUR dependency
// to scan (a non-root pending node with a clone dir). When false, the caller uses
// the flat single-package fast path — the tree scan must never make the common
// single-leaf case slower or noisier.
func hasScannableChildren(root *AURNode) bool {
	found := false
	walkTree(root, func(n *AURNode) {
		if !n.IsRoot && n.Status == statusPending && n.Dir != "" {
			found = true
		}
	})
	return found
}

func countAURNodes(root *AURNode) int {
	n := 0
	walkTree(root, func(node *AURNode) {
		if !node.IsRoot && node.PkgBase != "" {
			n++
		}
	})
	return n
}

func verdictRank(v string) int {
	switch v {
	case "malicious":
		return 2
	case "suspicious":
		return 1
	}
	return 0
}

// worstNode returns the most severe node (malicious > suspicious > ok; ties broken
// by confidence) — the one the focused block message points at.
func worstNode(nodes []*AURNode) *AURNode {
	var worst *AURNode
	for _, n := range nodes {
		if worst == nil {
			worst = n
			continue
		}
		ra, rb := verdictRank(n.Verdict.Verdict), verdictRank(worst.Verdict.Verdict)
		if ra > rb || (ra == rb && n.Verdict.Confidence > worst.Verdict.Confidence) {
			worst = n
		}
	}
	return worst
}

// treeExitCode maps the blocked set to wAURden's exit contract: 2 if any blocked
// node is malicious, else 1 (suspicious). The makepkg hook collapses both to "die",
// but the distinct codes are readable by the user and any wrapping script.
func treeExitCode(blocked []*AURNode) int {
	for _, n := range blocked {
		if n.Verdict.Verdict == "malicious" {
			return 2
		}
	}
	return 1
}

// --- scanning + gate orchestration ------------------------------------------

// scanNode scans a single node and fills its Verdict/Status/Hash. The root is
// scanned authoritatively from the already-collected on-disk pf (rootPF); a child
// is scanned from its clone. Per-node committer warnings are buffered on the node
// (not printed) so the live tree render stays intact; AUR/orphan warnings are left
// to each package's own gate at build time (avoids N× the network here).
func scanNode(cfg Config, db *sql.DB, node *AURNode, rootPF *PackageFiles, force bool) {
	var pf PackageFiles
	if node.IsRoot && rootPF != nil {
		pf = *rootPF
	} else {
		var err error
		pf, err = collectFiles(node.Dir)
		if err != nil {
			node.Status = statusError
			return
		}
		node.Name = pf.Name
		var existing *DBRecord
		if pf.Name != "unknown" {
			existing, _ = lookupRecord(db, pf.Name)
		}
		node.Warnings = collectNewCommitters(&pf, existing)
	}
	node.Hash = pf.Hash

	v, err := analyze(cfg, db, pf, force)
	if err != nil {
		node.Status = statusError
		return
	}
	node.Verdict = v
	if v.ScanFailed {
		node.Status = statusError
	} else {
		node.Status = v.Verdict
	}
	if pf.Name != "unknown" {
		_ = recordScan(db, pf.Name, pf.Hash, engineString(cfg), v, policyBlocks(cfg, v))
	}
}

// runTreeGate scans the whole dependency tree (children pre-scanned from clones,
// the root authoritatively from $PWD), renders it, and aggregates a single gate
// decision: a blocked node anywhere aborts the build (you don't want a malicious
// dep's siblings to keep compiling). It always exits the process.
func runTreeGate(cfg Config, db *sql.DB, pf PackageFiles, root *AURNode, existing *DBRecord) {
	treeScanActive = true // suppress analyze()'s per-scan line; the tree shows status
	tty := isTTY()
	treeColor = tty
	nodes := flattenTree(root)
	display := visibleTreeNodes(nodes) // repo leaves are pruned from the render

	// Dedup the tree render across makepkg phases. One AUR build fires this gate
	// once per phase (source-fetch, dep-check, build, fakeroot package()), each an
	// independent process that re-resolves and re-renders the identical tree — so
	// without this the whole tree reprints four-plus times per package. If this exact
	// root PKGBUILD was already gated within the quiet window, scan silently: every
	// node is still scanned and the block/warn/ack/exit logic below still runs and
	// prints, we just don't repaint the clean tree. Keyed on the root hash (like the
	// single-package OK-line dedup) and read before any recordScan so it matches only
	// a *prior* run, never this one.
	render := true
	if seen, _ := recentlyAnnounced(db, pf.Name, pf.Hash, cfg.GateQuietWindow); seen {
		render = false
	}

	if render {
		fmt.Fprintf(os.Stderr, "wAURden: scanning package tree for %s\n", root.Name)
		fmt.Fprintf(os.Stderr, "  Found %d dependent AUR package(s)\n", countAURNodes(root))
	}

	prev := 0
	if render && tty {
		prev = renderTree(os.Stderr, display, prev)
	}
	for _, n := range nodes {
		if n.Status != statusPending {
			continue // repo / skipped / clone-error — nothing to scan
		}
		n.Status = statusScanning
		if render && tty {
			prev = renderTree(os.Stderr, display, prev)
		}
		scanNode(cfg, db, n, &pf, false)
		if render && tty {
			prev = renderTree(os.Stderr, display, prev)
		} else if render {
			fmt.Fprintln(os.Stderr, nodeRenderLine(n))
		}
	}
	if render && tty {
		renderTree(os.Stderr, display, prev)
	}

	// Buffered per-node committer notes, printed once below the settled tree.
	if render {
		for _, n := range nodes {
			for _, w := range n.Warnings {
				fmt.Fprintln(os.Stderr, w)
			}
		}
	}

	// The root honours on_error exactly like the single-package path: an infra
	// failure to scan the package being built is a block only under on_error=block.
	if root.Verdict.ScanFailed {
		if cfg.OnError == "block" {
			fmt.Fprintf(os.Stderr, "wAURden: %s — build blocked, scan failed (on_error=block): %v\n",
				root.Name, root.Verdict.Summary)
			// Trip the run-level breaker and show recovery options, exactly like
			// the single-package gate (see runGateCmd's ScanFailed path).
			recordHalt(db, root.Name, root.Hash, "error", truncate(root.Verdict.Summary))
			printScanFailGuidance(cfg)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wAURden: %s — could not scan (%s); build allowed (on_error=warn)\n",
			root.Name, truncate(root.Verdict.Summary))
	}

	// Collect policy-blocked nodes, applying the hash-pinned ack short-circuit
	// (a pure hash compare, so it works even with no TTY — the makepkg hook path).
	var blocked []*AURNode
	for _, n := range nodes {
		if n.Verdict.ScanFailed || !policyBlocks(cfg, n.Verdict) {
			continue
		}
		if n.Name != "unknown" && n.Hash != "" {
			if rec, _ := lookupRecord(db, n.Name); rec != nil &&
				rec.AcknowledgedHash != "" && rec.AcknowledgedHash == n.Hash {
				fmt.Fprintf(os.Stderr, "wAURden: %s @ %s previously acknowledged — allowing\n",
					n.Name, short(n.Hash))
				continue
			}
		}
		blocked = append(blocked, n)
	}

	// Interactive override, per offending node, tiered by confidence (typed phrase
	// for high-confidence malicious, else y/N). Only on a real TTY in interactive mode.
	if len(blocked) > 0 && cfg.Interactive && tty {
		var remaining []*AURNode
		for _, n := range blocked {
			if !treeInteractiveAccept(db, n) {
				remaining = append(remaining, n)
			}
		}
		blocked = remaining
	}

	if len(blocked) > 0 {
		// Every blocked node trips the run-level breaker, so sibling gates in
		// this helper run halt too (see activeHalt in runGateCmd).
		for _, n := range blocked {
			recordHalt(db, n.Name, n.Hash, n.Verdict.Verdict, truncate(n.Verdict.Summary))
		}
		printTreeBlock(worstNode(blocked))
		os.Exit(treeExitCode(blocked))
	}

	// Flagged-but-not-blocked (warn_on) nodes: force an explicit y/n decision per
	// node at an interactive TTY, mirroring the single-package gate (confirmWarning
	// re-prompts until the user chooses). A passive Enter must not wave through a
	// warning like "~/.ssh exfiltration". Declining any one aborts the whole build
	// (its siblings shouldn't keep compiling).
	if tty {
		for _, n := range nodes {
			if n.Verdict.ScanFailed || policyBlocks(cfg, n.Verdict) || !policyWarns(cfg, n.Verdict) {
				continue
			}
			// Honour a prior hash-pinned warn acknowledgement so the same decision
			// isn't re-prompted every makepkg phase / rebuild of this exact node.
			if n.Name != "unknown" && n.Hash != "" {
				if rec, _ := lookupRecord(db, n.Name); rec != nil &&
					rec.AcknowledgedWarnHash != "" && rec.AcknowledgedWarnHash == n.Hash {
					fmt.Fprintf(os.Stderr, "wAURden: %s @ %s warning previously accepted — allowing\n",
						n.Name, short(n.Hash))
					continue
				}
			}
			if !confirmWarning(n.Name, n.Verdict) {
				fmt.Fprintf(os.Stderr, "wAURden: build aborted — %s warning not accepted.\n", n.Name)
				os.Exit(1)
			}
			// Remember the decision for this exact PKGBUILD hash (its own column, kept
			// apart from the block ack — a warn "y" must not satisfy a block override).
			if n.Name != "unknown" && n.Hash != "" {
				if _, err := storeWarnAcknowledgement(db, n.Name, n.Hash); err != nil {
					fmt.Fprintf(os.Stderr, "wAURden: could not remember your decision: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "wAURden: remembered — %s @ %s won't prompt again until the PKGBUILD changes\n",
						n.Name, short(n.Hash))
				}
			}
		}
	}

	// Clean (or accepted warn-level). Hold the render briefly so the block of results
	// is readable before the helper's compile output scrolls it away.
	if render && tty && cfg.TreePauseSeconds > 0 {
		time.Sleep(time.Duration(cfg.TreePauseSeconds) * time.Second)
	}
	os.Exit(0)
}

// printTreeBlock renders the focused, actionable block message for the worst node.
func printTreeBlock(n *AURNode) {
	verdict := strings.ToUpper(n.Verdict.Verdict)
	pkgbuild := filepath.Join(n.Dir, "PKGBUILD")
	fmt.Fprintf(os.Stderr, "\nwAURden: %s package found: %s\n", verdict, n.Name)
	if s := truncate(n.Verdict.Summary); s != "" {
		fmt.Fprintf(os.Stderr, "         %s\n", s)
	}
	fmt.Fprintf(os.Stderr, "         Review the PKGBUILD:  less %s\n", pkgbuild)
	fmt.Fprintf(os.Stderr, "         Details:              waurden show %s\n", n.Name)
	fmt.Fprintf(os.Stderr, "         Remove the package, or explicitly allow this exact version:\n")
	fmt.Fprintf(os.Stderr, "             waurden allow %s\n", n.Dir)
	fmt.Fprintf(os.Stderr, "         (allow shows the findings and requires typing \"I accept the risk\")\n")
}

// treeInteractiveAccept prompts to override a single blocked node and, on
// acceptance, offers to persist a hash-pinned acknowledgement. Mirrors the
// single-package gate's tiered friction. Returns true if the node was accepted.
func treeInteractiveAccept(db *sql.DB, n *AURNode) bool {
	reader := bufio.NewReader(os.Stdin)
	v := n.Verdict
	accepted := false
	if v.Verdict == "malicious" && v.Confidence >= 0.9 {
		fmt.Fprintf(os.Stderr, "\nwAURden: %s blocked — %s, confidence %.2f.\n", n.Name, v.Verdict, v.Confidence)
		fmt.Fprintf(os.Stderr, "To override, type exactly: I accept the risk\n> ")
		line, _ := reader.ReadString('\n')
		accepted = strings.EqualFold(strings.TrimSpace(line), "i accept the risk")
	} else {
		fmt.Fprintf(os.Stderr, "\nwAURden: %s blocked. Allow anyway? [y/N]: ", n.Name)
		line, _ := reader.ReadString('\n')
		accepted = strings.EqualFold(strings.TrimSpace(line), "y")
	}
	if !accepted {
		return false
	}
	if n.Name != "unknown" && n.Hash != "" {
		fmt.Fprintf(os.Stderr, "Remember this version (skip the prompt until the PKGBUILD changes)? [Y/n]: ")
		line, _ := reader.ReadString('\n')
		ans := strings.ToLower(strings.TrimSpace(line))
		if ans == "" || ans == "y" || ans == "yes" {
			if _, err := storeAcknowledgement(db, n.Name, n.Hash); err != nil {
				fmt.Fprintf(os.Stderr, "wAURden: could not store acknowledgement: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "wAURden: recorded ack: %s @ %s (cleared when the PKGBUILD changes)\n",
					n.Name, short(n.Hash))
			}
		}
	}
	return true
}
