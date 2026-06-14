package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"strings"
)

func runGate(cfg Config, db *sql.DB, pf PackageFiles) (Verdict, bool, error) {
	v, err := analyze(cfg, db, pf)
	if err != nil {
		return v, false, err
	}

	blocked := false
	for _, b := range cfg.BlockOn {
		if strings.EqualFold(v.Verdict, b) {
			blocked = true
			break
		}
	}

	for _, w := range cfg.WarnOn {
		if strings.EqualFold(v.Verdict, w) {
			fmt.Fprintf(os.Stderr, "wAURden WARNING: package %q verdict is %s\n", pf.Name, v.Verdict)
			break
		}
	}

	if blocked && cfg.Interactive && isTTY() {
		printReport(os.Stderr, pf.Name, v, "")
		fmt.Fprintf(os.Stderr, "\nwAURden: build blocked. Allow anyway? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.EqualFold(line, "y") {
			blocked = false
		}
	}

	return v, blocked, nil
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
