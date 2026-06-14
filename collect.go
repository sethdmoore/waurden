package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type PackageFiles struct {
	Dir         string
	Name        string
	PkgBase     string
	PKGBUILDRaw string
	PKGBUILDSrc string
	Hash        string
	HelperFiles map[string]string
}

func collectFiles(dir string) (PackageFiles, error) {
	pf := PackageFiles{
		Dir:         dir,
		HelperFiles: make(map[string]string),
	}

	pkgbuildPath := filepath.Join(dir, "PKGBUILD")
	data, err := os.ReadFile(pkgbuildPath)
	if err != nil {
		return pf, fmt.Errorf("cannot read PKGBUILD: %w", err)
	}

	pf.PKGBUILDRaw = string(data)
	sum := sha256.Sum256(data)
	pf.Hash = fmt.Sprintf("%x", sum)
	pf.PKGBUILDSrc = stripComments(pf.PKGBUILDRaw)
	pf.Name = extractPkgname(pf.PKGBUILDRaw)

	helperExts := []string{"*.install", "*.patch", "*.diff", ".SRCINFO"}
	for _, pattern := range helperExts {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			continue
		}
		for _, m := range matches {
			content, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			pf.HelperFiles[filepath.Base(m)] = string(content)
		}
	}

	if src, ok := pf.HelperFiles[".SRCINFO"]; ok {
		pf.PkgBase = extractPkgbase(src)
	}
	if pf.PkgBase == "" {
		pf.PkgBase = pf.Name
	}

	return pf, nil
}

func stripComments(src string) string {
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func extractPkgbase(srcinfo string) string {
	for _, line := range strings.Split(srcinfo, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pkgbase = ") {
			return strings.TrimPrefix(line, "pkgbase = ")
		}
	}
	return ""
}

func extractPkgname(src string) string {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pkgname=") {
			val := strings.TrimPrefix(line, "pkgname=")
			val = strings.Trim(val, `"'`)
			// Handle array form: pkgname=('foo' 'bar') → take first
			val = strings.TrimLeft(val, "(")
			val = strings.TrimRight(val, ")")
			val = strings.Trim(val, `"' `)
			if val != "" {
				return val
			}
		}
	}
	return "unknown"
}
