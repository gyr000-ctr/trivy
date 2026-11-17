// Package buildfile extracts declared dependencies from Gradle build scripts
// (build.gradle / build.gradle.kts) using a heuristic, line-based parser.
// It understands the string notation ("group:name:version") and the map
// notation (group: ..., name: ..., version: ...). References to version
// catalog accessors (libs.*) and non-literal versions are skipped.
package buildfile

import (
	"bufio"
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	// stringNotation matches quoted "group:name:version" coordinates,
	// e.g. implementation "org.apache.commons:commons-lang3:3.14.0"
	// or implementation("org.apache.commons:commons-lang3:3.14.0").
	stringNotation = regexp.MustCompile(`["']([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-+]+)["']`)

	// Map notation, Groovy (group: 'g', name: 'a', version: 'v') and
	// Kotlin (group = "g", name = "a", version = "v") DSLs.
	groupAttr   = regexp.MustCompile(`\bgroup\s*[:=]\s*["']([^"']+)["']`)
	nameAttr    = regexp.MustCompile(`\bname\s*[:=]\s*["']([^"']+)["']`)
	versionAttr = regexp.MustCompile(`\bversion\s*[:=]\s*["']([^"']+)["']`)

	// configurationName captures the configuration a dependency is added to,
	// e.g. "implementation", "testImplementation", "api".
	configurationName = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9_]*)\s*[(\s]`)
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse extracts dependency coordinates declared in a Gradle build script.
func (Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	seen := make(map[string]struct{})
	var pkgs []ftypes.Package

	scanner := bufio.NewScanner(r)
	var lineNum int
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comment lines (naive, but sufficient for a heuristic parser).
		if trimmed == "" || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		dev := isDevConfiguration(line)

		for _, m := range stringNotation.FindAllStringSubmatch(line, -1) {
			pkgs = appendPkg(pkgs, seen, m[1]+":"+m[2], m[3], dev, lineNum)
		}

		group, name, version := attr(groupAttr, line), attr(nameAttr, line), attr(versionAttr, line)
		if group != "" && name != "" && version != "" {
			pkgs = appendPkg(pkgs, seen, group+":"+name, version, dev, lineNum)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	// Stable output order
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].ID < pkgs[j].ID
	})

	return pkgs, nil, nil
}

func appendPkg(pkgs []ftypes.Package, seen map[string]struct{}, name, version string, dev bool, lineNum int) []ftypes.Package {
	id := dependency.ID(ftypes.Gradle, name, version)
	if _, ok := seen[id]; ok {
		return pkgs
	}
	seen[id] = struct{}{}
	return append(pkgs, ftypes.Package{
		ID:           id,
		Name:         name,
		Version:      version,
		Dev:          dev,
		Relationship: ftypes.RelationshipDirect,
		Locations: []ftypes.Location{
			{
				StartLine: lineNum,
				EndLine:   lineNum,
			},
		},
	})
}

// isDevConfiguration reports whether the dependency on this line is added to
// a test-only configuration (e.g. testImplementation).
func isDevConfiguration(line string) bool {
	m := configurationName.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	return strings.Contains(strings.ToLower(m[1]), "test")
}

func attr(re *regexp.Regexp, line string) string {
	if m := re.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return ""
}
