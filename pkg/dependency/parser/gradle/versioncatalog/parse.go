package versioncatalog

import (
	"context"
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// Distinguishable parsing errors. Callers can use errors.Is to tell failure modes apart.
var (
	// ErrInvalidTOML is returned when the file cannot be decoded as TOML.
	ErrInvalidTOML = errors.New("invalid TOML")
	// ErrCircularReference is returned when version references form a cycle.
	ErrCircularReference = errors.New("circular version reference")
	// ErrMissingField is returned when a declaration lacks a mandatory field (e.g. group/name or plugin id).
	ErrMissingField = errors.New("missing required field")
	// ErrUnknownReference is returned when a version.ref or bundle alias points to a non-existent entry.
	ErrUnknownReference = errors.New("unknown reference")
)

// catalog mirrors the Gradle version catalog TOML format.
// cf. https://docs.gradle.org/current/userguide/version_catalogs.html
type catalog struct {
	Versions  map[string]any      `toml:"versions"`
	Libraries map[string]any      `toml:"libraries"`
	Bundles   map[string][]string `toml:"bundles"`
	Plugins   map[string]any      `toml:"plugins"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse parses a Gradle version catalog (e.g. gradle/libs.versions.toml) and
// returns the declared libraries and plugins as packages.
func (Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}

	var cat catalog
	if _, err := toml.Decode(string(content), &cat); err != nil {
		return nil, nil, xerrors.Errorf("%w: %s", ErrInvalidTOML, err.Error())
	}

	lines := aliasLines(string(content))

	var pkgs []ftypes.Package

	// Libraries
	for _, e := range flatten(cat.Libraries) {
		pkg, skip, err := parseLibrary(e.name, e.value, cat.Versions)
		if err != nil {
			return nil, nil, err
		}
		if skip {
			continue
		}
		if line := lines.lookup("libraries", e.name); line > 0 {
			pkg.Locations = []ftypes.Location{{StartLine: line, EndLine: line}}
		}
		pkgs = append(pkgs, pkg)
	}

	// Plugins
	for _, e := range flatten(cat.Plugins) {
		pkg, skip, err := parsePlugin(e.name, e.value, cat.Versions)
		if err != nil {
			return nil, nil, err
		}
		if skip {
			continue
		}
		if line := lines.lookup("plugins", e.name); line > 0 {
			pkg.Locations = []ftypes.Location{{StartLine: line, EndLine: line}}
		}
		pkgs = append(pkgs, pkg)
	}

	// Bundles don't declare packages themselves, but their aliases must be resolvable.
	for name, aliases := range cat.Bundles {
		for _, alias := range aliases {
			if !hasAlias(cat.Libraries, alias) {
				return nil, nil, xerrors.Errorf("%w: bundle %q references unknown library alias %q", ErrUnknownReference, name, alias)
			}
		}
	}

	// Stable output order
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].ID < pkgs[j].ID
	})

	return pkgs, nil, nil
}

// entry is a flattened catalog entry: the alias and its raw TOML value.
type entry struct {
	name  string
	value any
}

// flatten turns a (possibly nested, via dotted keys or sub-tables) catalog section
// into a flat list of alias/value pairs. Nested aliases are joined with ".".
func flatten(section map[string]any) []entry {
	var entries []entry
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			v := m[k]
			if table, ok := v.(map[string]any); ok && !isDeclaration(table) {
				walk(name, table)
				continue
			}
			entries = append(entries, entry{name: name, value: v})
		}
	}
	walk("", section)
	return entries
}

// isDeclaration reports whether the table looks like a library/plugin/version
// declaration rather than a group of nested aliases.
func isDeclaration(table map[string]any) bool {
	for _, key := range []string{"module", "group", "name", "version", "version.ref", "id", "ref", "strictly", "require", "prefer"} {
		if _, ok := table[key]; ok {
			return true
		}
	}
	return false
}

// hasAlias reports whether the alias exists in the libraries section,
// taking dotted-alias nesting into account.
func hasAlias(libraries map[string]any, alias string) bool {
	for _, e := range flatten(libraries) {
		// Gradle normalizes alias separators ("-", "_", ".") to "-" for accessors,
		// but in the TOML file aliases are referenced as declared. Compare leniently.
		if e.name == alias || normalizeAlias(e.name) == normalizeAlias(alias) {
			return true
		}
	}
	return false
}

func normalizeAlias(alias string) string {
	return strings.NewReplacer(".", "-", "_", "-").Replace(alias)
}

// parseLibrary converts a single library declaration into a package.
// The second return value is true when the entry is valid but carries no
// version information (e.g. a version-less alias whose version comes from a
// platform/BOM) and should therefore be skipped.
func parseLibrary(alias string, v any, versions map[string]any) (ftypes.Package, bool, error) {
	var group, name string
	var versionSpec any
	hasVersion := false

	switch lib := v.(type) {
	case string:
		// Short notation: "group:name:version" or "group:name"
		parts := strings.Split(lib, ":")
		switch len(parts) {
		case 2:
			group, name = parts[0], parts[1]
		case 3:
			group, name = parts[0], parts[1]
			versionSpec, hasVersion = parts[2], true
		default:
			return ftypes.Package{}, false, xerrors.Errorf("%w: library %q has malformed notation %q", ErrMissingField, alias, lib)
		}
	case map[string]any:
		if module, ok := lib["module"].(string); ok {
			parts := strings.Split(module, ":")
			if len(parts) != 2 {
				return ftypes.Package{}, false, xerrors.Errorf("%w: library %q has malformed module %q", ErrMissingField, alias, module)
			}
			group, name = parts[0], parts[1]
		} else {
			group, _ = lib["group"].(string)
			name, _ = lib["name"].(string)
		}
		if group == "" || name == "" {
			return ftypes.Package{}, false, xerrors.Errorf("%w: library %q requires group and name (or module)", ErrMissingField, alias)
		}
		if spec, ok := lib["version"]; ok {
			versionSpec, hasVersion = spec, true
		}
		// "version.ref" written as a dotted key on a single line
		if ref, ok := lib["version.ref"].(string); ok {
			versionSpec, hasVersion = map[string]any{"ref": ref}, true
		}
	default:
		return ftypes.Package{}, false, xerrors.Errorf("%w: library %q has unsupported declaration", ErrMissingField, alias)
	}

	if !hasVersion {
		// Version-less alias: the version is supplied by a platform/BOM at build time.
		return ftypes.Package{}, true, nil
	}

	version, err := resolveVersion(versionSpec, versions, nil)
	if err != nil {
		return ftypes.Package{}, false, xerrors.Errorf("library %q: %w", alias, err)
	}
	if version == "" {
		return ftypes.Package{}, true, nil
	}

	return newPackage(group+":"+name, version), false, nil
}

// parsePlugin converts a single plugin declaration into a package.
// The plugin marker artifact ("id:id.gradle.plugin:version") is used as the
// package name so that the generated PURL points to a real Maven artifact.
func parsePlugin(alias string, v any, versions map[string]any) (ftypes.Package, bool, error) {
	table, ok := v.(map[string]any)
	if !ok {
		return ftypes.Package{}, false, xerrors.Errorf("%w: plugin %q requires a table with at least an id", ErrMissingField, alias)
	}

	id, _ := table["id"].(string)
	if id == "" {
		return ftypes.Package{}, false, xerrors.Errorf("%w: plugin %q requires an id", ErrMissingField, alias)
	}

	var versionSpec any
	hasVersion := false
	if spec, ok := table["version"]; ok {
		versionSpec, hasVersion = spec, true
	}
	if ref, ok := table["version.ref"].(string); ok {
		versionSpec, hasVersion = map[string]any{"ref": ref}, true
	}
	if !hasVersion {
		return ftypes.Package{}, true, nil
	}

	version, err := resolveVersion(versionSpec, versions, nil)
	if err != nil {
		return ftypes.Package{}, false, xerrors.Errorf("plugin %q: %w", alias, err)
	}
	if version == "" {
		return ftypes.Package{}, true, nil
	}

	return newPackage(id+":"+id+".gradle.plugin", version), false, nil
}

// resolveVersion resolves a version specification to a concrete version string.
// Supported forms:
//   - plain string: "1.0"
//   - rich version table: { strictly = "...", require = "...", prefer = "..." }
//   - reference table: { ref = "key" } pointing to the [versions] section
//
// For rich versions the effective version follows Gradle's conflict
// resolution semantics: strictly > require > prefer.
func resolveVersion(spec any, versions map[string]any, visiting map[string]bool) (string, error) {
	switch v := spec.(type) {
	case string:
		return v, nil
	case map[string]any:
		if ref, ok := v["ref"].(string); ok {
			return resolveVersionRef(ref, versions, visiting)
		}
		if s, _ := v["strictly"].(string); s != "" {
			return s, nil
		}
		if s, _ := v["require"].(string); s != "" {
			return s, nil
		}
		switch prefer := v["prefer"].(type) {
		case string:
			if prefer != "" {
				return prefer, nil
			}
		case []any:
			for _, p := range prefer {
				if s, ok := p.(string); ok && s != "" {
					return s, nil
				}
			}
		}
		// e.g. only "reject" is given: no usable version
		return "", nil
	default:
		return "", xerrors.Errorf("%w: unsupported version specification", ErrMissingField)
	}
}

// resolveVersionRef follows a version reference into the [versions] section,
// guarding against reference cycles.
func resolveVersionRef(ref string, versions map[string]any, visiting map[string]bool) (string, error) {
	if visiting == nil {
		visiting = make(map[string]bool)
	}
	if visiting[ref] {
		return "", xerrors.Errorf("%w: %q", ErrCircularReference, ref)
	}
	spec, ok := versions[ref]
	if !ok {
		return "", xerrors.Errorf("%w: version.ref %q is not declared in the [versions] section", ErrUnknownReference, ref)
	}
	visiting[ref] = true
	defer delete(visiting, ref)
	return resolveVersion(spec, versions, visiting)
}

func newPackage(name, version string) ftypes.Package {
	return ftypes.Package{
		ID:           dependency.ID(ftypes.Gradle, name, version),
		Name:         name,
		Version:      version,
		Relationship: ftypes.RelationshipDirect,
	}
}

// sectionLines maps section names ("libraries", "plugins") to alias -> line number.
type sectionLines map[string]map[string]int

func (s sectionLines) lookup(section, alias string) int {
	aliases, ok := s[section]
	if !ok {
		return 0
	}
	if line, ok := aliases[alias]; ok {
		return line
	}
	// Aliases may be declared with different separators than used for lookup.
	for a, line := range aliases {
		if normalizeAlias(a) == normalizeAlias(alias) {
			return line
		}
	}
	return 0
}

// aliasLines scans the raw TOML content and records the line on which each
// library/plugin alias is declared. It is a best-effort heuristic used only
// for package locations.
func aliasLines(content string) sectionLines {
	result := sectionLines{}
	var section string
	for i, line := range strings.Split(content, "\n") {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			// Section header, e.g. [libraries] or [libraries.groovy]
			section = strings.Trim(strings.TrimSpace(trimmed), "[]")
			continue
		}
		key := splitKey(trimmed)
		if key == "" {
			continue
		}
		// Only track sections we report locations for.
		base, sub, _ := strings.Cut(section, ".")
		if base != "libraries" && base != "plugins" {
			continue
		}
		// Skip nested keys of a declaration (e.g. "version.ref" inside a table is
		// written on the alias line itself, so a bare "version" key here would be a sub-table key).
		alias := key
		if sub != "" {
			alias = unquote(sub) + "." + key
		}
		if result[base] == nil {
			result[base] = map[string]int{}
		}
		if _, ok := result[base][alias]; !ok {
			result[base][alias] = lineNum
		}
	}
	return result
}

// splitKey extracts the (possibly quoted) key from a "key = value" line.
func splitKey(line string) string {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return ""
	}
	return unquote(strings.TrimSpace(line[:idx]))
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
