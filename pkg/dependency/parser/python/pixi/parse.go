package pixi

import (
	"context"
	"path"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// pixi.lock shares its file format versioning with the rattler lock file and
// is serialized as YAML. v4 is the first multi-environment layout used by
// pixi; v7 is currently the newest published version (relative file paths in
// URLs).
const (
	minSupportedVersion = 4
	maxSupportedVersion = 7
)

// Lock is the top-level pixi.lock document.
// cf. https://pixi.sh/latest/features/lockfile/
type Lock struct {
	Version      int                    `yaml:"version"`
	Environments map[string]Environment `yaml:"environments"`
	Packages     []Package              `yaml:"packages"`
}

// Environment describes one named environment and the package locations it
// resolves to per platform.
type Environment struct {
	Packages map[string][]PackageReference `yaml:"packages"`
}

// PackageReference is an entry under environments.<name>.packages.<platform>.
// Exactly one of Conda or PyPI is set and matches the location key used on the
// corresponding record in the top-level `packages` array.
type PackageReference struct {
	Conda string `yaml:"conda"`
	PyPI  string `yaml:"pypi"`
}

func (r PackageReference) location() string {
	return lo.Ternary(r.Conda != "", r.Conda, r.PyPI)
}

// Package is a single record of the top-level `packages` array. A record is
// keyed by its location, which also identifies the ecosystem: a `conda` key is
// a conda package, a `pypi` key a PyPI package.
type Package struct {
	Conda   string `yaml:"conda"`
	PyPI    string `yaml:"pypi"`
	Name    string `yaml:"name"`
	Version string `yaml:"version"`

	// Conda package metadata
	Depends []string `yaml:"depends"`
	License string   `yaml:"license"`

	// PyPI package metadata
	RequiresDist []string `yaml:"requires_dist"`
}

// Kind identifies the ecosystem a package record belongs to.
type Kind int

const (
	KindUnknown Kind = iota
	KindConda
	KindPyPI
)

func (p Package) kind() Kind {
	switch {
	case p.Conda != "":
		return KindConda
	case p.PyPI != "":
		return KindPyPI
	default:
		return KindUnknown
	}
}

// location returns the value of the `conda`/`pypi` key, which uniquely
// identifies a package record and is the value referenced from environments.
func (p Package) location() string {
	return lo.Ternary(p.Conda != "", p.Conda, p.PyPI)
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse decodes a pixi.lock file and returns its conda and PyPI packages as two
// independent package lists. The two ecosystems cannot share one
// types.Application because vulnerability detection and PURL generation are
// dispatched from the application type.
//
// Only packages reachable from at least one environment are returned; the
// top-level `packages` array may contain records no environment uses anymore.
// All work is linear in the number of package records, and the only growing
// structures are maps keyed by package name/location (no quadratic behavior).
func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) (
	condaPkgs, pypiPkgs ftypes.Packages, condaDeps, pypiDeps ftypes.Dependencies, err error,
) {
	var lock Lock
	if err = yaml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, nil, nil, nil, xerrors.Errorf("failed to decode pixi lock file: %w", err)
	}

	switch {
	case lock.Version == 0:
		return nil, nil, nil, nil, xerrors.New("pixi lock file must contain a `version` field")
	case lock.Version < minSupportedVersion:
		return nil, nil, nil, nil, xerrors.Errorf(
			"unsupported pixi lock file version %d: minimum supported version is %d",
			lock.Version, minSupportedVersion)
	case lock.Version > maxSupportedVersion:
		return nil, nil, nil, nil, xerrors.Errorf(
			"unsupported pixi lock file version %d: maximum supported version is %d",
			lock.Version, maxSupportedVersion)
	}

	// An empty lock (e.g. an environment without dependencies) is valid; there
	// is just nothing to report. A missing `packages` section decodes the same
	// way as an empty one.
	if len(lock.Packages) == 0 {
		return nil, nil, nil, nil, nil
	}

	// Index every package record by its location for O(1) environment lookups.
	records := make(map[string]Package, len(lock.Packages))
	for _, pkg := range lock.Packages {
		loc := pkg.location()
		if loc == "" {
			// A record without a conda/pypi key cannot be identified; skip it.
			continue
		}
		records[loc] = pkg
	}

	// Collect the locations actually referenced by an environment. Records that
	// exist but are not referenced belong to no resolved environment and must
	// neither be reported nor take part in dependency resolution.
	referenced := set.New[string]()
	for _, env := range lock.Environments {
		for _, refs := range env.Packages {
			for _, ref := range refs {
				if loc := ref.location(); loc != "" {
					referenced.Append(loc)
				}
			}
		}
	}

	// Build per-ecosystem name indexes from referenced records only, so every
	// resolved dependency edge points at a package that is also emitted. The
	// indexes keep dependency resolution linear in the record count.
	condaByName := make(map[string]string) // name -> package ID
	pypiByName := make(map[string]string)  // normalized name -> package ID
	for loc := range referenced.Iter() {
		pkg, ok := records[loc]
		if !ok {
			// Dangling reference: an environment points at a missing record.
			// It is skipped during the build loop below.
			continue
		}
		switch pkg.kind() {
		case KindConda:
			if name, version, ok := parseCondaLocation(pkg.Conda); ok {
				if _, exists := condaByName[name]; !exists {
					condaByName[name] = dependency.ID(ftypes.CondaPkg, name, version)
				}
			}
		case KindPyPI:
			name := python.NormalizePkgName(pkg.Name, true)
			if name != "" && pkg.Version != "" {
				if _, exists := pypiByName[name]; !exists {
					pypiByName[name] = dependency.ID(ftypes.Pip, name, pkg.Version)
				}
			}
		}
	}

	condaOut := make(map[string]ftypes.Package)
	pypiOut := make(map[string]ftypes.Package)
	condaDepends := make(map[string]set.Set[string])
	pypiDepends := make(map[string]set.Set[string])

	for loc := range referenced.Iter() {
		pkg, ok := records[loc]
		if !ok {
			// An environment references a location absent from the `packages`
			// array: a dangling reference in a broken lock file. Skip it rather
			// than failing the whole scan.
			continue
		}

		switch pkg.kind() {
		case KindConda:
			out, dependsOn, skip := buildCondaPackage(pkg, condaByName)
			if skip {
				continue
			}
			addPackage(condaOut, condaDepends, out, dependsOn)
		case KindPyPI:
			out, dependsOn, skip := buildPyPIPackage(pkg, pypiByName)
			if skip {
				continue
			}
			addPackage(pypiOut, pypiDepends, out, dependsOn)
		}
	}

	condaPkgs = lo.Values(condaOut)
	pypiPkgs = lo.Values(pypiOut)
	// Normalize empty slices to nil to match the other lockfile parsers.
	if len(condaPkgs) == 0 {
		condaPkgs = nil
	}
	if len(pypiPkgs) == 0 {
		pypiPkgs = nil
	}
	sort.Sort(condaPkgs)
	sort.Sort(pypiPkgs)

	return condaPkgs, pypiPkgs, toDependencies(condaDepends), toDependencies(pypiDepends), nil
}

// addPackage inserts a package once (keyed by ID) and merges dependency edges
// when the same package is referenced from multiple platforms/environments.
func addPackage(out map[string]ftypes.Package, deps map[string]set.Set[string],
	pkg ftypes.Package, dependsOn set.Set[string],
) {
	if _, exists := out[pkg.ID]; !exists {
		out[pkg.ID] = pkg
	}
	if existing, ok := deps[pkg.ID]; ok {
		existing.Append(dependsOn.Items()...)
		return
	}
	deps[pkg.ID] = dependsOn
}

// buildCondaPackage turns a conda record into a Trivy package. Conda records
// carry no explicit name/version fields, so both are derived from the location
// URL/path whose basename follows `<name>-<version>-<build>.(conda|tar.bz2)`.
func buildCondaPackage(pkg Package, condaByName map[string]string) (ftypes.Package, set.Set[string], bool) {
	name, version, ok := parseCondaLocation(pkg.Conda)
	if !ok {
		// Local path dependencies or otherwise unparseable locations cannot be
		// mapped to a named package and are skipped explicitly.
		return ftypes.Package{}, nil, true
	}

	id := dependency.ID(ftypes.CondaPkg, name, version)
	out := ftypes.Package{
		ID:           id,
		Name:         name,
		Version:      version,
		Licenses:     splitLicense(pkg.License),
		Relationship: ftypes.RelationshipUnknown,
		Identifier: ftypes.PkgIdentifier{
			PURL: packageurl.NewPackageURL(packageurl.TypeConda, "", name, version, nil, ""),
		},
	}

	dependsOn := set.New[string]()
	for _, spec := range pkg.Depends {
		depName := condaDependencyName(spec)
		if depName == "" || depName == name {
			continue
		}
		// Conda dependency specs are version constraints; the concrete pinned
		// version is reached through the name index built from all records.
		// Unresolved names produce no edge, keeping the graph self-consistent.
		if depID, ok := condaByName[depName]; ok {
			dependsOn.Append(depID)
		}
	}
	return out, dependsOn, false
}

// buildPyPIPackage turns a pypi record into a Trivy package. PyPI records carry
// explicit name/version fields. Names are normalized per PEP 503 so the result
// matches the pip/uv/poetry analyzers.
func buildPyPIPackage(pkg Package, pypiByName map[string]string) (ftypes.Package, set.Set[string], bool) {
	name := python.NormalizePkgName(pkg.Name, true)
	if name == "" || pkg.Version == "" {
		// Local path/wheel entries without resolved metadata (or malformed
		// records) cannot be scanned and are skipped.
		return ftypes.Package{}, nil, true
	}

	id := dependency.ID(ftypes.Pip, name, pkg.Version)
	out := ftypes.Package{
		ID:           id,
		Name:         name,
		Version:      pkg.Version,
		Relationship: ftypes.RelationshipUnknown,
		Identifier: ftypes.PkgIdentifier{
			PURL: packageurl.NewPackageURL(packageurl.TypePyPi, "", name, pkg.Version, nil, ""),
		},
	}

	dependsOn := set.New[string]()
	for _, spec := range pkg.RequiresDist {
		depName := python.NormalizePkgName(pypiDependencyName(spec), true)
		if depName == "" || depName == name {
			continue
		}
		if depID, ok := pypiByName[depName]; ok {
			dependsOn.Append(depID)
		}
	}
	return out, dependsOn, false
}

// parseCondaLocation extracts name and version from a conda package location.
// e.g. https://prefix.dev/conda-forge/linux-64/bzip2-1.0.8-hda65f42_103.conda
//
//	-> ("bzip2", "1.0.8", true)
//
// Local paths or names not following the `<name>-<version>-<build>` layout are
// rejected so the caller applies the local-dependency skip policy.
func parseCondaLocation(loc string) (string, string, bool) {
	base := path.Base(loc)
	base = strings.TrimSuffix(base, ".conda")
	base = strings.TrimSuffix(base, ".tar.bz2")

	parts := strings.Split(base, "-")
	if len(parts) < 3 {
		return "", "", false
	}
	// Layout: <name...>-<version>-<build>; the name itself may contain dashes,
	// so the build is always the last segment and version the one before it.
	name := strings.Join(parts[:len(parts)-2], "-")
	version := parts[len(parts)-2]
	if name == "" || version == "" || name == "." || name == ".." {
		return "", "", false
	}
	return name, version, true
}

// condaDependencyName returns the package name part of a conda dependency spec
// such as "libgcc >=14" or "python_abi 3.13.* *_cp313".
func condaDependencyName(spec string) string {
	name, _, ok := strings.Cut(strings.TrimSpace(spec), " ")
	if !ok {
		return strings.TrimSpace(spec)
	}
	return strings.TrimSpace(name)
}

// pypiDependencyName returns the project name part of a PEP 508 requirement
// string such as "jinja2>=2.7" or "ruff ; extra == 'dev'". Extras
// ("package[extra]") and environment markers are stripped.
func pypiDependencyName(spec string) string {
	s := strings.TrimSpace(spec)
	if s == "" {
		return ""
	}
	if before, _, ok := strings.Cut(s, ";"); ok {
		s = strings.TrimSpace(before)
	}
	// Stop at the first version/extras delimiter.
	if idx := strings.IndexAny(s, " \t><=!~[("); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func toDependencies(deps map[string]set.Set[string]) ftypes.Dependencies {
	out := make(ftypes.Dependencies, 0, len(deps))
	for id, edgeSet := range deps {
		items := edgeSet.Items()
		if len(items) == 0 {
			continue
		}
		sort.Strings(items)
		out = append(out, ftypes.Dependency{ID: id, DependsOn: items})
	}
	// Keep nil instead of an empty slice so serialized/asserted output matches
	// the other lockfile parsers.
	if len(out) == 0 {
		return nil
	}
	sort.Sort(out)
	return out
}

// splitLicense keeps a conda license expression as a single entry, matching the
// existing conda analyzers which do not split compound SPDX expressions.
func splitLicense(license string) []string {
	if license == "" {
		return nil
	}
	return []string{license}
}
