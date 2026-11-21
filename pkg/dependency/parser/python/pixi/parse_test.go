package pixi

import (
	"os"
	"sort"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func purl(t, name, version string) *packageurl.PackageURL {
	return packageurl.NewPackageURL(t, "", name, version, nil, "")
}

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name         string
		file         string
		wantConda    ftypes.Packages
		wantPyPI     ftypes.Packages
		wantCondaDep ftypes.Dependencies
		wantPyPIDep  ftypes.Dependencies
		wantErr      string
	}{
		{
			name: "multi environment with conda and pypi packages",
			file: "testdata/pixi_multi_env.lock",
			wantConda: ftypes.Packages{
				{
					ID:           "bzip2@1.0.8",
					Name:         "bzip2",
					Version:      "1.0.8",
					Relationship: ftypes.RelationshipUnknown,
					Licenses:     []string{"bzip2-1.0.6"},
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypeConda, "bzip2", "1.0.8")},
				},
				{
					ID:           "ca-certificates@2024.12.14",
					Name:         "ca-certificates",
					Version:      "2024.12.14",
					Relationship: ftypes.RelationshipUnknown,
					Licenses:     []string{"ISC"},
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypeConda, "ca-certificates", "2024.12.14")},
				},
				{
					ID:           "openssl@3.4.0",
					Name:         "openssl",
					Version:      "3.4.0",
					Relationship: ftypes.RelationshipUnknown,
					Licenses:     []string{"Apache-2.0"},
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypeConda, "openssl", "3.4.0")},
				},
				{
					ID:           "python@3.12.3",
					Name:         "python",
					Version:      "3.12.3",
					Relationship: ftypes.RelationshipUnknown,
					Licenses:     []string{"Python-2.0"},
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypeConda, "python", "3.12.3")},
				},
			},
			wantPyPI: ftypes.Packages{
				{
					ID:           "local-wheel@0.1.0",
					Name:         "local-wheel",
					Version:      "0.1.0",
					Relationship: ftypes.RelationshipUnknown,
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypePyPi, "local-wheel", "0.1.0")},
				},
				{
					ID:           "numpy@2.2.2",
					Name:         "numpy",
					Version:      "2.2.2",
					Relationship: ftypes.RelationshipUnknown,
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypePyPi, "numpy", "2.2.2")},
				},
				{
					ID:           "six@1.17.0",
					Name:         "six",
					Version:      "1.17.0",
					Relationship: ftypes.RelationshipUnknown,
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypePyPi, "six", "1.17.0")},
				},
			},
			wantCondaDep: ftypes.Dependencies{
				{ID: "openssl@3.4.0", DependsOn: []string{"ca-certificates@2024.12.14"}},
				{ID: "python@3.12.3", DependsOn: []string{"bzip2@1.0.8", "ca-certificates@2024.12.14"}},
			},
			wantPyPIDep: ftypes.Dependencies{
				{ID: "numpy@2.2.2", DependsOn: []string{"six@1.17.0"}},
			},
		},
		{
			name: "empty lock returns nothing",
			file: "testdata/pixi_empty.lock",
		},
		{
			name: "missing packages section returns nothing",
			file: "testdata/pixi_no_packages.lock",
		},
		{
			name: "local conda path dependency is skipped but remote packages are kept",
			file: "testdata/pixi_conda_local_path.lock",
			wantConda: ftypes.Packages{
				{
					ID:           "openssl@3.4.0",
					Name:         "openssl",
					Version:      "3.4.0",
					Relationship: ftypes.RelationshipUnknown,
					Licenses:     []string{"Apache-2.0"},
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypeConda, "openssl", "3.4.0")},
				},
			},
		},
		{
			name: "same pypi package with multiple versions keeps both",
			file: "testdata/pixi_multi_version.lock",
			wantPyPI: ftypes.Packages{
				{
					ID:           "requests@2.31.0",
					Name:         "requests",
					Version:      "2.31.0",
					Relationship: ftypes.RelationshipUnknown,
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypePyPi, "requests", "2.31.0")},
				},
				{
					ID:           "requests@2.32.3",
					Name:         "requests",
					Version:      "2.32.3",
					Relationship: ftypes.RelationshipUnknown,
					Identifier:   ftypes.PkgIdentifier{PURL: purl(packageurl.TypePyPi, "requests", "2.32.3")},
				},
			},
		},
		{
			name:    "broken YAML returns a decode error",
			file:    "testdata/pixi_broken.lock",
			wantErr: "failed to decode pixi lock file",
		},
		{
			name:    "non UTF-8 content returns a decode error",
			file:    "testdata/pixi_non_utf8.lock",
			wantErr: "failed to decode pixi lock file",
		},
		{
			name:    "version newer than supported is rejected",
			file:    "testdata/pixi_unsupported_version.lock",
			wantErr: "unsupported pixi lock file version 99: maximum supported version is 7",
		},
		{
			name:    "legacy version is rejected",
			file:    "testdata/pixi_legacy_version.lock",
			wantErr: "unsupported pixi lock file version 3: minimum supported version is 4",
		},
		{
			name:    "missing version field is rejected",
			file:    "testdata/pixi_missing_version.lock",
			wantErr: "pixi lock file must contain a `version` field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)
			defer f.Close()

			gotConda, gotPyPI, gotCondaDep, gotPyPIDep, err := NewParser().Parse(t.Context(), f)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantConda, gotConda)
			assert.Equal(t, tt.wantPyPI, gotPyPI)
			assert.Equal(t, tt.wantCondaDep, gotCondaDep)
			assert.Equal(t, tt.wantPyPIDep, gotPyPIDep)
		})
	}
}

func TestParser_Parse_RealWorldLock(t *testing.T) {
	// A trimmed, real-world pixi.lock (v7) containing hundreds of conda records
	// across five platforms plus PyPI records and multiple environments.
	f, err := os.Open("testdata/pixi_realworld.lock")
	require.NoError(t, err)
	defer f.Close()

	condaPkgs, pypiPkgs, condaDeps, pypiDeps, err := NewParser().Parse(t.Context(), f)
	require.NoError(t, err)
	require.NotEmpty(t, condaPkgs)
	require.NotEmpty(t, pypiPkgs)

	// Every emitted package must carry a PURL matching its ecosystem.
	for _, pkg := range condaPkgs {
		require.NotNil(t, pkg.Identifier.PURL)
		assert.Equal(t, packageurl.TypeConda, pkg.Identifier.PURL.Type)
		assert.NotEmpty(t, pkg.Name)
		assert.NotEmpty(t, pkg.Version)
	}
	for _, pkg := range pypiPkgs {
		require.NotNil(t, pkg.Identifier.PURL)
		assert.Equal(t, packageurl.TypePyPi, pkg.Identifier.PURL.Type)
		assert.NotEmpty(t, pkg.Name)
		assert.NotEmpty(t, pkg.Version)
	}

	// Package IDs are unique and output is sorted.
	condaIDs := make(map[string]struct{}, len(condaPkgs))
	for _, pkg := range condaPkgs {
		_, dup := condaIDs[pkg.ID]
		assert.False(t, dup, "duplicate conda package ID: %s", pkg.ID)
		condaIDs[pkg.ID] = struct{}{}
	}
	pypiIDs := make(map[string]struct{}, len(pypiPkgs))
	for _, pkg := range pypiPkgs {
		_, dup := pypiIDs[pkg.ID]
		assert.False(t, dup, "duplicate pypi package ID: %s", pkg.ID)
		pypiIDs[pkg.ID] = struct{}{}
	}
	// Output is sorted according to the canonical package ordering.
	assert.True(t, sort.SliceIsSorted(condaPkgs, func(i, j int) bool {
		return condaPkgs.Less(i, j)
	}))
	assert.True(t, sort.SliceIsSorted(pypiPkgs, func(i, j int) bool {
		return pypiPkgs.Less(i, j)
	}))

	// Every dependency edge must point at an emitted package in the same ecosystem.
	for _, dep := range condaDeps {
		assert.Contains(t, condaIDs, dep.ID)
		for _, target := range dep.DependsOn {
			assert.Contains(t, condaIDs, target)
		}
	}
	for _, dep := range pypiDeps {
		assert.Contains(t, pypiIDs, dep.ID)
		for _, target := range dep.DependsOn {
			assert.Contains(t, pypiIDs, target)
		}
	}
}

func TestParseCondaLocation(t *testing.T) {
	tests := []struct {
		loc        string
		wantName   string
		wantVer    string
		wantParsed bool
	}{
		{
			loc:        "https://prefix.dev/conda-forge/linux-64/bzip2-1.0.8-hda65f42_103.conda",
			wantName:   "bzip2",
			wantVer:    "1.0.8",
			wantParsed: true,
		},
		{
			loc:        "https://conda.anaconda.org/conda-forge/noarch/ca-certificates-2024.12.14-hbcca054_0.tar.bz2",
			wantName:   "ca-certificates",
			wantVer:    "2024.12.14",
			wantParsed: true,
		},
		{
			loc:        "https://prefix.dev/conda-forge/linux-64/libstdcxx-ng-14.2.0-h77fa898_1.conda",
			wantName:   "libstdcxx-ng",
			wantVer:    "14.2.0",
			wantParsed: true,
		},
		{
			loc:        "./local-pkgs/foo",
			wantParsed: false,
		},
		{
			// A basename without the <name>-<version>-<build> layout cannot be
			// decomposed into name/version.
			loc:        "https://example.com/single-segment.conda",
			wantParsed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.loc, func(t *testing.T) {
			name, version, ok := parseCondaLocation(tt.loc)
			assert.Equal(t, tt.wantParsed, ok)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVer, version)
		})
	}
}

func TestPypiDependencyName(t *testing.T) {
	tests := map[string]string{
		"jinja2>=2.7":             "jinja2",
		"verspec":                 "verspec",
		"ruff ; extra == 'dev'":   "ruff",
		"coverage[toml]":          "coverage",
		"charset-normalizer (<4)": "charset-normalizer",
		"":                        "",
	}
	for spec, want := range tests {
		t.Run(spec, func(t *testing.T) {
			assert.Equal(t, want, pypiDependencyName(spec))
		})
	}
}
