package pixi_test

import (
	"os"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pixi"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func purl(purlType, name, version string) *packageurl.PackageURL {
	return packageurl.NewPackageURL(purlType, "", name, version, nil, "")
}

func Test_pixiAnalyzer_PostAnalyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path emits separate conda and pypi applications",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.CondaPkg,
						FilePath: "pixi.lock",
						Packages: types.Packages{
							{
								ID:           "bzip2@1.0.8",
								Name:         "bzip2",
								Version:      "1.0.8",
								Relationship: types.RelationshipUnknown,
								Licenses:     []string{"bzip2-1.0.6"},
								Identifier:   types.PkgIdentifier{PURL: purl(packageurl.TypeConda, "bzip2", "1.0.8")},
							},
						},
					},
					{
						Type:     types.Pip,
						FilePath: "pixi.lock",
						Packages: types.Packages{
							{
								ID:           "requests@2.32.3",
								Name:         "requests",
								Version:      "2.32.3",
								Relationship: types.RelationshipUnknown,
								Identifier:   types.PkgIdentifier{PURL: purl(packageurl.TypePyPi, "requests", "2.32.3")},
							},
						},
					},
				},
			},
		},
		{
			// A broken lock file is logged and skipped without failing the scan.
			name: "broken lock file is skipped",
			dir:  "testdata/broken",
			want: &analyzer.AnalysisResult{},
		},
		{
			// Non-UTF-8 content cannot be decoded and is skipped, not fatal.
			name: "non UTF-8 file is skipped",
			dir:  "testdata/non-utf8",
			want: &analyzer.AnalysisResult{},
		},
		{
			// The analyzer only claims pixi.lock; an adjacent uv.lock is left
			// to the uv analyzer, so the same directory is not double-reported.
			name: "coexists with uv lock without claiming it",
			dir:  "testdata/coexist",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pip,
						FilePath: "pixi.lock",
						Packages: types.Packages{
							{
								ID:           "click@8.1.7",
								Name:         "click",
								Version:      "8.1.7",
								Relationship: types.RelationshipUnknown,
								Identifier:   types.PkgIdentifier{PURL: purl(packageurl.TypePyPi, "click", "8.1.7")},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := pixi.NewPixiAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pixiAnalyzer_Required(t *testing.T) {
	a, err := pixi.NewPixiAnalyzer(analyzer.AnalyzerOptions{})
	require.NoError(t, err)

	tests := []struct {
		filePath string
		want     bool
	}{
		{filePath: "pixi.lock", want: true},
		{filePath: "some/dir/pixi.lock", want: true},
		{filePath: "uv.lock", want: false},
		{filePath: "pixi.toml", want: false},
		{filePath: "requirements.txt", want: false},
		{filePath: "pixi.lock.bak", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.filePath, func(t *testing.T) {
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}

func Test_pixiAnalyzer_Type(t *testing.T) {
	a, err := pixi.NewPixiAnalyzer(analyzer.AnalyzerOptions{})
	require.NoError(t, err)
	assert.Equal(t, analyzer.TypePixi, a.Type())
	assert.Equal(t, 1, a.Version())
}
