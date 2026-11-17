package gradle

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_gradleVersionCatalogAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path: catalog merged with build.gradle.kts",
			dir:  "testdata/versioncatalog/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Gradle,
						FilePath: "gradle/libs.versions.toml",
						Packages: types.Packages{
							{
								ID:           "com.google.guava:guava:32.1.3-jre",
								Name:         "com.google.guava:guava",
								Version:      "32.1.3-jre",
								Relationship: types.RelationshipDirect,
								Locations:    []types.Location{{StartLine: 6, EndLine: 6}},
							},
							{
								ID:           "junit:junit:4.13.2",
								Name:         "junit:junit",
								Version:      "4.13.2",
								Relationship: types.RelationshipDirect,
								Locations:    []types.Location{{StartLine: 5, EndLine: 5}},
							},
							{
								ID:           "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin:1.9.23",
								Name:         "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin",
								Version:      "1.9.23",
								Relationship: types.RelationshipDirect,
								Locations:    []types.Location{{StartLine: 9, EndLine: 9}},
							},
							{
								ID:           "org.mockito:mockito-core:5.5.0",
								Name:         "org.mockito:mockito-core",
								Version:      "5.5.0",
								Dev:          true,
								Relationship: types.RelationshipDirect,
								Locations:    []types.Location{{StartLine: 3, EndLine: 3}},
							},
						},
					},
				},
			},
		},
		{
			name: "catalog without build file",
			dir:  "testdata/versioncatalog/catalog-only",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Gradle,
						FilePath: "gradle/libs.versions.toml",
						Packages: types.Packages{
							{
								ID:           "org.slf4j:slf4j-api:2.0.9",
								Name:         "org.slf4j:slf4j-api",
								Version:      "2.0.9",
								Relationship: types.RelationshipDirect,
								Locations:    []types.Location{{StartLine: 2, EndLine: 2}},
							},
						},
					},
				},
			},
		},
		{
			name: "broken catalog still yields build file dependencies",
			dir:  "testdata/versioncatalog/broken",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Gradle,
						FilePath: "gradle/libs.versions.toml",
						Packages: types.Packages{
							{
								ID:           "org.apache.commons:commons-lang3:3.14.0",
								Name:         "org.apache.commons:commons-lang3",
								Version:      "3.14.0",
								Relationship: types.RelationshipDirect,
								Locations:    []types.Location{{StartLine: 2, EndLine: 2}},
							},
						},
					},
				},
			},
		},
		{
			name: "no catalog",
			dir:  "testdata/lockfiles/happy",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newGradleVersionCatalogAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_gradleVersionCatalogAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "default catalog location",
			filePath: "gradle/libs.versions.toml",
			want:     true,
		},
		{
			name:     "custom catalog name",
			filePath: "gradle/deps.versions.toml",
			want:     true,
		},
		{
			name:     "build file does not trigger the analyzer",
			filePath: "build.gradle.kts",
			want:     false,
		},
		{
			name:     "other toml file",
			filePath: "gradle/wrapper.toml",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gradleVersionCatalogAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
