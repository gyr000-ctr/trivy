package buildfile

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []ftypes.Package
	}{
		{
			name:      "Groovy DSL",
			inputFile: "testdata/happy.gradle",
			want: []ftypes.Package{
				{
					ID:           "com.google.guava:guava:32.1.3-jre",
					Name:         "com.google.guava:guava",
					Version:      "32.1.3-jre",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 7, EndLine: 7}},
				},
				{
					ID:           "junit:junit:4.13.2",
					Name:         "junit:junit",
					Version:      "4.13.2",
					Dev:          true,
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 8, EndLine: 8}},
				},
				{
					ID:           "org.apache.commons:commons-lang3:3.14.0",
					Name:         "org.apache.commons:commons-lang3",
					Version:      "3.14.0",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 6, EndLine: 6}},
				},
				{
					ID:           "org.slf4j:slf4j-api:2.0.9",
					Name:         "org.slf4j:slf4j-api",
					Version:      "2.0.9",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 9, EndLine: 9}},
				},
			},
		},
		{
			name:      "Kotlin DSL",
			inputFile: "testdata/happy.gradle.kts",
			want: []ftypes.Package{
				{
					ID:           "junit:junit:4.13.2",
					Name:         "junit:junit",
					Version:      "4.13.2",
					Dev:          true,
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 7, EndLine: 7}},
				},
				{
					ID:           "org.apache.commons:commons-lang3:3.14.0",
					Name:         "org.apache.commons:commons-lang3",
					Version:      "3.14.0",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 6, EndLine: 6}},
				},
				{
					ID:           "org.slf4j:slf4j-api:2.0.9",
					Name:         "org.slf4j:slf4j-api",
					Version:      "2.0.9",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 8, EndLine: 8}},
				},
			},
		},
		{
			name:      "no dependencies",
			inputFile: "testdata/empty.gradle",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			pkgs, _, err := NewParser().Parse(t.Context(), f)
			require.NoError(t, err)
			assert.Equal(t, tt.want, pkgs)
		})
	}
}
