package versioncatalog

import (
	"errors"
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
		wantErr   error
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.versions.toml",
			want: []ftypes.Package{
				{
					ID:           "com.example:rich:1.0",
					Name:         "com.example:rich",
					Version:      "1.0",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 13, EndLine: 13}},
				},
				{
					ID:           "com.example:strict:2.0",
					Name:         "com.example:strict",
					Version:      "2.0",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 14, EndLine: 14}},
				},
				{
					ID:           "com.google.guava:guava:32.1.3-jre",
					Name:         "com.google.guava:guava",
					Version:      "32.1.3-jre",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 9, EndLine: 9}},
				},
				{
					ID:           "junit:junit:4.13.2",
					Name:         "junit:junit",
					Version:      "4.13.2",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 8, EndLine: 8}},
				},
				{
					ID:           "org.apache.commons:commons-lang3:3.14.0",
					Name:         "org.apache.commons:commons-lang3",
					Version:      "3.14.0",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 11, EndLine: 11}},
				},
				{
					ID:           "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin:1.9.23",
					Name:         "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin",
					Version:      "1.9.23",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 21, EndLine: 21}},
				},
				{
					ID:           "org.mockito:mockito-core:5.5.0",
					Name:         "org.mockito:mockito-core",
					Version:      "5.5.0",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 10, EndLine: 10}},
				},
				{
					ID:           "org.slf4j:slf4j-api:2.0.9",
					Name:         "org.slf4j:slf4j-api",
					Version:      "2.0.9",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 12, EndLine: 12}},
				},
				{
					ID:           "org.springframework.boot:org.springframework.boot.gradle.plugin:3.2.4",
					Name:         "org.springframework.boot:org.springframework.boot.gradle.plugin",
					Version:      "3.2.4",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 22, EndLine: 22}},
				},
			},
		},
		{
			name:      "nested aliases",
			inputFile: "testdata/nested.versions.toml",
			want: []ftypes.Package{
				{
					ID:           "commons-io:commons-io:2.15.1",
					Name:         "commons-io:commons-io",
					Version:      "2.15.1",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 5, EndLine: 5}},
				},
				{
					ID:           "org.codehaus.groovy:groovy:3.0.21",
					Name:         "org.codehaus.groovy:groovy",
					Version:      "3.0.21",
					Relationship: ftypes.RelationshipDirect,
					Locations:    []ftypes.Location{{StartLine: 2, EndLine: 2}},
				},
			},
		},
		{
			name:      "empty catalog",
			inputFile: "testdata/empty.versions.toml",
			want:      nil,
		},
		{
			name:      "invalid TOML",
			inputFile: "testdata/invalid.versions.toml",
			wantErr:   ErrInvalidTOML,
		},
		{
			name:      "circular version reference",
			inputFile: "testdata/circular.versions.toml",
			wantErr:   ErrCircularReference,
		},
		{
			name:      "unknown version reference",
			inputFile: "testdata/unknown-ref.versions.toml",
			wantErr:   ErrUnknownReference,
		},
		{
			name:      "unknown bundle alias",
			inputFile: "testdata/unknown-bundle-alias.versions.toml",
			wantErr:   ErrUnknownReference,
		},
		{
			name:      "missing group/name",
			inputFile: "testdata/missing-field.versions.toml",
			wantErr:   ErrMissingField,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			pkgs, _, err := NewParser().Parse(t.Context(), f)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				// The four failure modes must be distinguishable from each other.
				for _, other := range []error{ErrInvalidTOML, ErrCircularReference, ErrMissingField, ErrUnknownReference} {
					if !errors.Is(tt.wantErr, other) {
						require.NotErrorIs(t, err, other)
					}
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, pkgs)
		})
	}
}
