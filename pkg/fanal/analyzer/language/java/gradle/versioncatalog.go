package gradle

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/gradle/buildfile"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/gradle/versioncatalog"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeGradleVersionCatalog, newGradleVersionCatalogAnalyzer)
}

const gradleVersionCatalogVersion = 1

// gradleVersionCatalogAnalyzer analyzes Gradle version catalogs ('*.versions.toml')
// and merges them with dependencies declared in 'build.gradle(.kts)' files of the
// same project.
type gradleVersionCatalogAnalyzer struct {
	logger        *log.Logger
	catalogParser language.Parser
	buildParser   language.Parser
}

func newGradleVersionCatalogAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &gradleVersionCatalogAnalyzer{
		logger:        log.WithPrefix("gradle"),
		catalogParser: versioncatalog.NewParser(),
		buildParser:   buildfile.NewParser(),
	}, nil
}

func (a gradleVersionCatalogAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var catalogPaths, buildPaths []string
	required := func(filePath string, _ fs.DirEntry) bool {
		return isVersionCatalog(filePath) || isBuildFile(filePath)
	}
	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, _ io.Reader) error {
		if isVersionCatalog(filePath) {
			catalogPaths = append(catalogPaths, filePath)
		} else {
			buildPaths = append(buildPaths, filePath)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	// Group catalogs by project root: a catalog living in a 'gradle' directory
	// belongs to the parent directory, otherwise to its own directory.
	catalogsByRoot := make(map[string][]string)
	for _, p := range catalogPaths {
		root := projectRoot(p)
		catalogsByRoot[root] = append(catalogsByRoot[root], p)
	}

	// Assign each build file to the nearest ancestor project root.
	buildsByRoot := make(map[string][]string)
	for _, p := range buildPaths {
		if root, ok := nearestRoot(path.Dir(p), catalogsByRoot); ok {
			buildsByRoot[root] = append(buildsByRoot[root], p)
		}
	}

	roots := make([]string, 0, len(catalogsByRoot))
	for root := range catalogsByRoot {
		roots = append(roots, root)
	}
	sort.Strings(roots)

	var apps []types.Application
	for _, root := range roots {
		// Deterministic parse order: catalogs first (sorted), then build files (sorted).
		catalogs := catalogsByRoot[root]
		sort.Strings(catalogs)
		builds := buildsByRoot[root]
		sort.Strings(builds)

		seen := make(map[string]struct{})
		var pkgs types.Packages
		merge := func(filePath string, parser language.Parser) {
			app, err := a.parse(ctx, input.FS, filePath, parser)
			if err != nil {
				a.logger.Warn("Unable to parse the Gradle file", log.FilePath(filePath), log.Err(err))
				return
			}
			if app == nil {
				return
			}
			for _, pkg := range app.Packages {
				if _, ok := seen[pkg.ID]; ok {
					continue // deduplicate packages declared in multiple files
				}
				seen[pkg.ID] = struct{}{}
				pkgs = append(pkgs, pkg)
			}
		}

		for _, p := range catalogs {
			merge(p, a.catalogParser)
		}
		for _, p := range builds {
			merge(p, a.buildParser)
		}

		if len(pkgs) == 0 {
			continue
		}

		// Stable report order
		sort.Sort(pkgs)
		apps = append(apps, types.Application{
			Type:     types.Gradle,
			FilePath: catalogs[0],
			Packages: pkgs,
		})
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a gradleVersionCatalogAnalyzer) parse(ctx context.Context, fsys fs.FS, filePath string, parser language.Parser) (*types.Application, error) {
	f, err := fsys.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("open error: %w", err)
	}
	defer f.Close()

	app, err := language.Parse(ctx, types.Gradle, filePath, f, parser)
	if err != nil {
		return nil, xerrors.Errorf("%s parse error: %w", filePath, err)
	}
	return app, nil
}

func (a gradleVersionCatalogAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Only version catalogs trigger this analyzer. Build files are picked up
	// during the post-analysis walk when a catalog exists.
	return isVersionCatalog(filePath)
}

func (a gradleVersionCatalogAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGradleVersionCatalog
}

func (a gradleVersionCatalogAnalyzer) Version() int {
	return gradleVersionCatalogVersion
}

// isVersionCatalog reports whether the file is a Gradle version catalog,
// e.g. 'gradle/libs.versions.toml'.
func isVersionCatalog(filePath string) bool {
	return strings.HasSuffix(path.Base(filePath), ".versions.toml")
}

func isBuildFile(filePath string) bool {
	base := path.Base(filePath)
	return base == "build.gradle" || base == "build.gradle.kts"
}

// projectRoot returns the directory a version catalog belongs to:
// the parent directory for catalogs in a conventional 'gradle' directory,
// otherwise the catalog's own directory.
func projectRoot(catalogPath string) string {
	dir := path.Dir(catalogPath)
	if path.Base(dir) == "gradle" {
		return path.Dir(dir)
	}
	return dir
}

// nearestRoot finds the closest ancestor directory of dir that is a project root.
func nearestRoot(dir string, roots map[string][]string) (string, bool) {
	for d := dir; ; d = path.Dir(d) {
		if _, ok := roots[d]; ok {
			return d, true
		}
		parent := path.Dir(d)
		if parent == d {
			return "", false
		}
	}
}
