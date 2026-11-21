package pixi

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/xerrors"

	pixiparser "github.com/aquasecurity/trivy/pkg/dependency/parser/python/pixi"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePixi, NewPixiAnalyzer)
}

const version = 1

// parsedLock holds the packages of one pixi.lock split by ecosystem together
// with their dependency graphs.
type parsedLock struct {
	condaPkgs types.Packages
	pypiPkgs  types.Packages
	condaDeps types.Dependencies
	pypiDeps  types.Dependencies
}

type pixiAnalyzer struct {
	logger     *log.Logger
	lockParser *pixiparser.Parser
}

func NewPixiAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &pixiAnalyzer{
		logger:     log.WithPrefix("pixi"),
		lockParser: pixiparser.NewParser(),
	}, nil
}

// parse adapts the walk reader to a ReadSeekerAt and runs the lock parser.
func (a *pixiAnalyzer) parse(ctx context.Context, r io.Reader) (*parsedLock, error) {
	rr, err := xio.NewReadSeekerAt(r)
	if err != nil {
		return nil, xerrors.Errorf("reader error: %w", err)
	}
	condaPkgs, pypiPkgs, condaDeps, pypiDeps, err := a.lockParser.Parse(ctx, rr)
	if err != nil {
		return nil, err
	}
	if len(condaPkgs) == 0 && len(pypiPkgs) == 0 {
		return nil, nil
	}
	return &parsedLock{
		condaPkgs: condaPkgs,
		pypiPkgs:  pypiPkgs,
		condaDeps: condaDeps,
		pypiDeps:  pypiDeps,
	}, nil
}

func (a *pixiAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(_ string, _ fs.DirEntry) bool {
		// The Required func already limits the walk to pixi.lock files;
		// honor additional file patterns from the analysis options as well.
		return true
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		parsed, err := a.parse(ctx, r)
		if err != nil {
			// A broken/unsupported pixi.lock is reported and skipped, never fatal.
			a.logger.Warn("Failed to parse pixi lockfile", log.FilePath(filePath), log.Err(err))
			return nil
		}
		if parsed == nil {
			return nil
		}

		// One pixi.lock spans two ecosystems. Vulnerability detection and PURL
		// generation are dispatched from the application type, so conda and
		// PyPI packages are emitted as separate applications over the same file.
		if app := language.ToApplication(types.CondaPkg, filePath, parsed.condaPkgs, parsed.condaDeps); app != nil {
			apps = append(apps, *app)
		}
		if app := language.ToApplication(types.Pip, filePath, parsed.pypiPkgs, parsed.pypiDeps); app != nil {
			apps = append(apps, *app)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("pixi walk error: %w", err)
	}

	// Deterministic output regardless of filesystem walk order.
	sort.Sort(types.Applications(apps))

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a *pixiAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.PixiLock
}

func (a *pixiAnalyzer) Type() analyzer.Type {
	return analyzer.TypePixi
}

func (a *pixiAnalyzer) Version() int {
	return version
}
