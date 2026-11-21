package pixi

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// buildLargeLock builds a pixi.lock document larger than 10MB with the given
// number of package records, split evenly between conda and PyPI packages.
func buildLargeLock(n int) []byte {
	var b strings.Builder
	b.WriteString("version: 7\n")
	b.WriteString("environments:\n  default:\n    packages:\n      linux-64:\n")
	for i := range n {
		if i%2 == 0 {
			fmt.Fprintf(&b, "      - conda: https://example.com/linux-64/pkg-%d-1.2.3-h0_0.conda\n", i)
		} else {
			fmt.Fprintf(&b, "      - pypi: https://files.pythonhosted.org/packages/%d/pkg-%d-1.2.3-py3-none-any.whl\n", i, i)
		}
	}
	b.WriteString("packages:\n")
	for i := range n {
		if i%2 == 0 {
			fmt.Fprintf(&b, "- conda: https://example.com/linux-64/pkg-%d-1.2.3-h0_0.conda\n", i)
			fmt.Fprintf(&b, "  sha256: %064d\n  license: MIT\n  depends:\n  - pkg-%d >=1.0\n", i, (i+2)/2*2)
		} else {
			fmt.Fprintf(&b, "- pypi: https://files.pythonhosted.org/packages/%d/pkg-%d-1.2.3-py3-none-any.whl\n", i, i)
			// PyPI records use odd indexes; depend on the previous odd record so
			// the edge resolves within the PyPI name index.
			dep := i - 2
			if dep < 1 {
				dep = i
			}
			fmt.Fprintf(&b, "  name: pkg-%d\n  version: 1.2.3\n  requires_dist:\n  - pkg-%d>=1.0\n", i, dep)
		}
	}
	return []byte(b.String())
}

func TestParser_LargeLock(t *testing.T) {
	// 40k records produce a document larger than 10 MB (decimal).
	data := buildLargeLock(40000)
	const tenMB = 10_000_000
	if size := len(data); size < tenMB {
		t.Fatalf("synthetic lock too small for the perf target: %d bytes", size)
	}
	t.Logf("synthetic lock size: %.2f MB", float64(len(data))/(1024*1024))

	r := bytes.NewReader(data)
	condaPkgs, pypiPkgs, condaDeps, pypiDeps, err := NewParser().Parse(context.Background(), r)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(condaPkgs) == 0 || len(pypiPkgs) == 0 {
		t.Fatalf("expected both ecosystems populated, got conda=%d pypi=%d", len(condaPkgs), len(pypiPkgs))
	}
	if len(condaDeps) == 0 || len(pypiDeps) == 0 {
		t.Fatalf("expected dependency graphs, got condaDeps=%d pypiDeps=%d", len(condaDeps), len(pypiDeps))
	}
	// Output must be sorted and de-duplicated.
	if !sort.SliceIsSorted(condaPkgs, func(i, j int) bool { return condaPkgs.Less(i, j) }) ||
		!sort.SliceIsSorted(pypiPkgs, func(i, j int) bool { return pypiPkgs.Less(i, j) }) {
		t.Fatal("packages are not sorted")
	}
}

func BenchmarkParser_Parse(b *testing.B) {
	data := buildLargeLock(40000)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		r := bytes.NewReader(data)
		if _, _, _, _, err := NewParser().Parse(context.Background(), r); err != nil {
			b.Fatal(err)
		}
	}
}
