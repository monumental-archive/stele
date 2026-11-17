package level_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/level"
)

// TestTheReportCountsAnIgnoredFilter (stele#384): a source history a
// remote served without the commits-only filter is the same history,
// so nothing judges it — the report counts it beside the verdict, and
// says nothing at all where no history was fetched.
func TestTheReportCountsAnIgnoredFilter(t *testing.T) {
	t.Parallel()

	fetched := func(ignored bool) *level.Evidence {
		ev := sourceEvidence(wholeChain(t), restrictive())
		ev.HistoryFetch = &level.HistoryFetch{FilterIgnored: ignored}

		return ev
	}

	encode := func(a *level.Assessment) string {
		t.Helper()

		var buf bytes.Buffer
		if err := a.Report().Encode(&buf); err != nil {
			t.Fatalf("Encode = %v", err)
		}

		return buf.String()
	}

	for _, tc := range []struct {
		name string
		a    *level.Assessment
		want string
	}{
		{
			name: "a fetch whose filter held",
			a:    level.Assess(level.TrackSource, fetched(false)),
			want: `{"name":"gitFilterIgnored","value":"0"}`,
		},
		{
			name: "a fetch whose remote ignored the filter",
			a:    level.Assess(level.TrackSource, fetched(true)),
			want: `{"name":"gitFilterIgnored","value":"1"}`,
		},
		{
			name: "a population counts its members' ignored filters",
			a: level.AssessPopulation(level.TrackSource, []*level.Evidence{
				fetched(true), fetched(false), sourceEvidence(wholeChain(t), restrictive()), fetched(true),
			}, nil, fetched(false).Now),
			want: `{"name":"gitFilterIgnored","value":"2"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if doc := encode(tc.a); !strings.Contains(doc, tc.want) {
				t.Fatalf("the report does not carry %s:\n%s", tc.want, doc)
			}
		})
	}

	t.Run("no history fetched, no fact", func(t *testing.T) {
		t.Parallel()

		doc := encode(level.Assess(level.TrackSource, sourceEvidence(wholeChain(t), restrictive())))
		if strings.Contains(doc, "gitFilterIgnored") {
			t.Fatalf("a run that fetched nothing counted a fetch:\n%s", doc)
		}
	})
}
