// The upstream check on a recorded provenance map: the canon's pinned
// postgres:14-bookworm (index sha256:a54c8b1e…, read anonymously from
// Docker Hub on 2026-11-17), its five platforms' BuildKit provenance
// statements as served, trimmed of `buildConfig` and `metadata` —
// 400 KB of BuildKit build steps nothing here reads. Every row breaks
// one thing about that real map and asserts the message.

package baseimage_test

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/baseimage"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/oci"
)

const (
	pgRef        = "postgres:14-bookworm@sha256:a54c8b1e143b22f16b0fd3e249e9297a6f08828a143ee7108b1b5ca51f352765"
	pgRepository = "https://github.com/docker-library/postgres.git"
	pgSource     = pgRepository + "#9becbc9ded0ca27f7ff26af6a0b1a380035a55b9:14/bookworm"
)

// recorded reads the recorded map as the reader returns it: every
// platform, in platform order, with its one provenance statement.
func recorded(t *testing.T) []oci.PlatformStatements {
	t.Helper()

	raw, err := os.ReadFile("testdata/postgres-14-bookworm.provenance.json")
	if err != nil {
		t.Fatal(err)
	}

	m, err := jsonx.DecodeForeign[map[string]jsonx.Raw](raw)
	if err != nil {
		t.Fatal(err)
	}

	var out []oci.PlatformStatements

	for _, platform := range slices.Sorted(func(yield func(string) bool) {
		for k := range *m {
			if !yield(k) {
				return
			}
		}
	}) {
		out = append(out, oci.PlatformStatements{Platform: platform, Statements: [][]byte{(*m)[platform]}})
	}

	return out
}

func TestJudgeUpstreamConforms(t *testing.T) {
	t.Parallel()

	facts, err := baseimage.JudgeUpstream(pgRef, recorded(t), pgRepository, "14/bookworm")
	if err != nil {
		t.Fatalf("JudgeUpstream = %v", err)
	}

	// The predicate's facts, as the shell's jq rendered them: one
	// source (every platform built from one commit), the platforms
	// sorted, and the provenance type read.
	got, err := jsonx.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}

	want := `{"sources":["` + pgSource + `"],"platforms":["linux/386","linux/amd64","linux/arm/v7",` +
		`"linux/arm64/v8","linux/ppc64le"],"provenanceType":"https://slsa.dev/provenance/v0.2"}`
	if string(got) != want {
		t.Fatalf("facts =\n%s\nwant\n%s", got, want)
	}
}

func TestJudgeUpstreamRefusals(t *testing.T) {
	t.Parallel()

	rec := recorded(t)

	// clone copies the recorded map, so a row's edit touches only its own.
	clone := func() []oci.PlatformStatements {
		out := make([]oci.PlatformStatements, len(rec))
		for i := range rec {
			out[i] = oci.PlatformStatements{Platform: rec[i].Platform, Statements: slices.Clone(rec[i].Statements)}
		}

		return out
	}

	// edit replaces one platform's statement on a fresh copy.
	edit := func(platform, from, to string) []oci.PlatformStatements {
		ps := clone()
		for i := range ps {
			if ps[i].Platform == platform {
				ps[i].Statements = [][]byte{[]byte(strings.Replace(string(ps[i].Statements[0]), from, to, 1))}
			}
		}

		return ps
	}

	// with sets one platform's statements on a fresh copy.
	with := func(i int, statements [][]byte) []oci.PlatformStatements {
		ps := clone()
		ps[i].Statements = statements

		return ps
	}

	tests := []struct {
		name      string
		platforms []oci.PlatformStatements
		directory string
		want      string
	}{
		{
			// .github#212: every platform is asserted, never one —
			// a check of the first platform alone would pass this.
			name:      "one platform names another path",
			platforms: edit("linux/ppc64le", ":14/bookworm", ":14/bullseye"),
			want: pgRef + ": linux/ppc64le's provenance names " + pgRepository +
				"#9becbc9ded0ca27f7ff26af6a0b1a380035a55b9:14/bullseye, not " + pgRepository +
				" at 14/bookworm — refusing to attest a verification that failed",
		},
		{
			name: "one platform names another repository",
			platforms: edit("linux/amd64", pgSource,
				strings.Replace(pgSource, "docker-library/postgres", "someone/postgres", 1)),
			want: "linux/amd64's provenance names https://github.com/someone/postgres.git#",
		},
		{
			name:      "a directory that only ends like the expected one",
			platforms: clone(),
			directory: "4/bookworm",
			want:      "not " + pgRepository + " at 4/bookworm",
		},
		{
			name:      "none published",
			platforms: []oci.PlatformStatements{{Platform: "linux/amd64"}},
			want:      pgRef + ": upstream publishes no provenance — refusing to verify nothing",
		},
		{
			name:      "an index with no platforms at all",
			platforms: nil,
			want:      pgRef + ": upstream publishes no provenance — refusing to verify nothing",
		},
		{
			// The shell's own comment promised this and its jq never
			// held it: a platform missing from the provenance map was
			// simply not iterated.
			name:      "one platform carries none",
			platforms: with(2, nil),
			want:      pgRef + ": linux/arm/v7 carries no provenance — an unverifiable base is a red run",
		},
		{
			name:      "a statement that is not one",
			platforms: with(0, [][]byte{[]byte("{")}),
			want:      pgRef + ": linux/386: the provenance is not a statement",
		},
		{
			name:      "another predicate type",
			platforms: edit("linux/386", "https://slsa.dev/provenance/v0.2", "https://spdx.dev/Document"),
			want:      pgRef + ": linux/386: the provenance is not https://slsa.dev/provenance/v0.2",
		},
		{
			name:      "no config source",
			platforms: edit("linux/386", `"configSource"`, `"configElsewhere"`),
			want:      pgRef + ": linux/386: the provenance names no config source",
		},
		{
			name:      "a config source that is not a git context",
			platforms: edit("linux/386", pgSource, "https://github.com/docker-library/postgres.git"),
			want:      "linux/386's provenance names https://github.com/docker-library/postgres.git, not",
		},
		{
			name:      "a git context naming no directory",
			platforms: edit("linux/386", ":14/bookworm", ""),
			want:      "linux/386's provenance names " + pgRepository + "#9becbc9ded0ca27f7ff26af6a0b1a380035a55b9, not",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			directory := tt.directory
			if directory == "" {
				directory = "14/bookworm"
			}

			facts, err := baseimage.JudgeUpstream(pgRef, tt.platforms, pgRepository, directory)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("JudgeUpstream = %+v, %v; want the refusal %q", facts, err, tt.want)
			}
		})
	}
}
