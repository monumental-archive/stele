// The repro comparison's table (stele#96): every divergence kind one
// fact at a time, the clean pass, and the ordering contract.
//
// The judged set and the published set are one here unless a row says
// otherwise, which is the unscoped release: what is under test and
// what the release shipped are the same artifacts. A scoped judgment
// separates them (stele#223), and the row that does carries its own
// reason.

package verify_test

import (
	"reflect"
	"testing"

	"github.com/monumental-archive/stele/internal/verify"
)

func TestRepro(t *testing.T) {
	t.Parallel()

	released := []verify.Subject{
		{Name: "stele_linux_amd64.tar.gz", SHA256: "aa"},
		{Name: "stele_darwin_arm64.tar.gz", SHA256: "bb"},
		{Name: "checksums.txt", SHA256: "cc"},
	}

	for _, tc := range []struct {
		name    string
		rebuilt []verify.Subject
		// published defaults to the judged set — the unscoped release.
		published []verify.Subject
		want      []verify.ReproDivergence
	}{
		{
			name: "clean reproduction",
			rebuilt: []verify.Subject{
				{Name: "stele_linux_amd64.tar.gz", SHA256: "aa"},
				{Name: "stele_darwin_arm64.tar.gz", SHA256: "bb"},
				{Name: "checksums.txt", SHA256: "cc"},
			},
			want: nil,
		},
		{
			name: "one artifact diverges",
			rebuilt: []verify.Subject{
				{Name: "stele_linux_amd64.tar.gz", SHA256: "aa"},
				{Name: "stele_darwin_arm64.tar.gz", SHA256: "XX"},
				{Name: "checksums.txt", SHA256: "cc"},
			},
			want: []verify.ReproDivergence{{
				Name: "stele_darwin_arm64.tar.gz", Kind: verify.ReproDiverged, Released: "bb", Rebuilt: "XX",
			}},
		},
		{
			name: "one artifact absent from the rebuild",
			rebuilt: []verify.Subject{
				{Name: "stele_linux_amd64.tar.gz", SHA256: "aa"},
				{Name: "checksums.txt", SHA256: "cc"},
			},
			want: []verify.ReproDivergence{{
				Name: "stele_darwin_arm64.tar.gz", Kind: verify.ReproAbsent, Released: "bb",
			}},
		},
		{
			name: "the rebuild produced extras, reported by name in order",
			rebuilt: []verify.Subject{
				{Name: "stele_linux_amd64.tar.gz", SHA256: "aa"},
				{Name: "stele_darwin_arm64.tar.gz", SHA256: "bb"},
				{Name: "checksums.txt", SHA256: "cc"},
				{Name: "zz-scratch.log", SHA256: "dd"},
				{Name: "aa-scratch.log", SHA256: "ee"},
			},
			want: []verify.ReproDivergence{
				{Name: "aa-scratch.log", Kind: verify.ReproExtra, Rebuilt: "ee"},
				{Name: "zz-scratch.log", Kind: verify.ReproExtra, Rebuilt: "dd"},
			},
		},
		{
			// A scoped judgment: the rebuild produced an artifact the
			// release DID ship, outside the population under test. It is
			// not extra — the release shipped it — and it is not absent,
			// because nobody put it under test. It produces nothing
			// (stele#223).
			name: "an artifact outside the judged scope produces nothing",
			rebuilt: []verify.Subject{
				{Name: "stele_linux_amd64.tar.gz", SHA256: "aa"},
				{Name: "stele_darwin_arm64.tar.gz", SHA256: "bb"},
				{Name: "checksums.txt", SHA256: "cc"},
				{Name: "stele_windows_amd64.zip", SHA256: "dd"},
			},
			published: []verify.Subject{
				{Name: "stele_linux_amd64.tar.gz", SHA256: "aa"},
				{Name: "stele_darwin_arm64.tar.gz", SHA256: "bb"},
				{Name: "checksums.txt", SHA256: "cc"},
				{Name: "stele_windows_amd64.zip", SHA256: "dd"},
			},
			want: nil,
		},
		{
			name:    "an empty rebuild is every artifact unreproduced",
			rebuilt: nil,
			want: []verify.ReproDivergence{
				{Name: "stele_linux_amd64.tar.gz", Kind: verify.ReproAbsent, Released: "aa"},
				{Name: "stele_darwin_arm64.tar.gz", Kind: verify.ReproAbsent, Released: "bb"},
				{Name: "checksums.txt", Kind: verify.ReproAbsent, Released: "cc"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			published := tc.published
			if published == nil {
				published = released
			}

			got := verify.Repro(
				verify.ReproSets{Judged: released, Rebuilt: tc.rebuilt, Published: published},
				func(string, ...any) {})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Repro = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestReproJudgesNothingOverNothing: two empty manifests compare
// clean here — the POPULATION judgment belongs to the caller's seal,
// and this documents that the engine deliberately does not smuggle
// one in.
func TestReproJudgesNothingOverNothing(t *testing.T) {
	t.Parallel()

	if got := verify.Repro(verify.ReproSets{}, func(string, ...any) {}); got != nil {
		t.Fatalf("Repro = %+v, want nil — zero coverage is the seal's question", got)
	}
}
