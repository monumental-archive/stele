// The account an unevaluated inventory rung owes.
//
// "No inventory was found" over a repository that publishes one on
// every merge reads as an accusation, and the producer cannot act on
// it without being told which places this run looked at and what came
// back empty from each. That was the defect's shape (stele#249): the
// answer was correct about what it had looked at and never said what
// that was.

package level_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/level"
)

// TestUnevaluatedInventoryNamesEverySurface: the reason names each
// surface that yielded no publish and every absence on it, and names
// nothing about a surface that DID yield one.
func TestUnevaluatedInventoryNamesEverySurface(t *testing.T) {
	t.Parallel()

	stream := level.PublishSurface{
		Name: "continuous-digest registry.example.test/atelier/loom:rolling",
		Missing: []string{
			"no attestation over the published digest 0123456789ab or its 2 artifact digest(s)" +
				" carries a dependency inventory (an SPDX or CycloneDX document)",
			"no attestation over those digests carries a triage decision (an OpenVEX document)",
			"2 of the 2 artifact digest(s) the publish names carry no attestation at all",
		},
	}
	release := level.PublishSurface{
		Name:    "release",
		Missing: []string{"this repository has published no release this tool can order"},
	}

	for _, tc := range []struct {
		name     string
		surfaces []level.PublishSurface
		want     []string
		absent   []string
	}{
		{
			name:     "no surface was looked at",
			surfaces: nil,
			want:     []string{"this run looked at no publish surface"},
		},
		{
			name:     "one stream, every absence named distinctly",
			surfaces: []level.PublishSurface{stream},
			want: []string{
				"registry.example.test/atelier/loom:rolling",
				"carries a dependency inventory (an SPDX or CycloneDX document)",
				"carries a triage decision (an OpenVEX document)",
				"carry no attestation at all",
				"1 surface(s)",
			},
		},
		{
			// The both-absent case: a repository declaring both
			// surfaces and publishing on neither is owed BOTH accounts,
			// because fixing one of them still leaves the other true.
			name:     "both surfaces declared and neither published on",
			surfaces: []level.PublishSurface{release, stream},
			want: []string{
				"2 surface(s)",
				"release: this repository has published no release this tool can order",
				"registry.example.test/atelier/loom:rolling",
			},
		},
		{
			// A surface that yielded a publish has nothing to answer
			// for. Naming it here would send a reader to the one place
			// that was working.
			name:     "a reached surface is not named among the absences",
			surfaces: []level.PublishSurface{{Name: "release"}, stream},
			want:     []string{"registry.example.test/atelier/loom:rolling", "1 of the 2 surface(s)"},
			absent:   []string{"release:"},
		},
		{
			// Every surface answered and none of them named an artifact:
			// not the same statement as an absent surface, and a reader
			// told the wrong one of the two goes looking in the wrong
			// place.
			name:     "every surface reached and none named an artifact",
			surfaces: []level.PublishSurface{{Name: "release"}},
			want:     []string{"a publish was reached, but it named no artifact"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := level.Assess(level.TrackDependency, &level.Evidence{
				Owner: "atelier", Repo: "loom", Now: epoch, PublishSurfaces: tc.surfaces,
			})

			var buf bytes.Buffer
			if err := got.Report().Encode(&buf); err != nil {
				t.Fatalf("Encode = %v", err)
			}

			doc := buf.String()

			if !strings.Contains(doc, "UNDETERMINED") {
				t.Fatalf("an unreached publish did not leave the inventory rung undetermined:\n%s", doc)
			}

			for _, want := range tc.want {
				if !strings.Contains(doc, want) {
					t.Errorf("the reason does not carry %q:\n%s", want, doc)
				}
			}

			for _, absent := range tc.absent {
				if strings.Contains(doc, absent) {
					t.Errorf("the reason names %q, and that surface was reached:\n%s", absent, doc)
				}
			}
		})
	}
}

// TestPublishSurfaceReached: the one predicate everything above turns
// on. A surface with nothing missing was reached; anything missing
// means it was not.
func TestPublishSurfaceReached(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		surface level.PublishSurface
		want    bool
	}{
		{name: "nothing missing", surface: level.PublishSurface{Name: "release"}, want: true},
		{
			name:    "one thing missing",
			surface: level.PublishSurface{Name: "release", Missing: []string{"no release"}},
			want:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.surface.Reached(); got != tc.want {
				t.Errorf("Reached() = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestSurfacesNeverLiftARung is the standing law, stated as a test:
// a declaration says where to look and can never say what is true.
//
// The direction matters. A surface this run could not see WITHHOLDS a
// rung, because the coverage claim is then smaller than the
// repository — that is the row above. What no surface may ever do is
// the other direction: turn a rung the evidence does not support into
// one that holds. A surface list claiming everything was seen adds
// nothing, and a refutation the evidence establishes survives any
// account of where this run looked.
func TestSurfacesNeverLiftARung(t *testing.T) {
	t.Parallel()

	seen := []level.PublishSurface{{Name: "release"}, {Name: "continuous-digest registry.example.test/x:y"}}

	t.Run("a refutation survives a surface claiming everything was seen", func(t *testing.T) {
		t.Parallel()

		got := level.Assess(level.TrackDependency, &level.Evidence{
			Owner: "atelier", Repo: "loom", Now: epoch,
			PublishSurfaces: seen,
			Inventoried:     []string{"loom_linux_amd64"},
			Uninventoried:   []string{"loom_darwin_arm64"},
		})

		if d := got.Rungs()[0].Determination; d != level.Refuted {
			t.Errorf("the inventory rung is %s, want the refutation the evidence establishes", d)
		}
	})

	t.Run("no surface makes an empty gather hold", func(t *testing.T) {
		t.Parallel()

		got := level.Assess(level.TrackDependency, &level.Evidence{
			Owner: "atelier", Repo: "loom", Now: epoch, PublishSurfaces: seen,
		})

		if d := got.Rungs()[0].Determination; d != level.Undetermined {
			t.Errorf("the inventory rung is %s, want it undetermined — no artifact was reached", d)
		}
	})
}

// TestUnseenSurfaceUnseatsAnInventoryRung is the coverage law at the
// artifact grain, and the one row a reader is most likely to think
// unnecessary.
//
// A repository publishing on TWO surfaces, one of them whole and one
// of them unreadable, must not seal the inventory rung on the strength
// of the half that answered. The artifacts the unseen surface
// publishes were never asked the question, and a rung established over
// a population this run knowingly did not cover is exactly the
// "absence read as compliance" that costs more than a missing rung.
//
// Measured live before it was written: monumental-archive/release-lab
// publishes both a release and a rolling digest, and its release
// carries an inventory covering fourteen artifacts while its stream's
// two digests carry none — which sealed DEPENDENCY_LEVEL_1 and said
// nothing at all about the stream.
func TestUnseenSurfaceUnseatsAnInventoryRung(t *testing.T) {
	t.Parallel()

	whole := []level.PublishSurface{{Name: "release"}}
	half := []level.PublishSurface{
		{Name: "release"},
		{
			Name:    "continuous-digest registry.example.test/atelier/loom:rolling",
			Missing: []string{"no attestation over the published digest carries a dependency inventory"},
		},
	}

	covered := func(surfaces []level.PublishSurface) *level.Assessment {
		return level.Assess(level.TrackDependency, &level.Evidence{
			Owner: "atelier", Repo: "loom", Now: epoch,
			PublishSurfaces: surfaces,
			Inventoried:     []string{"loom_linux_amd64", "loom_darwin_arm64"},
			Scanned:         true,
			Findings:        1, Triaged: 1,
			DependencySources: map[string]bool{"https://mirror.example.test/cargo": true},
		})
	}

	if got := covered(whole).Rungs()[0].Determination; got != level.Held {
		t.Fatalf("with every surface seen the inventory rung is %s, want it held", got)
	}

	partial := covered(half)

	if got := partial.Rungs()[0].Determination; got != level.Undetermined {
		t.Errorf("with one surface unseen the inventory rung is %s, want it undetermined", got)
	}

	var buf bytes.Buffer
	if err := partial.Report().Encode(&buf); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	for _, want := range []string{
		"registry.example.test/atelier/loom:rolling",
		"2 artifact(s) another surface published are covered",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the reason does not carry %q:\n%s", want, buf.String())
		}
	}
}
