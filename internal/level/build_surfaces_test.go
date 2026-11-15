// The coverage question every Build detector asks first (stele#355).

package level_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/level"
)

// TestBuildAsksCoverageFirst holds the one shared Build guard to each
// of its branches. A surface this run could not see makes every Build
// detector undetermined with that surface named, even where another
// surface answered with artifacts that would otherwise establish the
// rung.
func TestBuildAsksCoverageFirst(t *testing.T) {
	t.Parallel()

	stream := level.PublishSurface{
		Name:    "continuous-digest registry.example.test/atelier/loom:rolling",
		Missing: []string{"the registry holds nothing under the rolling tag registry.example.test/atelier/loom:rolling"},
	}

	for _, tc := range []struct {
		name     string
		surfaces []level.PublishSurface
		subjects bool
		want     string
	}{
		{
			name: "no surface was looked at",
			want: "UNDETERMINED: this run looked at no publish surface, so no provenance could be looked for",
		},
		{
			name:     "every surface reached and none named an artifact",
			surfaces: []level.PublishSurface{{Name: "release"}},
			want:     "UNDETERMINED: no published artifact was reached, so no provenance could be looked for",
		},
		{
			name:     "one surface unseen beside one that answered",
			surfaces: []level.PublishSurface{{Name: "release"}, stream},
			subjects: true,
			want: "UNDETERMINED: 1 of the 2 surface(s) this repository publishes on yielded no publish this run" +
				" could see, so whatever they publish has not been asked for provenance — " + stream.Name + ": " +
				stream.Missing[0],
		},
		{
			// Hand-assembled evidence with no surface account: the
			// artifacts are still artifacts, and they are judged.
			name:     "artifacts with no surface account are judged",
			subjects: true,
			want:     "HELD: all 1 published artifact(s) carry provenance identifying them by digest",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ev := buildEvidence()
			ev.PublishSurfaces = tc.surfaces

			if !tc.subjects {
				ev.Subjects = nil
			}

			var buf bytes.Buffer
			if err := level.Assess(level.TrackBuild, ev).Report().Encode(&buf); err != nil {
				t.Fatalf("Encode = %v", err)
			}

			doc := buf.String()
			for _, r := range level.Requirements(level.TrackBuild) {
				if tc.subjects && tc.surfaces == nil {
					break // the judged row: each detector answers its own question
				}

				if !strings.Contains(doc, `"`+r.ID+`","value":"`+tc.want) {
					t.Errorf("%s does not answer %q:\n%s", r.ID, tc.want, doc)
				}
			}

			if !strings.Contains(doc, tc.want) {
				t.Errorf("the report does not carry %q:\n%s", tc.want, doc)
			}
		})
	}
}
