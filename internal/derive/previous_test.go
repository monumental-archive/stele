// The previous block as a value: what it states, and what it refuses
// to state as an empty string.

package derive_test

import (
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/derive"
	"github.com/monumental-archive/stele/internal/jsonx"
)

func TestPreviousOf(t *testing.T) {
	for _, tc := range []struct {
		name string
		base derive.Base
		want derive.Previous
	}{
		// A first release has no predecessor. Every field stays absent
		// rather than empty: a consumer told version "" and tag "" has
		// to decide what those mean, which is the interpretation this
		// block exists to remove.
		{
			name: "a namespace that has never released",
			base: derive.Base{},
			want: derive.Previous{},
		},
		{
			name: "a release under the v namespace",
			base: derive.Base{Version: semver.MustParse("0.19.1"), Tag: "v0.19.1"},
			want: derive.Previous{Exists: true, Version: "0.19.1", Tag: "v0.19.1"},
		},
		// The imported repository: the version is ordinary, the tag is
		// whatever its old scheme minted, and the block reports the tag
		// it was read from rather than the one a scheme predicts.
		{
			name: "a release under a per-crate namespace",
			base: derive.Base{Version: semver.MustParse("1.2.3"), Tag: "edtf-postgres-v1.2.3"},
			want: derive.Previous{Exists: true, Version: "1.2.3", Tag: "edtf-postgres-v1.2.3"},
		},
		// Debris beside the base changes nothing about the previous
		// release: it was skipped and named where it was found.
		{
			name: "debris in the namespace does not reach the block",
			base: derive.Base{
				Version: semver.MustParse("1.0.0"), Tag: "v1.0.0",
				Skipped: []string{"v0.9-pre-import"},
			},
			want: derive.Previous{Exists: true, Version: "1.0.0", Tag: "v1.0.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := derive.PreviousOf(tc.base)

			if got != tc.want {
				t.Errorf("PreviousOf(%+v) = %+v, want %+v", tc.base, got, tc.want)
			}

			// The forge half is nobody's business here: this package
			// reads a tag list, and a derivation that could reach a
			// network would behave differently offline.
			if got.ForgeAsked || got.Release != nil {
				t.Errorf("PreviousOf reported a forge answer it never asked for: %+v", got)
			}
		})
	}
}

// The encoding is the contract — a consumer decodes this, so the
// distinctions have to survive the round trip to JSON rather than
// living only in the Go type.
func TestPreviousEncodesItsAbsences(t *testing.T) {
	for _, tc := range []struct {
		name     string
		previous derive.Previous
		want     string
	}{
		{
			name:     "a first release says so; no empty version, no empty tag",
			previous: derive.Previous{},
			want:     `{"exists":false,"forgeAsked":false}`,
		},
		{
			name:     "a tag nobody asked a forge about",
			previous: derive.Previous{Exists: true, Version: "1.2.3", Tag: "edtf-postgres-v1.2.3"},
			want:     `{"exists":true,"version":"1.2.3","tag":"edtf-postgres-v1.2.3","forgeAsked":false}`,
		},
		{
			name: "a forge that was asked and hangs nothing there",
			previous: derive.Previous{
				Exists: true, Version: "1.2.3", Tag: "v1.2.3", ForgeAsked: true,
			},
			want: `{"exists":true,"version":"1.2.3","tag":"v1.2.3","forgeAsked":true}`,
		},
		{
			name: "a release that published nothing carries an empty list",
			previous: derive.Previous{
				Exists: true, Version: "1.0.0", Tag: "v1.0.0", ForgeAsked: true,
				Release: &derive.ForgeRelease{ID: 7, Assets: []derive.ForgeAsset{}},
			},
			want: `{"exists":true,"version":"1.0.0","tag":"v1.0.0","forgeAsked":true,` +
				`"release":{"id":7,"assets":[]}}`,
		},
		{
			name: "a release and where its artifacts live",
			previous: derive.Previous{
				Exists: true, Version: "1.2.3", Tag: "edtf-postgres-v1.2.3", ForgeAsked: true,
				Release: &derive.ForgeRelease{
					ID: 42, Name: "edtf-postgres-v1.2.3", URL: "https://forge.example/r/42",
					Assets: []derive.ForgeAsset{
						{Name: "edtf_postgres-1.2.3-pg14-linux-amd64.tar.gz", URL: "https://forge.example/d/pg14"},
					},
				},
			},
			want: `{"exists":true,"version":"1.2.3","tag":"edtf-postgres-v1.2.3","forgeAsked":true,` +
				`"release":{"id":42,"name":"edtf-postgres-v1.2.3","url":"https://forge.example/r/42",` +
				`"assets":[{"name":"edtf_postgres-1.2.3-pg14-linux-amd64.tar.gz",` +
				`"url":"https://forge.example/d/pg14"}]}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := jsonx.Marshal(tc.previous)
			if err != nil {
				t.Fatalf("Marshal = %v", err)
			}

			if string(encoded) != tc.want {
				t.Errorf("encoded =\n%s\nwant\n%s", encoded, tc.want)
			}

			// One line, always: the block travels as one key=value pair
			// through a job output, and a newline inside it would split
			// one fact into two the reader cannot rejoin.
			if strings.ContainsAny(string(encoded), "\n\r") {
				t.Errorf("the encoded block spans lines:\n%s", encoded)
			}
		})
	}
}
