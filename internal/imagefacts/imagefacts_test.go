// Every refusal the resolver can produce, as a row — including the
// ones the bash guarded with a post-hoc jq assertion and this package
// makes structural, because a guard that fires only in a degraded
// state is the least exercised code there is.
//
// The licence rows are also the adopt-check for github/go-spdx,
// pinned as tests rather than left in a commit message: they are what
// the canon's embedded Python validated, so a library bump that
// stopped refusing one of them is a red build.

package imagefacts_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/imagefacts"
)

const rev = "aaaabbbbccccddddeeeeffff0000111122223333"

func committed() time.Time { return time.Date(2026, 8, 18, 9, 30, 0, 0, time.UTC) }

// good is a provenance that resolves; each row below breaks exactly
// one fact, so a failing row names its guard and nothing else.
func good() *imagefacts.Provenance {
	return &imagefacts.Provenance{
		ServerURL:  "https://github.com",
		Repository: "acme/widget",
		Revision:   rev,
		Committed:  committed(),
		Licence:    "Apache-2.0",
	}
}

func TestResolveVersioned(t *testing.T) {
	t.Parallel()

	f, err := imagefacts.Resolve(imagefacts.Versioned{Version: "1.2.3"}, good(), imagefacts.Editorial{})
	if err != nil {
		t.Fatalf("Resolve = %v", err)
	}

	m := f.Map()

	want := map[string]string{
		imagefacts.KeySource:   "https://github.com/acme/widget",
		imagefacts.KeyRevision: rev,
		imagefacts.KeyVersion:  "1.2.3",
		imagefacts.KeyCreated:  "2026-08-18T09:30:00Z",
		imagefacts.KeyLicenses: "Apache-2.0",
		imagefacts.KeyTitle:    "widget",
	}

	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}

	if _, ok := m[imagefacts.KeyDescription]; ok {
		t.Error("an absent description was emitted rather than omitted")
	}

	// One instant, two renderings: the epoch and the annotation are
	// both the released commit's own time, neither derived from the
	// other's output.
	if f.Epoch() != committed().Unix() {
		t.Errorf("Epoch = %d, want %d", f.Epoch(), committed().Unix())
	}
}

// The continuous archetype carries no version FIELD, so a continuous
// release with a version is unspellable rather than refused.
func TestResolveContinuousHasNoVersion(t *testing.T) {
	t.Parallel()

	f, err := imagefacts.Resolve(imagefacts.Continuous{}, good(), imagefacts.Editorial{})
	if err != nil {
		t.Fatalf("Resolve = %v", err)
	}

	if _, ok := f.Map()[imagefacts.KeyVersion]; ok {
		t.Fatal("the continuous archetype rendered a version")
	}

	// Every provenance key is still present: they are struct fields,
	// so "a provenance fact is missing" cannot happen.
	for _, k := range []string{
		imagefacts.KeySource, imagefacts.KeyRevision, imagefacts.KeyCreated, imagefacts.KeyLicenses,
	} {
		if f.Map()[k] == "" {
			t.Errorf("%s is absent from a continuous fact set", k)
		}
	}
}

func TestResolveRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		archetype imagefacts.Archetype
		breakIt   func(*imagefacts.Provenance)
		editorial imagefacts.Editorial
		want      string
	}{
		{
			name: "no archetype at all",
			want: "an archetype is required",
		},
		{
			name:      "a versioned release with no version",
			archetype: imagefacts.Versioned{},
			want:      "needs a version",
		},
		{
			name:      "an abbreviated revision",
			archetype: imagefacts.Continuous{},
			breakIt:   func(p *imagefacts.Provenance) { p.Revision = "aaaabbbb" },
			want:      "not a full lowercase commit SHA",
		},
		{
			name:      "an uppercase revision",
			archetype: imagefacts.Continuous{},
			breakIt:   func(p *imagefacts.Provenance) { p.Revision = strings.ToUpper(rev) },
			want:      "not a full lowercase commit SHA",
		},
		{
			name:      "no repository",
			archetype: imagefacts.Continuous{},
			breakIt:   func(p *imagefacts.Provenance) { p.Repository = "" },
			want:      "repository is required",
		},
		{
			name:      "no commit time",
			archetype: imagefacts.Continuous{},
			breakIt:   func(p *imagefacts.Provenance) { p.Committed = time.Time{} },
			want:      "the released commit dates the release",
		},
		{
			name:      "no forge server",
			archetype: imagefacts.Continuous{},
			breakIt:   func(p *imagefacts.Provenance) { p.ServerURL = "" },
			want:      "server URL is required",
		},
		{
			name:      "a manifest repository that went stale after a transfer",
			archetype: imagefacts.Continuous{},
			breakIt:   func(p *imagefacts.Provenance) { p.RepositoryField = "https://github.com/old/widget" },
			want:      "update the repository field",
		},
		{
			name:      "an editorial value carrying control characters",
			archetype: imagefacts.Continuous{},
			editorial: imagefacts.Editorial{Description: "line\nbreak"},
			want:      "carries control characters",
		},
		{
			name:      "an editorial value padded with whitespace",
			archetype: imagefacts.Continuous{},
			editorial: imagefacts.Editorial{Title: " widget "},
			want:      "padded with whitespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := good()
			if tt.breakIt != nil {
				tt.breakIt(p)
			}

			_, err := imagefacts.Resolve(tt.archetype, p, tt.editorial)
			if err == nil {
				t.Fatalf("Resolve = nil error, want %q", tt.want)
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Resolve = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// The manifest's repository field is compared after the renderings
// that do not change its meaning are stripped.
func TestRepositoryFieldNormalisation(t *testing.T) {
	t.Parallel()

	for _, declared := range []string{
		"https://github.com/acme/widget",
		"https://github.com/acme/widget/",
		"https://github.com/acme/widget.git",
	} {
		p := good()
		p.RepositoryField = declared

		if _, err := imagefacts.Resolve(imagefacts.Continuous{}, p, imagefacts.Editorial{}); err != nil {
			t.Errorf("Resolve with repository %q = %v", declared, err)
		}
	}
}

// The licence rows: what the canon's embedded Python validated, kept
// as the adopt-check for the library that replaced it.
func TestLicenceExpressions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		licence string
		want    string // "" means it must resolve
	}{
		{"a single id", "MIT", ""},
		{"a disjunction", "MIT OR Apache-2.0", ""},
		{"an exception", "Apache-2.0 WITH LLVM-exception", ""},
		{"a parenthesised compound", "(MIT OR Apache-2.0) AND BSD-3-Clause", ""},
		{"the or-later operator", "GPL-2.0+", ""},

		{"absent", "", "no licence expression"},
		{"whitespace only", "   ", "no licence expression"},
		{"the legacy slash syntax", "MIT/Apache-2.0", "not a valid SPDX expression"},
		{"two ids with no operator", "MIT Apache-2.0", "not a valid SPDX expression"},
		{"two operators in a row", "MIT AND OR MIT", "not a valid SPDX expression"},
		{"an id that is not listed", "MIT OR NotALicense", "not a valid SPDX expression"},
		{"NOASSERTION", "NOASSERTION", "not a valid SPDX expression"},
		// Deprecated-but-listed ids are valid SPDX and the canon's
		// validator accepts them too (it checks membership of the full
		// id list). Refusing them would be a NEW org rule invented
		// during a port, which is exactly what the bash-is-reference
		// law forbids — so this row pins acceptance, not refusal.
		{"a deprecated but listed id", "GPL-2.0", ""},

		{"a LicenseRef dangles in a bare annotation", "LicenseRef-Proprietary", "dangles"},
		{"a DocumentRef dangles too", "DocumentRef-Spdx:LicenseRef-X", "dangles"},

		{"a lowercase id", "mit", "canonical spelling"},
		{"an uppercase id", "APACHE-2.0", "canonical spelling"},
		// Operators are case-SENSITIVE in SPDX, so this is a syntax
		// error rather than a casing slip the normaliser can repair.
		{"a lowercase operator", "MIT or Apache-2.0", "operators are case-sensitive"},
		{"a lowercase exception", "Apache-2.0 WITH llvm-exception", "canonical spelling"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := good()
			p.Licence = tt.licence

			f, err := imagefacts.Resolve(imagefacts.Continuous{}, p, imagefacts.Editorial{})

			if tt.want == "" {
				if err != nil {
					t.Fatalf("Resolve = %v, want %q to be accepted", err, tt.licence)
				}

				if got := f.Map()[imagefacts.KeyLicenses]; got != tt.licence {
					t.Fatalf("licence shipped as %q, want the declared %q", got, tt.licence)
				}

				return
			}

			if err == nil {
				t.Fatalf("Resolve accepted %q, want %q", tt.licence, tt.want)
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Resolve = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// A refusal names the canonical form, because the operator's next
// move is to write it.
func TestCanonicalSpellingIsNamed(t *testing.T) {
	t.Parallel()

	p := good()
	p.Licence = "apache-2.0 with llvm-exception"

	_, err := imagefacts.Resolve(imagefacts.Continuous{}, p, imagefacts.Editorial{})
	if err == nil {
		t.Fatal("Resolve accepted a non-canonical expression")
	}

	if !strings.Contains(err.Error(), `"Apache-2.0 WITH LLVM-exception"`) {
		t.Fatalf("Resolve = %v, want it to name the canonical spelling", err)
	}
}

// An absent declaration is its own error, so a caller can tell "the
// tree declares no licence" from "the tree declares nonsense".
func TestNoLicenceIsItsOwnError(t *testing.T) {
	t.Parallel()

	p := good()
	p.Licence = ""

	_, err := imagefacts.Resolve(imagefacts.Continuous{}, p, imagefacts.Editorial{})
	if !errors.Is(err, imagefacts.ErrNoLicence) {
		t.Fatalf("Resolve = %v, want ErrNoLicence", err)
	}
}

// Editorial defaults: the title falls back to the repository's own
// name, the description is omitted rather than emitted empty.
func TestEditorialDefaults(t *testing.T) {
	t.Parallel()

	f, err := imagefacts.Resolve(imagefacts.Continuous{}, good(),
		imagefacts.Editorial{Description: "a widget"})
	if err != nil {
		t.Fatalf("Resolve = %v", err)
	}

	if got := f.Map()[imagefacts.KeyTitle]; got != "widget" {
		t.Errorf("title = %q, want the repository name", got)
	}

	if got := f.Map()[imagefacts.KeyDescription]; got != "a widget" {
		t.Errorf("description = %q", got)
	}

	explicit, err := imagefacts.Resolve(imagefacts.Continuous{}, good(),
		imagefacts.Editorial{Title: "Widget Pro"})
	if err != nil {
		t.Fatalf("Resolve = %v", err)
	}

	if got := explicit.Map()[imagefacts.KeyTitle]; got != "Widget Pro" {
		t.Errorf("title = %q, want the caller's override", got)
	}
}
