package provenance_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/provenance"
)

const (
	repoURL   = "https://github.com/acme/widget"
	commitHex = "e1ad2dde9fd24fc521b4b37453dac052e655212b"
	otherHex  = "1111111111111111111111111111111111111111"
)

// valid mirrors the shape GitHub-hosted builds emit: the source
// checkout beside an unrelated dependency, deliberately NOT first —
// selection must be by content, and a fixture where position and
// content agree could not tell the two apart.
const valid = `{
  "buildDefinition": {
    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
    "externalParameters": {"workflow": {"ref": "refs/tags/v1.0.0"}},
    "internalParameters": {"github": {"event_name": "push"}},
    "resolvedDependencies": [
      {"uri": "oci://docker.io/library/debian",
       "digest": {"sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"}},
      {"uri": "git+https://github.com/acme/widget@refs/tags/v1.0.0", "digest": {"gitCommit": "` + commitHex + `"}}
    ]
  },
  "runDetails": {
    "builder": {"id": "https://github.com/acme/signer/.github/workflows/sign.yml@refs/tags/v2"},
    "metadata": {"invocationId": "https://github.com/acme/widget/actions/runs/1"}
  }
}`

func decode(t *testing.T, doc string) *provenance.Predicate {
	t.Helper()

	p, err := jsonx.Decode[provenance.Predicate](strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Decode = %v", err)
	}

	return p
}

func mutate(t *testing.T, from, to string) string {
	t.Helper()

	if n := strings.Count(valid, from); n != 1 {
		t.Fatalf("mutation target %q occurs %d times, want exactly 1", from, n)
	}

	return strings.Replace(valid, from, to, 1)
}

func TestValidate(t *testing.T) {
	t.Parallel()

	if err := decode(t, valid).Validate(); err != nil {
		t.Fatalf("Validate(valid) = %v", err)
	}
}

func TestValidateRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		from string
		to   string
		want string
	}{
		{
			"buildDefinition null",
			`"buildDefinition": {
    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
    "externalParameters": {"workflow": {"ref": "refs/tags/v1.0.0"}},
    "internalParameters": {"github": {"event_name": "push"}},
    "resolvedDependencies": [
      {"uri": "oci://docker.io/library/debian",
       "digest": {"sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"}},
      {"uri": "git+https://github.com/acme/widget@refs/tags/v1.0.0", "digest": {"gitCommit": "` + commitHex + `"}}
    ]
  }`,
			`"buildDefinition": null`,
			"buildDefinition is absent",
		},
		{
			"buildType absent",
			`"buildType": "https://actions.github.io/buildtypes/workflow/v1",`,
			``,
			"buildType",
		},
		{
			"buildType not a URI",
			`"buildType": "https://actions.github.io/buildtypes/workflow/v1"`,
			`"buildType": "workflow/v1"`,
			"buildType",
		},
		{
			"externalParameters absent",
			`"externalParameters": {"workflow": {"ref": "refs/tags/v1.0.0"}},`,
			``,
			"externalParameters is absent",
		},
		{
			"runDetails null",
			`"runDetails": {
    "builder": {"id": "https://github.com/acme/signer/.github/workflows/sign.yml@refs/tags/v2"},
    "metadata": {"invocationId": "https://github.com/acme/widget/actions/runs/1"}
  }`,
			`"runDetails": null`,
			"runDetails is absent",
		},
		{
			"builder null",
			`"builder": {"id": "https://github.com/acme/signer/.github/workflows/sign.yml@refs/tags/v2"}`,
			`"builder": null`,
			"runDetails.builder is absent",
		},
		{
			"builder id empty",
			`"id": "https://github.com/acme/signer/.github/workflows/sign.yml@refs/tags/v2"`,
			`"id": ""`,
			"builder.id is absent or empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := mutate(t, tt.from, tt.to)

			p, err := jsonx.Decode[provenance.Predicate](strings.NewReader(doc))
			if err != nil {
				if !strings.Contains(err.Error(), tt.want) {
					t.Errorf("Decode error = %q, want it to name %q", err, tt.want)
				}

				return
			}

			if err := p.Validate(); err == nil {
				t.Fatal("Validate accepted a predicate it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

func TestSourceRevision(t *testing.T) {
	t.Parallel()

	got, err := decode(t, valid).SourceRevision(repoURL)
	if err != nil {
		t.Fatalf("SourceRevision = %v", err)
	}

	if got != commitHex {
		t.Errorf("SourceRevision = %q, want %q", got, commitHex)
	}
}

func TestSourceRevisionRefusals(t *testing.T) {
	t.Parallel()

	source := `{"uri": "git+https://github.com/acme/widget@refs/tags/v1.0.0",` +
		` "digest": {"gitCommit": "` + commitHex + `"}}`

	tests := []struct {
		name string
		doc  string
		repo string
		want string
	}{
		{
			"no entry names the repo",
			valid, "https://github.com/acme/other",
			"no resolvedDependencies entry names the source repository",
		},
		{
			"prefix of a longer repo name is not a match",
			valid, "https://github.com/acme/widge",
			"no resolvedDependencies entry names the source repository",
		},
		{
			"matching entry without gitCommit",
			strings.Replace(valid, `"digest": {"gitCommit": "`+commitHex+`"}`,
				`"digest": {"sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"}`, 1),
			repoURL,
			"carries no gitCommit digest",
		},
		{
			"two entries disagree",
			strings.Replace(valid, source,
				source+`,
      {"uri": "git+https://github.com/acme/widget", "digest": {"gitCommit": "`+otherHex+`"}}`, 1),
			repoURL,
			"disagree on the revision",
		},
		{
			"invalid predicate refused before selection",
			strings.Replace(valid, `"builder": {"id": "https://github.com/acme/signer/.github/workflows/sign.yml@refs/tags/v2"}`,
				`"builder": null`, 1),
			repoURL,
			"runDetails.builder is absent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := decode(t, tt.doc).SourceRevision(tt.repo); err == nil {
				t.Fatal("SourceRevision returned a revision it must refuse")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("SourceRevision error = %q, want it to name %q", err, tt.want)
			}
		})
	}
}

// TestSourceRevisionAgreeingDuplicates pins the tolerant edge: two
// entries naming the repo with the SAME revision are agreement, not
// ambiguity — refusing them would fail honest producers that list a
// checkout twice (fetch and submodule-style).
func TestSourceRevisionAgreeingDuplicates(t *testing.T) {
	t.Parallel()

	source := `{"uri": "git+https://github.com/acme/widget@refs/tags/v1.0.0",` +
		` "digest": {"gitCommit": "` + commitHex + `"}}`
	doc := strings.Replace(valid, source,
		source+`,
      {"uri": "git+https://github.com/acme/widget", "digest": {"gitCommit": "`+commitHex+`"}}`, 1)

	got, err := decode(t, doc).SourceRevision(repoURL)
	if err != nil {
		t.Fatalf("SourceRevision(agreeing duplicates) = %v", err)
	}

	if got != commitHex {
		t.Errorf("SourceRevision = %q, want %q", got, commitHex)
	}
}
