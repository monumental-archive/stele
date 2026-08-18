// The shape's own table: what a build-enrichment predicate must
// carry before any org's expectations are consulted. Each row breaks
// exactly one fact of a valid claim.

package enrichment_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/enrichment"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
)

const (
	revision = "1111111111111111111111111111111111111111"
	lockSHA  = "2222222222222222222222222222222222222222222222222222222222222222"
	treeSHA  = "3333333333333333333333333333333333333333333333333333333333333333"
)

// valid is one complete claim, as JSON — decoded through jsonx, the
// module's one JSON boundary, so the tests judge what the verifier
// judges.
const valid = `{
  "resourceUri": "pkg:github/acme/widget@v1.2.3",
  "sourceRevision": {
    "uri": "https://github.com/acme/widget",
    "digest": {"gitCommit": "` + revision + `"}
  },
  "policy": {
    "uri": "https://github.com/acme/canon/blob/abc/slsa/verify-policy.json",
    "digest": {"sha256": "` + treeSHA + `"}
  },
  "resolvedDependencies": [
    {
      "name": "toolbelt-lock",
      "uri": "https://github.com/acme/canon/blob/abc/mise/mise.lock",
      "digest": {"sha256": "` + lockSHA + `"}
    },
    {"name": "base", "uri": "oci://docker.io/library/postgres:17"}
  ]
}`

func decode(t *testing.T, doc string) *enrichment.Predicate {
	t.Helper()

	pred, err := jsonx.DecodeBytes[enrichment.Predicate]([]byte(doc))
	if err != nil {
		t.Fatalf("decode = %v", err)
	}

	return pred
}

// TestValid is the clean claim, and the two accessors the verifier
// reads off it. A digestless entry is deliberately legal: an entry
// identified by uri alone is how an image named by a digested
// mapping file travels.
func TestValid(t *testing.T) {
	t.Parallel()

	pred := decode(t, valid)

	if err := pred.Validate(); err != nil {
		t.Fatalf("Validate = %v", err)
	}

	if got := pred.Revision(); got != revision {
		t.Errorf("Revision = %q, want %q", got, revision)
	}

	got := pred.Names()
	if len(got) != 2 || got[0] != "toolbelt-lock" || got[1] != "base" {
		t.Errorf("Names = %v, want the claim's names in claim order", got)
	}
}

func TestValidateRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			name: "a claim naming no artifact",
			doc:  strings.Replace(valid, `"resourceUri": "pkg:github/acme/widget@v1.2.3"`, `"resourceUri": ""`, 1),
			want: "names no artifact",
		},
		{
			name: "a claim unbound to a commit",
			doc:  strings.Replace(valid, `"uri": "https://github.com/acme/widget"`, `"uri": ""`, 1),
			want: "belongs to no named repository",
		},
		{
			name: "a revision that is a branch name",
			doc:  strings.Replace(valid, `"gitCommit": "`+revision+`"`, `"gitCommit": ""`, 1),
			want: "a branch name is not a revision",
		},
		{
			name: "a revision digest of the wrong shape",
			doc:  strings.Replace(valid, `"gitCommit": "`+revision+`"`, `"gitCommit": "abc"`, 1),
			want: "not 40 lowercase hex",
		},
		{
			name: "a policy tree named by a moving ref",
			doc:  strings.Replace(valid, `"sha256": "`+treeSHA+`"`, `"sha256": ""`, 1),
			want: "a moving ref pins nothing",
		},
		{
			name: "a policy tree with no address",
			doc: strings.Replace(valid,
				`"uri": "https://github.com/acme/canon/blob/abc/slsa/verify-policy.json"`, `"uri": ""`, 1),
			want: "policy.uri is absent",
		},
		{
			name: "a policy digest of the wrong shape",
			doc:  strings.Replace(valid, `"sha256": "`+treeSHA+`"`, `"sha256": "abc"`, 1),
			want: "not 64 lowercase hex",
		},
		{
			name: "an unnamed dependency",
			doc:  strings.Replace(valid, `"name": "toolbelt-lock"`, `"name": ""`, 1),
			want: "cannot be declared or missed",
		},
		{
			name: "a dependency nobody can fetch",
			doc:  strings.Replace(valid, `"uri": "oci://docker.io/library/postgres:17"`, `"uri": ""`, 1),
			want: "not evidence",
		},
		{
			name: "a dependency digest of the wrong shape",
			doc:  strings.Replace(valid, `"sha256": "`+lockSHA+`"`, `"sha256": "abc"`, 1),
			want: "not 64 lowercase hex",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pred := decode(t, tc.doc)

			err := pred.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s", tc.name)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// A predicate with a section missing entirely — distinct from one
// whose fields are empty, and the reason the decode type uses
// pointers. The empty claim lives here too: it is the failure this
// predicate exists to make impossible.
func TestAbsentSections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		drop func(p *enrichment.Predicate)
		want string
	}{
		{
			name: "no sourceRevision at all",
			drop: func(p *enrichment.Predicate) { p.SourceRevision = nil },
			want: "facts unbound to a commit",
		},
		{
			name: "no policy at all",
			drop: func(p *enrichment.Predicate) { p.Policy = nil },
			want: "unauditable",
		},
		{
			name: "no resourceUri at all",
			drop: func(p *enrichment.Predicate) { p.ResourceURI = nil },
			want: "names no artifact",
		},
		{
			name: "no resolved dependencies at all",
			drop: func(p *enrichment.Predicate) { p.ResolvedDependencies = nil },
			want: "resolving nothing claims nothing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pred := decode(t, valid)
			tc.drop(pred)

			err := pred.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a predicate with %s", tc.name)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want it to name %q", err, tc.want)
			}
		})
	}
}

// The digest rule is intoto's one rule, not a second copy: an
// unknown algorithm needs a value, exactly as a statement's subjects
// are judged.
func TestUnknownDigestAlgorithm(t *testing.T) {
	t.Parallel()

	pred := decode(t, valid)
	pred.ResolvedDependencies[0].Digest = map[string]string{"sha512": ""}

	err := pred.Validate()
	if err == nil || !strings.Contains(err.Error(), "empty value") {
		t.Fatalf("Validate = %v, want the shared digest rule to refuse an empty value", err)
	}

	pred.ResolvedDependencies[0].Digest = map[string]string{"sha512": "anything"}
	if err := pred.Validate(); err != nil {
		t.Fatalf("Validate = %v, want an unknown algorithm with a value accepted", err)
	}

	if pred.SourceRevision.Digest[intoto.AlgGitCommit] != revision {
		t.Fatal("the revision moved during validation")
	}
}
