package ctlog_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/ctlog"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// capturedDir holds the two real certificates the reconciliation tests
// use; their source is recorded in its SOURCE.md. Shared with
// internal/assert rather than copied: one capture, one record.
const capturedDir = "../assert/testdata/signer-certificates"

type capturedEntries struct {
	Entries []struct {
		LeafInput string `json:"leaf_input"`
		ExtraData string `json:"extra_data"`
	} `json:"entries"`
}

// capturedLeaf reads the leaf of one captured get-entries answer.
func capturedLeaf(t *testing.T, index string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(capturedDir, "ct-"+index+".json")) //nolint:gosec // a fixture this test names
	if err != nil {
		t.Fatal(err)
	}

	got, err := jsonx.DecodeBytes[capturedEntries](b)
	if err != nil {
		t.Fatal(err)
	}

	if len(got.Entries) != 1 {
		t.Fatalf("the capture holds %d entries, want 1", len(got.Entries))
	}

	leaf, err := base64.StdEncoding.DecodeString(got.Entries[0].LeafInput)
	if err != nil {
		t.Fatal(err)
	}

	return leaf
}

// The claims of the two real certificates, as Fulcio wrote them — the
// same values the canon's reconciler decoded from the same bytes.
func TestParseLeafReadsTheRealCertificates(t *testing.T) {
	t.Parallel()

	const sign = "https://github.com/monumental-archive/signer/.github/workflows/sign.yml@"

	cases := []struct {
		index, signer, run, config string
	}{
		{
			index:  "443908396",
			signer: "cffec9441210d46f237099d8785098aacf5b8273",
			run:    "https://github.com/monumental-archive/.github/actions/runs/43671235061/attempts/1",
			config: "https://github.com/monumental-archive/.github/.github/workflows/self-publish.yml@refs/tags/v1.67.0",
		},
		{
			index:  "335460347",
			signer: "e50552beb52c8220c470e15702310561d7a3cfb1",
			run:    "https://github.com/monumental-archive/.github/actions/runs/31536050844/attempts/1",
			config: "https://github.com/monumental-archive/.github/.github/workflows/vex-attest.yml@refs/heads/main",
		},
	}

	for _, tc := range cases {
		t.Run(tc.index, func(t *testing.T) {
			t.Parallel()

			cert, err := ctlog.ParseLeaf(capturedLeaf(t, tc.index))
			if err != nil {
				t.Fatal(err)
			}

			if len(cert.URIs) != 1 || cert.URIs[0] != sign+tc.signer {
				t.Fatalf("URIs = %q, want [%s%s]", cert.URIs, sign, tc.signer)
			}

			ext, err := cert.Fulcio()
			if err != nil {
				t.Fatal(err)
			}

			for name, pair := range map[string][2]string{
				"issuer":            {ext.Issuer, "https://token.actions.githubusercontent.com"},
				"buildSignerURI":    {ext.BuildSignerURI, sign + tc.signer},
				"buildSignerDigest": {ext.BuildSignerDigest, tc.signer},
				"runInvocationURI":  {ext.RunInvocationURI, tc.run},
				"buildConfigURI":    {ext.BuildConfigURI, tc.config},
			} {
				if pair[0] != pair[1] {
					t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
				}
			}
		})
	}
}

// Every refusal ParseLeaf makes, each named.
func TestParseLeafRefuses(t *testing.T) {
	t.Parallel()

	captured := capturedLeaf(t, "443908396")

	cases := []struct {
		name string
		leaf []byte
		want string
	}{
		{"empty", nil, "is not an RFC 6962 MerkleTreeLeaf"},
		{"trailing bytes", append(append([]byte{}, captured...), 0), "trailing bytes"},
		{"truncated", captured[:len(captured)/2], "is not an RFC 6962 MerkleTreeLeaf"},
		{"not a timestamped entry", append([]byte{0, 1}, captured[2:]...), "is not an RFC 6962 MerkleTreeLeaf"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := ctlog.ParseLeaf(tc.leaf)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}
