package manifest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/manifest"
)

func reuseTree(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "REUSE.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return dir
}

// The shape the org's image repositories carry: one aggregate
// annotation over the whole tree.
const reuseAggregate = `version = 1
SPDX-PackageName = "demo"

[[annotations]]
path = ["**"]
precedence = "aggregate"
SPDX-FileCopyrightText = "2026 Demo"
SPDX-License-Identifier = "AGPL-3.0-only"
`

func TestReuseLicence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
		want string
		ok   bool
	}{
		{name: "one annotation, one licence", body: reuseAggregate, want: "AGPL-3.0-only", ok: true},
		{
			name: "two annotations naming the same licence are one declaration",
			body: reuseAggregate + "\n[[annotations]]\npath = \"docs/**\"\nSPDX-License-Identifier = \"AGPL-3.0-only\"\n",
			want: "AGPL-3.0-only", ok: true,
		},
		{
			name: "a copyright-only annotation declares no second licence",
			body: reuseAggregate + "\n[[annotations]]\npath = \"logo.svg\"\nSPDX-FileCopyrightText = \"2026 Other\"\n",
			want: "AGPL-3.0-only", ok: true,
		},
		{
			name: "a one-element list is the same declaration as a string",
			body: "version = 1\n\n[[annotations]]\npath = \"**\"\nSPDX-License-Identifier = [\"MIT\"]\n",
			want: "MIT", ok: true,
		},
		{
			name: "two annotations naming different licences declare none",
			body: reuseAggregate + "\n[[annotations]]\npath = \"vendor/**\"\nSPDX-License-Identifier = \"MIT\"\n",
		},
		{
			name: "a list of two licences declares none",
			body: "version = 1\n\n[[annotations]]\npath = \"**\"\nSPDX-License-Identifier = [\"MIT\", \"0BSD\"]\n",
		},
		{name: "no annotations at all", body: "version = 1\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok, err := manifest.ReuseLicence(reuseTree(t, tc.body))
			if err != nil {
				t.Fatal(err)
			}

			if got != tc.want || ok != tc.ok {
				t.Fatalf("ReuseLicence = (%q, %t), want (%q, %t)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// A tree with no REUSE.toml is a legitimate shape, not an error.
func TestReuseLicenceAbsent(t *testing.T) {
	t.Parallel()

	got, ok, err := manifest.ReuseLicence(t.TempDir())
	if err != nil || ok || got != "" {
		t.Fatalf("ReuseLicence = (%q, %t, %v), want absence", got, ok, err)
	}
}

func TestReuseLicenceRefusals(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
		want string
	}{
		{name: "not TOML", body: "[[annotations\n", want: "not readable as TOML"},
		{
			name: "a licence that is a number",
			body: "[[annotations]]\nSPDX-License-Identifier = 3\n",
			want: "neither a string nor a list of strings",
		},
		{name: "annotations that is not a list", body: "annotations = 3\n", want: "is not a list of tables"},
		{name: "annotations holding a number", body: "annotations = [3]\n", want: "is not a list of tables"},
		{
			name: "a list holding a number",
			body: "[[annotations]]\nSPDX-License-Identifier = [\"MIT\", 3]\n",
			want: "holds a value that is not a string",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, ok, err := manifest.ReuseLicence(reuseTree(t, tc.body))
			if err == nil || ok {
				t.Fatalf("ReuseLicence accepted it (ok=%t, err=%v)", ok, err)
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// An unreadable REUSE.toml is an error, never an absence: the file is
// there, and treating it as missing would fall through to a detector
// the tree's author meant to overrule.
func TestReuseLicenceUnreadable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "REUSE.toml"), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := manifest.ReuseLicence(dir); err == nil || ok {
		t.Fatalf("ReuseLicence read a directory as a file (ok=%t, err=%v)", ok, err)
	}
}
