// The subject readers and the rehearsal. Every refusal row asserts its
// message; the judgment itself is internal/assert's (assert published).

package published_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/published"
)

const (
	hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	ref  = "ghcr.io/acme/app"
)

func TestParseFiles(t *testing.T) {
	t.Parallel()

	got, err := published.ParseFiles("\n" + hexA + "  app-1.0.0.crate\r\n\n" + hexB + "  @scope+pkg-1.0.0.tgz\n")
	if err != nil {
		t.Fatalf("ParseFiles = %v", err)
	}

	want := []published.File{{SHA256: hexA, Name: "app-1.0.0.crate"}, {SHA256: hexB, Name: "@scope+pkg-1.0.0.tgz"}}
	if !slices.Equal(got, want) {
		t.Fatalf("ParseFiles = %+v, want %+v", got, want)
	}

	if got, err := published.ParseFiles(""); err != nil || len(got) != 0 {
		t.Fatalf("ParseFiles(\"\") = %v, %v; want nothing", got, err)
	}
}

func TestParseFilesRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, text, want string
	}{
		{"one space", hexA + " app.crate\n", "subject line 1 is not a sha256sum record"},
		{"uppercase hex", strings.ToUpper(hexA) + "  app.crate\n", "subject line 1 is not a sha256sum record"},
		{"a short digest", hexA[:63] + "  app.crate\n", "subject line 1 is not a sha256sum record"},
		{"no name", hexA + "  \n", "subject line 1 is not a sha256sum record"},
		{"a name with a space", hexA + "  app 1.crate\n", "subject line 1 is not a sha256sum record"},
		{"a binary-mode marker's extra space", hexA + "   app.crate\n", "subject line 1 is not a sha256sum record"},
		{
			"counted among the records, blank lines skipped",
			hexA + "  a.crate\n\n" + hexB + "  b.crate\n$(curl evil)\n",
			"subject line 3 is not a sha256sum record",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := published.ParseFiles(tt.text)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("ParseFiles = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseImages(t *testing.T) {
	t.Parallel()

	got, err := published.ParseImages(`[{"image": "` + ref + `", "tag": "1.0.0", "digest": "sha256:` + hexA +
		`", "platform": "ignored"}, {"image": "docker.io/library/app", "tag": "v1_rc-2.x", "digest": "sha256:` +
		hexB + `"}]`)
	if err != nil {
		t.Fatalf("ParseImages = %v", err)
	}

	want := []published.Image{
		{Image: ref, Tag: "1.0.0", Digest: "sha256:" + hexA},
		{Image: "docker.io/library/app", Tag: "v1_rc-2.x", Digest: "sha256:" + hexB},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ParseImages = %+v, want %+v", got, want)
	}

	if got, err := published.ParseImages(" \n"); err != nil || got != nil {
		t.Fatalf("ParseImages(blank) = %v, %v; want no images", got, err)
	}
}

func TestParseImagesRefusals(t *testing.T) {
	t.Parallel()

	entry := func(image, tag, digest string) string {
		return fmt.Sprintf(`[{"image": %q, "tag": %q, "digest": %q}]`, image, tag, digest)
	}

	const (
		shape           = "images is not a JSON array of {image, tag, digest}"
		untaggedRefusal = "image 1 is not an untagged image reference"
	)

	tests := []struct {
		name, text, want string
	}{
		{"not JSON", "{", shape},
		{"an object, not an array", `{"image": "x"}`, shape},
		{"an empty array", `[]`, shape},
		{"a missing key", `[{"image": "` + ref + `", "tag": "1"}]`, shape},
		{"a number where a string goes", `[{"image": "` + ref + `", "tag": 1, "digest": "x"}]`, shape},
		{"trailing data", entry(ref, "1", "sha256:"+hexA) + " []", shape},
		{"a tagged reference", entry(ref+":1.0.0", "1.0.0", "sha256:"+hexA), untaggedRefusal},
		{"a digested reference", entry(ref+"@sha256:"+hexA, "1", "sha256:"+hexA), untaggedRefusal},
		{"no registry, which the parser would default", entry("acme/app", "1", "sha256:"+hexA), untaggedRefusal},
		{"an implied library namespace", entry("docker.io/app", "1", "sha256:"+hexA), untaggedRefusal},
		{"an uppercase repository", entry("ghcr.io/Acme/app", "1", "sha256:"+hexA), untaggedRefusal},
		{"an empty tag", entry(ref, "", "sha256:"+hexA), "image 1 has an implausible tag"},
		{"a tag with a slash", entry(ref, "a/b", "sha256:"+hexA), "image 1 has an implausible tag"},
		{"a tag opening with a dot", entry(ref, ".x", "sha256:"+hexA), "image 1 has an implausible tag"},
		{"a bare hex digest", entry(ref, "1", hexA), "image 1 digest is not sha256:<64 lowercase hex>"},
		{"another algorithm", entry(ref, "1", "sha512:"+hexA), "image 1 digest is not sha256:<64 lowercase hex>"},
		{
			"the position is the second image's",
			`[{"image": "` + ref + `", "tag": "1", "digest": "sha256:` + hexA + `"}, ` +
				`{"image": "` + ref + `", "tag": "1", "digest": "sha256:` + strings.ToUpper(hexA) + `"}]`,
			"image 2 digest is not sha256:<64 lowercase hex>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := published.ParseImages(tt.text)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("ParseImages = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRehearse(t *testing.T) {
	t.Parallel()

	var logs []string

	got := published.Rehearse(
		[]published.File{{Name: "app-1.0.0.crate", SHA256: hexA}},
		[]published.Image{{Image: ref, Tag: "1.0.0", Digest: "sha256:" + hexB}},
		func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
	)

	want := []string{hexA + "  app-1.0.0.crate", hexB + "  " + ref}

	lines := make([]string, 0, len(got))
	for _, l := range got {
		lines = append(lines, l.String())
	}

	if !slices.Equal(lines, want) {
		t.Fatalf("Rehearse = %q, want %q", lines, want)
	}

	wantLogs := []string{
		"rehearsal: app-1.0.0.crate was NOT proved against a registry",
		"rehearsal: " + ref + ":1.0.0 was NOT resolved against the registry",
	}
	if !slices.Equal(logs, wantLogs) {
		t.Fatalf("logs = %q, want %q", logs, wantLogs)
	}
}
