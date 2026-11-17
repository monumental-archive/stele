package published

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// File is one file subject: the name it is published under and the
// sha256 the build recorded for it, lowercase hex.
type File struct {
	Name   string
	SHA256 string
}

// Image is one image subject: the untagged reference, the tag the
// release advertises, and the attested index digest (sha256:<hex>).
type Image struct {
	Image  string
	Tag    string
	Digest string
}

// Line is one line of a manifest — the sha256sum shape the signer
// attests, so a line here is a subject there.
type Line struct {
	SHA256 string
	Name   string
}

// String renders the line as sha256sum writes it.
func (l Line) String() string { return l.SHA256 + "  " + l.Name }

// recordRE is one sha256sum record: 64 lowercase hex, two spaces, and
// a name with no whitespace in it — the shape the verifier downstream
// holds every subject to, so a name it would refuse is refused here,
// at the reader, rather than after a registry was asked about it.
var recordRE = regexp.MustCompile(`^([0-9a-f]{64}) {2}(\S+)$`)

// ParseFiles reads a sha256sum manifest. Blank lines are skipped and a
// CR before the newline is tolerated; anything else that is not a
// record refuses, by its position among the records and never by its
// text — the line is caller-controlled.
func ParseFiles(text string) ([]File, error) {
	var (
		files []File
		count int
	)

	for raw := range strings.Lines(text) {
		line := strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r")
		if line == "" {
			continue
		}

		count++

		m := recordRE.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("subject line %d is not a sha256sum record", count)
		}

		files = append(files, File{SHA256: m[1], Name: m[2]})
	}

	return files, nil
}

// imageEntry is one element of the images input. The input is the
// build's signing-matrix output passed through unchanged, so keys this
// reader does not use are tolerated; the three it does use are
// required, and absent is told apart from empty.
type imageEntry struct {
	Image  *string `json:"image"`
	Tag    *string `json:"tag"`
	Digest *string `json:"digest"`
}

// The shapes an image subject is held to. The tag grammar is the OCI
// distribution spec's; the digest is the one algorithm the attested
// index is named by.
var (
	tagRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ParseImages reads the image subjects: a JSON array of {image, tag,
// digest}. Blank input is no images. Each refusal names the image by
// its position, never by its caller-controlled text.
//
// The reference is held to the OCI reference grammar and nothing
// narrower: which registry an organisation publishes to is not this
// reader's to know. It must be UNTAGGED — the manifest line carries
// the bare reference, because that is the subject name the signer
// attested — and the grammar's own lowercase rule holds.
func ParseImages(text string) ([]Image, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}

	const shape = "images is not a JSON array of {image, tag, digest}"

	entries, err := jsonx.DecodeForeign[[]imageEntry]([]byte(text))
	if err != nil || len(*entries) == 0 {
		return nil, errors.New(shape)
	}

	images := make([]Image, 0, len(*entries))

	for i, e := range *entries {
		n := i + 1

		switch {
		case e.Image == nil || e.Tag == nil || e.Digest == nil:
			return nil, errors.New(shape)
		case !untagged(*e.Image):
			return nil, fmt.Errorf("image %d is not an untagged image reference", n)
		case !tagRE.MatchString(*e.Tag):
			return nil, fmt.Errorf("image %d has an implausible tag", n)
		case !digestRE.MatchString(*e.Digest):
			return nil, fmt.Errorf("image %d digest is not sha256:<64 lowercase hex>", n)
		}

		images = append(images, Image{Image: *e.Image, Tag: *e.Tag, Digest: *e.Digest})
	}

	return images, nil
}

// untagged reports whether ref is a repository reference carrying
// neither a tag nor a digest, with every part spelled out: strict
// validation refuses a reference the parser would otherwise default (a
// missing registry, an implied library/ namespace), which would widen
// it into a name the signer never attested.
func untagged(ref string) bool {
	_, err := name.NewRepository(ref, name.StrictValidation)

	return err == nil
}

// ErrEmpty is the refusal for a proof with nothing in it — a
// rehearsal included: an empty rehearsal rehearses nothing.
var ErrEmpty = errors.New("nothing to verify — an empty proof is not a proof")

// Rehearse is the dry run's half: nothing was published, so there are
// no served bytes to pull back. The manifest passes through as built,
// and every subject says, by name, that it was NOT proved — a rehearsal
// must never be mistaken for proof. The caller refuses an empty one
// first, as it refuses an empty proof (ErrEmpty).
func Rehearse(files []File, images []Image, log func(format string, args ...any)) []Line {
	lines := make([]Line, 0, len(files)+len(images))

	for _, f := range files {
		lines = append(lines, Line{SHA256: f.SHA256, Name: f.Name})
		log("rehearsal: %s was NOT proved against a registry", f.Name)
	}

	for _, img := range images {
		lines = append(lines, Line{SHA256: strings.TrimPrefix(img.Digest, "sha256:"), Name: img.Image})
		log("rehearsal: %s:%s was NOT resolved against the registry", img.Image, img.Tag)
	}

	return lines
}
