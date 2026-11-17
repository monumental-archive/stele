// This file: a first-party base's pin, and the ref that produced it.
// The pin must carry both a tag and a digest: the digest is what is
// verified, the tag is what the producing ref is derived from, and a
// base pinned by either alone cannot be judged (.github#715). Which
// tags map to which refs is a declared convention — rules arrive from
// the caller, in order, and the first whose pattern matches the tag
// names the ref.

package baseimage

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// digestRE is the one digest form a pin may carry.
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Pin is one base reference read whole: the repository it names, the
// tag it advertises, and the digest it is pinned at.
type Pin struct {
	Ref        string
	Repository string
	Tag        string
	Digest     string
}

// ParsePin reads a reference pinned as image:tag@sha256:…, refusing
// each half missing in the words the pin form is taught by.
func ParsePin(ref string) (Pin, error) {
	image, digest, ok := strings.Cut(ref, "@")
	if !ok {
		return Pin{}, fmt.Errorf("%s is a first-party base with no digest — there is nothing to verify; pin as"+
			" image:tag@sha256:…", ref)
	}

	if !digestRE.MatchString(digest) {
		return Pin{}, fmt.Errorf("%s: the digest is not sha256:<64 lowercase hex>; pin as image:tag@sha256:…", ref)
	}

	tag, err := name.NewTag(image, name.StrictValidation)
	if err != nil {
		if _, rerr := name.NewRepository(image, name.StrictValidation); rerr == nil {
			return Pin{}, fmt.Errorf("%s carries a digest but no tag, so the ref that produced it cannot be"+
				" derived — pin as image:tag@sha256:… (Renovate rolls both together)", ref)
		}

		return Pin{}, fmt.Errorf("%s is not an image reference; pin as image:tag@sha256:…", ref)
	}

	return Pin{Ref: ref, Repository: tag.Context().Name(), Tag: tag.TagStr(), Digest: digest}, nil
}

// RefRule is one declared convention: a tag pattern, its named groups
// available to the ref template as ${name}.
type RefRule struct {
	Tag *regexp.Regexp
	Ref string
}

// DeriveRef names the ref that produced the pinned bytes: the first
// rule whose pattern matches the tag, its template expanded from the
// match. A tag no rule matches is a shape the declared publish path
// cannot produce, so it is refused rather than guessed at.
func DeriveRef(pin Pin, rules []RefRule) (string, error) {
	for _, r := range rules {
		m := r.Tag.FindStringSubmatchIndex(pin.Tag)
		if m == nil {
			continue
		}

		return string(r.Tag.ExpandString(nil, r.Ref, pin.Tag, m)), nil
	}

	patterns := make([]string, 0, len(rules))
	for _, r := range rules {
		patterns = append(patterns, r.Tag.String())
	}

	return "", fmt.Errorf("%s: cannot derive the ref that produced it from tag '%s' — the declared tags are %s",
		pin.Ref, pin.Tag, strings.Join(patterns, ", "))
}
