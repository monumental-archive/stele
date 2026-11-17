// This file: an official image's upstream check (stele#402), under the
// policy's evidence.baseImages.upstream entries. The build that
// instantiates the image hands `stele verify base` its reference; the
// entry says which source its published provenance must name.

package assert

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/monumental-archive/stele/internal/baseimage"
	"github.com/monumental-archive/stele/internal/oci"
)

// assertUpstream is the judgment an upstream entry records a
// reference under.
const assertUpstream = "upstream-provenance"

// Assertion names the judgment this entry records a reference under.
func (u *UpstreamBase) Assertion() string { return assertUpstream + ":" + *u.Image }

// Covers reports whether a reference is of this entry's image, pinned
// or not: a reference with no digest is still this image's, and is
// refused under it rather than passed by as nobody's. Both sides are
// read through the reference grammar, so a declared
// docker.io/library/postgres covers postgres:14 and index.docker.io's
// spelling alike.
func (u *UpstreamBase) Covers(ref string) bool {
	declared, err := name.NewRepository(*u.Image)
	if err != nil {
		return false
	}

	image, _, _ := strings.Cut(ref, "@")

	got, err := name.ParseReference(image)

	return err == nil && got.Context().Name() == declared.Name()
}

// CheckBinds refuses a caller binding naming a group the entry's tag
// pattern does not capture: a cross-check of nothing is no check.
func (u *UpstreamBase) CheckBinds(binds map[string]string) error {
	re, err := u.Pattern()
	if err != nil {
		return fmt.Errorf("assert: upstream %s %w", *u.Image, err)
	}

	for _, group := range slices.Sorted(maps.Keys(binds)) {
		if group == "" || !slices.Contains(re.SubexpNames(), group) {
			return fmt.Errorf("--bind names %q, which %s's tag pattern %s does not capture",
				group, *u.Image, *u.TagPattern)
		}
	}

	return nil
}

// Expected is the directory the entry's provenance must name for one
// pinned tag: the tag read by the pattern, every caller binding held
// to the group it names, the path expanded from the groups. A tag the
// pattern does not read, or a group that disagrees with its binding,
// is what is wrong with the base — the caller records it.
func (u *UpstreamBase) Expected(pin baseimage.Pin, binds map[string]string) (string, error) {
	re, err := u.Pattern()
	if err != nil {
		return "", fmt.Errorf("assert: upstream %s %w", *u.Image, err)
	}

	m := re.FindStringSubmatchIndex(pin.Tag)
	if m == nil {
		return "", fmt.Errorf("%s: tag '%s' does not match %s — the source it must name cannot be derived",
			pin.Ref, pin.Tag, *u.TagPattern)
	}

	for _, group := range slices.Sorted(maps.Keys(binds)) {
		got := string(re.ExpandString(nil, "${"+group+"}", pin.Tag, m))
		if got != binds[group] {
			return "", fmt.Errorf("%s: the tag's %s is %q, the caller bound %q", pin.Ref, group, got, binds[group])
		}
	}

	return string(re.ExpandString(nil, *u.Path, pin.Tag, m)), nil
}

// JudgeUpstream judges one official image under this entry: the pin
// read, the expected directory derived, every platform's provenance
// read and held to the entry's source at that directory. diverge
// records what is wrong with the image; the facts are the verified
// upstream's, zero when it was not verified; the error is a read the
// run could not make.
func (u *UpstreamBase) JudgeUpstream(
	ref string, binds map[string]string, reader oci.StatementReader, diverge func(string),
) (baseimage.UpstreamFacts, error) {
	pin, err := baseimage.ParseUpstreamPin(ref)
	if err != nil {
		diverge(err.Error())

		return baseimage.UpstreamFacts{}, nil
	}

	directory, err := u.Expected(pin, binds)
	if err != nil {
		diverge(err.Error())

		return baseimage.UpstreamFacts{}, nil
	}

	platforms, err := reader.Statements(pin.Repository, pin.Digest, baseimage.ProvenanceV02)
	if err != nil {
		return baseimage.UpstreamFacts{}, fmt.Errorf("verify: reading %s's provenance: %w", pin.Ref, err)
	}

	facts, err := baseimage.JudgeUpstream(pin.Ref, platforms, *u.Source, directory)
	if err != nil {
		diverge(err.Error())

		return baseimage.UpstreamFacts{}, nil
	}

	return *facts, nil
}
