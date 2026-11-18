// Package baseimage judges the base images a build instantiates
// (stele#402): a first-party base against the org's own provenance,
// an official image against the upstream provenance it publishes.
// Nothing here names an organisation, a registry or a repository —
// every expectation arrives from the caller's declaration — and
// nothing here reads a Dockerfile: which images a build uses is the
// build's to say.
//
// This file: the upstream check. A Docker Official Image carries
// BuildKit in-toto provenance (slsa.dev/provenance/v0.2) per platform,
// unsigned — which is why the org's signed statement about having
// verified it is the strongest claim available without owning the
// build. Every platform in the pinned index must carry provenance whose
// configSource names the expected repository and directory; a platform
// with none, or naming any other source, refuses (.github#212).
package baseimage

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/oci"
)

// ProvenanceV02 is the predicate type BuildKit's provenance carries.
const ProvenanceV02 = "https://slsa.dev/provenance/v0.2"

// UpstreamFacts are what a verified upstream check states: the source
// revisions the platforms were built from (deduplicated — a healthy
// index builds every platform from one commit), the platforms verified,
// and the provenance type read. Field order is the approval predicate's.
type UpstreamFacts struct {
	Sources        []string `json:"sources"`
	Platforms      []string `json:"platforms"`
	ProvenanceType string   `json:"provenanceType"`
}

// statement is the part of a BuildKit provenance statement the check
// reads: the predicate type, and the build's config source.
type statement struct {
	PredicateType *string `json:"predicateType"`
	Predicate     *struct {
		Invocation *struct {
			ConfigSource *struct {
				URI *string `json:"uri"`
			} `json:"configSource"`
		} `json:"invocation"`
	} `json:"predicate"`
}

// errNoProvenance is the refusal for an image that publishes none.
var errNoProvenance = errors.New("upstream publishes no provenance — refusing to verify nothing")

// JudgeUpstream holds every platform of one pinned image to the
// expected source: repository is the git URL the config source names
// (BuildKit's <repository>#<ref>:<directory> context), and directory
// the path within it. ref names the image in every refusal.
func JudgeUpstream(
	ref string, platforms []oci.PlatformStatements, repository, directory string,
) (*UpstreamFacts, error) {
	published := slices.ContainsFunc(platforms, func(p oci.PlatformStatements) bool { return len(p.Statements) > 0 })
	if !published {
		return nil, fmt.Errorf("%s: %w", ref, errNoProvenance)
	}

	facts := &UpstreamFacts{ProvenanceType: ProvenanceV02}

	for _, p := range platforms {
		if len(p.Statements) == 0 {
			return nil, fmt.Errorf("%s: %s carries no provenance — an unverifiable base is a red run", ref, p.Platform)
		}

		for _, raw := range p.Statements {
			uri, err := configSource(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", ref, p.Platform, err)
			}

			if !names(uri, repository, directory) {
				return nil, fmt.Errorf("%s: %s's provenance names %s, not %s at %s — refusing to attest a"+
					" verification that failed", ref, p.Platform, uri, repository, directory)
			}

			if !slices.Contains(facts.Sources, uri) {
				facts.Sources = append(facts.Sources, uri)
			}
		}

		facts.Platforms = append(facts.Platforms, p.Platform)
	}

	slices.Sort(facts.Sources)
	slices.Sort(facts.Platforms)

	return facts, nil
}

// configSource reads the config source a provenance statement names.
func configSource(raw []byte) (string, error) {
	st, err := jsonx.DecodeForeign[statement](raw)
	if err != nil {
		return "", fmt.Errorf("the provenance is not a statement: %w", err)
	}

	switch {
	case st.PredicateType == nil || *st.PredicateType != ProvenanceV02:
		return "", fmt.Errorf("the provenance is not %s", ProvenanceV02)
	case st.Predicate == nil || st.Predicate.Invocation == nil || st.Predicate.Invocation.ConfigSource == nil ||
		st.Predicate.Invocation.ConfigSource.URI == nil:
		return "", errors.New("the provenance names no config source")
	}

	return *st.Predicate.Invocation.ConfigSource.URI, nil
}

// names reports whether a BuildKit git context — <repository>#<ref>:
// <directory> — is the expected repository and directory. Exact on
// both: a prefix match on the directory would accept 114/bookworm for
// 14/bookworm.
func names(uri, repository, directory string) bool {
	repo, rest, ok := strings.Cut(uri, "#")
	if !ok || repo != repository {
		return false
	}

	_, dir, ok := strings.Cut(rest, ":")

	return ok && dir == directory
}
