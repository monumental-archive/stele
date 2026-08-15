// Package provenance implements the SLSA provenance v1 predicate —
// the evidence the build track's verdict summarises. Spec:
// slsa.dev/provenance/v1. Only the fields verification reads are
// judged here; externalParameters and internalParameters stay raw
// because their shape belongs to the buildType, and the policy names
// which buildTypes exist.
package provenance

import (
	"errors"
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// PredicateType is the spec's predicate type URI.
const PredicateType = "https://slsa.dev/provenance/v1"

// Predicate is the provenance predicate, decoded strictly.
type Predicate struct {
	BuildDefinition *BuildDefinition `json:"buildDefinition"`
	RunDetails      *RunDetails      `json:"runDetails"`
}

// BuildDefinition describes the build. BuildType and
// ExternalParameters are the spec's REQUIRED pair; both travel
// onward for the policy comparison.
type BuildDefinition struct {
	BuildType            *string                     `json:"buildType"`
	ExternalParameters   jsonx.Raw                   `json:"externalParameters"`
	InternalParameters   jsonx.Raw                   `json:"internalParameters"`
	ResolvedDependencies []intoto.ResourceDescriptor `json:"resolvedDependencies"`
}

// RunDetails carries the builder identity and run metadata.
type RunDetails struct {
	Builder    *Builder  `json:"builder"`
	Metadata   jsonx.Raw `json:"metadata"`
	Byproducts jsonx.Raw `json:"byproducts"`
}

// Builder names the build platform. ID is the spec's REQUIRED field
// and the anchor of the level lookup.
type Builder struct {
	ID                  *string                     `json:"id"`
	Version             map[string]string           `json:"version"`
	BuilderDependencies []intoto.ResourceDescriptor `json:"builderDependencies"`
}

// Validate refuses a predicate missing the spec's required fields.
func (p *Predicate) Validate() error {
	if p.BuildDefinition == nil {
		return errors.New("provenance: buildDefinition is absent")
	}

	if p.BuildDefinition.BuildType == nil || !strings.HasPrefix(*p.BuildDefinition.BuildType, "https://") {
		return errors.New("provenance: buildDefinition.buildType must be present and an https URI")
	}

	if len(p.BuildDefinition.ExternalParameters) == 0 {
		return errors.New("provenance: buildDefinition.externalParameters is absent")
	}

	if p.RunDetails == nil {
		return errors.New("provenance: runDetails is absent")
	}

	if p.RunDetails.Builder == nil {
		return errors.New("provenance: runDetails.builder is absent")
	}

	if p.RunDetails.Builder.ID == nil || *p.RunDetails.Builder.ID == "" {
		return errors.New("provenance: runDetails.builder.id is absent or empty")
	}

	return nil
}

// SourceRevision selects the attested source revision: the
// resolvedDependencies entry whose uri names the given repository.
// Selection is by content, never by position — the spec gives the
// array no order, so an index read is a bet on the producer's habits
// (the bash oracle's resolvedDependencies[0] read, logged as
// disagreement 1 in docs/policy-schema.md). Exactly one entry must
// match and it must carry a gitCommit digest; zero matches, two
// matches, or a matching entry without the digest are refusals.
func (p *Predicate) SourceRevision(repoURL string) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}

	var revision string

	for _, dep := range p.BuildDefinition.ResolvedDependencies {
		if dep.URI == nil || !namesRepository(*dep.URI, repoURL) {
			continue
		}

		got, ok := dep.Digest[intoto.AlgGitCommit]
		if !ok {
			return "", fmt.Errorf("provenance: the source entry for %s carries no gitCommit digest", repoURL)
		}

		if revision != "" && revision != got {
			return "", fmt.Errorf("provenance: two source entries for %s disagree on the revision", repoURL)
		}

		revision = got
	}

	if revision == "" {
		return "", fmt.Errorf("provenance: no resolvedDependencies entry names the source repository %s", repoURL)
	}

	return revision, nil
}

// namesRepository reports whether an SPDX download-location URI names
// exactly the given repository: "git+<repo>" alone or followed by an
// @ref — never a prefix of a longer repository name.
func namesRepository(uri, repoURL string) bool {
	rest, ok := strings.CutPrefix(uri, "git+"+repoURL)
	if !ok {
		return false
	}

	return rest == "" || strings.HasPrefix(rest, "@")
}
