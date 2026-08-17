// The assert policy: everything org-shaped the evidence walk needs,
// as committed data — class names, their bundle assets, the store-VSA
// epoch, the debt file, the population expectation. Zero org names in
// code; the schema is docs/assert-policy-schema.md, written first.
// Decode contract: pointer fields, strict decode, explicit nil
// rejection (the jsonx law).

package assert

import (
	"errors"
	"fmt"
	"io"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// Policy is the committed assert policy. Constructor: LoadPolicy.
type Policy struct {
	Schema   *int            `json:"schema"`
	Evidence *EvidencePolicy `json:"evidence"`
}

// EvidencePolicy parameterises the evidence walk.
type EvidencePolicy struct {
	// SBOMSuffix names the release's SBOM asset by suffix.
	SBOMSuffix *string `json:"sbomSuffix"`
	// Checksums is the checksum manifest asset every release carries.
	Checksums *string `json:"checksums"`
	// UmbrellaBundle is the single-bundle name a release may truthfully
	// use when one bundle covers the whole release.
	UmbrellaBundle *string `json:"umbrellaBundle"`
	// ManifestAsset names the release's own evidence manifest — the
	// declared contract; releases without one fall back to the
	// workflow adapter, and releases with neither are legacy.
	ManifestAsset *string `json:"manifestAsset"`
	// Classes maps each evidence class to its required assets.
	Classes map[string]ClassPolicy `json:"classes"`
	// StoreVSAFromCanon is the canon version (inclusive) from which
	// verdicts are store-resident; before it the legacy VSA bundles
	// ride as release assets.
	StoreVSAFromCanon *string `json:"storeVsaFromCanon"`
	// DebtFile is the committed exceptions file (repo-relative in the
	// policy repo's checkout) holding human-asserted evidence debt.
	DebtFile *string `json:"debtFile"`
	// ExpectedRepos, when set, is the declared org population — a
	// listing that sees a different count cannot judge.
	ExpectedRepos *int `json:"expectedRepos,omitempty"`
}

// ClassPolicy is one evidence class's asset obligations.
type ClassPolicy struct {
	// Bundles are the attestation bundle assets the class requires.
	Bundles []string `json:"bundles"`
	// LegacyVSABundles are additionally required BEFORE the store-VSA
	// epoch.
	LegacyVSABundles []string `json:"legacyVsaBundles,omitempty"`
	// AssetPrefixes are non-bundle assets required by prefix match.
	AssetPrefixes []string `json:"assetPrefixes,omitempty"`
}

// LoadPolicy reads and validates the committed assert policy.
func LoadPolicy(r io.Reader) (*Policy, error) {
	p, err := jsonx.Decode[Policy](r)
	if err != nil {
		return nil, fmt.Errorf("assert: policy: %w", err)
	}

	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("assert: policy: %w", err)
	}

	return p, nil
}

func (p *Policy) validate() error {
	if p.Schema == nil || *p.Schema != 1 {
		return errors.New("schema must be 1")
	}

	e := p.Evidence
	if e == nil {
		return errors.New("evidence is absent")
	}

	for name, field := range map[string]*string{
		"evidence.sbomSuffix":     e.SBOMSuffix,
		"evidence.checksums":      e.Checksums,
		"evidence.umbrellaBundle": e.UmbrellaBundle,
		"evidence.manifestAsset":  e.ManifestAsset,
		"evidence.debtFile":       e.DebtFile,
	} {
		if field == nil || *field == "" {
			return fmt.Errorf("%s is absent or empty", name)
		}
	}

	if len(e.Classes) == 0 {
		return errors.New("evidence.classes is empty — a walk with no classes asserts nothing")
	}

	for name, c := range e.Classes {
		if len(c.Bundles) == 0 && len(c.AssetPrefixes) == 0 {
			return fmt.Errorf("evidence.classes.%s requires nothing — an empty class asserts nothing", name)
		}
	}

	if e.StoreVSAFromCanon != nil {
		if _, err := semver.NewVersion(*e.StoreVSAFromCanon); err != nil {
			return fmt.Errorf("evidence.storeVsaFromCanon: %w", err)
		}
	}

	if e.ExpectedRepos != nil && *e.ExpectedRepos <= 0 {
		return errors.New("evidence.expectedRepos must be positive when set")
	}

	return nil
}

// storeVSA reports whether a release under the given canon version
// keeps its verdicts in the attestation store. No epoch configured
// means store-resident always.
func (e *EvidencePolicy) storeVSA(canonVersion string) bool {
	if e.StoreVSAFromCanon == nil {
		return true
	}

	epoch := semver.MustParse(*e.StoreVSAFromCanon)

	v, err := semver.NewVersion(canonVersion)
	if err != nil {
		// An unparsable pin cannot prove the pre-epoch exemption;
		// fail toward the stricter obligation.
		return true
	}

	return !v.LessThan(epoch)
}
