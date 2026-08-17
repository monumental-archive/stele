// Package assert is the comparison verb's engine: read evidence,
// read a declaration, report divergence — never mint anything. Each
// target returns a sealed report; infrastructure failure (a fetch
// that died, bytes that decode as nothing) returns an error instead,
// which the CLI seals as CANNOT_JUDGE: "I found drift" and "I could
// not look" stay distinct all the way out (docs/report-schema.md).
//
// This file: image facts. A published image's index annotations and
// every per-architecture config's labels must EQUAL the resolved
// facts map — equality, not presence: presence lets a wrong revision
// through, which is worse than a missing one. Judged against the
// published bytes by digest, the same posture as every other proof:
// a claim is asserted of the artifact a stranger will pull, never of
// a local twin.
package assert

import (
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/oci"
	"github.com/monumental-archive/stele/internal/report"
)

// Logf receives progress lines; the caller owns the stream.
type Logf func(format string, args ...any)

// ociIndexMediaType is what the index must declare. A Docker manifest
// list here means the per-arch push exporter ran without
// oci-mediatypes=true, and buildx dropped the annotations SILENTLY
// (docker/buildx#1965) — the failure mode that looks exactly like
// success, and the reason this assertion exists.
const ociIndexMediaType = "application/vnd.oci.image.index.v1+json"

// The assertion vocabulary for image-facts findings.
const (
	assertMediaType = "index-media-type"
	assertIndexAnn  = "index-annotations"
	assertLabels    = "config-labels"
	assertHygiene   = "fact-hygiene"
)

var (
	digestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	controlRE = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// indexDoc is the strict shape of what the engine judges in a fetched
// manifest. Foreign-decoded: the OCI image spec is somebody else's
// evolving schema and registries extend it — but required fields are
// pointers, so absent still refuses.
type indexDoc struct {
	MediaType   *string           `json:"mediaType"`
	Annotations map[string]string `json:"annotations"`
	Manifests   []manifestDoc     `json:"manifests"`
}

type manifestDoc struct {
	Digest   *string      `json:"digest"`
	Platform *platformDoc `json:"platform"`
}

type platformDoc struct {
	OS           *string `json:"os"`
	Architecture *string `json:"architecture"`
}

// ImageFacts asserts one published image against its facts map and
// seals the verdict. The facts values re-pass the hygiene rules
// independently of whoever resolved them — a resolver bug cannot
// self-certify.
func ImageFacts(image, digest string, factsJSON []byte, r oci.Reader, log Logf) (*report.Report, error) {
	if image == "" {
		return nil, errors.New("assert: IMAGE is required")
	}

	if !digestRE.MatchString(digest) {
		return nil, fmt.Errorf("assert: DIGEST %q is not a sha256 digest", digest)
	}

	facts, err := jsonx.DecodeBytes[map[string]string](factsJSON)
	if err != nil {
		return nil, fmt.Errorf("assert: FACTS is not a flat string map: %w", err)
	}

	subject := image + "@" + digest

	var findings []report.Finding

	findings = append(findings, hygieneFindings(subject, *facts)...)

	raw, err := r.Index(image, digest)
	if err != nil {
		return nil, fmt.Errorf("assert: %w", err)
	}

	idx, err := jsonx.DecodeForeign[indexDoc](raw)
	if err != nil {
		return nil, fmt.Errorf("assert: index at %s: %w", subject, err)
	}

	findings = append(findings, indexFindings(subject, idx, *facts)...)

	children := platformChildren(idx)

	for _, child := range children {
		f, cerr := labelFindings(image, child, *facts, r)
		if cerr != nil {
			return nil, cerr
		}

		findings = append(findings, f...)

		log("assert: image-facts: %s labels checked", child.platform)
	}

	pop := report.PopulationFromEvidence(len(children), "platform manifests in the index")

	return report.Seal("assert image-facts", subject, pop, findings, nil, report.NoCanary()), nil
}

// hygieneFindings re-checks every fact value: non-empty, no control
// characters. Independent of the registry read by design.
func hygieneFindings(subject string, facts map[string]string) []report.Finding {
	var out []report.Finding

	for _, k := range sortedKeys(facts) {
		v := facts[k]
		switch {
		case v == "":
			out = append(out, report.Finding{
				Subject: subject, Assertion: assertHygiene, Actual: "",
				Detail: fmt.Sprintf("fact %q is empty", k),
			})
		case controlRE.MatchString(v):
			out = append(out, report.Finding{
				Subject: subject, Assertion: assertHygiene,
				Detail: fmt.Sprintf("fact %q carries control characters", k),
			})
		}
	}

	return out
}

// indexFindings judges the index document: media type, then the
// annotations map against the facts map, drift named per key.
func indexFindings(subject string, idx *indexDoc, facts map[string]string) []report.Finding {
	var out []report.Finding

	mt := ""
	if idx.MediaType != nil {
		mt = *idx.MediaType
	}

	if mt != ociIndexMediaType {
		out = append(out, report.Finding{
			Subject: subject, Assertion: assertMediaType,
			Expected: ociIndexMediaType, Actual: mt,
			Detail: "not an OCI index — annotations were dropped (oci-mediatypes=false somewhere)",
		})
	}

	out = append(out, mapFindings(subject, assertIndexAnn, idx.Annotations, facts)...)

	return out
}

// child pairs one platform manifest's digest with its platform name.
type child struct {
	digest   string
	platform string
}

// platformChildren selects the manifests that are images: attestation
// manifests (unknown/unknown platform) are BuildKit provenance, not
// images, and carry no config labels. A child with no digest cannot
// be fetched and is skipped here — the population count then reflects
// only what was actually judgeable.
func platformChildren(idx *indexDoc) []child {
	var out []child

	for _, m := range idx.Manifests {
		if m.Digest == nil || m.Platform == nil || m.Platform.OS == nil || *m.Platform.OS == "unknown" {
			continue
		}

		arch := ""
		if m.Platform.Architecture != nil {
			arch = *m.Platform.Architecture
		}

		out = append(out, child{digest: *m.Digest, platform: *m.Platform.OS + "/" + arch})
	}

	return out
}

// labelFindings judges one per-architecture config's labels — what
// `docker inspect` shows a consumer, and what the smoke test ran
// against.
func labelFindings(image string, c child, facts map[string]string, r oci.Reader) ([]report.Finding, error) {
	labels, err := r.ConfigLabels(image, c.digest)
	if err != nil {
		return nil, fmt.Errorf("assert: %w", err)
	}

	return mapFindings(image+"@"+c.digest+" ("+c.platform+")", assertLabels, labels, facts), nil
}

// mapFindings compares got against want key by key, both directions —
// a drifted value, a missing key and a surplus key are three findings
// that each name themselves.
func mapFindings(subject, assertion string, got, want map[string]string) []report.Finding {
	var out []report.Finding

	for _, k := range sortedKeys(want) {
		gv, ok := got[k]
		switch {
		case !ok:
			out = append(out, report.Finding{
				Subject: subject, Assertion: assertion, Expected: want[k],
				Detail: fmt.Sprintf("key %q is absent", k),
			})
		case gv != want[k]:
			out = append(out, report.Finding{
				Subject: subject, Assertion: assertion, Expected: want[k], Actual: gv,
				Detail: fmt.Sprintf("key %q diverges", k),
			})
		}
	}

	for _, k := range sortedKeys(got) {
		if _, ok := want[k]; !ok {
			out = append(out, report.Finding{
				Subject: subject, Assertion: assertion, Actual: got[k],
				Detail: fmt.Sprintf("key %q is not in the facts map", k),
			})
		}
	}

	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}
