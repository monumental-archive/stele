// The continuous-digest publish surface: a stream, judged.
//
// A continuous publish has no version and no release. It moves a
// rolling tag onto a fresh image and the evidence that gated it lives
// where evidence can live without a release to hang it off — the
// registry, and the attestation store keyed by digest. Everything
// here is that pair, read live: the tag is resolved at the registry
// rather than at a platform's package API, so a surface declaring a
// registry is readable at ANY registry, a stranger's included.
//
// ONE ASYMMETRY WITH THE RELEASE SURFACE IS DELIBERATE, and it is the
// whole reason this file cannot simply reuse that leg. A release's
// asset list enumerates everything that publish emitted, so an
// inventory missing from it is an inventory the producer did not
// publish — the release leg may refute on that. Reading a digest's
// attestations enumerates nothing of the kind: the store is keyed by
// subject digest, so evidence a publish emitted about OTHER bytes is
// invisible from the image however completely it exists. Measured on
// the first live continuous member (monumental-archive/release-lab,
// 2026-08-24): the publish's signed dependency decision verifies, and
// is reachable only by a caller who already holds the inventory
// documents it decided about, because their bytes' own digests are
// its subjects. So an absence here is could-not-see, never
// did-not-publish, and this leg contributes NO artifact unless it
// found an inventory. Unevaluated with the absences named is the
// honest answer; a refutation would be this tool reporting a gap in
// what an organisation publishes as a gap in what it does.
//
// The absences are named one clause each because they are cleared one
// at a time, and the reason should narrow as they are.

package cli

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/oci"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/verify"
	"github.com/monumental-archive/stele/internal/vexjoin"
)

// dependencyOnContinuous gathers one continuous-digest surface: what
// the rolling tag names now, and what the attestation store holds
// about those bytes under the surface's declared signer.
func (la *levelArgs) dependencyOnContinuous(
	ev *level.Evidence, surface *level.PublishSurface, s population.Surface, forge gh.Forge, out *latch,
) {
	image, tag := *s.Registry, *s.Tag

	// Compiled here rather than assumed: the declaration's load
	// already refused an unparsable pattern, and a gather that PANICS
	// on one instead of reporting it would be the wrong failure at the
	// wrong altitude.
	identity, err := regexp.Compile(*s.Identity)
	if err != nil {
		surface.Missing = append(surface.Missing,
			fmt.Sprintf("the declared signer pattern does not compile: %v", err))

		return
	}

	pub, missing := la.publishedDigests(newOCIReader(), image, tag, out)
	if missing != "" {
		surface.Missing = append(surface.Missing, missing)

		return
	}

	measurer, code := la.measurer(out)
	if code != exitOK {
		surface.Missing = append(surface.Missing,
			"no trust material could be resolved, so nothing the store holds could be proven")

		return
	}

	held := la.storeEvidence(forge, pub, identity, measurer, out)

	surface.Missing = append(surface.Missing, held.absences(*s.Identity, pub)...)

	out.logf("level: %s:%s: %s: %d artifact digest(s), %d inventory attestation(s), %d decision document(s)",
		image, tag, shortDigest(pub.index), len(pub.artifacts), len(held.inventories), held.decided)

	if len(held.inventories) == 0 {
		return
	}

	// The same union rule the release surface applies, for the same
	// reason: one document covering the publish covers each artifact
	// of it, and demanding one document per artifact would be this
	// tool inventing a publishing convention.
	covered := inventoryCovers(held.inventories)

	for _, d := range pub.artifacts {
		name := image + "@" + d
		if covered {
			ev.Inventoried = append(ev.Inventoried, name)

			continue
		}

		ev.Uninventoried = append(ev.Uninventoried, name)
	}

	scanAndJoin(ev, held.inventories, held.decisions, image+":"+tag, out)
	la.gatherSources(ev, held.inventories)
}

// publish is what the registry says is published under a rolling tag:
// the digest the tag names, and the digests of the artifacts it
// resolves to.
//
// The two are kept apart because they answer different questions. The
// index is the address a consumer pulls and the place a publisher
// attests the image as a whole; the artifacts are the bytes each
// platform actually runs, which is the grain a per-architecture
// inventory is taken at. An index that names no children is its own
// artifact — a single-platform publish is a publish.
type publish struct {
	index     string
	artifacts []string
}

// digests is every digest this publish is addressed by: the index and
// its artifacts. Evidence may be attested against any of them, and a
// run that looked at only one of the two would report an absence that
// was really a choice the publisher made about where to attach.
func (p publish) digests() []string {
	return append([]string{p.index}, p.artifacts...)
}

// publishedDigests resolves the rolling tag and reads what it names.
//
// A tag holding nothing is an ANSWER — a surface declared and never
// published on — so it comes back as an absence to report rather than
// as an error to log and forget.
//
//nolint:gocritic // unnamedResult: the publish, then the absence to report when there is none
func (la *levelArgs) publishedDigests(
	reader oci.Reader, image, tag string, out *latch,
) (publish, string) {
	digest, err := reader.Resolve(image, tag)
	if err != nil {
		out.logf("level: %s:%s could not be resolved: %v", image, tag, err)

		return publish{}, fmt.Sprintf("the registry could not be asked what %s:%s names: %v", image, tag, err)
	}

	if digest == "" {
		return publish{}, fmt.Sprintf("the registry holds nothing under the rolling tag %s:%s", image, tag)
	}

	manifest, err := reader.Index(image, digest)
	if err != nil {
		out.logf("level: %s@%s could not be read: %v", image, digest, err)

		return publish{}, fmt.Sprintf("%s names %s and that manifest could not be read: %v", tag, digest, err)
	}

	children, err := manifestChildren(manifest)
	if err != nil {
		return publish{}, fmt.Sprintf("%s names %s and that manifest could not be parsed: %v", tag, digest, err)
	}

	if len(children) == 0 {
		// Not an index: the tag names one artifact directly.
		return publish{index: digest, artifacts: []string{digest}}, ""
	}

	return publish{index: digest, artifacts: children}, ""
}

// manifestIndex is the part of a manifest this read needs: the
// children an index names. A manifest that is not an index simply
// carries none, which is why this decodes rather than branching on a
// media type — the shape answers the question.
type manifestIndex struct {
	Manifests []struct {
		Digest *string `json:"digest"`
	} `json:"manifests"`
}

// manifestChildren lists the digests an index names, in the order the
// index names them.
func manifestChildren(manifest []byte) ([]string, error) {
	doc, err := jsonx.DecodeForeign[manifestIndex](manifest)
	if err != nil {
		return nil, fmt.Errorf("the manifest is not readable JSON: %w", err)
	}

	out := make([]string, 0, len(doc.Manifests))

	for _, m := range doc.Manifests {
		if m.Digest != nil && *m.Digest != "" {
			out = append(out, *m.Digest)
		}
	}

	return out, nil
}

// stored is what the attestation store held for one publish's
// digests, under the surface's declared signer.
type stored struct {
	// inventories are the dependency inventories found, keyed by the
	// digest they were attested against — the same map shape the
	// release surface's asset inventories take, so everything
	// downstream is shared.
	inventories map[string][]byte
	// decisions are the triage decisions found, parsed for the join.
	decisions *vexjoin.Decisions
	// decided counts the decision documents that reached that join.
	decided int
	// bundles is how many attestations the store held at all, and mine
	// how many of them verified under the declared signer. The pair
	// separates "the publisher attests nothing here" from "somebody
	// else's identity is signing these bytes", which are different
	// things to go and fix.
	bundles, mine int
	// bare are the artifact digests the store held nothing for.
	bare []string
}

// storeEvidence reads the attestation store for every digest this
// publish is addressed by, and keeps what verifies under the declared
// signer.
//
// The signer decides WHERE to look and never what is true. An
// attestation under some other identity is not this surface's
// evidence and produces nothing — no finding, no count — the same way
// a reference outside a base scope's registry prefix is out of scope
// rather than a defect. What it can never do is establish anything:
// a bundle still has to CARRY an inventory or a decision to count for
// one, and the declared identity only says whose bundles are read.
func (la *levelArgs) storeEvidence(
	forge gh.Forge, pub publish, identity *regexp.Regexp, measurer verify.Measurer, out *latch,
) stored {
	held := stored{inventories: map[string][]byte{}, decisions: &vexjoin.Decisions{}}
	artifacts := map[string]bool{}

	for _, d := range pub.artifacts {
		artifacts[d] = true
	}

	for _, d := range pub.digests() {
		bundles, err := forge.Attestations(la.owner, la.name, strings.TrimPrefix(d, "sha256:"))
		if err != nil {
			out.logf("level: attestations of %s unreadable: %v", shortDigest(d), err)

			continue
		}

		if len(bundles) == 0 && artifacts[d] {
			held.bare = append(held.bare, d)
		}

		held.bundles += len(bundles)

		for _, raw := range bundles {
			held.keep(raw, d, identity, measurer, out)
		}
	}

	return held
}

// keep classifies one verified bundle: an inventory, a triage
// decision, or neither.
//
// Both are recognised BY CONTENT, the rule the release surface
// already follows for the same documents as release assets. SPDX,
// CycloneDX and OpenVEX each name themselves inside their own bytes,
// so a producer may attest them under whatever predicate type they
// like — and the alternative, a declared predicate URI per document
// kind, would make a standard format's identity into a convention
// every adopter had to restate.
func (h *stored) keep(
	raw jsonx.Raw, digest string, identity *regexp.Regexp, measurer verify.Measurer, out *latch,
) {
	verified, err := measurer.MeasureAttestation(raw, strings.TrimPrefix(digest, "sha256:"))
	if err != nil {
		return
	}

	if !identity.MatchString(verified.SAN) {
		return // somebody else's signature over these bytes: not this surface's evidence
	}

	h.mine++

	predicate, ok := attestationPredicate(verified.Payload)
	if !ok {
		return
	}

	switch {
	case bytes.Contains(predicate, []byte(`"spdxVersion"`)), bytes.Contains(predicate, []byte(`"bomFormat"`)):
		h.inventories[digest] = predicate
	case bytes.Contains(predicate, []byte("openvex.dev/ns")):
		if perr := vexjoin.Parse(h.decisions, predicate, shortDigest(digest)); perr != nil {
			out.logf("level: triage document attested for %s unreadable: %v", shortDigest(digest), perr)

			return
		}

		h.decided++
	}
}

// absences names what this surface was asked for and did not hold.
//
// One clause per absence, each naming a thing a producer can publish.
// A single sentence covering all of them would go on saying the same
// thing until the last was fixed, and the point of the account is
// that it narrows.
func (h *stored) absences(identity string, pub publish) []string {
	var out []string

	if len(h.inventories) == 0 {
		out = append(out, fmt.Sprintf(
			"no attestation over the published digest %s or its %d artifact digest(s) carries a dependency"+
				" inventory (an SPDX or CycloneDX document)", shortDigest(pub.index), len(pub.artifacts)))
	}

	if h.decided == 0 {
		out = append(out, "no attestation over those digests carries a triage decision (an OpenVEX document)")
	}

	if len(h.bare) > 0 {
		out = append(out, fmt.Sprintf(
			"%d of the %d artifact digest(s) the publish names carry no attestation at all",
			len(h.bare), len(pub.artifacts)))
	}

	if h.bundles > 0 && h.mine == 0 {
		out = append(out, fmt.Sprintf(
			"%d attestation(s) were held over these digests and none verifies under the declared signer %q",
			h.bundles, identity))
	}

	return out
}

// attestationPredicate takes the document an attestation is ABOUT out
// of the statement that carries it.
//
// The statement is the envelope, not the evidence: an inventory
// attested over a digest is an in-toto statement whose predicate IS
// the inventory, and handing the whole statement to a scanner or a
// decision parser would give each of them a document in a shape it
// does not read.
func attestationPredicate(statement []byte) (jsonx.Raw, bool) {
	stmt, err := jsonx.DecodeForeign[struct {
		Predicate jsonx.Raw `json:"predicate"`
	}](statement)
	if err != nil || len(stmt.Predicate) == 0 {
		return nil, false
	}

	return stmt.Predicate, true
}

// shortDigest renders a digest for a human-facing line.
func shortDigest(d string) string {
	const shown = 12

	trimmed := strings.TrimPrefix(d, "sha256:")
	if len(trimmed) <= shown {
		return trimmed
	}

	return trimmed[:shown]
}
