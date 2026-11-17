// This file: the build-enrichment predicate's write side (stele#392) —
// the canon verify-release.yml's "Compute the enrichment facts" step.
// The policy's build.enrichment says WHICH names a claim must and may
// carry; where each name's bytes come from is the caller's typed input
// (stele#86: the contents are the write side's concern, and a verifier
// that knew how to compute them would be the writer inverted). Nothing
// here names a file, a tree or a registry: the kinds are code, every
// parameter arrives from the caller.

package emit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/monumental-archive/stele/internal/enrichment"
	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/policy"
)

// The two trees a claimed file is read from: the policy's own tree,
// pinned by the machinery digest, and the released source at the
// attested revision.
const (
	TreePolicy = "policy"
	TreeSource = "source"
)

// Source is one claimed name and where its bytes come from. A file
// source claims the file itself; a rows source claims one digestless
// entry per selected row of a TOML table file (the base-image kind: an
// image named by a separately-digested mapping file).
type Source struct {
	Name string
	Tree string
	Path string
	// Rows makes this a rows source; nil is a file source.
	Rows *Rows
}

// Rows parameterises a rows source: which tables to read, the prefix
// each row's value is claimed under, the keys the caller declares its
// build consumed, and the name the rows' own file is claimed under
// beside them ("" claims it not).
type Rows struct {
	Tables []string
	Prefix string
	Keys   []string
	File   string
}

// Trees reads the two trees and says where a stranger fetches each
// file. Read reports absence as (nil, false, nil): absence is an
// answer, and what it means is decided here, by the name's obligation.
type Trees interface {
	Read(tree, path string) ([]byte, bool, error)
	URI(tree, path string) string
}

// EnrichmentInputs binds one claim: the resource and repository the
// policy's templates expand to, the attested revision, and the policy
// tree it was computed under.
type EnrichmentInputs struct {
	ResourceURI      string
	SourceRepository string
	SourceRevision   string
	PolicyURI        string
	PolicySHA256     string
	PolicyCommit     string
	Sources          []Source
}

// Enrichment computes one enrichment predicate. Every name a source
// declares must be one the policy requires or permits (the closed
// set), and every name the policy requires must have a source. A
// required file that is absent refuses; a permitted one is simply not
// claimed — not every repository has every lockfile. Rows are claimed
// only for the keys the caller declares, so a build that consumed no
// base claims none: a signed false dependency is worse than an
// omitted one.
//
// The result is validated by the shape's own rule and the names
// re-judged before it is returned: the producing side holds itself to
// what the consuming side will hold it to.
func Enrichment(e *policy.Enrichment, in *EnrichmentInputs, trees Trees, log Logf) (*enrichment.Predicate, error) {
	if e == nil {
		return nil, errors.New("emit: the policy declares no build.enrichment — no enrichment is owed, and none" +
			" is emitted")
	}

	if err := declaredNames(e, in.Sources); err != nil {
		return nil, err
	}

	var deps []intoto.ResourceDescriptor

	for i := range in.Sources {
		got, err := computeSource(e, &in.Sources[i], trees, log)
		if err != nil {
			return nil, err
		}

		deps = append(deps, got...)
	}

	pred := &enrichment.Predicate{
		ResourceURI: &in.ResourceURI,
		SourceRevision: &intoto.ResourceDescriptor{
			URI:    &in.SourceRepository,
			Digest: map[string]string{intoto.AlgGitCommit: in.SourceRevision},
		},
		Policy: &intoto.ResourceDescriptor{
			URI:    &in.PolicyURI,
			Digest: map[string]string{intoto.AlgSHA256: in.PolicySHA256, intoto.AlgGitCommit: in.PolicyCommit},
		},
		ResolvedDependencies: deps,
	}

	if err := pred.Validate(); err != nil {
		return nil, fmt.Errorf("emit: %w", err)
	}

	for _, name := range e.Required {
		if !slices.Contains(pred.Names(), name) {
			return nil, fmt.Errorf("emit: the policy requires enrichment name %q and the claim carries none", name)
		}
	}

	log("emit: enrichment: %d resolved dependencies", len(deps))

	return pred, nil
}

// declaredNames holds the declared sources to the closed set, before
// any byte is read.
func declaredNames(e *policy.Enrichment, sources []Source) error {
	seen := map[string]bool{}

	declare := func(name string) error {
		switch {
		case !e.Permits(name):
			return fmt.Errorf("emit: a source names %q, which the policy neither requires nor permits — "+
				"the declared set is closed", name)
		case seen[name]:
			return fmt.Errorf("emit: two sources name %q — one name, one source", name)
		}

		seen[name] = true

		return nil
	}

	for i := range sources {
		if err := declare(sources[i].Name); err != nil {
			return err
		}

		if r := sources[i].Rows; r != nil && r.File != "" {
			if err := declare(r.File); err != nil {
				return err
			}
		}
	}

	for _, name := range e.Required {
		if !seen[name] {
			return fmt.Errorf("emit: the policy requires enrichment name %q and no source declares where it "+
				"comes from", name)
		}
	}

	return nil
}

// computeSource claims what one source yields.
func computeSource(e *policy.Enrichment, s *Source, trees Trees, log Logf) ([]intoto.ResourceDescriptor, error) {
	if s.Rows != nil && len(s.Rows.Keys) == 0 {
		log("emit: enrichment: %s: no keys declared — no rows claimed", s.Name)

		return nil, nil
	}

	content, ok, err := trees.Read(s.Tree, s.Path)
	if err != nil {
		return nil, fmt.Errorf("emit: enrichment: %s: reading %s from the %s tree: %w", s.Name, s.Path, s.Tree, err)
	}

	if !ok {
		return absent(e, s, log)
	}

	uri := trees.URI(s.Tree, s.Path)
	if s.Rows == nil {
		log("emit: enrichment: %s from the %s tree", s.Path, s.Tree)

		return []intoto.ResourceDescriptor{fileClaim(s.Name, uri, content)}, nil
	}

	return rowClaims(s, uri, content)
}

// absent decides what a missing file means: nothing, for a permitted
// file; a refusal, for a required one or for rows the caller declared.
func absent(e *policy.Enrichment, s *Source, log Logf) ([]intoto.ResourceDescriptor, error) {
	switch {
	case s.Rows != nil:
		return nil, fmt.Errorf("emit: enrichment: %s: rows are declared for keys %s, but the %s tree carries no %s"+
			" — the declaration cannot be honoured", s.Name, strings.Join(s.Rows.Keys, ","), s.Tree, s.Path)
	case e.Requires(s.Name):
		return nil, fmt.Errorf("emit: enrichment: the policy requires %q, and the %s tree carries no %s",
			s.Name, s.Tree, s.Path)
	}

	log("emit: enrichment: %s: the %s tree carries no %s — not claimed", s.Name, s.Tree, s.Path)

	return nil, nil
}

// fileClaim is one file, named, addressed and digested.
func fileClaim(name, uri string, content []byte) intoto.ResourceDescriptor {
	sum := sha256.Sum256(content)

	return intoto.ResourceDescriptor{
		Name:   &name,
		URI:    &uri,
		Digest: map[string]string{intoto.AlgSHA256: hex.EncodeToString(sum[:])},
	}
}

// rowClaims reads the selected rows: the file itself first when the
// caller names it, then one entry per declared key and table, in the
// order declared. A declared key a table lacks refuses — the build
// said it consumed a row the pinned file does not hold.
func rowClaims(s *Source, uri string, content []byte) ([]intoto.ResourceDescriptor, error) {
	var tables map[string]any

	if err := toml.Unmarshal(content, &tables); err != nil {
		return nil, fmt.Errorf("emit: enrichment: %s: %s is not TOML: %w", s.Name, s.Path, err)
	}

	var out []intoto.ResourceDescriptor

	if s.Rows.File != "" {
		out = append(out, fileClaim(s.Rows.File, uri, content))
	}

	for _, key := range s.Rows.Keys {
		for _, table := range s.Rows.Tables {
			// A missing table reads as no rows, and its row as missing.
			rows, isTable := tables[table].(map[string]any)
			value, isRow := rows[key].(string)

			if !isTable || !isRow || value == "" {
				return nil, fmt.Errorf("emit: enrichment: %s: declared key %s has no %s row in %s — the "+
					"declaration cannot be honoured", s.Name, key, table, s.Path)
			}

			name, rowURI := s.Name, s.Rows.Prefix+value
			out = append(out, intoto.ResourceDescriptor{Name: &name, URI: &rowURI})
		}
	}

	return out, nil
}
