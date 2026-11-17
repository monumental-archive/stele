// The population as a document (stele#388): what a resolved set
// holds, printed for a caller that must act on the population without
// keeping a second copy of the rules that produced it. Every field is
// read off the Set the one enumeration returned — a resolved track list
// is the member's own bears(), the exclusion is the same membership
// read the walks filter by — so the printed population and the one a
// walk receives are one value, never two derivations of it.

package population

import (
	"slices"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/level"
)

// Document is a resolved population as printed.
type Document struct {
	// Schema is the live-read document epoch (docs/versioning.md): the
	// population is generated fresh by the run that prints it.
	Schema int `json:"schema"`
	// Owner is the account every member sits under.
	Owner string `json:"owner"`
	// Declared reports whether an organisation's declaration (rather
	// than the default predicate) produced the set.
	Declared bool `json:"declared"`
	// Members are the repositories the set holds, in listing order.
	Members []MemberDoc `json:"members"`
	// Reconciliation is how the listing and the declaration accounted
	// for each other.
	Reconciliation Reconciliation `json:"reconciliation"`
}

// MemberDoc is one member as printed.
type MemberDoc struct {
	// Repo is the bare repository name.
	Repo string `json:"repo"`
	// Tracks are the tracks the member bears evidence on, resolved: a
	// membership that named none resolves to every track this release
	// judges, and an exclusion is the empty list. Spec order.
	Tracks []string `json:"tracks"`
	// TracksDeclared reports whether the declaration NAMED the tracks
	// (a narrowing, or an exclusion) rather than leaving the default.
	// The two read alike today and part ways the day a track is added:
	// only the default reaches it.
	TracksDeclared bool `json:"tracksDeclared"`
	// Exclusion marks a member that bears evidence on no track at all:
	// listed, so walks that ask no track question still read it, and
	// silent on every evidence track.
	Exclusion bool `json:"exclusion"`
	// Visibility is the forge listing's own word for the repository,
	// verbatim and never judged; absent where no listing was read
	// (the single-repository scope) or the listing did not say.
	Visibility string `json:"visibility,omitempty"`
	// ReleaseTags reports whether the repository carries a tag the
	// policy's tags.tagPattern selects — the definition the tag audit
	// reads. Absent where the policy declares no tags section, or the
	// caller did not ask; never false for "could not see".
	ReleaseTags *bool `json:"releaseTags,omitempty"`
}

// Reconciliation is the two directions of the name reconciliation, and
// the members the declared coverage put out of sight. Each list is
// present (possibly empty) so a consumer never mistakes an absent key
// for agreement.
type Reconciliation struct {
	// Undeclared are listed repositories the declaration does not
	// account for.
	Undeclared []string `json:"undeclared"`
	// Unlisted are declared repositories the listing does not show.
	Unlisted []string `json:"unlisted"`
	// Unexercised are declared members outside the enumeration's
	// declared coverage: never members, and never clean.
	Unexercised []string `json:"unexercised"`
}

// Document prints the set. The reconciliation is empty in both
// directions by construction — Resolve returns a set only when the
// two sides accounted for each other — and RefusedDocument prints the
// other case.
func (s *Set) Document() Document {
	doc := Document{
		Schema:   jsonx.Epoch,
		Owner:    s.owner,
		Declared: s.declared,
		Members:  make([]MemberDoc, 0, len(s.members)),
		Reconciliation: Reconciliation{
			Undeclared:  []string{},
			Unlisted:    []string{},
			Unexercised: s.UnexercisedRoster(),
		},
	}

	for _, m := range s.members {
		doc.Members = append(doc.Members, m.document())
	}

	return doc
}

// RefusedDocument prints a reconciliation that refused: no members —
// a run that does not know its population has none to print — and
// both directions by name, exactly as the refusal carries them.
func (e *ReconcileError) RefusedDocument() Document {
	return Document{
		Schema:   jsonx.Epoch,
		Owner:    e.Owner,
		Declared: true,
		Members:  []MemberDoc{},
		Reconciliation: Reconciliation{
			Undeclared:  slices.Clone(e.Undeclared),
			Unlisted:    slices.Clone(e.Unlisted),
			Unexercised: []string{},
		},
	}
}

// Member is one repository's resolved membership in the set, ok=false
// when the set does not hold it.
func (s *Set) Member(repo string) (MemberDoc, bool) {
	for _, m := range s.members {
		if m.name == repo {
			return m.document(), true
		}
	}

	return MemberDoc{}, false
}

// Declared reports whether a declaration, rather than the default
// predicate, placed the set's members.
func (s *Set) Declared() bool { return s.declared }

// document reads one member through the same bears() every walk
// filters by.
func (m member) document() MemberDoc {
	doc := MemberDoc{Repo: m.name, Tracks: []string{}, TracksDeclared: !m.all, Visibility: m.visibility}

	for _, t := range level.Tracks() {
		if m.bears(t) {
			doc.Tracks = append(doc.Tracks, t.Key())
		}
	}

	doc.Exclusion = len(doc.Tracks) == 0

	return doc
}
