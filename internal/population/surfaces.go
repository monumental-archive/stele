// Publish surfaces: where a repository publishes, declared per
// repository and plural.
//
// This is the THIRD fact a roster row carries, and it is neither of
// the other two. Membership says whether a repository is asked;
// visibility says whether the enumeration could have shown it; a
// surface says WHERE to go and look once it has been asked. None of
// them can reach a rung — the level judge receives evidence and never
// a declaration (stele#125) — and a surface is the weakest of the
// three: it cannot even narrow a population, because a repository
// that declares no surface is still a member, still counted, and
// still judged on whatever was found.
//
// It is declared because it is not derivable. Which surfaces a
// repository publishes on is a per-repository fact, and the engine
// encoded it as a constant: every Dependency-track detector judged a
// RELEASE, so a repository publishing rolling digests instead of
// releases was permanently Unevaluated on that track no matter what
// its publish path enforced (stele#249). The release surface has not
// gone away; it has become the DEFAULT EXPRESSION of this
// declaration, which is what an adopter who cuts releases needs and
// what a stranger gets with no configuration at all.
//
// PLURALITY IS THE ADOPTER'S. A repository may publish on one
// surface, on both, on two of the same kind at two registries, or on
// none this engine can read. What this package owns is the set of
// surface KINDS, because each kind names a place the gather knows how
// to look; how many a row declares, and with which parameters, is
// policy and never code — the cardinality law stele#247 wrote down
// after a base-approval block was made singular because this
// organisation happened to have exactly one.
//
// The vocabulary is open upward: a surface kind this release cannot
// look at is ABSENT from it, refused at load by name rather than
// loaded and silently computing nothing.

package population

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// SurfaceKind names one publish surface this engine knows how to
// look at. The kinds are code and their parameters are policy — the
// standard/convention split the assert policy's base-approval scopes
// already take (stele#247).
type SurfaceKind string

const (
	// SurfaceRelease is the versioned surface: the repository's newest
	// release, the artifacts its digest manifest names, and the
	// evidence documents published beside them as assets. It takes no
	// parameters — the release is found by ordering the repository's
	// own released versions, and everything on it is found BY CONTENT,
	// so there is no convention for an adopter to declare.
	SurfaceRelease SurfaceKind = "release"
	// SurfaceContinuousDigest is the rolling-digest surface: an image
	// republished under a moving tag, with no version and no release
	// to hang evidence off, so its evidence lives in the registry and
	// the attestation store. Its parameters address that pair.
	SurfaceContinuousDigest SurfaceKind = "continuous-digest"
)

// Surface is one publish surface a repository declares: the kind, and
// that kind's parameters. The parameters sit flat in the surface
// rather than nested under the kind because a surface IS one kind's
// declaration — and validate refuses a parameter the declared kind
// does not read, so a key that means nothing where it sits is a load
// refusal rather than a silent no-op.
type Surface struct {
	// Kind selects where to look. A surface that will not say what it
	// is cannot be looked at.
	Kind *SurfaceKind `json:"kind"`
	// Registry is the image repository the rolling tag lives in,
	// spelled as a registry reference without a tag or digest
	// (continuous-digest).
	Registry *string `json:"registry,omitempty"`
	// Tag is the rolling tag the publish moves (continuous-digest).
	Tag *string `json:"tag,omitempty"`
	// Identity is a regular expression over the signing certificate's
	// subject alternative name: which publisher's attestations are
	// THIS surface's evidence. A pattern rather than a literal because
	// a workflow identity carries the ref it ran at, which moves every
	// publish, and a declaration that had to be edited per publish
	// would be a declaration nobody kept true.
	//
	// It decides WHERE to look and never what is true. An attestation
	// signed under some other identity is not this surface's evidence
	// and produces nothing — no finding, no count — the same way a
	// reference outside a base scope's registry prefix is out of scope
	// rather than a defect. A pattern pointed at the wrong publisher
	// therefore yields "looked there, found nothing", which is
	// unevaluated: a statement about this run's sight, never a level
	// (continuous-digest).
	Identity *string `json:"identity,omitempty"`
}

// DefaultSurfaces is the surface set that stands where a repository
// declares none: the release surface alone.
//
// It is the default EXPRESSION of a declaration rather than a rule in
// the gather, for the reason the archived/fork predicate is one here
// too — a default nobody can restate is a constant wearing a
// default's name, and the whole defect this section closes was one
// such constant.
func DefaultSurfaces() []Surface {
	kind := SurfaceRelease

	return []Surface{{Kind: &kind}}
}

// Surfaces are the publish surfaces one member declared, or the
// default set where it declared none.
//
// A repository this set does not hold gets the default too. That is
// not a guess about it: this door is asked only about a repository
// the caller is already measuring, and a caller measuring something
// outside its own population has a bigger problem than which surface
// it reads.
func (s *Set) Surfaces(repo string) []Surface {
	for _, m := range s.members {
		if m.name == repo && m.surfaces != nil {
			return *m.surfaces
		}
	}

	return DefaultSurfaces()
}

// Name is how one surface names itself in a report: enough for a
// reader to go and look at the same place this run looked at.
func (s Surface) Name() string {
	if s.Kind == nil {
		return "an unnamed surface"
	}

	if *s.Kind == SurfaceContinuousDigest && s.Registry != nil && s.Tag != nil {
		return string(*s.Kind) + " " + *s.Registry + ":" + *s.Tag
	}

	return string(*s.Kind)
}

// surfaceParams is every parameter this engine knows how to read off
// a surface, whichever kind owns it. One table, so "required by my
// kind" and "read by nobody here" are answered from the same list and
// cannot drift apart.
func (s Surface) surfaceParams() map[string]*string {
	return map[string]*string{
		"registry": s.Registry,
		"tag":      s.Tag,
		"identity": s.Identity,
	}
}

// ownsSurface names the parameters one kind reads, in the order its
// refusals report them. A kind absent from this switch is a kind this
// engine cannot look at — the one place that fact is written.
//
// The release surface owns NONE, and the second result is what says
// so: a kind with no parameters and a kind this engine does not
// implement are otherwise the same empty list, and the difference
// between them is a load refusal.
func ownsSurface(k SurfaceKind) ([]string, bool) {
	switch k {
	case SurfaceRelease:
		return nil, true
	case SurfaceContinuousDigest:
		return []string{"registry", "tag", "identity"}, true
	default:
		return nil, false
	}
}

// surfaceKinds is the vocabulary, spelled for a diagnostic.
func surfaceKinds() []string {
	return []string{string(SurfaceRelease), string(SurfaceContinuousDigest)}
}

// validateSurfaces holds one repository's declared surfaces to
// exactly their kinds' parameters, and refuses a set that says the
// same thing twice.
//
// An EMPTY list is legal and is not silence: it declares that this
// repository publishes on no surface this engine can read, and the
// gather answers it by naming what it went looking for and did not
// find. That is loud, which is why it needs no written reason — an
// exclusion produces nothing and therefore has to be justified, while
// this produces an unevaluated rung a reader cannot miss.
func validateSurfaces(surfaces []Surface, where string) error {
	seen := map[string]bool{}

	for i, s := range surfaces {
		if err := s.validate(fmt.Sprintf("%s.surfaces[%d]", where, i)); err != nil {
			return err
		}

		key := s.key()
		if seen[key] {
			return fmt.Errorf(
				"%s.surfaces[%d] declares %s a second time with the same parameters — two identical surfaces"+
					" are one place looked at twice", where, i, key)
		}

		seen[key] = true
	}

	return nil
}

// validate holds one surface to its kind's parameters: each one it
// owns declared, and none it does not. Declaring a parameter the kind
// never reads is refused as firmly as omitting one it needs — a key
// nothing looks at is the descriptive half this section exists to
// refuse.
func (s Surface) validate(where string) error {
	if s.Kind == nil || *s.Kind == "" {
		return fmt.Errorf("%s.kind is absent or empty — a surface that will not say what it is cannot be"+
			" looked at", where)
	}

	owned, known := ownsSurface(*s.Kind)
	if !known {
		return fmt.Errorf("%s.kind is %q, which is no publish surface this release can look at (%s)"+
			" — a kind that loaded and computed nothing would read as a surface nobody publishes on",
			where, *s.Kind, strings.Join(surfaceKinds(), ", "))
	}

	params := s.surfaceParams()

	for _, name := range owned {
		if v := params[name]; v == nil || *v == "" {
			return fmt.Errorf("%s.%s is absent or empty — the %s surface cannot be addressed without it",
				where, name, *s.Kind)
		}
	}

	for name, v := range params {
		if v != nil && !slices.Contains(owned, name) {
			return fmt.Errorf("%s.%s is declared, and the %s surface never reads it", where, name, *s.Kind)
		}
	}

	if s.Identity != nil {
		if _, err := regexp.Compile(*s.Identity); err != nil {
			return fmt.Errorf("%s.identity: %w", where, err)
		}
	}

	return nil
}

// key renders one surface as the place it names, for the duplicate
// check and for a diagnostic. Two surfaces with the same key address
// the same publish.
func (s Surface) key() string {
	owned, _ := ownsSurface(*s.Kind)
	if len(owned) == 0 {
		return string(*s.Kind)
	}

	params := s.surfaceParams()

	parts := make([]string, 0, len(owned))
	for _, name := range owned {
		parts = append(parts, name+"="+*params[name])
	}

	return string(*s.Kind) + "(" + strings.Join(parts, " ") + ")"
}
