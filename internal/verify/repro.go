// The reproducibility judgment (stele#96): a release's checksum
// manifest against the digests an independent rebuild produced. The
// REBUILD is orchestration and stays outside — a build cannot live in
// the verifier — so this leg is a pure comparison: two manifests in,
// typed divergences out, every category its own answer rather than a
// diff hunk in workflow bash.
//
// SLSA v1.2 names verified reproducibility only as a future-directions
// candidate; accordingly nothing here claims a level or feeds one —
// the verdict is information a policy or a human consumes, and the
// vocabulary stays open.

package verify

import "sort"

// The divergence kinds — each an answer, never interchangeable.
const (
	// ReproDiverged: rebuilt, and the bytes differ.
	ReproDiverged = "diverged"
	// ReproAbsent: released, and the rebuild produced no artifact of
	// that name — an unreproduced artifact, not a clean one.
	ReproAbsent = "absent-from-rebuild"
	// ReproExtra: the rebuild produced an artifact the release never
	// shipped — the artifact SET diverged, which is a different defect
	// from a byte difference.
	ReproExtra = "extra-in-rebuild"
	// ReproUntypedTarget: a DECLARED rebuild target the released
	// manifest cannot place. It is recorded by the judge that resolved
	// the population rather than by the comparison below, because
	// there is no artifact to compare — but it belongs here, with its
	// siblings, because the assertion vocabulary one verdict speaks is
	// one set and a reader scanning `repro/…` must find all of it in
	// one place.
	ReproUntypedTarget = "target-not-typed"
)

// ReproDivergence is one artifact's failure to reproduce.
type ReproDivergence struct {
	// Name is the artifact name the manifests carry.
	Name string
	// Kind is one of the constants above.
	Kind string
	// Released and Rebuilt are the two digests where both exist;
	// empty on the side that has no artifact.
	Released string
	Rebuilt  string
}

// ReproSets are the three sets one comparison needs. Judged and
// Published were one set until a scoped judgment made them different
// questions (stele#223): what is under test decides what must
// reproduce, while what the RELEASE published decides what is extra.
// An artifact of another class or another target is outside this
// judgment — it is not an artifact the release never shipped, and
// reporting it as one is a false statement about the release.
//
// Unscoped, Published is Judged and nothing changes.
type ReproSets struct {
	// Judged is the population under test, in released order.
	Judged []Subject
	// Rebuilt is what the independent rebuild produced.
	Rebuilt []Subject
	// Published is every build subject the release published,
	// whatever scope it belongs to.
	Published []Subject
}

// Repro compares the judged subjects against the rebuild's, in
// released order with rebuild-only extras appended by name. A clean
// comparison returns nil — and judging NOTHING is the caller's
// question: an empty judged population is a population of zero, which
// no comparison may launder into a pass.
func Repro(sets ReproSets, log Logf) []ReproDivergence {
	built := make(map[string]string, len(sets.Rebuilt))
	for _, s := range sets.Rebuilt {
		built[s.Name] = s.SHA256
	}

	var out []ReproDivergence

	shipped := make(map[string]bool, len(sets.Published))
	for _, s := range sets.Published {
		shipped[s.Name] = true
	}

	for _, s := range sets.Judged {
		got, ok := built[s.Name]

		switch {
		case !ok:
			out = append(out, ReproDivergence{Name: s.Name, Kind: ReproAbsent, Released: s.SHA256})
		case got != s.SHA256:
			out = append(out, ReproDivergence{Name: s.Name, Kind: ReproDiverged, Released: s.SHA256, Rebuilt: got})
		default:
			log("verify: repro: %s reproduced", s.Name)
		}
	}

	extras := make([]string, 0, len(built))

	for name := range built {
		if !shipped[name] {
			extras = append(extras, name)
		}
	}

	sort.Strings(extras)

	for _, name := range extras {
		out = append(out, ReproDivergence{Name: name, Kind: ReproExtra, Rebuilt: built[name]})
	}

	return out
}
