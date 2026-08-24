// The previous release, as a stated fact rather than a guess anyone
// downstream repeats.
//
// Resolving it is not new work: deciding a version already requires
// knowing which release a range is measured from, so LatestTag has
// always produced this answer and thrown away everything but the
// number. What is new is saying it out loud. The canon's pgrx upgrade
// derivation needs the same fact — which release came before, and
// where its artifacts live — and re-derived it in bash three
// assumptions deep: that the tag is "v<base>", that the tarballs hang
// on that tag, that they are packed with our own prefix. Each layer
// failed on its own run against an imported repository whose eleven
// published versions were tagged "edtf-postgres-v1.2.3" and friends
// (.github#762, #780). One fact derived twice is the seam
// .github#358 names, and every imported repository meets it once, at
// its first canonical release.
//
// So the block reports what was ACTUALLY resolved, never what a
// scheme would predict: the version, the tag it was read from
// whatever that tag's scheme, and — when a forge was named and hangs
// a release there — that release's identity and the addresses its
// assets are served from.
//
// What a tarball contains is deliberately not here. Archive layout is
// the consumer's packaging convention, and a tool that opened one to
// describe it would be asserting a fact about someone else's build.

package derive

// Previous is the release a version derivation measured its range
// from. Three absences it keeps apart, because a consumer that
// conflates them acts on a fact the run never established:
//
//   - Exists false — the namespace has never released. Nothing else
//     is filled in, rather than filled in empty: a first release is a
//     state, not a release named "".
//   - ForgeAsked false — no forge was named, so nobody looked. An
//     absent Release here says nothing about what the forge carries.
//   - ForgeAsked true with no Release — the forge was asked and hangs
//     no release on that tag. This is the imported repository's
//     shape: "v1.2.3" exists as a bare tag while the artifacts sit on
//     the tag the old scheme used.
type Previous struct {
	Exists bool `json:"exists"`
	// Version is the base the range was measured from, and Tag the tag
	// it was read from — verbatim, whatever namespace scheme minted it.
	Version string `json:"version,omitempty"`
	Tag     string `json:"tag,omitempty"`
	// ForgeAsked reports whether a forge was consulted for the release
	// hanging on Tag. The discriminator between the two absences above,
	// and the reason a nil Release is never ambiguous.
	ForgeAsked bool `json:"forgeAsked"`
	// Release is what hangs on Tag, when anything does.
	Release *ForgeRelease `json:"release,omitempty"`
}

// ForgeRelease is one published release, decoded: enough to name it
// in a log and to fetch what it published, and nothing else. A
// forge's own payload carries dozens of fields whose meanings are the
// forge's; re-publishing them here would make this tool's output a
// second definition of somebody else's API.
type ForgeRelease struct {
	ID   int64  `json:"id"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
	// Assets are the published artifacts and the addresses they are
	// served from. Always a list, empty when the release published
	// nothing — "this release carries no assets" is an answer, and a
	// missing key would leave a consumer unable to tell it from a
	// release nobody read.
	Assets []ForgeAsset `json:"assets"`
}

// ForgeAsset is one published artifact: its filename and where it
// lives.
type ForgeAsset struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// PreviousOf states what the base resolution found. The forge half is
// the caller's to attach: this package reads a tag list and nothing
// else, and a derivation that could reach the network would be one
// that behaves differently offline.
func PreviousOf(base Base) Previous {
	if base.Version == nil {
		return Previous{}
	}

	return Previous{Exists: true, Version: base.Version.String(), Tag: base.Tag}
}
