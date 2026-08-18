// The trusted-root argument surface, shared by every verb that
// verifies. Four verbs registered the flag and read the file
// themselves, which was four places for the boundary to drift; the
// origin is now planned once, resolved once, and recorded once. The
// resolution is a seam because one of its two origins reaches the
// network, and the gate reaches nothing.

package cli

import (
	"flag"

	"github.com/monumental-archive/stele/internal/chain"
	"github.com/monumental-archive/stele/internal/report"
	"github.com/monumental-archive/stele/internal/trust"
)

// The two names under which a run records its trust material. Facts,
// never judgment inputs: they say what was held, not what was proved.
const (
	factTrustedRoot    = "trustedRoot"
	factTrustedRootSHA = "trustedRootSha256"
)

// resolveTrustedRoot obtains the planned root's bytes. Swapped only
// by test setup: the file origin is proven in internal/trust, the
// TUF origin in shadow mode against the live instance.
//
//nolint:gochecknoglobals // test seam, written only by test setup
var resolveTrustedRoot = trust.ResolveRoot

// rootFlags is one verb's trusted-root surface plus what its
// resolution turned out to be. The plan and digest are recorded so
// the report can name the trust material the run actually held.
type rootFlags struct {
	file   string
	anchor string
	mirror string

	plan   trust.RootPlan
	digest string
}

// register declares the three flags on one verb's flag set. None is
// required: naming none takes the TUF path from the anchor pinned in
// this binary, which is what lets a stranger verify with no setup
// step at all.
func (rf *rootFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&rf.file, "trusted-root", "",
		"path to a Sigstore trusted-root document — the offline path; absent resolves one through TUF")
	fs.StringVar(&rf.anchor, "tuf-root", "",
		"path to the pinned initial TUF root, declared with --tuf-mirror (absent: the anchor pinned in this binary)")
	fs.StringVar(&rf.mirror, "tuf-mirror", "",
		"base URL of the TUF instance, declared with --tuf-root (absent: the Sigstore public-good instance)")
}

// resolve plans the origin and obtains the trusted-root document.
// Called at most once per invocation by design: the org's audit walks
// many repositories in one run, and a root re-resolved per subject
// could differ between them — one run, one root of trust.
func (rf *rootFlags) resolve() ([]byte, error) {
	plan, err := trust.PlanRoot(rf.file, rf.anchor, rf.mirror)
	if err != nil {
		return nil, err
	}

	content, err := resolveTrustedRoot(plan)
	if err != nil {
		return nil, err
	}

	rf.plan, rf.digest = plan, chain.SHA256Hex(content)

	return content, nil
}

// facts records what this run trusted, beside the verdict and never
// part of it. Empty when nothing was resolved — a walk with no
// cryptographic half held no trust material, and claiming one would
// be a fact about nothing.
func (rf *rootFlags) facts() []report.Fact {
	if rf.digest == "" {
		return nil
	}

	return []report.Fact{
		{Name: factTrustedRoot, Value: rf.plan.Describe()},
		{Name: factTrustedRootSHA, Value: rf.digest},
	}
}
