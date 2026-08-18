// The requirements catalogue: what SLSA asks for, level by level,
// transcribed from the specification and owned by this file alone.
//
// This is the tool's spine. A level is not a number an organization
// writes down and this tool repeats back — it is the set of
// requirements below, each one either established from evidence or
// not. No policy may add a requirement, remove one, move one to a
// different level, or redefine what one means. An organization that
// wants to claim Source Level 4 does not declare Level 4; it enforces
// two-party review, and this tool finds it.
//
// Each requirement carries the spec's own words. That is deliberate:
// when a report says a level is not established, the reader is owed
// the requirement as the specification states it, not this author's
// paraphrase of it.
//
// Sources, read at the v1.2 tag of slsa-framework/slsa:
//   - build-requirements.md, verifying-artifacts.md (Build L0–L3)
//   - source-requirements.md (Source L1–L4)
//   - the draft dependency-track.md, marked as draft everywhere it
//     surfaces, because SLSA v1.2 approves no such track

package level

// The level numbers the catalogue places requirements at. Named so the
// catalogue reads as the specification's tables do, and so a level is
// never a bare integer in a data structure whose whole job is to be
// checked against a specification.
const (
	levelOne = iota + 1
	levelTwo
	levelThree
	levelFour
)

// Requirement is one thing the specification asks for at one level of
// one track. Constructed only by this file's catalogue.
type Requirement struct {
	// ID is the stable identifier a report names and a detector
	// registers against.
	ID string
	// Level is the level this requirement belongs to. The spec's
	// cumulative rule does the rest: a level implies those below it.
	Level int
	// Text is what the specification requires, in its own words.
	Text string
	// Evidence names, in one line, where a detector looks. It is
	// documentation, not dispatch: the registry binds detectors by ID.
	//
	// There is deliberately no "this cannot be established" flag. A
	// requirement with no detector registered is UNDETERMINED and the
	// report names it as unevaluated — which is a statement about this
	// tool, not about the world. Marking a requirement unknowable
	// would bake one author's imagination into the spine, and the
	// author was wrong twice already: the build platform's isolation
	// and its capability boundary read as assessment questions until
	// you notice the certificate carries the platform's own attested
	// claims about both.
	Evidence string
}

// buildRequirements is the Build track, from build-requirements.md's
// two tables (provenance generation, isolation strength) and the
// verification procedure in verifying-artifacts.md.
//
//nolint:gochecknoglobals // the catalogue is a constant; Go has no const slice
var buildRequirements = []Requirement{
	{
		ID:    "build/provenance-exists",
		Level: levelOne,
		Text: "The build process MUST generate provenance that unambiguously identifies the output package" +
			" by cryptographic digest and describes how that package was produced.",
		Evidence: "the provenance attestation in the store, verified over the artifact's digest",
	},
	{
		ID:       "build/provenance-distributed",
		Level:    1,
		Text:     "The producer MUST distribute provenance to artifact consumers.",
		Evidence: "the store a stranger queries, keyed by the artifact digest",
	},
	{
		ID:    "build/provenance-authentic",
		Level: levelTwo,
		Text: "Consumers MUST be able to validate the authenticity of the provenance attestation:" +
			" verify that the digital signature is valid and the provenance was not tampered with after the build.",
		Evidence: "the DSSE signature and its Fulcio certificate chain",
	},
	{
		ID:    "build/hosted",
		Level: levelTwo,
		Text: "All build steps ran using a hosted build platform on shared or dedicated infrastructure," +
			" not on an individual's workstation.",
		Evidence: "the certificate's runner-environment claim, issued by the platform's own OIDC issuer",
	},
	{
		ID:    "build/external-parameters-complete",
		Level: levelThree,
		Text: "External parameters MUST be fully enumerated. Every field in the provenance MUST be generated" +
			" or verified by the build platform in a trusted control plane.",
		Evidence: "the provenance's externalParameters against the buildType's declared key set",
	},
	{
		ID:    "build/unforgeable",
		Level: levelThree,
		Text: "Provenance MUST be strongly resistant to forgery by tenants: secret material used for" +
			" authenticating the provenance MUST NOT be accessible to the environment running the" +
			" user-defined build steps.",
		Evidence: "the certificate's job-workflow-ref, and that workflow's content at that commit:" +
			" the signing job must run no caller-controlled step",
	},
	{
		ID:    "build/isolated",
		Level: levelThree,
		Text: "The build platform ensured that the build steps ran in an isolated environment, free of" +
			" unintended external influence: builds cannot influence one another, and an ephemeral build" +
			" environment is provisioned for each build.",
		Evidence: "the certificate's runner-environment claim: a hosted runner is ephemeral per build by construction",
	},
}

// sourceRequirements is the Source track, from source-requirements.md's
// Organization and Source Control System tables.
//
// The identifiers are the ecosystem's, not this tool's. The SLSA
// source proof-of-concept — the SCS implementation the specification
// itself points at — names one control per requirement, and a VSA it
// issues carries those names. A consumer that invented its own dialect
// could not read another SCS's attestations, and being able to is what
// "universal" has to mean: stele must judge a repository whose chain
// was issued by someone else's control plane.
//
//nolint:gochecknoglobals // the catalogue is a constant; Go has no const slice
var sourceRequirements = []Requirement{
	{
		ID:    "SLSA_SOURCE_ORG_SCS",
		Level: levelOne,
		Text: "An organization producing source revisions MUST select a source control system capable of" +
			" reaching their desired SLSA Source Level.",
		Evidence: "the SCS serving this repository issues source attestations at all",
	},
	{
		ID:       "SLSA_SOURCE_SCS_REPO_ID",
		Level:    levelOne,
		Text:     "The repository ID MUST be uniquely identifiable within the context of the SCS with a stable locator.",
		Evidence: "the forge's stable identifier for the repository",
	},
	{
		ID:    "SLSA_SOURCE_SCS_REVISION_ID",
		Level: levelOne,
		Text: "Revisions MUST be immutable and uniquely identifiable within the context of the repository." +
			" When the revision ID is a digest of the content of the revision, nothing more is needed.",
		Evidence: "the revision identifier is a content digest (git)",
	},
	{
		ID:    "SLSA_SOURCE_SCS_DIFF_DISPLAY",
		Level: levelOne,
		Text: "The SCS MUST provide tooling to display changes between one source revision and another in a" +
			" human readable form for all plain-text changes.",
		Evidence: "the SCS serves the walked revisions as parented content-addressed commits",
	},
	{
		ID:    "SLSA_SOURCE_SCS_VSA",
		Level: levelOne,
		Text: "The SCS MUST generate a source verification summary attestation to indicate the SLSA Source Level" +
			" of any revision at Level 1 or above. If the SCS DOES NOT generate a VSA for a revision, the" +
			" revision has Source Level 0.",
		Evidence: "a source VSA at the tip that verifies",
	},
	{
		ID:    "SLSA_SOURCE_ORG_ACCESS_CONTROL",
		Level: levelTwo,
		Text: "The organization MUST configure access controls to restrict sensitive operations on the source" +
			" repository, implemented using the SCS-provided identity management capability.",
		// Which controls were configured WHEN a revision landed is not
		// recoverable afterwards — a rules API answers about now. The
		// contemporaneous attestation is the only possible evidence,
		// which is why the specification asks the SCS to record it.
		Evidence: "the control the SCS recorded for this revision, with its continuity start",
	},
	{
		ID:    "SLSA_SOURCE_ORG_SAFE_EXPUNGE",
		Level: levelTwo,
		Text: "An organization MUST document the Safe Expunging Process and describe how requests and actions" +
			" are tracked.",
		// Git has no expunge: content leaves a branch only by force
		// push. So protected refs ARE the control, and the SLSA source
		// proof-of-concept establishes it the same way.
		Evidence: "protected refs: without force push, content cannot be expunged",
	},
	{
		ID:    "SLSA_SOURCE_ORG_CONTINUITY",
		Level: levelTwo,
		Text: "The organization MUST provide evidence of continuous enforcement for any claims made in the" +
			" source provenance attestations or VSAs.",
		Evidence: "the controls recorded at the tip, each with a continuity start predating the revision",
	},
	{
		ID:    "SLSA_SOURCE_SCS_HISTORY",
		Level: levelTwo,
		Text: "The SCS MUST ensure that a branch can only be updated to point to revisions that descend from" +
			" the current revision. In git, this requires a technical control to prohibit `git push --force`.",
		Evidence: "every revision on the branch descends from its predecessor, walked first-parent",
	},
	{
		ID:    "SLSA_SOURCE_SCS_CONTINUITY",
		Level: levelTwo,
		Text: "For each technical control claimed in a VSA, continuity MUST be established and tracked from a" +
			" specific start revision. If there is a lapse in continuity for a specific control, continuity of" +
			" that control MUST be re-established from a new revision.",
		Evidence: "chain coverage from genesis with no unattested revision between links",
	},
	{
		ID:    "SLSA_SOURCE_SCS_IDENTITY",
		Level: levelTwo,
		Text: "The SCS MUST provide an identity management system or some other means of identifying and" +
			" authenticating actors, and MUST document how actors are identified for attribution.",
		Evidence: "each link is signed by an SCS-authenticated identity carried in its certificate",
	},
	{
		ID:    "SLSA_SOURCE_SCS_PROVENANCE",
		Level: levelTwo,
		Text: "Source provenance MUST be created contemporaneously with the branch being updated such that they" +
			" provide a credible, auditable record of changes.",
		Evidence: "a link at each revision, timed against that revision's commit time",
	},
	{
		ID:    "SLSA_SOURCE_SCS_PROTECTED_REFS",
		Level: levelThree,
		Text: "The SCS MUST record technical controls enforced on named references in contemporaneously produced" +
			" attestations associated with the corresponding source revisions.",
		Evidence: "the controls recorded in each revision's own signed provenance",
	},
	{
		ID:    "SLSA_SOURCE_SCS_TWO_PARTY_REVIEW",
		Level: levelFour,
		Text: "Changes in protected branches MUST be agreed to by two or more trusted persons prior to" +
			" submission: the final revision submitted MUST be reviewed, approvals are context-specific, and" +
			" the reviewer MUST be presented with a clear representation of the result of accepting the change.",
		Evidence: "the control the SCS recorded, or the approvals on the change that produced each revision",
	},
}

// dependencyRequirements is the DRAFT dependency track, from the draft
// page's requirements table. SLSA v1.2 approves no dependency track;
// every output carrying one of these levels says so.
//
//nolint:gochecknoglobals // the catalogue is a constant; Go has no const slice
var dependencyRequirements = []Requirement{
	{
		ID:    "dependency/inventory",
		Level: levelOne,
		Text: "An organization producing artifacts MUST implement tooling that inventories dependencies for" +
			" every version they release.",
		Evidence: "an inventory published for every artifact the release ships",
	},
	{
		ID:    "dependency/scanned",
		Level: levelTwo,
		Text: "An organization MUST proactively identify third-party dependencies in their build that have" +
			" known vulnerabilities.",
		Evidence: "the inventories scanned against a vulnerability database",
	},
	{
		ID:    "dependency/triaged",
		Level: levelTwo,
		Text: "An organization MUST triage all known vulnerabilities and either remediate the vulnerability," +
			" or not remediate in the given release.",
		Evidence: "every finding matched to a published triage decision",
	},
	{
		ID:    "dependency/producer-controlled",
		Level: levelThree,
		Text: "The build process MUST consume all third-party build dependencies only from artifact" +
			" producer-controlled locations, instead of directly from upstream.",
		Evidence: "the resolved sources in the release's own lockfiles and inventories",
	},
	{
		ID:    "dependency/secure-ingestion",
		Level: levelFour,
		Text: "An organization MUST consume dependencies that have been determined to have acceptable risk," +
			" enforcing a secure ingestion policy over third-party build dependencies.",
		Evidence: "the ingestion controls the producer publishes",
	},
}

// Requirements lists one track's requirements, in level order.
func Requirements(t Track) []Requirement {
	var src []Requirement

	switch t.name {
	case TrackBuild.name:
		src = buildRequirements
	case TrackSource.name:
		src = sourceRequirements
	case TrackDependency.name:
		src = dependencyRequirements
	default:
		return nil
	}

	out := make([]Requirement, len(src))
	copy(out, src)

	return out
}

// RequirementsAt lists the requirements one level of one track asks
// for — the set a detector run must establish in full for that level
// to hold.
func RequirementsAt(t Track, level int) []Requirement {
	var out []Requirement

	for _, r := range Requirements(t) {
		if r.Level == level {
			out = append(out, r)
		}
	}

	return out
}
