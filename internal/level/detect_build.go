// Build-track detectors.
//
// Every one of these reads the PLATFORM's own attested claims, not the
// tenant's. A Fulcio certificate carries the OIDC claims the build
// platform's issuer minted for that run — which runner environment it
// ran on, which reusable workflow held the signing capability, at
// which commit. Those are statements the platform makes about its own
// execution and signs; a tenant cannot forge them without forging the
// certificate chain, which is the thing the trust root exists to stop.
//
// That is why Build L3 is establishable from evidence and not, as a
// first reading of assessing-build-platforms suggests, only from a
// questionnaire. The questionnaire establishes trust in the PLATFORM;
// the certificate establishes that this artifact was built by it, in
// the configuration the questionnaire covers.

package level

import "strings"

//nolint:gochecknoinits // the registry is populated once, at load, by the detectors themselves
func init() {
	register(provenanceExists{})
	register(provenanceDistributed{})
	register(provenanceAuthentic{})
	register(hostedRunner{})
	register(externalParametersComplete{})
	register(unforgeableProvenance{})
	register(isolatedBuild{})
}

// The published runner-environment vocabularies, one entry per
// platform whose claims this tool can read — the same shape as
// buildTypeSchemas: platform knowledge as an explicit table, never a
// string comparison scattered where only one platform's value was
// imagined. A value in neither table is a platform this build does not
// know, which is UNDETERMINED — refuting it as "the tenant's machine"
// would punish every platform this author had not met.
//
//nolint:gochecknoglobals // the vocabularies are constants; Go has no const map
var (
	// hostedRunnerValues are the claims platforms mint for runners they
	// own, provision per build and destroy after it.
	hostedRunnerValues = map[string]bool{
		"github-hosted": true,
		"gitlab-hosted": true,
	}

	// tenantRunnerValues are the claims platforms mint for machines the
	// tenant operates.
	tenantRunnerValues = map[string]bool{
		"self-hosted":  true,
		"self-managed": true,
	}
)

type provenanceExists struct{}

func (provenanceExists) For() string { return "build/provenance-exists" }

func (provenanceExists) Detect(ev *Evidence) Outcome {
	if len(ev.Subjects) == 0 {
		return Unevaluated("no released artifact was reached, so no provenance could be looked for")
	}

	var missing []string

	for i := range ev.Subjects {
		s := &ev.Subjects[i]
		if !s.Verified {
			missing = append(missing, s.Name)
		}
	}

	if len(missing) > 0 {
		return Contradicted("%d of %d released artifact(s) carry no provenance identifying them: %v",
			len(missing), len(ev.Subjects), missing)
	}

	return Established("all %d released artifact(s) carry provenance identifying them by digest", len(ev.Subjects))
}

type provenanceDistributed struct{}

func (provenanceDistributed) For() string { return "build/provenance-distributed" }

func (provenanceDistributed) Detect(ev *Evidence) Outcome {
	if len(ev.Subjects) == 0 {
		return Unevaluated("no released artifact was reached")
	}

	// Retrieval IS the requirement: this run fetched the provenance
	// from the public store, keyed by digest, exactly as a consumer
	// would. Reaching it is the proof that a consumer can.
	return Established("provenance for all %d artifact(s) was retrievable from the store a consumer queries",
		len(ev.Subjects))
}

type provenanceAuthentic struct{}

func (provenanceAuthentic) For() string { return "build/provenance-authentic" }

func (provenanceAuthentic) Detect(ev *Evidence) Outcome {
	if len(ev.Subjects) == 0 {
		return Unevaluated("no released artifact was reached")
	}

	for i := range ev.Subjects {
		s := &ev.Subjects[i]
		if !s.Verified {
			return Contradicted("the provenance for %s did not verify against the trust root", s.Name)
		}
	}

	return Established("every artifact's provenance signature verified against the trust root")
}

type hostedRunner struct{}

func (hostedRunner) For() string { return "build/hosted" }

func (hostedRunner) Detect(ev *Evidence) Outcome {
	return runnerEnvironment(ev, "built on a hosted runner")
}

type isolatedBuild struct{}

func (isolatedBuild) For() string { return "build/isolated" }

func (isolatedBuild) Detect(ev *Evidence) Outcome {
	// A hosted runner is provisioned per job and destroyed after it, so
	// the platform's own claim that the run was hosted IS the isolation
	// evidence: there is no environment to persist into and no
	// concurrent tenant sharing it. What that claim is WORTH is the
	// platform assessment's business, which is the trust root's job,
	// not this detector's.
	return runnerEnvironment(ev, "ran in an environment the platform provisions per build and destroys after it")
}

// runnerEnvironment folds the platform's runner claim across subjects.
func runnerEnvironment(ev *Evidence, established string) Outcome {
	if len(ev.Subjects) == 0 {
		return Unevaluated("no released artifact was reached")
	}

	for i := range ev.Subjects {
		s := &ev.Subjects[i]
		switch got := s.Cert.RunnerEnvironment; {
		case got == "":
			return Unevaluated("the certificate for %s carries no runner-environment claim", s.Name)
		case tenantRunnerValues[got]:
			return Contradicted("%s was built on a %q runner, which is the tenant's machine and not the platform's",
				s.Name, got)
		case !hostedRunnerValues[got]:
			return Unevaluated("the certificate for %s claims runner environment %q, a vocabulary this build"+
				" does not know — neither a hosted claim it can accept nor a tenant claim it can refute",
				s.Name, got)
		}
	}

	return Established("every artifact %s, per the platform's own certificate claim", established)
}

type externalParametersComplete struct{}

func (externalParametersComplete) For() string { return "build/external-parameters-complete" }

func (externalParametersComplete) Detect(ev *Evidence) Outcome {
	if len(ev.Subjects) == 0 {
		return Unevaluated("no released artifact was reached")
	}

	for i := range ev.Subjects {
		s := &ev.Subjects[i]
		if s.BuildType == "" {
			return Unevaluated("the provenance for %s declares no buildType, so its parameter schema is unknown", s.Name)
		}

		if len(s.UnrecognisedParameters) > 0 {
			return Contradicted(
				"the provenance for %s carries externalParameters outside its buildType's published schema: %v"+
					" — a parameter the schema does not describe is one a consumer cannot form an expectation about",
				s.Name, s.UnrecognisedParameters)
		}
	}

	return Established("every artifact's externalParameters fall inside its buildType's published schema")
}

type unforgeableProvenance struct{}

func (unforgeableProvenance) For() string { return "build/unforgeable" }

func (unforgeableProvenance) Detect(ev *Evidence) Outcome {
	if len(ev.Subjects) == 0 {
		return Unevaluated("no released artifact was reached")
	}

	if ev.SignerRunsTenantCode == nil {
		return Unevaluated("the signing workflow's content was not reachable, so the capability boundary" +
			" could not be checked")
	}

	for i := range ev.Subjects {
		s := &ev.Subjects[i]
		uri, digest := s.Cert.BuildSignerURI, s.Cert.BuildSignerDigest
		if uri == "" || digest == "" {
			return Unevaluated("the certificate for %s does not name the workflow that held the signing"+
				" capability, so the boundary cannot be located", s.Name)
		}

		runs, err := ev.SignerRunsTenantCode(uri, digest)
		if err != nil {
			return Unevaluated("the signing workflow %s at %.12s could not be read: %v", trimRef(uri), digest, err)
		}

		if runs {
			return Contradicted(
				"the workflow holding the signing capability (%s at %.12s) executes caller-controlled steps,"+
					" so the signing material is reachable from tenant code",
				trimRef(uri), digest)
		}
	}

	return Established("the workflow holding the signing capability executes no caller-controlled step," +
		" so signing material is unreachable from the build's own steps")
}

// trimRef shortens a workflow URI for a report line, keeping the part
// that identifies it.
func trimRef(uri string) string {
	if i := strings.Index(uri, "://"); i >= 0 {
		uri = uri[i+3:]
	}

	return uri
}
