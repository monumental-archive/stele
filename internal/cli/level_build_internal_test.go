// The Build leg over every declared publish surface (stele#355).
//
// The stream here is monumental-archive-db's real publish, read
// 2026-11-16: testdata/monumental-archive-db-latest holds the index
// its rolling tag named (two platform manifests) and the build
// provenance the attestation store held for that index — the only
// provenance in the publish; the platform manifests carry an
// inventory and a release decision and nothing else. The fixture is
// that publish's shape, not an imitation of one.

package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/level"
	"github.com/monumental-archive/stele/internal/population"
	"github.com/monumental-archive/stele/internal/trust"
)

// The real stream's names and digests.
const (
	dbImage  = "ghcr.io/monumental-archive/monumental-archive-db"
	dbTag    = "latest"
	dbSigner = `^https://github\.com/monumental-archive/signer/`
	dbSAN    = "https://github.com/monumental-archive/signer/.github/workflows/sign.yml@" +
		"dd3d0824d5d450a646de64df0d17e5714efca5c4"
	dbIndex = "sha256:8fd73f31851b7f982946c5df603c799d75fa96ab88e7fe4018c26ff596664378"
	dbAMD   = "sha256:5cb11af565ce5d55a7e225b22210d92436161de7de64e63dfa4f5fc90168b481"
	dbARM   = "sha256:74c49f65b7181d7d488ae6a13d29e78d0d2d96818f2ea189f7bea527cee61e04"
)

// distributedRefuted is the fact a publish whose two platform
// artifacts carry no provenance under the declared signer owes
// (stele#369): nothing was retrieved, so nothing is "retrievable".
const distributedRefuted = `"build/provenance-distributed","value":"REFUTED: provenance for 2 of 2 published` +
	` artifact(s) could not be retrieved from the store a consumer queries: [` +
	dbImage + "@" + dbAMD + " " + dbImage + "@" + dbARM + `]`

// dbFixture reads one committed document of the real publish.
func dbFixture(t *testing.T, name string) string {
	t.Helper()

	raw, err := fs.ReadFile(os.DirFS(filepath.Join("testdata", "monumental-archive-db-latest")), name)
	if err != nil {
		t.Fatal(err)
	}

	return string(raw)
}

// dbSurface is the stream's roster declaration.
func dbSurface() population.Surface {
	kind := population.SurfaceContinuousDigest
	registry, tag, identity := dbImage, dbTag, dbSigner

	return population.Surface{Kind: &kind, Registry: &registry, Tag: &tag, Identity: &identity}
}

// provenanceFor is the real index provenance re-pointed at another
// digest — what a publisher attesting per platform would emit.
func provenanceFor(t *testing.T, digest string) string {
	t.Helper()

	return strings.Replace(dbFixture(t, "index.provenance.json"),
		strings.TrimPrefix(dbIndex, "sha256:"), strings.TrimPrefix(digest, "sha256:"), 1)
}

// buildRun is one gathered and judged build track: the evidence, the
// rendered report and the walk's log.
type buildRun struct {
	ev       *level.Evidence
	doc, log string
}

// buildReport gathers the build track over the given surfaces and
// renders the judged report.
func buildReport(t *testing.T, la *levelArgs, forge *storeForgeStream) buildRun {
	t.Helper()

	var log bytes.Buffer

	ev := la.gather(forge, &latch{w: &log})

	var doc bytes.Buffer
	if err := level.Assess(level.TrackBuild, ev).Report().Encode(&doc); err != nil {
		t.Fatalf("Encode = %v", err)
	}

	return buildRun{ev: ev, doc: doc.String(), log: log.String()}
}

// checkBuildRun asserts the subjects a run measured, the lines its
// report carries, and — for a run that could not see its surface —
// that every Build detector is undetermined with the unreached account.
func checkBuildRun(t *testing.T, run buildRun, subjects, want []string, blind bool) {
	t.Helper()

	names := make([]string, 0, len(run.ev.Subjects))
	for i := range run.ev.Subjects {
		names = append(names, run.ev.Subjects[i].Name)
	}

	if strings.Join(names, " ") != strings.Join(subjects, " ") {
		t.Errorf("subjects = %v, want %v\n%s", names, subjects, run.log)
	}

	for _, w := range want {
		if !strings.Contains(run.doc, w) {
			t.Errorf("the report does not carry %q:\n%s", w, run.doc)
		}
	}

	if !blind {
		return
	}

	for _, id := range buildDetectors() {
		if !strings.Contains(run.doc, `"`+id+`","value":"UNDETERMINED: 1 of the 1 surface(s)`) {
			t.Errorf("%s is not undetermined with the unreached account:\n%s", id, run.doc)
		}
	}
}

// buildDetectors are the requirements every coverage row must leave
// undetermined: the whole Build catalogue, read from the judge.
func buildDetectors() []string {
	reqs := level.Requirements(level.TrackBuild)
	out := make([]string, 0, len(reqs))

	for _, r := range reqs {
		out = append(out, r.ID)
	}

	return out
}

// TestBuildOverAStream holds the stream gather to each Done-when row
// and each guard branch, with the exact account each one owes.
//
//nolint:maintidx // one table, one row per guard: splitting it would hide the set
func TestBuildOverAStream(t *testing.T) {
	inv, invVerified := signedBy("inventory", spdxStatement)

	indexProv := jsonx.Raw("index provenance")
	amdProv, armProv := jsonx.Raw("amd64 provenance"), jsonx.Raw("arm64 provenance")
	strangerProv := jsonx.Raw("someone else's provenance")

	proven := map[string]*trust.Verified{
		"inventory":        invVerified,
		"index provenance": {SAN: dbSAN, Payload: []byte(dbFixture(t, "index.provenance.json"))},
		"amd64 provenance": {SAN: dbSAN, Payload: []byte(provenanceFor(t, dbAMD))},
		"arm64 provenance": {SAN: dbSAN, Payload: []byte(provenanceFor(t, dbARM))},
		"someone else's provenance": {
			SAN:     "https://github.com/elsewhere/builder/.github/workflows/build.yml@refs/heads/main",
			Payload: []byte(dbFixture(t, "index.provenance.json")),
		},
	}

	index := dbFixture(t, "index.json")
	single := `{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`
	children := map[string][]jsonx.Raw{bare(dbAMD): {inv}, bare(dbARM): {inv}}

	with := func(extra map[string][]jsonx.Raw) map[string][]jsonx.Raw {
		out := map[string][]jsonx.Raw{}
		maps.Copy(out, children)

		for k, v := range extra {
			out[k] = append(append([]jsonx.Raw{}, out[k]...), v...)
		}

		return out
	}

	for _, tt := range []struct {
		name     string
		reader   scriptedOCI
		bundles  map[string][]jsonx.Raw
		attErr   error
		identity string
		noTrust  bool
		subjects []string
		want     []string
		blind    bool
	}{
		{
			name:     "the index carries the provenance and the children none",
			reader:   scriptedOCI{resolved: dbIndex, index: index},
			bundles:  with(map[string][]jsonx.Raw{bare(dbIndex): {indexProv}}),
			subjects: []string{dbImage + "@" + dbIndex},
			want: []string{`"build/provenance-exists","value":"HELD: all 1 published artifact(s)` +
				` carry provenance identifying them by digest"`},
		},
		{
			name:     "each child carries provenance and the index none",
			reader:   scriptedOCI{resolved: dbIndex, index: index},
			bundles:  with(map[string][]jsonx.Raw{bare(dbAMD): {amdProv}, bare(dbARM): {armProv}}),
			subjects: []string{dbImage + "@" + dbAMD, dbImage + "@" + dbARM},
			want: []string{`"build/provenance-exists","value":"HELD: all 2 published artifact(s)` +
				` carry provenance identifying them by digest"`},
		},
		{
			name:     "no provenance anywhere refutes per child",
			reader:   scriptedOCI{resolved: dbIndex, index: index},
			bundles:  children,
			subjects: []string{dbImage + "@" + dbAMD, dbImage + "@" + dbARM},
			want: []string{
				`"build/provenance-exists","value":"REFUTED: 2 of 2 published artifact(s)` +
					` carry no provenance identifying them: [` + dbImage + "@" + dbAMD + " " + dbImage + "@" + dbARM + `]`,
				distributedRefuted,
			},
		},
		{
			name:     "provenance only under an identity the surface does not declare",
			reader:   scriptedOCI{resolved: dbIndex, index: index},
			bundles:  with(map[string][]jsonx.Raw{bare(dbIndex): {strangerProv}}),
			subjects: []string{dbImage + "@" + dbAMD, dbImage + "@" + dbARM},
			want:     []string{`"build/provenance-exists","value":"REFUTED: 2 of 2 published artifact(s)`, distributedRefuted},
		},
		{
			name:     "a tag naming one manifest is its own artifact",
			reader:   scriptedOCI{resolved: dbIndex, index: single},
			bundles:  map[string][]jsonx.Raw{},
			subjects: []string{dbImage + "@" + dbIndex},
			want: []string{`"build/provenance-exists","value":"REFUTED: 1 of 1 published artifact(s)` +
				` carry no provenance identifying them: [` + dbImage + "@" + dbIndex + `]`},
		},
		{
			name:   "the tag holds nothing",
			reader: scriptedOCI{resolved: ""},
			want: []string{"has not been asked for provenance — continuous-digest " + dbImage + ":" + dbTag +
				": the registry holds nothing under the rolling tag " + dbImage + ":" + dbTag},
			blind: true,
		},
		{
			name:   "the registry could not be asked",
			reader: scriptedOCI{resolveErr: errors.New("registry refused")},
			want: []string{"the registry could not be asked what " + dbImage + ":" + dbTag +
				" names: registry refused"},
			blind: true,
		},
		{
			name:   "the index could not be read",
			reader: scriptedOCI{resolved: dbIndex, indexErr: errors.New("manifest refused")},
			want: []string{dbTag + " names " + dbIndex +
				" and that manifest could not be read: manifest refused"},
			blind: true,
		},
		{
			name:   "the store could not be read for a digest",
			reader: scriptedOCI{resolved: dbIndex, index: index},
			attErr: errors.New("store refused"),
			want: []string{"the attestation store could not be read for " + dbImage + "@" + dbIndex +
				": store refused"},
			blind: true,
		},
		{
			name:     "a signer pattern that does not compile",
			reader:   scriptedOCI{resolved: dbIndex, index: index},
			identity: "(",
			want:     []string{"the declared signer pattern does not compile"},
			blind:    true,
		},
		{
			name:    "no trust material",
			reader:  scriptedOCI{resolved: dbIndex, index: index},
			bundles: with(map[string][]jsonx.Raw{bare(dbIndex): {indexProv}}),
			noTrust: true,
			want:    []string{noTrustMaterial},
			blind:   true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			forge := &storeForgeStream{bundles: tt.bundles, attErr: tt.attErr}
			swapStreamSeams(t, forge, tt.reader, proven)

			if tt.noTrust {
				orig := resolveTrustedRoot
				resolveTrustedRoot = func(trust.RootPlan) ([]byte, error) { return nil, errors.New("no root") }

				t.Cleanup(func() { resolveTrustedRoot = orig })
			}

			surface := dbSurface()
			if tt.identity != "" {
				surface.Identity = &tt.identity
			}

			la := &levelArgs{
				track: trackBuild, owner: "monumental-archive", name: "monumental-archive-db",
				repo: "monumental-archive/monumental-archive-db", surfaces: []population.Surface{surface},
			}

			checkBuildRun(t, buildReport(t, la, forge), tt.subjects, tt.want, tt.blind)
		})
	}
}

// TestBuildNeverAnswersOneSurfaceWithAnother: a repository declaring
// both surfaces, whose release answered with verifying provenance and
// whose stream could not be resolved, is not established on the
// release alone — every Build detector is undetermined and says which
// surface it could not see.
func TestBuildNeverAnswersOneSurfaceWithAnother(t *testing.T) {
	const artifact = "9999999999999999999999999999999999999999999999999999999999999999"

	prov := jsonx.Raw("release provenance")
	forge := &storeForgeStream{bundles: map[string][]jsonx.Raw{artifact: {prov}}}
	forge.tags = []string{"v1.0.0"}
	forge.assets = []string{"checksums.txt", "widget"}
	forge.files = map[string][]byte{
		"checksums.txt": []byte(artifact + "  widget\n"),
		"widget":        []byte("\x7fELF binary bytes"),
	}

	swapStreamSeams(t, forge, scriptedOCI{resolveErr: errors.New("registry refused")}, map[string]*trust.Verified{
		"release provenance": {SAN: dbSAN, Payload: []byte(provenanceFor(t, "sha256:"+artifact))},
	})

	release := population.SurfaceRelease
	la := &levelArgs{
		track: trackBuild, owner: "monumental-archive", name: "monumental-archive-db",
		repo:     "monumental-archive/monumental-archive-db",
		surfaces: []population.Surface{{Kind: &release}, dbSurface()},
	}

	run := buildReport(t, la, forge)
	doc := run.doc

	if len(run.ev.Subjects) != 1 || !run.ev.Subjects[0].Verified {
		t.Fatalf("the release did not answer with its one verified artifact: %+v\n%s", run.ev.Subjects, run.log)
	}

	for _, id := range buildDetectors() {
		want := `"` + id + `","value":"UNDETERMINED: 1 of the 2 surface(s)`
		if !strings.Contains(doc, want) {
			t.Errorf("%s was answered on the release alone:\n%s", id, doc)
		}
	}

	if !strings.Contains(doc, "continuous-digest "+dbImage+":"+dbTag+": the registry could not be asked") {
		t.Errorf("the account does not name the stream it could not see:\n%s", doc)
	}
}

// TestBuildReleaseSurfaceReportsItsAbsence: the release surface's
// absences land in its own surface's account rather than only in the
// log, so the detectors can say which surface was not seen.
func TestBuildReleaseSurfaceReportsItsAbsence(t *testing.T) {
	for _, tt := range []struct {
		name    string
		forge   *storeForgeStream
		noTrust bool
		want    string
	}{
		{
			name:  "no release this tool can order",
			forge: &storeForgeStream{},
			want:  "release: this repository has published no release this tool can order",
		},
		{
			name: "no trust material",
			forge: func() *storeForgeStream {
				f := &storeForgeStream{}
				f.tags = []string{"v1.0.0"}
				f.assets = []string{"checksums.txt"}
				f.files = map[string][]byte{"checksums.txt": []byte(strings.Repeat("8", 64) + "  widget\n")}

				return f
			}(),
			noTrust: true,
			want:    "release: " + noTrustMaterial,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			swapStreamSeams(t, tt.forge, scriptedOCI{}, nil)

			if tt.noTrust {
				orig := resolveTrustedRoot
				resolveTrustedRoot = func(trust.RootPlan) ([]byte, error) { return nil, errors.New("no root") }

				t.Cleanup(func() { resolveTrustedRoot = orig })
			}

			la := &levelArgs{track: trackBuild, owner: "acme", name: "widget", repo: "acme/widget"}

			doc := buildReport(t, la, tt.forge).doc

			for _, id := range buildDetectors() {
				want := `"` + id + `","value":"UNDETERMINED: 1 of the 1 surface(s)`
				if !strings.Contains(doc, want) {
					t.Errorf("%s is not undetermined with the unreached account:\n%s", id, doc)
				}
			}

			if !strings.Contains(doc, tt.want) {
				t.Errorf("the report does not carry %q:\n%s", tt.want, doc)
			}
		})
	}
}
