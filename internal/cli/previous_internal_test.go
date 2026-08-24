// `derive version`'s previous block, end to end: the four shapes a
// real repository presents, and the guards around them.
//
// The shapes are measured, not invented (stele#250). A repository the
// org released from the start carries "v<base>" with the artifacts on
// it; an imported one carries the same base under whatever scheme it
// published with — edtf's extension tarballs sit on
// "edtf-postgres-v1.2.3" while a bare "v1.2.3" tag exists with no
// release object at all. Both resolve through this one path, and the
// block reports which of them it found rather than which one a scheme
// would predict.

package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
)

// withReleases scripts the forge's by-tag read: a body per tag that
// carries a release, a 404 for every tag that does not. Nothing else
// is served, so a run that asked a question this test did not
// anticipate fails rather than passing on a default.
func withReleases(t *testing.T, bodies map[string]string) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/widget/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		tag := strings.TrimPrefix(r.URL.Path, "/repos/acme/widget/releases/tags/")

		body, published := bodies[tag]
		if !published {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("writing the scripted release: %v", err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	swapReleaseClient(t, func() *gh.Client {
		return &gh.Client{Base: srv.URL, Download: srv.URL, HTTP: srv.Client()}
	})
}

// swapReleaseClient installs a forge seam for one test and restores
// the real one after.
func swapReleaseClient(t *testing.T, build func() *gh.Client) {
	t.Helper()

	previous := newReleaseClient
	newReleaseClient = build

	t.Cleanup(func() { newReleaseClient = previous })
}

// The release body edtf's extension tarballs actually hang on,
// abbreviated to the fields this block reports.
const edtfRelease = `{"id": 367295915, "tag_name": "edtf-postgres-v1.2.3",
  "name": "edtf-postgres-v1.2.3", "draft": false,
  "html_url": "https://forge.example/acme/widget/releases/tag/edtf-postgres-v1.2.3",
  "assets": [
    {"name": "edtf_postgres-1.2.3-pg14-linux-amd64.tar.gz",
     "browser_download_url": "https://forge.example/d/edtf_postgres-1.2.3-pg14-linux-amd64.tar.gz"}]}`

const steleRelease = `{"id": 374082140, "tag_name": "v0.19.1", "name": "v0.19.1", "draft": false,
  "html_url": "https://forge.example/acme/widget/releases/tag/v0.19.1",
  "assets": [{"name": "checksums.txt", "browser_download_url": "https://forge.example/d/checksums.txt"}]}`

func TestDeriveVersionPreviousBlock(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		hist     *stubHistory
		releases map[string]string
		want     string
		alsoWant []string
	}{
		// The first release of anything: there is no previous, and the
		// block says that rather than naming version "" at tag "".
		{
			name: "a first release has no previous",
			hist: &stubHistory{
				commits:  []string{"a"},
				messages: map[string]string{"a": "feat: the first thing"},
			},
			want: `previous={"exists":false,"forgeAsked":false}`,
		},
		// The same first release with a repository named. The forge is
		// still not asked: there is no tag to ask about, and a run that
		// asked anyway would be asking where the artifacts of a release
		// that does not exist live.
		{
			name: "a first release asks no forge even when one is named",
			args: []string{"--repo", "acme/widget"},
			hist: &stubHistory{
				commits:  []string{"a"},
				messages: map[string]string{"a": "feat: the first thing"},
			},
			releases: map[string]string{},
			want:     `previous={"exists":false,"forgeAsked":false}`,
		},
		// No repository named: the tag is reported and the block says
		// plainly that nobody looked. An absent release here is not a
		// statement about the forge.
		{
			name: "a tag nobody asked a forge about",
			hist: &stubHistory{
				tags:     []string{"v1.2.3"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "fix: repair it"},
			},
			want: `previous={"exists":true,"version":"1.2.3","tag":"v1.2.3","forgeAsked":false}`,
		},
		// The org's own shape: "v<base>" with the artifacts on it.
		{
			name: "the v namespace, with the release on the tag",
			args: []string{"--repo", "acme/widget"},
			hist: &stubHistory{
				tags:     []string{"v0.19.1"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "fix: repair it"},
			},
			releases: map[string]string{"v0.19.1": steleRelease},
			want: `previous={"exists":true,"version":"0.19.1","tag":"v0.19.1","forgeAsked":true,` +
				`"release":{"id":374082140,"name":"v0.19.1",` +
				`"url":"https://forge.example/acme/widget/releases/tag/v0.19.1",` +
				`"assets":[{"name":"checksums.txt","url":"https://forge.example/d/checksums.txt"}]}}`,
		},
		// The imported repository's shape, resolved through the same
		// path: a per-crate tag namespace, the artifacts on the tag its
		// old scheme minted.
		{
			name: "a per-crate namespace, with the release on its own tag",
			args: []string{"--tag-prefix", "edtf-postgres-v", "--repo", "acme/widget"},
			hist: &stubHistory{
				tags:     []string{"v1.2.3", "edtf-postgres-v1.2.3"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "feat: another thing"},
			},
			releases: map[string]string{"edtf-postgres-v1.2.3": edtfRelease},
			want: `previous={"exists":true,"version":"1.2.3","tag":"edtf-postgres-v1.2.3","forgeAsked":true,` +
				`"release":{"id":367295915,"name":"edtf-postgres-v1.2.3",` +
				`"url":"https://forge.example/acme/widget/releases/tag/edtf-postgres-v1.2.3",` +
				`"assets":[{"name":"edtf_postgres-1.2.3-pg14-linux-amd64.tar.gz",` +
				`"url":"https://forge.example/d/edtf_postgres-1.2.3-pg14-linux-amd64.tar.gz"}]}}`,
		},
		// The other half of the same repository, and the defect this
		// block exists to end: "v1.2.3" is a real tag with no release
		// object, so a consumer that assumed the artifacts hang there
		// fetches nothing. Asked, and answered with an absence.
		{
			name: "a tag the forge hangs no release on",
			args: []string{"--repo", "acme/widget"},
			hist: &stubHistory{
				tags:     []string{"v1.2.3", "edtf-postgres-v1.2.3"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "fix: repair it"},
			},
			releases: map[string]string{"edtf-postgres-v1.2.3": edtfRelease},
			want:     `previous={"exists":true,"version":"1.2.3","tag":"v1.2.3","forgeAsked":true}`,
			alsoWant: []string{"no release hangs on v1.2.3"},
		},
		// A release that published nothing is an answer: the list is
		// empty and present.
		{
			name: "a release that carries no assets",
			args: []string{"--repo", "acme/widget"},
			hist: &stubHistory{
				tags:     []string{"v1.0.0"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "fix: repair it"},
			},
			releases: map[string]string{
				"v1.0.0": `{"id": 1, "tag_name": "v1.0.0", "draft": false, "assets": []}`,
			},
			want: `previous={"exists":true,"version":"1.0.0","tag":"v1.0.0","forgeAsked":true,` +
				`"release":{"id":1,"assets":[]}}`,
		},
		// The previous release is the derivation's INPUT, so it is
		// reported whether or not the range calls for a new one. A
		// consumer that had to cut a release to learn which one came
		// before would be back to guessing.
		{
			name: "a range that releases nothing still states its previous",
			hist: &stubHistory{
				tags:     []string{"v1.2.3"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "chore: tidy"},
			},
			want:     `previous={"exists":true,"version":"1.2.3","tag":"v1.2.3","forgeAsked":false}`,
			alsoWant: []string{"release=false"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHistory(t, tc.hist, nil)

			if tc.releases != nil {
				withReleases(t, tc.releases)
			} else {
				// No forge is named in these rows, so touching the seam
				// at all is the defect: an offline derivation that
				// dialled out would be a different command.
				swapReleaseClient(t, func() *gh.Client {
					t.Error("the forge was asked although no repository was named")

					return gh.New("")
				})
			}

			var stdout, stderr bytes.Buffer

			args := append([]string{"version", "--git-dir", "."}, tc.args...)
			if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitOK, stderr.String())
			}

			for _, want := range append(tc.alsoWant, tc.want) {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout =\n%s\nwant it to contain\n%s", stdout.String(), want)
				}
			}
		})
	}
}

// A forge that cannot be read REFUSES the run. The alternative is
// publishing "no release" as a derived fact when what happened is
// that nobody could see — the absence a consumer would then act on.
func TestDeriveVersionRefusesAnUnreadableForge(t *testing.T) {
	withHistory(t, &stubHistory{
		tags:     []string{"v1.2.3"},
		commits:  []string{"a"},
		messages: map[string]string{"a": "fix: repair it"},
	}, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	swapReleaseClient(t, func() *gh.Client {
		return &gh.Client{Base: srv.URL, Download: srv.URL, HTTP: srv.Client()}
	})

	var stdout, stderr bytes.Buffer

	args := []string{"version", "--git-dir", ".", "--repo", "acme/widget"}
	if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
		t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
	}

	if !strings.Contains(stderr.String(), "the release on v1.2.3") {
		t.Errorf("stderr = %q, want it to name the tag it could not read", stderr.String())
	}

	// Nothing is reported from a run that refused: a previous block
	// printed beside a refusal is a fact the run did not establish.
	if strings.Contains(stdout.String(), "previous=") {
		t.Errorf("a refused run still published a previous block:\n%s", stdout.String())
	}
}

func TestDeriveVersionRepoMustBeOwnerName(t *testing.T) {
	withHistory(t, &stubHistory{}, nil)

	var stdout, stderr bytes.Buffer

	args := []string{"version", "--git-dir", ".", "--repo", "widget"}
	if got := deriveCmd(args, &stdout, &stderr); got != exitUsage {
		t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitUsage, stderr.String())
	}

	if !strings.Contains(stderr.String(), "--repo must be owner/name") {
		t.Errorf("stderr = %q, want it to say what --repo takes", stderr.String())
	}
}

// The flag belongs to the mode that reports the block. Offering it on
// a mode that cannot act on it would be a surface promising a fact it
// never produces.
func TestPreviousRepoFlagIsVersionOnly(t *testing.T) {
	for _, mode := range []string{"notes", "bump", "release-plan"} {
		t.Run(mode, func(t *testing.T) {
			withHistory(t, &stubHistory{}, nil)

			var stdout, stderr bytes.Buffer

			args := []string{mode, "--git-dir", ".", "--repo", "acme/widget"}
			if got := deriveCmd(args, &stdout, &stderr); got != exitUsage {
				t.Errorf("deriveCmd %s --repo = %d, want %d (stderr: %s)",
					mode, got, exitUsage, stderr.String())
			}
		})
	}
}
