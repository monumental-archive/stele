// The decoded by-tag release read: what hangs on a tag, and the three
// answers a caller must be able to tell apart — a release, no release,
// and a forge that could not be read.
//
// The middle one is the reason this read exists (stele#250). An
// imported repository's history is full of tags nothing was ever
// published on, and a caller deciding where a previous release's
// artifacts live must not read "the forge has none" out of a run that
// never got an answer.

package gh_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
)

// releaseServer scripts one by-tag endpoint per tag it is given.
func releaseServer(t *testing.T, bodies map[string]string, statuses map[string]int) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()

	for tag, body := range bodies {
		mux.HandleFunc("/repos/acme/widget/releases/tags/"+tag, func(w http.ResponseWriter, _ *http.Request) {
			if status, scripted := statuses[tag]; scripted {
				w.WriteHeader(status)

				return
			}

			writeBody(w, []byte(body))
		})
	}

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &gh.Client{Base: srv.URL, Download: srv.URL, HTTP: srv.Client()}
}

func TestReleaseByTagDecodes(t *testing.T) {
	t.Parallel()

	client := releaseServer(t, map[string]string{
		"v1.0.0": `{"id": 42, "tag_name": "v1.0.0", "name": "v1.0.0 the release",
		  "html_url": "https://forge.example/acme/widget/releases/tag/v1.0.0", "draft": false,
		  "assets": [
		    {"name": "app-1.0.0-linux-amd64.tar.gz",
		     "browser_download_url": "https://forge.example/d/app-1.0.0-linux-amd64.tar.gz"},
		    {"name": "checksums.txt", "browser_download_url": "https://forge.example/d/checksums.txt"}]}`,
	}, nil)

	release, found, err := client.ReleaseByTag("acme", "widget", "v1.0.0")
	if err != nil || !found {
		t.Fatalf("ReleaseByTag = (%v, %t, %v), want a release", release, found, err)
	}

	want := &gh.Release{
		ID: 42, Name: "v1.0.0 the release",
		URL: "https://forge.example/acme/widget/releases/tag/v1.0.0",
		Assets: []gh.ReleaseAsset{
			{Name: "app-1.0.0-linux-amd64.tar.gz", URL: "https://forge.example/d/app-1.0.0-linux-amd64.tar.gz"},
			{Name: "checksums.txt", URL: "https://forge.example/d/checksums.txt"},
		},
	}

	if !reflect.DeepEqual(release, want) {
		t.Errorf("ReleaseByTag = %+v, want %+v", release, want)
	}
}

// A release that published nothing is an answer, not an absence: the
// list is empty and present, so a caller can tell it from a release
// nobody read.
func TestReleaseByTagCarriesNoAssets(t *testing.T) {
	t.Parallel()

	client := releaseServer(t, map[string]string{
		"v1.0.0": `{"id": 7, "tag_name": "v1.0.0", "draft": false, "assets": []}`,
	}, nil)

	release, found, err := client.ReleaseByTag("acme", "widget", "v1.0.0")
	if err != nil || !found {
		t.Fatalf("ReleaseByTag = (%v, %t, %v), want a release", release, found, err)
	}

	if release.Assets == nil || len(release.Assets) != 0 {
		t.Errorf("assets = %#v, want an empty list rather than a missing one", release.Assets)
	}
}

// The imported repository's shape: the tag is real and nothing was
// ever published on it. Reported, never raised.
func TestReleaseByTagAbsentIsAnAnswer(t *testing.T) {
	t.Parallel()

	client := releaseServer(t,
		map[string]string{"v1.2.3": ""},
		map[string]int{"v1.2.3": http.StatusNotFound})

	release, found, err := client.ReleaseByTag("acme", "widget", "v1.2.3")
	if err != nil {
		t.Fatalf("ReleaseByTag = %v, want no error for a tag with no release", err)
	}

	if found || release != nil {
		t.Errorf("ReleaseByTag = (%v, %t), want (nil, false)", release, found)
	}
}

// A credential that cannot read the release says so. Absent and
// unreadable are the two answers a consumer must never merge.
func TestReleaseByTagForbidden(t *testing.T) {
	t.Parallel()

	client := releaseServer(t,
		map[string]string{"v1.0.0": ""},
		map[string]int{"v1.0.0": http.StatusForbidden})

	_, found, err := client.ReleaseByTag("acme", "widget", "v1.0.0")
	if !errors.Is(err, gh.ErrForbidden) {
		t.Errorf("ReleaseByTag error = %v, want %v", err, gh.ErrForbidden)
	}

	if found {
		t.Error("a forbidden read reported a release")
	}
}

func TestReleaseByTagUnreadableBody(t *testing.T) {
	t.Parallel()

	client := releaseServer(t, map[string]string{"v1.0.0": `{"id": "not a number"}`}, nil)

	if _, found, err := client.ReleaseByTag("acme", "widget", "v1.0.0"); err == nil || found {
		t.Errorf("ReleaseByTag = (%t, %v), want a decode refusal", found, err)
	}
}

// TestAssetURL holds the one spelling of a release asset's public
// address, for the forge and for an enterprise host: every path segment
// escaped, so a name cannot climb out of the release it names.
func TestAssetURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, server, tag, asset, want string
	}{
		{
			"the public forge", gh.DefaultServer, "v1.0.0", "app.tar.gz",
			"https://github.com/acme/widget/releases/download/v1.0.0/app.tar.gz",
		},
		{
			"an enterprise host", "https://forge.example.com/", "v1.0.0", "app.bin",
			"https://forge.example.com/acme/widget/releases/download/v1.0.0/app.bin",
		},
		{
			"a name that tries to leave its release", gh.DefaultServer, "release/1", "../../x y",
			"https://github.com/acme/widget/releases/download/release%2F1/..%2F..%2Fx%20y",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := gh.NewForServer(tt.server, "").AssetURL("acme", "widget", tt.tag, tt.asset); got != tt.want {
				t.Fatalf("AssetURL = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestFileURLs holds the forge's two citations of a file: its page and
// its bytes, on the public forge and on an enterprise host.
func TestFileURLs(t *testing.T) {
	t.Parallel()

	const rev = "1111111111111111111111111111111111111111"

	pub := gh.New("")
	ent := gh.NewForServer("https://forge.example.com", "")

	tests := []struct{ got, want string }{
		{
			pub.BlobURL("acme", "policy", rev, "slsa/verify policy.json"),
			"https://github.com/acme/policy/blob/" + rev + "/slsa/verify%20policy.json",
		},
		{
			pub.RawURL("acme", "widget", rev, "Cargo.lock"),
			"https://raw.githubusercontent.com/acme/widget/" + rev + "/Cargo.lock",
		},
		{
			ent.BlobURL("acme", "policy", rev, "mise/mise.lock"),
			"https://forge.example.com/acme/policy/blob/" + rev + "/mise/mise.lock",
		},
		{
			ent.RawURL("acme", "widget", rev, "sub/package-lock.json"),
			"https://forge.example.com/acme/widget/raw/" + rev + "/sub/package-lock.json",
		},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("got %s, want %s", tt.got, tt.want)
		}
	}
}

// TestCommitSHA holds the ref resolution's three answers: a commit, no
// such ref, and a body that is not a commit.
func TestCommitSHA(t *testing.T) {
	t.Parallel()

	const sha = "1111111111111111111111111111111111111111"

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/canon/commits/v1.68.8", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`{"sha": "`+sha+`", "commit": {"message": "x"}}`))
	})
	mux.HandleFunc("/repos/acme/canon/commits/garbled", func(w http.ResponseWriter, _ *http.Request) {
		writeBody(w, []byte(`[1, 2]`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	ownTransport(c, srv)

	got, ok, err := c.CommitSHA("acme", "canon", "v1.68.8")
	if err != nil || !ok || got != sha {
		t.Fatalf("CommitSHA = %q, %v, %v", got, ok, err)
	}

	if got, ok, err := c.CommitSHA("acme", "canon", "v0.0.0"); err != nil || ok || got != "" {
		t.Fatalf("an unknown ref = %q, %v, %v; want no answer and no error", got, ok, err)
	}

	if _, _, err := c.CommitSHA("acme", "canon", "garbled"); err == nil ||
		!strings.Contains(err.Error(), "gh: commit acme/canon@garbled") {
		t.Fatalf("a body that is no commit = %v", err)
	}
}

// The recorded owner-level answers (testdata/owner-attestations/SOURCE.md).
const (
	labPgHex = "ca2d60b355aeaf2837e96cdb5b7595cf09398260c864e08bcf39c91f79f76384"
	miseHex  = "23ba592fcbc61f057e2b82c1eafd085832712ba0c759b714ca16cd06babca378"
)

// recordedOwner reads one recorded answer.
func recordedOwner(t *testing.T, name string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("testdata", "owner-attestations", name)) //nolint:gosec // fixed testdata
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// ownerForge serves the recorded owner-level answers, each at the one
// documented path for its kind of account, so a read through the other
// form finds nothing there.
func ownerForge(t *testing.T) *gh.Client {
	t.Helper()

	mux := http.NewServeMux()

	for path, file := range map[string]string{
		"/users/monumental-archive": "type-monumental-archive.json",
		"/users/jdx":                "type-jdx.json",
		"/orgs/monumental-archive/attestations/sha256:" + labPgHex:              "orgs-monumental-archive.json",
		"/users/jdx/attestations/sha256:" + miseHex:                             "users-jdx.json",
		"/repos/monumental-archive/release-lab/attestations/sha256:" + labPgHex: "orgs-monumental-archive.json",
	} {
		body := recordedOwner(t, file)

		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) { writeBody(w, body) })
	}

	for path, body := range map[string]string{
		"/users/ghost-bot":  `{"login": "ghost-bot", "type": "Bot"}`,
		"/users/typeless":   `{"login": "typeless"}`,
		"/users/unparsable": `not json`,
		"/users/unreadable": ``,
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			if body == "" {
				w.WriteHeader(http.StatusForbidden)

				return
			}

			writeBody(w, []byte(body))
		})
	}

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := gh.New("")
	c.Base = srv.URL
	c.Sleep = func(time.Duration) {}
	ownTransport(c, srv)

	return c
}

// TestOwnerAttestations holds the owner-level read on the recorded
// answers: an empty repository asks the owner's whole store, in the
// documented form for the owner's kind — an organisation's under
// /orgs, a user's under /users — through the same envelope as a
// repository's store.
func TestOwnerAttestations(t *testing.T) {
	t.Parallel()

	c := ownerForge(t)

	for _, tt := range []struct{ owner, repo, hex string }{
		{"monumental-archive", "", labPgHex},
		{"jdx", "", miseHex},
		{"monumental-archive", "release-lab", labPgHex},
	} {
		got, err := c.Attestations(tt.owner, tt.repo, tt.hex)
		if err != nil || len(got) != 1 || !strings.Contains(string(got[0]), `"dsseEnvelope"`) {
			t.Fatalf("Attestations(%s, %q) = %d bundle(s), %v; want the recorded one", tt.owner, tt.repo, len(got), err)
		}
	}

	// A digest the owner's store holds nothing for is an empty store,
	// the answer the repository read gives too.
	if got, err := c.Attestations("monumental-archive", "", strings.Repeat("1", 64)); err != nil || len(got) != 0 {
		t.Fatalf("an absent digest = %v, %v; want the empty store", got, err)
	}
}

// TestOwnerAttestationsRefusals: an owner whose store cannot be named
// is refused by name, never read as an empty store — an empty answer
// there would be a finding against a base nobody could look up.
func TestOwnerAttestationsRefusals(t *testing.T) {
	t.Parallel()

	c := ownerForge(t)

	for owner, want := range map[string]string{
		"nobody":     `gh: owner "nobody" does not exist`,
		"ghost-bot":  `gh: owner "ghost-bot" is a Bot account, which keeps no attestation store`,
		"typeless":   `gh: owner "typeless": the forge states no account type`,
		"unparsable": "gh: owner unparsable:",
		"unreadable": "HTTP 403",
	} {
		if got, err := c.Attestations(owner, "", labPgHex); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Attestations(%s) = %v, %v; want the refusal %q", owner, got, err, want)
		}
	}
}
