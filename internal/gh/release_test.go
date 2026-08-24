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
	"reflect"
	"testing"

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
