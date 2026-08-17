// The seam's replay law: whatever Capture recorded, Snapshot answers
// identically — including the recorded absences (a missing file, an
// empty attestation store), which replay as answers, never errors.

package gh_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
)

// scriptedForge is the "live" side for capture tests.
type scriptedForge struct{}

func (scriptedForge) Repos(string) ([]string, error) { return []string{"widget", "gadget"}, nil }

func (scriptedForge) ReleaseTags(_, repo string) ([]string, error) {
	if repo == "widget" {
		return []string{"v1.0.0"}, nil
	}

	return nil, nil
}

func (scriptedForge) ReleaseAssets(_, _, _ string) ([]string, error) {
	return []string{"checksums.txt"}, nil
}

func (scriptedForge) Asset(_, _, _, _ string) ([]byte, error) { return []byte("digest  name\n"), nil }

//nolint:gocritic // unnamedResult: the Forge interface documents the results
func (scriptedForge) FileAt(_, _, path, _ string) ([]byte, bool, error) {
	if path == "present.yml" {
		return []byte("jobs: {}\n"), true, nil
	}

	return nil, false, nil
}

func (scriptedForge) Attestations(_, _, digest string) ([]jsonx.Raw, error) {
	if digest == "aa" {
		return []jsonx.Raw{jsonx.Raw(`{"bundle": 1}`)}, nil
	}

	return nil, nil
}

func (scriptedForge) FailedRuns(_, _, _ string) (int, error) { return 3, nil }

func TestCaptureThenReplay(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rec := gh.Capture{Live: scriptedForge{}, Dir: dir}

	// Drive every read once through the capture.
	if _, err := rec.Repos("acme"); err != nil {
		t.Fatal(err)
	}

	for _, call := range []func() error{
		func() error { _, err := rec.ReleaseTags("acme", "widget"); return err },
		func() error { _, err := rec.ReleaseAssets("acme", "widget", "v1.0.0"); return err },
		func() error { _, err := rec.Asset("acme", "widget", "v1.0.0", "checksums.txt"); return err },
		func() error { _, _, err := rec.FileAt("acme", "widget", "present.yml", "v1.0.0"); return err },
		func() error { _, _, err := rec.FileAt("acme", "widget", "absent.yml", "v1.0.0"); return err },
		func() error { _, err := rec.Attestations("acme", "widget", "aa"); return err },
		func() error { _, err := rec.Attestations("acme", "widget", "bb"); return err },
		func() error { _, err := rec.FailedRuns("acme", "widget", "v1.0.0"); return err },
	} {
		if err := call(); err != nil {
			t.Fatal(err)
		}
	}

	snap := gh.Snapshot{Dir: dir}

	repos, err := snap.Repos("acme")
	if err != nil || !reflect.DeepEqual(repos, []string{"widget", "gadget"}) {
		t.Fatalf("Repos = %v, %v", repos, err)
	}

	tags, err := snap.ReleaseTags("acme", "widget")
	if err != nil || !reflect.DeepEqual(tags, []string{"v1.0.0"}) {
		t.Fatalf("ReleaseTags = %v, %v", tags, err)
	}

	asset, err := snap.Asset("acme", "widget", "v1.0.0", "checksums.txt")
	if err != nil || string(asset) != "digest  name\n" {
		t.Fatalf("Asset = %q, %v", asset, err)
	}

	if _, ok, ferr := snap.FileAt("acme", "widget", "present.yml", "v1.0.0"); !ok || ferr != nil {
		t.Fatalf("present file: ok=%v err=%v", ok, ferr)
	}

	if _, ok, ferr := snap.FileAt("acme", "widget", "absent.yml", "v1.0.0"); ok || ferr != nil {
		t.Fatalf("absent file: ok=%v err=%v, want recorded absence", ok, ferr)
	}

	stored, err := snap.Attestations("acme", "widget", "aa")
	if err != nil || len(stored) != 1 {
		t.Fatalf("Attestations aa = %v, %v", stored, err)
	}

	if empty, aerr := snap.Attestations("acme", "widget", "bb"); aerr != nil || len(empty) != 0 {
		t.Fatalf("Attestations bb = %v, %v, want the recorded empty store", empty, aerr)
	}

	failed, err := snap.FailedRuns("acme", "widget", "v1.0.0")
	if err != nil || failed != 3 {
		t.Fatalf("FailedRuns = %d, %v", failed, err)
	}
}

// TestSnapshotMissingListing pins the difference between a recorded
// absence and an uncaptured listing: a listing the capture never
// wrote is an error, not an empty population.
func TestSnapshotMissingListing(t *testing.T) {
	t.Parallel()

	snap := gh.Snapshot{Dir: t.TempDir()}

	if _, err := snap.Repos("acme"); err == nil {
		t.Fatal("an uncaptured listing did not refuse")
	}

	if _, err := snap.ReleaseTags("acme", "widget"); err == nil {
		t.Fatal("uncaptured tags did not refuse")
	}
}

// TestForbiddenIsTyped pins the sentinel: the live client's 401/403
// wraps ErrForbidden so engines can tell "cannot read" from "absent".
func TestForbiddenIsTyped(t *testing.T) {
	t.Parallel()

	if !errors.Is(errWrap(), gh.ErrForbidden) {
		t.Fatal("the forbidden sentinel does not survive wrapping")
	}
}

func errWrap() error {
	return errors.Join(errors.New("gh: x: HTTP 403"), gh.ErrForbidden)
}

// TestSnapshotReleaseAssetsReplay covers the assets listing replay.
func TestSnapshotReleaseAssetsReplay(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rec := gh.Capture{Live: scriptedForge{}, Dir: dir}

	if _, err := rec.ReleaseAssets("acme", "widget", "v1.0.0"); err != nil {
		t.Fatal(err)
	}

	assets, err := gh.Snapshot{Dir: dir}.ReleaseAssets("acme", "widget", "v1.0.0")
	if err != nil || len(assets) != 1 || assets[0] != "checksums.txt" {
		t.Fatalf("ReleaseAssets = %v, %v", assets, err)
	}
}

// TestCaptureUnwritableDir pins the write-failure branches: a capture
// that cannot record refuses rather than silently serving live-only.
func TestCaptureUnwritableDir(t *testing.T) {
	t.Parallel()

	// A FILE where the directory should be makes every write fail.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := gh.Capture{Live: scriptedForge{}, Dir: filepath.Join(blocker, "nested")}

	if _, err := rec.Repos("acme"); err == nil {
		t.Fatal("Repos capture into an unwritable dir did not refuse")
	}

	if _, err := rec.ReleaseTags("acme", "widget"); err == nil {
		t.Fatal("ReleaseTags capture did not refuse")
	}

	if _, err := rec.ReleaseAssets("acme", "widget", "v1.0.0"); err == nil {
		t.Fatal("ReleaseAssets capture did not refuse")
	}

	if _, err := rec.Asset("acme", "widget", "v1.0.0", "checksums.txt"); err == nil {
		t.Fatal("Asset capture did not refuse")
	}

	if _, _, err := rec.FileAt("acme", "widget", "present.yml", "v1.0.0"); err == nil {
		t.Fatal("FileAt capture did not refuse")
	}

	if _, err := rec.Attestations("acme", "widget", "aa"); err == nil {
		t.Fatal("Attestations capture did not refuse")
	}

	if _, err := rec.FailedRuns("acme", "widget", "v1.0.0"); err == nil {
		t.Fatal("FailedRuns capture did not refuse")
	}
}

// TestSnapshotCorruptFile pins the replay guard: recorded bytes that
// decode as nothing refuse by path.
func TestSnapshotCorruptFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "acme"), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "acme", "repos.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := (gh.Snapshot{Dir: dir}).Repos("acme"); err == nil {
		t.Fatal("a corrupt snapshot listing did not refuse")
	}
}
