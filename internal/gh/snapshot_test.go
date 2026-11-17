// The seam's replay law: whatever Capture recorded, Snapshot answers
// identically — including the recorded absences (a missing file, an
// empty attestation store), which replay as answers, never errors.

package gh_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/workflow"
)

// scriptedForge is the "live" side for capture tests.
type scriptedForge struct{ noDigest bool }

func (scriptedForge) ListRepos(string) ([]gh.Repo, error) {
	return []gh.Repo{{Name: "widget"}, {Name: "gadget"}}, nil
}

func (scriptedForge) ReleaseTags(_, repo string) ([]string, error) {
	if repo == "widget" {
		return []string{"v1.0.0"}, nil
	}

	return nil, nil
}

func (scriptedForge) ReleaseAssets(_, _, _ string) ([]string, error) {
	return []string{"checksums.txt"}, nil
}

func (scriptedForge) ReleaseDate(_, _, _ string) (time.Time, error) {
	return time.Unix(0, 0).UTC(), nil
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
	switch digest {
	case "aa":
		return []jsonx.Raw{jsonx.Raw(`{"bundle": 1}`)}, nil
	case "unrenderable":
		// A bundle whose bytes are not JSON: the live read carried them,
		// and the capture must refuse to record what it cannot render.
		return []jsonx.Raw{jsonx.Raw(`not json`)}, nil
	default:
		return nil, nil
	}
}

// noDigest makes the rolling tag point at nothing — the answer a
// capture must record as an absence rather than a file.
func (f scriptedForge) PackageVersionDigest(_, _, _ string) (string, error) {
	if f.noDigest {
		return "", nil
	}

	return "sha256:" + strings.Repeat("a", 64), nil
}

func (scriptedForge) Workflows(_, _ string) ([]workflow.File, error) {
	return []workflow.File{{Name: "ci.yml", Content: []byte("jobs: {}\n")}}, nil
}

func (scriptedForge) FailedRuns(_, _, _ string) ([]string, error) { return []string{"publish"}, nil }

func TestCaptureThenReplay(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rec := gh.Capture{Live: scriptedForge{}, Dir: dir}

	// Drive every read once through the capture.
	if _, err := rec.ListRepos("acme"); err != nil {
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
		func() error { _, err := rec.PackageVersionDigest("acme", "widget", "latest"); return err },
		func() error { _, err := rec.Workflows("acme", "widget"); return err },
	} {
		if err := call(); err != nil {
			t.Fatal(err)
		}
	}

	snap := gh.Snapshot{Dir: dir}

	repos, err := snap.ListRepos("acme")
	if err != nil || !reflect.DeepEqual(repos, []gh.Repo{{Name: "widget"}, {Name: "gadget"}}) {
		t.Fatalf("ListRepos = %v, %v", repos, err)
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

	digest, err := snap.PackageVersionDigest("acme", "widget", "latest")
	if err != nil || digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("PackageVersionDigest = %q, %v", digest, err)
	}

	if absent, aerr := snap.PackageVersionDigest("acme", "widget", "no-such"); aerr != nil || absent != "" {
		t.Fatalf("uncaptured tag = %q, %v — a recorded absence", absent, aerr)
	}

	wf, err := snap.Workflows("acme", "widget")
	if err != nil || len(wf) != 1 {
		t.Fatalf("Workflows = %v, %v", wf, err)
	}

	if none, werr := snap.Workflows("acme", "ghost"); werr != nil || none != nil {
		t.Fatalf("uncaptured workflows = %v, %v — a recorded absence", none, werr)
	}

	failed, err := snap.FailedRuns("acme", "widget", "v1.0.0")
	if err != nil || len(failed) != 1 || failed[0] != "publish" {
		t.Fatalf("FailedRuns = %v, %v", failed, err)
	}
}

// TestSnapshotMissingListing pins the difference between a recorded
// absence and an uncaptured listing: a listing the capture never
// wrote is an error, not an empty population.
func TestSnapshotMissingListing(t *testing.T) {
	t.Parallel()

	snap := gh.Snapshot{Dir: t.TempDir()}

	if _, err := snap.ListRepos("acme"); err == nil {
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

	if _, err := rec.ListRepos("acme"); err == nil {
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

	if _, err := rec.PackageVersionDigest("acme", "widget", "latest"); err == nil {
		t.Fatal("PackageVersionDigest capture did not refuse")
	}

	if _, err := rec.Workflows("acme", "widget"); err == nil {
		t.Fatal("Workflows capture did not refuse")
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

	if _, err := (gh.Snapshot{Dir: dir}).ListRepos("acme"); err == nil {
		t.Fatal("a corrupt snapshot listing did not refuse")
	}
}

// snapshotRead is one named read on a replayed snapshot, reduced to
// its error.
type snapshotRead struct {
	name string
	call func(gh.Snapshot) error
}

// everySnapshotRead is the whole replay surface, once each.
func everySnapshotRead() []snapshotRead {
	return []snapshotRead{
		{"ListRepos", func(s gh.Snapshot) error { _, err := s.ListRepos("acme"); return err }},
		{"ReleaseTags", func(s gh.Snapshot) error { _, err := s.ReleaseTags("acme", "widget"); return err }},
		{"ReleaseAssets", func(s gh.Snapshot) error {
			_, err := s.ReleaseAssets("acme", "widget", "v1.0.0")

			return err
		}},
		{"Attestations", func(s gh.Snapshot) error { _, err := s.Attestations("acme", "widget", "aa"); return err }},
		{"PackageVersionDigest", func(s gh.Snapshot) error {
			_, err := s.PackageVersionDigest("acme", "widget", "latest")

			return err
		}},
		{"FailedRuns", func(s gh.Snapshot) error { _, err := s.FailedRuns("acme", "widget", "v1.0.0"); return err }},
	}
}

// captureWholeSeam drives every read once through a Capture and
// returns the directory it recorded — the layout under test, built by
// the code that owns it rather than by hand-written paths.
func captureWholeSeam(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	rec := gh.Capture{Live: scriptedForge{}, Dir: dir}

	for _, call := range []func() error{
		func() error { _, err := rec.ListRepos("acme"); return err },
		func() error { _, err := rec.ReleaseTags("acme", "widget"); return err },
		func() error { _, err := rec.ReleaseAssets("acme", "widget", "v1.0.0"); return err },
		func() error { _, err := rec.Attestations("acme", "widget", "aa"); return err },
		func() error { _, err := rec.PackageVersionDigest("acme", "widget", "latest"); return err },
		func() error { _, err := rec.FailedRuns("acme", "widget", "v1.0.0"); return err },
	} {
		if err := call(); err != nil {
			t.Fatalf("capturing: %v", err)
		}
	}

	return dir
}

// TestSnapshotRefusesTypeConfusedFiles is the corruption that matters:
// "not json" is obvious, but a bare NUMBER decodes cleanly as a JSON
// document and only fails at the target type. If any read shrugged at
// that, replay would hand its caller a zero value indistinguishable
// from a recorded empty.
func TestSnapshotRefusesTypeConfusedFiles(t *testing.T) {
	t.Parallel()

	dir := captureWholeSeam(t)

	// Root-scoped: the walk and the writes both go through one os.Root,
	// so no step re-resolves a path the walk already resolved.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("opening the snapshot: %v", err)
	}
	t.Cleanup(func() {
		if cerr := root.Close(); cerr != nil {
			t.Errorf("closing the snapshot root: %v", cerr)
		}
	})

	rewrite := func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}

		return root.WriteFile(filepath.FromSlash(path), []byte("0"), 0o600)
	}

	if err := fs.WalkDir(root.FS(), ".", rewrite); err != nil {
		t.Fatalf("rewriting the snapshot: %v", err)
	}

	for _, r := range everySnapshotRead() {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()

			if err := r.call(gh.Snapshot{Dir: dir}); err == nil {
				t.Fatalf("%s accepted a number where its own shape belongs", r.name)
			}
		})
	}
}

// TestSnapshotUncapturedReads pins the difference the seam exists for:
// a read the shadow run never made is a HOLE in the snapshot and must
// refuse, while the reads that document absence-as-answer replay their
// recorded absence. Both halves over the same empty directory.
func TestSnapshotUncapturedReads(t *testing.T) {
	t.Parallel()

	snap := gh.Snapshot{Dir: t.TempDir()}

	for _, r := range everySnapshotRead() {
		switch r.name {
		case "Attestations", "PackageVersionDigest", "FailedRuns", "ChainNotes":
			continue // recorded absences, asserted below
		}

		t.Run(r.name, func(t *testing.T) {
			t.Parallel()

			if err := r.call(snap); err == nil {
				t.Fatalf("%s replayed a read the capture never made", r.name)
			}
		})
	}

	t.Run("recorded absences replay as answers", func(t *testing.T) {
		t.Parallel()

		if runs, err := snap.FailedRuns("acme", "widget", "v1.0.0"); err != nil || runs != nil {
			t.Errorf("FailedRuns = %v, %v — an uncaptured run list is the recorded empty", runs, err)
		}

		if _, err := snap.Asset("acme", "widget", "v1.0.0", "checksums.txt"); err == nil {
			t.Error("an uncaptured asset replayed as bytes — a missing artifact is not an empty one")
		}
	})
}

// TestSnapshotUnreadablePaths: a snapshot is operator-supplied, so a
// path that exists but cannot be read as what the layout says it is
// must refuse. Read as absence, each of these would be a hole the
// walk reports as clean.
func TestSnapshotUnreadablePaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// A file's place taken by a directory, and a directory's place
	// taken by a file — the two type confusions the filesystem allows.
	for _, p := range []string{
		filepath.Join("acme", "widget", "files", "v1.0.0", "ci.yml"),
		filepath.Join("acme", "gadget", "workflows", "sub"),
	} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0o750); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.MkdirAll(filepath.Join(dir, "acme", "widget"), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "acme", "widget", "workflows"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	snap := gh.Snapshot{Dir: dir}

	if _, ok, err := snap.FileAt("acme", "widget", "ci.yml", "v1.0.0"); err == nil {
		t.Errorf("FileAt = %v, %v — a directory is not a recorded file", ok, err)
	}

	if _, err := snap.Workflows("acme", "widget"); err == nil {
		t.Error("Workflows read a file as a directory")
	}

	if _, err := snap.Workflows("acme", "gadget"); err == nil {
		t.Error("Workflows read a directory as a workflow")
	}
}

// failingForge refuses every read: the live forge is down.
type failingForge struct{}

var errForgeDown = errors.New("the forge is down")

func (failingForge) ListRepos(string) ([]gh.Repo, error)            { return nil, errForgeDown }
func (failingForge) ReleaseTags(_, _ string) ([]string, error)      { return nil, errForgeDown }
func (failingForge) ReleaseAssets(_, _, _ string) ([]string, error) { return nil, errForgeDown }
func (failingForge) Asset(_, _, _, _ string) ([]byte, error)        { return nil, errForgeDown }
func (failingForge) ReleaseDate(_, _, _ string) (time.Time, error) {
	return time.Time{}, errForgeDown
}

//nolint:gocritic // unnamedResult: the Forge interface documents the results
func (failingForge) FileAt(_, _, _, _ string) ([]byte, bool, error) { return nil, false, errForgeDown }

func (failingForge) Attestations(_, _, _ string) ([]jsonx.Raw, error) { return nil, errForgeDown }
func (failingForge) PackageVersionDigest(_, _, _ string) (string, error) {
	return "", errForgeDown
}
func (failingForge) Workflows(_, _ string) ([]workflow.File, error) { return nil, errForgeDown }
func (failingForge) FailedRuns(_, _, _ string) ([]string, error)    { return nil, errForgeDown }

// TestCaptureRecordsNoFailures pins the documented stance: a snapshot
// holds FACTS, and a failed read is not a fact about the subject. So
// every read passes its error through AND leaves the directory empty
// — a recorded failure would replay as an answer on the next run.
func TestCaptureRecordsNoFailures(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rec := gh.Capture{Live: failingForge{}, Dir: dir}

	reads := []struct {
		name string
		call func() error
	}{
		{"ListRepos", func() error { _, err := rec.ListRepos("acme"); return err }},
		{"ReleaseTags", func() error { _, err := rec.ReleaseTags("acme", "widget"); return err }},
		{"ReleaseAssets", func() error { _, err := rec.ReleaseAssets("acme", "widget", "v1.0.0"); return err }},
		{"Asset", func() error { _, err := rec.Asset("acme", "widget", "v1.0.0", "checksums.txt"); return err }},
		{"FileAt", func() error { _, _, err := rec.FileAt("acme", "widget", "ci.yml", "v1.0.0"); return err }},
		{"Attestations", func() error { _, err := rec.Attestations("acme", "widget", "aa"); return err }},
		{"PackageVersionDigest", func() error {
			_, err := rec.PackageVersionDigest("acme", "widget", "latest")

			return err
		}},
		{"Workflows", func() error { _, err := rec.Workflows("acme", "widget"); return err }},
		{"FailedRuns", func() error { _, err := rec.FailedRuns("acme", "widget", "v1.0.0"); return err }},
	}

	for _, r := range reads {
		if err := r.call(); !errors.Is(err, errForgeDown) {
			t.Errorf("%s = %v, want the live error passed through", r.name, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 0 {
		t.Fatalf("the capture wrote %d entries for reads that failed", len(entries))
	}
}

// TestCaptureRecordsNoAbsence: a rolling tag pointing at nothing is
// an ANSWER, and replay reads a missing file as exactly that — so
// writing one would be recording the same fact twice, in a shape the
// replay side would then have to agree with.
func TestCaptureRecordsNoAbsence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rec := gh.Capture{Live: scriptedForge{noDigest: true}, Dir: dir}

	got, err := rec.PackageVersionDigest("acme", "widget", "latest")
	if err != nil || got != "" {
		t.Fatalf("PackageVersionDigest = %q, %v", got, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 0 {
		t.Fatalf("the capture recorded an absence as %d entries", len(entries))
	}
}

// TestCaptureRefusesUnrenderableBytes: the live read carried bundle
// bytes that are not JSON. Rendering them into the snapshot would
// write a file replay cannot read, so the capture refuses at the
// write instead of leaving a corrupt fixture behind.
func TestCaptureRefusesUnrenderableBytes(t *testing.T) {
	t.Parallel()

	rec := gh.Capture{Live: scriptedForge{}, Dir: t.TempDir()}

	if _, err := rec.Attestations("acme", "widget", "unrenderable"); err == nil {
		t.Fatal("the capture recorded bytes it cannot render")
	}
}

// TestCaptureFileInTheWayOfAFile pins the other write failure: the
// destination path exists, as a directory. MkdirAll is happy and the
// write is not, and a capture that swallowed that would serve
// live-only while claiming to have recorded.
func TestCaptureFileInTheWayOfAFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "acme", "repos.json"), 0o750); err != nil {
		t.Fatal(err)
	}

	rec := gh.Capture{Live: scriptedForge{}, Dir: dir}

	if _, err := rec.ListRepos("acme"); err == nil {
		t.Fatal("the capture wrote a file over a directory")
	}
}
