package derive_test

import (
	"testing"

	"github.com/Masterminds/semver/v3"

	"github.com/monumental-archive/stele/internal/convcommit"
	"github.com/monumental-archive/stele/internal/derive"
)

// The conventions these tests measure against. Kept here rather than in
// the package: they are one project's judgement, and the engine holds
// none of its own.
func testRules(t *testing.T, zeroMajorBumpsMinor bool) derive.Rules {
	t.Helper()

	// The org's cliff.toml, as measured: features raise the minor, and
	// no_increment_regex names the silent types. Everything else patches.
	rules, err := derive.NewRules(
		[]string{"feat"},
		[]string{"chore", "ci", "docs", "style", "test"},
		zeroMajorBumpsMinor,
	)
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}

	return rules
}

func mustVersion(t *testing.T, s string) *semver.Version {
	t.Helper()

	v, err := semver.StrictNewVersion(s)
	if err != nil {
		t.Fatalf("StrictNewVersion(%q): %v", s, err)
	}

	return v
}

func parseAll(t *testing.T, messages ...string) []convcommit.Commit {
	t.Helper()

	out := make([]convcommit.Commit, 0, len(messages))

	for _, m := range messages {
		c, err := convcommit.Parse(m)
		if err != nil {
			t.Fatalf("Parse(%q): %v", m, err)
		}

		out = append(out, c)
	}

	return out
}

// The prefix is git's, not SemVer's. These rows are the seam between the
// two spellings — the only place the conversion happens.
func TestParseTag(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prefix  string
		in      string
		want    string
		wantErr bool
	}{
		{name: "plain tag", prefix: "v", in: "v1.2.3", want: "1.2.3"},
		{name: "prerelease tag", prefix: "v", in: "v1.0.0-rc.1", want: "1.0.0-rc.1"},
		{name: "build metadata tag", prefix: "v", in: "v1.0.0+exp.sha.5114f8", want: "1.0.0+exp.sha.5114f8"},
		// A real monorepo namespace, from a repository carrying seven.
		{name: "component namespace", prefix: "edtf-core-v", in: "edtf-core-v1.0.0", want: "1.0.0"},
		{name: "no prefix at all", prefix: "v", in: "1.2.3", wantErr: true},
		{name: "uppercase V is a different ref", prefix: "v", in: "V1.2.3", wantErr: true},
		{name: "prefix alone", prefix: "v", in: "v", wantErr: true},
		{name: "partial version", prefix: "v", in: "v1.2", wantErr: true},
		{name: "leading zero", prefix: "v", in: "v01.2.3", wantErr: true},
		{name: "not a version at all", prefix: "v", in: "vlatest", wantErr: true},
		// Both real, from monument-legacy.
		{name: "pre-adoption debris in the namespace", prefix: "v", in: "v0.9-pre-import", wantErr: true},
		{name: "another component's tag", prefix: "v", in: "edtf-cli-v1.0.0", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := derive.ParseTag(tc.prefix, tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseTag(%q, %q) = %s, want an error", tc.prefix, tc.in, got)
				}

				return
			}

			if err != nil {
				t.Fatalf("ParseTag(%q, %q): %v", tc.prefix, tc.in, err)
			}

			if got.String() != tc.want {
				t.Errorf("ParseTag(%q, %q) = %q, want %q", tc.prefix, tc.in, got.String(), tc.want)
			}

			if derive.Tag(tc.prefix, got) != tc.in {
				t.Errorf("Tag round trip = %q, want %q", derive.Tag(tc.prefix, got), tc.in)
			}
		})
	}
}

// Selecting the base out of a real tag list. The rows are the shapes
// measured in the corpus, not invented ones.
func TestLatestTag(t *testing.T) {
	// One history, seven namespaces — the edtf shape, abbreviated.
	monorepo := []string{
		"v1.2.2", "v1.2.3",
		"edtf-core-v1.0.0", "edtf-core-v1.1.0",
		"edtf-cli-v0.9.0",
	}

	for _, tc := range []struct {
		name        string
		prefix      string
		tags        []string
		wantVersion string
		wantSkipped []string
	}{
		{
			name:   "workspace namespace ignores component tags",
			prefix: "v", tags: monorepo, wantVersion: "1.2.3",
		},
		{
			name:   "component namespace ignores the workspace and its siblings",
			prefix: "edtf-core-v", tags: monorepo, wantVersion: "1.1.0",
		},
		{
			name:   "a namespace nothing has released is empty, not zero",
			prefix: "edtf-wasm-v", tags: monorepo,
		},
		{
			name:   "no tags at all",
			prefix: "v",
		},
		// The trap a string sort walks into: "1.10.0" sorts below
		// "1.9.0" lexically, and the org has releases past .9.
		{
			name:   "ordering is by version, not by string",
			prefix: "v", tags: []string{"v1.9.0", "v1.10.0", "v1.8.0"}, wantVersion: "1.10.0",
		},
		{
			name:   "a release outranks its own candidate",
			prefix: "v", tags: []string{"v1.0.0-rc.1", "v1.0.0", "v1.0.0-rc.2"}, wantVersion: "1.0.0",
		},
		// monument-legacy, exactly as it is on disk.
		{
			name:   "pre-adoption debris is skipped and named",
			prefix: "v", tags: []string{"style-v1", "v0.9-pre-import"},
			wantSkipped: []string{"v0.9-pre-import"},
		},
		{
			name:   "debris does not hide a real release",
			prefix: "v", tags: []string{"v0.9-pre-import", "v1.0.0"},
			wantVersion: "1.0.0", wantSkipped: []string{"v0.9-pre-import"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := derive.LatestTag(tc.prefix, tc.tags)

			switch {
			case tc.wantVersion == "":
				if got.Version != nil {
					t.Errorf("Version = %s, want nil for an unreleased namespace", got.Version)
				}
			case got.Version == nil:
				t.Errorf("Version = nil, want %s", tc.wantVersion)
			case got.Version.String() != tc.wantVersion:
				t.Errorf("Version = %s, want %s", got.Version, tc.wantVersion)
			}

			if len(got.Skipped) != len(tc.wantSkipped) {
				t.Fatalf("Skipped = %v, want %v", got.Skipped, tc.wantSkipped)
			}

			for i, want := range tc.wantSkipped {
				if got.Skipped[i] != want {
					t.Errorf("Skipped[%d] = %q, want %q", i, got.Skipped[i], want)
				}
			}
		})
	}
}

func TestNewRulesRefuses(t *testing.T) {
	for _, tc := range []struct {
		name          string
		minor, silent []string
	}{
		{name: "empty type in minor", minor: []string{""}},
		{name: "empty type in silent", silent: []string{""}},
		{name: "type listed twice across lists", minor: []string{"feat"}, silent: []string{"feat"}},
		{name: "type listed twice in one list", minor: []string{"feat", "feat"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := derive.NewRules(tc.minor, tc.silent, false); err == nil {
				t.Fatal("NewRules accepted an ambiguous rule set")
			}
		})
	}
}

func TestDecideRefuses(t *testing.T) {
	t.Run("rules not built by NewRules", func(t *testing.T) {
		var zero derive.Rules

		if _, err := zero.Decide(mustVersion(t, "1.0.0"), nil); err == nil {
			t.Fatal("a zero Rules decided a version; an unbuilt rule set must not vote silently")
		}
	})

	t.Run("no base", func(t *testing.T) {
		if _, err := testRules(t, false).Decide(nil, nil); err == nil {
			t.Fatal("a nil base decided a version")
		}
	})

	// Also the one input where the library's IncPatch means "promote the
	// candidate" rather than "increment the patch": refusing it keeps
	// that ambiguity unreachable instead of resolved by accident.
	t.Run("prerelease base", func(t *testing.T) {
		base, err := semver.StrictNewVersion("1.2.0-rc.1")
		if err != nil {
			t.Fatalf("StrictNewVersion: %v", err)
		}

		if _, err := testRules(t, false).Decide(base, nil); err == nil {
			t.Fatal("a prerelease base decided a bump; promote-or-increment must be the caller's choice")
		}
	})
}

// The range decides by its LARGEST change, whatever order the commits
// arrive in. Ordering the enum is what makes that a max rather than a
// precedence table, so the ordering is what these rows measure.
func TestDecideTakesTheLargestChange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		base      string
		messages  []string
		requested derive.Bump
		applied   derive.Bump
		next      string
	}{
		{
			name: "nothing to release", base: "1.2.3",
			messages:  []string{"chore: tidy", "docs: fix a typo", "ci: bump an action"},
			requested: derive.BumpNone, applied: derive.BumpNone,
		},
		{
			name: "empty range", base: "1.2.3",
			requested: derive.BumpNone, applied: derive.BumpNone,
		},
		{
			name: "patch only", base: "1.2.3",
			messages:  []string{"fix: a thing", "chore: tidy"},
			requested: derive.BumpPatch, applied: derive.BumpPatch, next: "1.2.4",
		},
		{
			name: "a feature outvotes fixes regardless of order", base: "1.2.3",
			messages:  []string{"fix: a thing", "feat: a feature", "fix: another"},
			requested: derive.BumpMinor, applied: derive.BumpMinor, next: "1.3.0",
		},
		{
			name: "a feature first still outvotes later fixes", base: "1.2.3",
			messages:  []string{"feat: a feature", "fix: a thing"},
			requested: derive.BumpMinor, applied: derive.BumpMinor, next: "1.3.0",
		},
		{
			name: "a break outvotes everything", base: "1.2.3",
			messages:  []string{"feat: a feature", "fix!: a breaking fix", "fix: another"},
			requested: derive.BumpMajor, applied: derive.BumpMajor, next: "2.0.0",
		},
		// §13 puts the marker on any type: a chore that removed a flag
		// is a breaking change whatever noun it chose.
		{
			name: "a breaking chore is still a break", base: "1.2.3",
			messages:  []string{"chore!: drop a flag"},
			requested: derive.BumpMajor, applied: derive.BumpMajor, next: "2.0.0",
		},
		{
			name: "a breaking footer on a silent type outranks silence", base: "1.2.3",
			messages:  []string{"docs: rewrite the guide\n\nBREAKING CHANGE: the old flag is gone"},
			requested: derive.BumpMajor, applied: derive.BumpMajor, next: "2.0.0",
		},
		// The deny-list default: a type nobody classified still ships.
		// A revert that repairs a live bug must not vanish.
		{
			name: "an unclassified type patches", base: "1.2.3",
			messages:  []string{"refactor: move a file"},
			requested: derive.BumpPatch, applied: derive.BumpPatch, next: "1.2.4",
		},
		{
			name: "a revert patches", base: "1.2.3",
			messages:  []string{"revert: undo the broken change"},
			requested: derive.BumpPatch, applied: derive.BumpPatch, next: "1.2.4",
		},
		{
			name: "a type invented tomorrow patches", base: "1.2.3",
			messages:  []string{"deps: bump a pin"},
			requested: derive.BumpPatch, applied: derive.BumpPatch, next: "1.2.4",
		},
		{
			name: "silent types beside a real change do not lower it", base: "1.2.3",
			messages:  []string{"docs: a typo", "perf: speed it up", "chore: tidy"},
			requested: derive.BumpPatch, applied: derive.BumpPatch, next: "1.2.4",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := mustVersion(t, tc.base)

			got, err := testRules(t, false).Decide(base, parseAll(t, tc.messages...))
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}

			if got.Requested() != tc.requested {
				t.Errorf("Requested() = %s, want %s", got.Requested(), tc.requested)
			}

			if got.Applied() != tc.applied {
				t.Errorf("Applied() = %s, want %s", got.Applied(), tc.applied)
			}

			if got.Base().String() != tc.base {
				t.Errorf("Base() = %s, want %s", got.Base(), tc.base)
			}

			next, releases := got.Next()
			if releases != (tc.next != "") {
				t.Fatalf("Next() releases = %v, want %v", releases, tc.next != "")
			}

			if got.Releases() != releases {
				t.Errorf("Releases() = %v, disagrees with Next()'s ok", got.Releases())
			}

			if releases && next.String() != tc.next {
				t.Errorf("Next() = %s, want %s", next, tc.next)
			}
		})
	}
}

// The zero-major rule: below 1.0.0 the major is not yet a compatibility
// promise, so a break raises the minor rather than declaring 1.0.0 by
// accident. Requested still reports the break — a changelog that reads
// Applied as the requested bump tells its reader nothing broke.
func TestZeroMajorRule(t *testing.T) {
	for _, tc := range []struct {
		name      string
		on        bool
		base      string
		messages  []string
		requested derive.Bump
		applied   derive.Bump
		next      string
	}{
		{
			name: "on: a break below 1.0.0 raises the minor", on: true, base: "0.4.2",
			messages:  []string{"feat!: change the shape"},
			requested: derive.BumpMajor, applied: derive.BumpMinor, next: "0.5.0",
		},
		{
			name: "on: a feature below 1.0.0 is unaffected", on: true, base: "0.4.2",
			messages:  []string{"feat: add a thing"},
			requested: derive.BumpMinor, applied: derive.BumpMinor, next: "0.5.0",
		},
		{
			name: "on: a fix below 1.0.0 is unaffected", on: true, base: "0.4.2",
			messages:  []string{"fix: a thing"},
			requested: derive.BumpPatch, applied: derive.BumpPatch, next: "0.4.3",
		},
		{
			name: "on: at 1.0.0 and above the rule does not apply", on: true, base: "1.0.0",
			messages:  []string{"feat!: change the shape"},
			requested: derive.BumpMajor, applied: derive.BumpMajor, next: "2.0.0",
		},
		{
			name: "off: a break below 1.0.0 declares 1.0.0", on: false, base: "0.4.2",
			messages:  []string{"feat!: change the shape"},
			requested: derive.BumpMajor, applied: derive.BumpMajor, next: "1.0.0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := testRules(t, tc.on).Decide(mustVersion(t, tc.base), parseAll(t, tc.messages...))
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}

			if got.Requested() != tc.requested {
				t.Errorf("Requested() = %s, want %s", got.Requested(), tc.requested)
			}

			if got.Applied() != tc.applied {
				t.Errorf("Applied() = %s, want %s", got.Applied(), tc.applied)
			}

			next, releases := got.Next()
			if !releases {
				t.Fatal("Next() released nothing")
			}

			if next.String() != tc.next {
				t.Errorf("Next() = %s, want %s", next, tc.next)
			}
		})
	}
}

func TestBumpString(t *testing.T) {
	for _, tc := range []struct {
		bump derive.Bump
		want string
	}{
		{derive.BumpNone, "none"},
		{derive.BumpPatch, "patch"},
		{derive.BumpMinor, "minor"},
		{derive.BumpMajor, "major"},
		{derive.Bump(99), "Bump(99)"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.bump.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The ordering is the contract: max() over these values is what makes
// "the largest change decides" true, so a reordering of the constants
// must fail here rather than silently change every version decision.
func TestBumpOrderingIsTheContract(t *testing.T) {
	ascending := []derive.Bump{derive.BumpNone, derive.BumpPatch, derive.BumpMinor, derive.BumpMajor}
	for i := 1; i < len(ascending); i++ {
		if ascending[i-1] >= ascending[i] {
			t.Errorf("%s is not ordered below %s", ascending[i-1], ascending[i])
		}
	}
}
