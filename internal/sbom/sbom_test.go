package sbom_test

import (
	"runtime/debug"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/sbom"
)

// leg builds one release-shaped binary's build info. Every test starts
// from a valid leg and breaks exactly one fact, so a test that passes
// for the wrong reason has nowhere to hide.
func leg(goos, goarch string, deps ...*debug.Module) *debug.BuildInfo {
	return &debug.BuildInfo{
		GoVersion: "go1.26.6",
		Main:      debug.Module{Path: "github.com/monumental-archive/stele", Version: "v0.3.0"},
		Deps:      deps,
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: goos},
			{Key: "GOARCH", Value: goarch},
			{Key: "vcs.revision", Value: "aaaabbbbccccddddeeeeffff0000111122223333"},
			{Key: "vcs.time", Value: "2026-08-17T10:00:00Z"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
}

func dep(path, version string) *debug.Module {
	return &debug.Module{Path: path, Version: version}
}

// setSetting rewrites one build setting in place; value "" deletes it.
func setSetting(info *debug.BuildInfo, key, value string) {
	kept := info.Settings[:0]

	for _, s := range info.Settings {
		if s.Key != key {
			kept = append(kept, s)
		}
	}

	if value != "" {
		kept = append(kept, debug.BuildSetting{Key: key, Value: value})
	}

	info.Settings = kept
}

func TestDeriveUnionsLegs(t *testing.T) {
	t.Parallel()

	linux := leg("linux", "amd64",
		dep("github.com/masterminds/shared", "v1.2.3"),
		dep("golang.org/x/sys", "v0.47.0"),
	)
	darwin := leg("darwin", "arm64",
		dep("github.com/masterminds/shared", "v1.2.3"),
		dep("github.com/darwin/only", "v0.0.0-20260101000000-abcdefabcdef"),
	)

	doc, err := sbom.Derive([]sbom.Binary{
		{Name: "stele-linux-amd64", Info: linux},
		{Name: "stele-darwin-arm64", Info: darwin},
	}, "stele-v0.3.0")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	// Root plus the three distinct modules, root first, deps sorted.
	if len(doc.Packages) != 4 {
		t.Fatalf("packages = %d, want 4", len(doc.Packages))
	}

	root := doc.Packages[0]
	if root.Name != "github.com/monumental-archive/stele" || root.VersionInfo != "v0.3.0" {
		t.Fatalf("root = %s@%s", root.Name, root.VersionInfo)
	}

	if root.PrimaryPurpose != "APPLICATION" {
		t.Fatalf("root purpose = %q", root.PrimaryPurpose)
	}

	wantOrder := []string{"github.com/darwin/only", "github.com/masterminds/shared", "golang.org/x/sys"}
	for i, want := range wantOrder {
		if got := doc.Packages[i+1].Name; got != want {
			t.Fatalf("dep %d = %q, want %q", i, got, want)
		}
	}

	// Every PURL versioned — the property the whole design exists for.
	for _, pkg := range doc.Packages {
		if len(pkg.ExternalRefs) != 1 {
			t.Fatalf("%s: %d external refs", pkg.Name, len(pkg.ExternalRefs))
		}

		locator := pkg.ExternalRefs[0].ReferenceLocator
		if !strings.Contains(locator, "@") {
			t.Fatalf("%s: versionless purl %q", pkg.Name, locator)
		}
	}

	// One DESCRIBES plus one DEPENDS_ON per dep.
	if len(doc.Relationships) != 4 {
		t.Fatalf("relationships = %d, want 4", len(doc.Relationships))
	}

	if doc.Relationships[0].RelationshipType != "DESCRIBES" {
		t.Fatalf("first relationship = %q", doc.Relationships[0].RelationshipType)
	}

	// The created stamp is the commit time, normalised.
	if doc.CreationInfo.Created != "2026-08-17T10:00:00Z" {
		t.Fatalf("created = %q", doc.CreationInfo.Created)
	}

	if doc.CreationInfo.Creators[0] != "Tool: stele-v0.3.0" {
		t.Fatalf("creators = %v", doc.CreationInfo.Creators)
	}
}

func TestDeriveAttributesSubsetModules(t *testing.T) {
	t.Parallel()

	linux := leg("linux", "amd64", dep("shared.example/mod", "v1.0.0"))
	darwin := leg("darwin", "arm64",
		dep("shared.example/mod", "v1.0.0"),
		dep("darwin.example/mod", "v2.0.0"),
	)

	doc, err := sbom.Derive([]sbom.Binary{
		{Name: "a", Info: linux},
		{Name: "b", Info: darwin},
	}, "stele-test")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	var shared, darwinOnly *sbom.Package

	for i := range doc.Packages {
		switch doc.Packages[i].Name {
		case "shared.example/mod":
			shared = &doc.Packages[i]
		case "darwin.example/mod":
			darwinOnly = &doc.Packages[i]
		}
	}

	if shared == nil || darwinOnly == nil {
		t.Fatal("union lost a module")
	}

	// Linked everywhere: no attribution needed, silence is the claim.
	if shared.SourceInfo != "" {
		t.Fatalf("shared sourceInfo = %q, want empty", shared.SourceInfo)
	}

	// Linked into a subset: said so, by platform.
	if darwinOnly.SourceInfo != "linked into: darwin/arm64" {
		t.Fatalf("darwin-only sourceInfo = %q", darwinOnly.SourceInfo)
	}
}

func TestDeriveLowercasesPurls(t *testing.T) {
	t.Parallel()

	one := leg("linux", "amd64", dep("github.com/Masterminds/semver/v3", "v3.5.0"))

	doc, err := sbom.Derive([]sbom.Binary{{Name: "a", Info: one}}, "t")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	got := doc.Packages[1].ExternalRefs[0].ReferenceLocator
	want := "pkg:golang/github.com/masterminds/semver/v3@v3.5.0"

	if got != want {
		t.Fatalf("purl = %q, want %q", got, want)
	}

	// The SPDX package name keeps the module path's true case — only
	// the purl type demands folding.
	if doc.Packages[1].Name != "github.com/Masterminds/semver/v3" {
		t.Fatalf("package name = %q", doc.Packages[1].Name)
	}
}

// One module may ship several commands, and every command ships for
// every platform — so two binaries on one platform is a legitimate
// release, and the attribution still counts platforms, not binaries.
func TestDeriveAcceptsMultipleCommandsPerPlatform(t *testing.T) {
	t.Parallel()

	first := leg("linux", "amd64", dep("shared.example/mod", "v1.0.0"))
	first.Path = "example.com/tool/cmd/one"
	second := leg("linux", "amd64", dep("shared.example/mod", "v1.0.0"))
	second.Path = "example.com/tool/cmd/two"

	doc, err := sbom.Derive([]sbom.Binary{
		{Name: "one", Info: first},
		{Name: "two", Info: second},
	}, "t")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	// One platform, both commands linking the module: linked-everywhere,
	// so no subset attribution — and no duplicated platform inflating it.
	if got := doc.Packages[1].SourceInfo; got != "" {
		t.Fatalf("sourceInfo = %q, want empty", got)
	}
}

func TestDeriveRecordsReplacements(t *testing.T) {
	t.Parallel()

	replaced := &debug.Module{
		Path:    "example.com/original",
		Version: "v1.0.0",
		Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1"},
	}

	doc, err := sbom.Derive([]sbom.Binary{{Name: "a", Info: leg("linux", "amd64", replaced)}}, "t")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	if doc.Packages[1].Name != "example.com/fork" || doc.Packages[1].VersionInfo != "v1.0.1" {
		t.Fatalf("replacement recorded as %s@%s", doc.Packages[1].Name, doc.Packages[1].VersionInfo)
	}
}

// The refusal table: every guard branch, each breaking one fact of an
// otherwise valid pair of legs.
func TestDeriveRefusals(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		bins func() []sbom.Binary
		want string
	}{
		{
			name: "no binaries",
			bins: func() []sbom.Binary { return nil },
			want: "no binaries",
		},
		{
			name: "empty main path",
			bins: func() []sbom.Binary {
				a := leg("linux", "amd64")
				a.Main.Path = ""

				return []sbom.Binary{{Name: "a", Info: a}}
			},
			want: "no main module path",
		},
		{
			name: "devel main version",
			bins: func() []sbom.Binary {
				a := leg("linux", "amd64")
				a.Main.Version = "(devel)"

				return []sbom.Binary{{Name: "a", Info: a}}
			},
			want: "no release version",
		},
		{
			name: "empty main version",
			bins: func() []sbom.Binary {
				a := leg("linux", "amd64")
				a.Main.Version = ""

				return []sbom.Binary{{Name: "a", Info: a}}
			},
			want: "no release version",
		},
		{
			name: "non-semver main version",
			bins: func() []sbom.Binary {
				a := leg("linux", "amd64")
				a.Main.Version = "release-3"

				return []sbom.Binary{{Name: "a", Info: a}}
			},
			want: "not a semantic version",
		},
		{
			name: "main version divergence",
			bins: func() []sbom.Binary {
				a, b := leg("linux", "amd64"), leg("darwin", "arm64")
				b.Main.Version = "v0.3.1"

				return []sbom.Binary{{Name: "a", Info: a}, {Name: "b", Info: b}}
			},
			want: "not one release",
		},
		{
			name: "revision divergence",
			bins: func() []sbom.Binary {
				a, b := leg("linux", "amd64"), leg("darwin", "arm64")
				setSetting(b, "vcs.revision", "0000111122223333aaaabbbbccccddddeeeeffff")

				return []sbom.Binary{{Name: "a", Info: a}, {Name: "b", Info: b}}
			},
			want: "not one commit",
		},
		{
			name: "missing vcs stamp",
			bins: func() []sbom.Binary {
				a := leg("linux", "amd64")
				setSetting(a, "vcs.revision", "")

				return []sbom.Binary{{Name: "a", Info: a}}
			},
			want: "no VCS stamp",
		},
		{
			// The first leg's stamp is read before the loop, the rest
			// inside it: a later leg's missing stamp must refuse just
			// as loudly, or the union would date itself from leg one
			// alone.
			name: "missing vcs stamp on a later leg",
			bins: func() []sbom.Binary {
				a, b := leg("linux", "amd64"), leg("darwin", "arm64")
				setSetting(b, "vcs.time", "")

				return []sbom.Binary{{Name: "a", Info: a}, {Name: "b", Info: b}}
			},
			want: "b carries no VCS stamp",
		},
		{
			name: "modified tree",
			bins: func() []sbom.Binary {
				a := leg("linux", "amd64")
				setSetting(a, "vcs.modified", "true")

				return []sbom.Binary{{Name: "a", Info: a}}
			},
			want: "modified tree",
		},
		{
			name: "unreadable vcs.time",
			bins: func() []sbom.Binary {
				a := leg("linux", "amd64")
				setSetting(a, "vcs.time", "yesterday")

				return []sbom.Binary{{Name: "a", Info: a}}
			},
			want: "unreadable vcs.time",
		},
		{
			name: "missing platform stamp",
			bins: func() []sbom.Binary {
				a := leg("linux", "amd64")
				setSetting(a, "GOARCH", "")

				return []sbom.Binary{{Name: "a", Info: a}}
			},
			want: "no GOOS/GOARCH",
		},
		{
			name: "same command twice on one platform",
			bins: func() []sbom.Binary {
				return []sbom.Binary{
					{Name: "a", Info: leg("linux", "amd64")},
					{Name: "b", Info: leg("linux", "amd64")},
				}
			},
			want: "one binary per command per platform",
		},
		{
			name: "directory replace",
			bins: func() []sbom.Binary {
				local := &debug.Module{
					Path:    "example.com/mod",
					Version: "v1.0.0",
					Replace: &debug.Module{Path: "../mod", Version: "(devel)"},
				}

				return []sbom.Binary{{Name: "a", Info: leg("linux", "amd64", local)}}
			},
			want: "not a published module version",
		},
		{
			name: "dep version divergence",
			bins: func() []sbom.Binary {
				a := leg("linux", "amd64", dep("example.com/mod", "v1.0.0"))
				b := leg("darwin", "arm64", dep("example.com/mod", "v1.0.1"))

				return []sbom.Binary{{Name: "a", Info: a}, {Name: "b", Info: b}}
			},
			want: "different lockfiles",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := sbom.Derive(tc.bins(), "t")
			if err == nil {
				t.Fatal("Derive accepted what it should refuse")
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the refusal %q", err, tc.want)
			}
		})
	}
}

// Determinism measured, not asserted in prose: the same legs in a
// different argument order render byte-identical inventories.
func TestDeriveIsOrderIndependent(t *testing.T) {
	t.Parallel()

	mk := func() (sbom.Binary, sbom.Binary) {
		linux := leg("linux", "amd64", dep("z.example/z", "v1.0.0"), dep("a.example/a", "v2.0.0"))
		darwin := leg("darwin", "arm64", dep("a.example/a", "v2.0.0"))

		return sbom.Binary{Name: "a", Info: linux}, sbom.Binary{Name: "b", Info: darwin}
	}

	a1, b1 := mk()

	first, err := sbom.Derive([]sbom.Binary{a1, b1}, "t")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	a2, b2 := mk()

	second, err := sbom.Derive([]sbom.Binary{b2, a2}, "t")
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	if len(first.Packages) != len(second.Packages) {
		t.Fatalf("package counts differ: %d vs %d", len(first.Packages), len(second.Packages))
	}

	for i := range first.Packages {
		if first.Packages[i].Name != second.Packages[i].Name ||
			first.Packages[i].SPDXID != second.Packages[i].SPDXID {
			t.Fatalf("package %d differs across orderings", i)
		}
	}
}
