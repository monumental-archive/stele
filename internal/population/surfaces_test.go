// Publish surfaces: the declaration's own refusals, and the default
// that stands where nothing is declared.
//
// Every branch here is a guard, and a guard that skips when it should
// run looks exactly like success — so each one is a row. The two that
// matter most are opposites: a surface set that is ABSENT resolves to
// the release surface (which is what every adopter cutting releases
// has, and what a stranger gets with no configuration), and a surface
// set that is DECLARED EMPTY resolves to nothing at all. Reading
// either as the other would silently change where a judgment looked.

package population_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/population"
)

// surfaceEntry builds one roster row with the given surfaces.
func surfaceEntry(repo string, surfaces *[]population.Surface) population.Entry {
	return population.Entry{Repo: new(repo), Surfaces: surfaces}
}

// continuousSurface is the shape an adopter publishing a stream
// declares — foreign names throughout, because nothing here may be
// this organisation's.
func continuousSurface() population.Surface {
	return population.Surface{
		Kind:     new(population.SurfaceContinuousDigest),
		Registry: new("registry.example.test/atelier/loom"),
		Tag:      new("rolling"),
		Identity: new(`^https://forge\.example\.test/atelier/keeper/\.forge/flows/seal\.yml@`),
	}
}

// TestSurfaceValidation is the load-time refusal table: a declaration
// that cannot mean what it says never reaches a gather.
func TestSurfaceValidation(t *testing.T) {
	t.Parallel()

	release := population.Surface{Kind: new(population.SurfaceRelease)}

	for _, tc := range []struct {
		name     string
		surfaces []population.Surface
		want     string
	}{
		{
			name:     "no kind at all",
			surfaces: []population.Surface{{}},
			want:     "kind is absent or empty",
		},
		{
			name:     "an empty kind",
			surfaces: []population.Surface{{Kind: new(population.SurfaceKind(""))}},
			want:     "kind is absent or empty",
		},
		{
			name:     "a kind this release cannot look at",
			surfaces: []population.Surface{{Kind: new(population.SurfaceKind("npm-dist-tag"))}},
			want:     "no publish surface this release can look at",
		},
		{
			name: "the release surface carrying a parameter it never reads",
			surfaces: []population.Surface{{
				Kind: new(population.SurfaceRelease), Registry: new("registry.example.test/atelier/loom"),
			}},
			want: "registry is declared, and the release surface never reads it",
		},
		{
			name: "a continuous surface with no registry",
			surfaces: []population.Surface{{
				Kind: new(population.SurfaceContinuousDigest),
				Tag:  new("rolling"), Identity: new("^https://"),
			}},
			want: "registry is absent or empty",
		},
		{
			name: "a continuous surface with no rolling tag",
			surfaces: []population.Surface{{
				Kind:     new(population.SurfaceContinuousDigest),
				Registry: new("registry.example.test/atelier/loom"), Identity: new("^https://"),
			}},
			want: "tag is absent or empty",
		},
		{
			name: "a continuous surface with no signer",
			surfaces: []population.Surface{{
				Kind:     new(population.SurfaceContinuousDigest),
				Registry: new("registry.example.test/atelier/loom"), Tag: new("rolling"),
			}},
			want: "identity is absent or empty",
		},
		{
			name: "a continuous surface with an empty registry",
			surfaces: []population.Surface{{
				Kind: new(population.SurfaceContinuousDigest), Registry: new(""),
				Tag: new("rolling"), Identity: new("^https://"),
			}},
			want: "registry is absent or empty",
		},
		{
			name: "a signer pattern that is not a pattern",
			surfaces: []population.Surface{{
				Kind:     new(population.SurfaceContinuousDigest),
				Registry: new("registry.example.test/atelier/loom"), Tag: new("rolling"),
				Identity: new("^https://forge(.example"),
			}},
			want: "identity:",
		},
		{
			name:     "the same surface twice",
			surfaces: []population.Surface{release, release},
			want:     "declares release a second time with the same parameters",
		},
		{
			name:     "the same continuous surface twice",
			surfaces: []population.Surface{continuousSurface(), continuousSurface()},
			want:     "a second time with the same parameters",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &population.Declaration{Repositories: []population.Entry{
				surfaceEntry("loom", &tc.surfaces),
			}}

			err := d.Validate()
			if err == nil {
				t.Fatalf("the declaration loaded, and it cannot mean what it says")
			}

			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

// TestSurfacesAccepted: the shapes that must LOAD, including the two
// an over-eager validator would reject — plurality of one kind, and a
// declared empty set.
func TestSurfacesAccepted(t *testing.T) {
	t.Parallel()

	second := continuousSurface()
	second.Registry = new("registry.example.test/atelier/spindle")

	for _, tc := range []struct {
		name     string
		surfaces []population.Surface
	}{
		{name: "a declared empty set", surfaces: []population.Surface{}},
		{name: "the release surface alone", surfaces: []population.Surface{{Kind: new(population.SurfaceRelease)}}},
		{
			name:     "both surfaces at once",
			surfaces: []population.Surface{{Kind: new(population.SurfaceRelease)}, continuousSurface()},
		},
		{
			// Plurality is the ADOPTER'S (stele#247): two streams at two
			// registries is a world, and a schema that could not say so
			// would be cardinality baked into code again.
			name:     "two continuous surfaces at two registries",
			surfaces: []population.Surface{continuousSurface(), second},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := &population.Declaration{Repositories: []population.Entry{
				surfaceEntry("loom", &tc.surfaces),
			}}

			if err := d.Validate(); err != nil {
				t.Fatalf("the declaration was refused: %v", err)
			}
		})
	}
}

// TestSurfacesResolved: absent and declared-empty are opposites, and
// the resolved set is what a gather actually reads.
func TestSurfacesResolved(t *testing.T) {
	t.Parallel()

	empty := []population.Surface{}
	declared := []population.Surface{continuousSurface()}

	d := &population.Declaration{Repositories: []population.Entry{
		surfaceEntry("loom", &declared),
		surfaceEntry("spindle", &empty),
		{Repo: new("anvil")},
	}}

	set, err := population.Scope{Org: "atelier"}.Resolve(listing{"loom", "spindle", "anvil"}, d)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	for _, tc := range []struct {
		name string
		repo string
		want int
	}{
		{name: "a declared continuous surface", repo: "loom", want: 1},
		{name: "a declared empty set is no surface at all", repo: "spindle", want: 0},
		{name: "no declaration takes the default expression", repo: "anvil", want: 1},
		{name: "a repository this set does not hold takes it too", repo: "stranger", want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := set.Surfaces(tc.repo); len(got) != tc.want {
				t.Fatalf("%s publishes on %d surface(s), want %d: %+v", tc.repo, len(got), tc.want, got)
			}
		})
	}

	// The default is the release surface, not merely one of something.
	if got := set.Surfaces("anvil"); *got[0].Kind != population.SurfaceRelease {
		t.Errorf("the default surface is %q, want the release surface", *got[0].Kind)
	}

	if got := set.Surfaces("loom"); *got[0].Kind != population.SurfaceContinuousDigest {
		t.Errorf("loom publishes on %q, want the surface it declared", *got[0].Kind)
	}
}

// TestDefaultSurfaces: the default expression stands alone, so a
// caller holding no set at all still knows where to look.
func TestDefaultSurfaces(t *testing.T) {
	t.Parallel()

	got := population.DefaultSurfaces()
	if len(got) != 1 || *got[0].Kind != population.SurfaceRelease {
		t.Fatalf("DefaultSurfaces() = %+v, want the release surface alone", got)
	}
}

// TestSurfaceName: a surface has to name a place a reader can go and
// look at, including when it is too broken to name one.
func TestSurfaceName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		surface population.Surface
		want    string
	}{
		{
			name:    "the release surface",
			surface: population.Surface{Kind: new(population.SurfaceRelease)},
			want:    "release",
		},
		{
			name:    "a continuous surface names its registry and tag",
			surface: continuousSurface(),
			want:    "continuous-digest registry.example.test/atelier/loom:rolling",
		},
		{
			name:    "a continuous surface missing its parameters names its kind",
			surface: population.Surface{Kind: new(population.SurfaceContinuousDigest)},
			want:    "continuous-digest",
		},
		{
			name:    "a surface with no kind at all",
			surface: population.Surface{},
			want:    "an unnamed surface",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.surface.Name(); got != tc.want {
				t.Errorf("Name() = %q, want %q", got, tc.want)
			}
		})
	}
}

// listing is a forge that shows exactly these repositories.
type listing []string

func (l listing) ListRepos(string) ([]gh.Repo, error) {
	out := make([]gh.Repo, 0, len(l))
	for _, name := range l {
		out = append(out, gh.Repo{Name: name})
	}

	return out, nil
}
