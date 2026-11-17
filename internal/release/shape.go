// A class's subject shape, as its assert-policy entry declares it
// (stele#442). Which classes exist and how their assets are named are
// one organisation's packaging conventions, so they are policy; what
// this file owns is the set of shape KINDS, because each kind names a
// judgment the engine computes — the baseImages mechanism rule
// (docs/assert-policy-schema.md). A kind takes exactly its own
// parameters, its templates name only the entry pattern's own groups,
// and every one of those facts is refused at load, never at release
// time.

package release

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// ShapeKind names one subject judgment this engine implements.
type ShapeKind string

const (
	// ShapeFiles is a class whose subjects are files a planned leg
	// leaves in a directory: each leg's assets, matched by suffix,
	// every one present exactly once and none unplanned.
	ShapeFiles ShapeKind = "files"
	// ShapeRegistry is a class whose subjects were pushed to a
	// registry: each planned leg leaves one digest document naming
	// its leg, the image and the digest pushed.
	ShapeRegistry ShapeKind = "registry"
)

// SubjectShape is a class's declared subject shape: the kind, then
// that kind's parameters, flat — a shape IS one kind's declaration,
// and a parameter the kind does not read is a load refusal rather
// than a silent no-op.
type SubjectShape struct {
	// Kind selects the judgment.
	Kind *ShapeKind `json:"kind"`
	// Entry is the anchored pattern a planned leg must match; its
	// named groups are the only placeholders a template may use
	// (both kinds).
	Entry *string `json:"entry"`
	// Unit is what one planned entry is called in a refusal: "the
	// plan names no <unit>s" (both kinds).
	Unit *string `json:"unit,omitempty"`
	// Shape says, in a refusal, what an entry failing Entry is not:
	// `planned <unit> "x" is not <shape>` (both kinds).
	Shape *string `json:"shape,omitempty"`
	// Extension is the suffix every subject file carries; a file
	// with it that no leg claims is unplanned (both kinds).
	Extension *string `json:"extension"`
	// Label is the leg-grouped manifest's prefix for a leg, a
	// template over Entry's groups (files).
	Label *string `json:"label,omitempty"`
	// Assets are what one leg produces, in the order its lines are
	// written (files).
	Assets []ShapeAsset `json:"assets,omitempty"`
	// LegField is the field of each digest document that names its
	// leg (registry).
	LegField *string `json:"legField,omitempty"`
}

// ShapeAsset is one asset a files leg must produce exactly once.
type ShapeAsset struct {
	// Noun names the asset in a refusal: "expected exactly one
	// <noun> for <of>".
	Noun *string `json:"noun"`
	// Of names the leg in that refusal, a template over the entry's
	// groups.
	Of *string `json:"of"`
	// Suffix is the asset name's ending, a template over the entry's
	// groups; any non-empty, non-hidden stem before it is the
	// release's own naming.
	Suffix *string `json:"suffix"`
}

// The parameter names shared by both kinds.
const (
	paramEntry     = "entry"
	paramUnit      = "unit"
	paramShape     = "shape"
	paramExtension = "extension"
)

// Fields a digest document always carries beside its leg field.
const (
	docImage  = "image"
	docTag    = "tag"
	docDigest = "digest"
)

// owns names the parameters one kind reads, in the order its
// refusals report them. A kind absent from this switch is a kind this
// engine does not implement — the one place that fact is written.
func owns(k ShapeKind) []string {
	switch k {
	case ShapeFiles:
		return []string{paramEntry, paramUnit, paramShape, paramExtension, "label", "assets"}
	case ShapeRegistry:
		return []string{paramEntry, paramUnit, paramShape, paramExtension, "legField"}
	default:
		return nil
	}
}

// Compiled is a class's shape made executable: exactly one of the two
// is set, by kind.
type Compiled struct {
	Files    *AssetClass
	Registry *RegistryClass
}

// Compile validates the shape declared for class and returns its
// executable form. Every refusal is prefixed with where the shape
// sits in the assert policy.
func (s *SubjectShape) Compile(class string) (*Compiled, error) {
	where := "evidence.classes." + class + ".subjects"

	if s.Kind == nil || *s.Kind == "" {
		return nil, fmt.Errorf("%s.kind is absent or empty", where)
	}

	owned := owns(*s.Kind)
	if owned == nil {
		return nil, fmt.Errorf("%s.kind %q is not a subject shape this stele implements", where, *s.Kind)
	}

	declared := s.params()

	for _, name := range owned {
		if !declared[name] {
			return nil, fmt.Errorf("%s.%s is absent or empty — the %s kind requires it", where, name, *s.Kind)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(declared)) {
		if declared[name] && !slices.Contains(owned, name) {
			return nil, fmt.Errorf("%s.%s is declared but the %s kind does not read it", where, name, *s.Kind)
		}
	}

	entry, err := anchored(where, *s.Entry)
	if err != nil {
		return nil, err
	}

	if *s.Kind == ShapeRegistry {
		return s.compileRegistry(class, where, entry)
	}

	return s.compileFiles(class, where, entry)
}

// params is every parameter this engine reads off a shape, whichever
// kind owns it — one table, so "required by my kind" and "read by
// nobody here" are answered from the same list.
func (s *SubjectShape) params() map[string]bool {
	set := func(p *string) bool { return p != nil && *p != "" }

	return map[string]bool{
		paramEntry:     set(s.Entry),
		paramUnit:      set(s.Unit),
		paramShape:     set(s.Shape),
		paramExtension: set(s.Extension),
		"label":        set(s.Label),
		"assets":       len(s.Assets) > 0,
		"legField":     set(s.LegField),
	}
}

// anchored compiles the entry pattern, refusing one that does not
// anchor both ends: an unanchored pattern accepts any entry merely
// containing a match, and the templates would then splice a fragment
// of what the plan said into a name the plan never meant.
func anchored(where, pattern string) (*regexp.Regexp, error) {
	if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") || strings.HasSuffix(pattern, `\$`) {
		return nil, fmt.Errorf("%s.entry %q is not anchored — it must begin with ^ and end with $, "+
			"or a planned entry merely containing a match would pass", where, pattern)
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("%s.entry: %w", where, err)
	}

	return re, nil
}

func (s *SubjectShape) compileFiles(class, where string, entry *regexp.Regexp) (*Compiled, error) {
	ext := *s.Extension

	if err := placeholders(where+".label", *s.Label, entry); err != nil {
		return nil, err
	}

	assets := make([]ShapeAsset, len(s.Assets))

	for i, a := range s.Assets {
		at := fmt.Sprintf("%s.assets[%d]", where, i)

		for name, f := range map[string]*string{"noun": a.Noun, "of": a.Of, "suffix": a.Suffix} {
			if f == nil || *f == "" {
				return nil, fmt.Errorf("%s.%s is absent or empty", at, name)
			}
		}

		for name, f := range map[string]*string{"of": a.Of, "suffix": a.Suffix} {
			if err := placeholders(at+"."+name, *f, entry); err != nil {
				return nil, err
			}
		}

		// Assets are listed by the extension, so a suffix ending in
		// anything else names a file the listing can never see — a
		// leg that is missing on every run.
		if !strings.HasSuffix(*a.Suffix, ext) {
			return nil, fmt.Errorf("%s.suffix %q does not end in the extension %q — no listed file could match it",
				at, *a.Suffix, ext)
		}

		assets[i] = a
	}

	label := *s.Label
	unit, shape := *s.Unit, *s.Shape

	return &Compiled{Files: &AssetClass{
		Name: class, Unit: unit, Kind: *assets[0].Noun, Extension: ext,
		leg: func(e string) (Leg, error) {
			match := entry.FindStringSubmatchIndex(e)
			if match == nil {
				return Leg{}, fmt.Errorf("planned %s %q is not %s", unit, e, shape)
			}

			expand := func(tmpl string) string { return string(entry.ExpandString(nil, tmpl, e, match)) }

			leg := Leg{Entry: e, Label: expand(label)}
			for _, a := range assets {
				leg.Assets = append(leg.Assets, Expected{Kind: *a.Noun, Of: expand(*a.Of), Suffix: expand(*a.Suffix)})
			}

			return leg, nil
		},
	}}, nil
}

func (s *SubjectShape) compileRegistry(class, where string, entry *regexp.Regexp) (*Compiled, error) {
	field := *s.LegField
	if field == docImage || field == docTag || field == docDigest {
		return nil, fmt.Errorf("%s.legField %q is a field every digest document already carries for itself — "+
			"the leg needs a field of its own", where, field)
	}

	return &Compiled{Registry: &RegistryClass{
		Name: class, Unit: *s.Unit, Shape: *s.Shape, Extension: *s.Extension, LegField: field,
		entry: entry,
	}}, nil
}

// placeholderRE finds a template's placeholders in regexp.Expand's
// own vocabulary: $name, ${name}, and $$ for a literal dollar.
var placeholderRE = regexp.MustCompile(`\$(\$|\{([^}]*)\}|([A-Za-z0-9_]*))`)

// placeholders refuses a template naming anything but one of the
// entry pattern's named groups. The vocabulary is closed: Expand
// renders an undefined name, a numbered position or a malformed
// placeholder as nothing, and a suffix that silently lost a segment
// matches assets the plan never named.
func placeholders(where, template string, entry *regexp.Regexp) error {
	for _, m := range placeholderRE.FindAllStringSubmatch(template, -1) {
		const (
			whole = 1
			brace = 2
			bare  = 3
		)

		if m[whole] == "$" {
			continue
		}

		name := m[brace] + m[bare]

		switch {
		case name == "":
			return fmt.Errorf("%s %q carries a $ that names no group — write $$ for a literal dollar", where, template)
		case strings.Trim(name, "0123456789") == "":
			return fmt.Errorf("%s %q names group %s by position — name it", where, template, name)
		case entry.SubexpIndex(name) < 0:
			return fmt.Errorf("%s %q names the group %q, which entry does not define", where, template, name)
		}
	}

	return nil
}
