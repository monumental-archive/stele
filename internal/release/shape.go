// A class's subject shape, as its assert-policy entry declares it
// (stele#442). Which classes exist and how their assets are named are
// one organisation's packaging conventions, so they are policy; what
// this file owns is the set of shape KINDS (and a registry class's
// digest FORMS), because each names a judgment the engine computes —
// the baseImages mechanism rule (docs/assert-policy-schema.md). A kind
// takes exactly its own parameters, its templates name only the entry
// pattern's own groups, and every one of those facts is refused at
// load, never at release time.

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
	// registry: each planned leg leaves one file recording the digest
	// it pushed, in the class's declared form.
	ShapeRegistry ShapeKind = "registry"
)

// RegistryForm names one way a registry leg records what it pushed.
type RegistryForm string

const (
	// FormDocument is a JSON digest document per leg, naming its leg
	// in a declared field beside the image, the tag and the digest.
	FormDocument RegistryForm = "document"
	// FormBareDigest is a file per leg holding one bare
	// `sha256:<hex>` digest; the leg is the file's name.
	FormBareDigest RegistryForm = "bare-digest"
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
	Unit *string `json:"unit"`
	// Extension is the suffix every subject file carries; a file
	// with it that no leg claims is unplanned (files, and the
	// registry document form; optional for a bare digest).
	Extension *string `json:"extension,omitempty"`
	// Label is the leg-grouped manifest's prefix for a leg, a
	// template over Entry's groups (files).
	Label *string `json:"label,omitempty"`
	// Assets are what one leg produces, in the order its lines are
	// written (files).
	Assets []ShapeAsset `json:"assets,omitempty"`
	// Form is how each leg records its digest (registry).
	Form *RegistryForm `json:"form,omitempty"`
	// LegField is the field of each digest document that names its
	// leg (registry, document form).
	LegField *string `json:"legField,omitempty"`
}

// ShapeAsset is one asset a files leg must produce exactly once.
type ShapeAsset struct {
	// Noun names the asset in a refusal: "expected exactly one
	// <noun> for <of>".
	Noun *string `json:"noun"`
	// Of names the leg in that refusal, a template over the entry's
	// groups. Absent, the leg is named as the plan wrote it.
	Of *string `json:"of,omitempty"`
	// Suffix is the asset name's ending, a template over the entry's
	// groups; any non-empty, non-hidden stem before it is the
	// release's own naming.
	Suffix *string `json:"suffix"`
}

// The parameter names more than one kind or form reads.
const (
	paramEntry     = "entry"
	paramUnit      = "unit"
	paramExtension = "extension"
	paramForm      = "form"
)

// Fields a digest document always carries beside its leg field.
const (
	docImage  = "image"
	docTag    = "tag"
	docDigest = "digest"
)

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

	reader, err := s.reader(where)
	if err != nil {
		return nil, err
	}

	required, optional := owns(*s.Kind, s.form())
	declared := s.params()

	for _, name := range required {
		if !declared[name] {
			return nil, fmt.Errorf("%s.%s is absent or empty — the %s requires it", where, name, reader)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(declared)) {
		if declared[name] && !slices.Contains(required, name) && !slices.Contains(optional, name) {
			return nil, fmt.Errorf("%s.%s is declared but the %s does not read it", where, name, reader)
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

// reader names the judgment a shape selects, for its refusals, and
// refuses a kind or a form this engine does not implement — by name,
// before any parameter is read.
func (s *SubjectShape) reader(where string) (string, error) {
	switch *s.Kind {
	case ShapeFiles:
		return "files kind", nil
	case ShapeRegistry:
	default:
		return "", fmt.Errorf("%s.kind %q is not a subject shape this stele implements", where, *s.Kind)
	}

	switch f := s.form(); f {
	case "":
		return "", fmt.Errorf("%s.form is absent or empty — the registry kind requires it", where)
	case FormDocument, FormBareDigest:
		return "registry kind's " + string(f) + " form", nil
	default:
		return "", fmt.Errorf("%s.form %q is not a registry form this stele implements", where, f)
	}
}

func (s *SubjectShape) form() RegistryForm {
	if s.Form == nil {
		return ""
	}

	return *s.Form
}

// params is every parameter this engine reads off a shape, whichever
// kind owns it — one table, so "required by my kind" and "read by
// nobody here" are answered from the same list.
func (s *SubjectShape) params() map[string]bool {
	set := func(p *string) bool { return p != nil && *p != "" }

	return map[string]bool{
		paramEntry:     set(s.Entry),
		paramUnit:      set(s.Unit),
		paramExtension: set(s.Extension),
		"label":        set(s.Label),
		"assets":       len(s.Assets) > 0,
		paramForm:      s.form() != "",
		"legField":     set(s.LegField),
	}
}

// owns names the parameters one kind (and, for a registry, one form)
// requires and those it reads when declared, in the order refusals
// report them. A kind or form absent from this switch is one this
// engine does not implement — reader refuses it first.
//
//nolint:gocritic // unnamedResult: required, then optional
func owns(k ShapeKind, f RegistryForm) ([]string, []string) {
	switch {
	case k == ShapeFiles:
		return []string{paramEntry, paramUnit, paramExtension, "label", "assets"}, nil
	case f == FormDocument:
		return []string{paramEntry, paramUnit, paramForm, paramExtension, "legField"}, nil
	default: // the bare digest: the file's name is the leg
		return []string{paramEntry, paramUnit, paramForm}, []string{paramExtension}
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

// mismatch is the one refusal for a planned entry its class's
// pattern does not accept. It prints the declared pattern itself: a
// prose restatement would be a second copy that could disagree.
func mismatch(unit, e string, entry *regexp.Regexp) error {
	return fmt.Errorf("planned %s %q does not match %s", unit, e, entry)
}

func (s *SubjectShape) compileFiles(class, where string, entry *regexp.Regexp) (*Compiled, error) {
	ext := *s.Extension

	if err := placeholders(where+".label", *s.Label, entry); err != nil {
		return nil, err
	}

	for i, a := range s.Assets {
		at := fmt.Sprintf("%s.assets[%d]", where, i)

		for name, f := range map[string]*string{"noun": a.Noun, "suffix": a.Suffix} {
			if f == nil || *f == "" {
				return nil, fmt.Errorf("%s.%s is absent or empty", at, name)
			}
		}

		templates := map[string]*string{"suffix": a.Suffix}
		if a.Of != nil {
			templates["of"] = a.Of
		}

		for _, name := range slices.Sorted(maps.Keys(templates)) {
			if err := placeholders(at+"."+name, *templates[name], entry); err != nil {
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
	}

	assets := slices.Clone(s.Assets)
	label, unit := *s.Label, *s.Unit

	return &Compiled{Files: &AssetClass{
		Name: class, Unit: unit, Kind: *assets[0].Noun, Extension: ext,
		leg: func(e string) (Leg, error) {
			match := entry.FindStringSubmatchIndex(e)
			if match == nil {
				return Leg{}, mismatch(unit, e, entry)
			}

			expand := func(tmpl string) string { return string(entry.ExpandString(nil, tmpl, e, match)) }

			leg := Leg{Entry: e, Label: expand(label)}
			for _, a := range assets {
				of := e
				if a.Of != nil {
					of = expand(*a.Of)
				}

				leg.Assets = append(leg.Assets, Expected{Kind: *a.Noun, Of: of, Suffix: expand(*a.Suffix)})
			}

			return leg, nil
		},
	}}, nil
}

func (s *SubjectShape) compileRegistry(class, where string, entry *regexp.Regexp) (*Compiled, error) {
	c := &RegistryClass{Name: class, Unit: *s.Unit, Form: *s.Form, entry: entry}

	if s.Extension != nil {
		c.Extension = *s.Extension
	}

	if c.Form == FormDocument {
		c.LegField = *s.LegField
		if c.LegField == docImage || c.LegField == docTag || c.LegField == docDigest {
			return nil, fmt.Errorf("%s.legField %q is a field every digest document already carries for itself — "+
				"the leg needs a field of its own", where, c.LegField)
		}
	}

	return &Compiled{Registry: c}, nil
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
