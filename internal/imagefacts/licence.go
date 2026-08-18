// The licence expression check.
//
// This replaces ~90 lines of Python embedded in a bash heredoc: a
// hand-written recursive-descent parser for the SPDX expression
// grammar, plus membership lookups against a vendored id list. The
// grammar and the id lists are somebody else's spec and somebody
// else's data, maintained on somebody else's cadence — the same
// relationship the org has to osv-scanner and to Masterminds/semver,
// and the same conclusion: adopt, do not reimplement.
//
// github.com/github/go-spdx covers the grammar, the id and exception
// lists, the legacy `/` syntax, NOASSERTION and the empty
// expression. Two rules it does not enforce are kept here, and both
// are facts about the spec or about OCI annotations rather than org
// conventions, which is why they are code and not policy:
//
//   - LicenseRef-/DocumentRef- are pointers INTO an SPDX document.
//     They resolve against that document's own extracted-licensing
//     info; in a bare OCI annotation there is no document, so the
//     reference dangles and the annotation says nothing.
//   - The canonical spelling. SPDX ids parse case-insensitively, so
//     `mit` is a valid expression — but the value ships as an
//     annotation consumers string-match, and `mit` matches nothing
//     looking for `MIT`. Normalising and comparing catches this for
//     ids, exception ids and operators at once, which is strictly
//     more than the Python managed: it checked ids by hand and let
//     `with` through with a hint.

package imagefacts

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
)

// refPrefixes are the reference forms that dangle in a bare
// annotation. A function, not a package variable: this is a closed
// fact about SPDX, and nothing should be able to reassign it.
func refPrefixes() []string { return []string{"LicenseRef-", "DocumentRef-"} }

// ErrNoLicence reports an absent declaration.
var ErrNoLicence = errors.New("imagefacts: no licence expression")

// checkLicence validates one declared expression and returns it in
// its canonical spelling. The returned value is what ships: a
// resolver that accepted `mit` and then published `mit` would have
// validated one string and annotated another.
func checkLicence(expr string) (string, error) {
	if strings.TrimSpace(expr) == "" {
		return "", ErrNoLicence
	}

	for _, prefix := range refPrefixes() {
		if strings.Contains(expr, prefix) {
			return "", fmt.Errorf("imagefacts: licence %q: %s is a pointer into an SPDX document and dangles"+
				" in a bare annotation; use listed identifiers", expr, strings.TrimSuffix(prefix, "-"))
		}
	}

	normalised, invalid := spdxexp.ValidateAndNormalizeLicensesWithOptions(
		[]string{expr}, spdxexp.ValidateLicensesOptions{})
	if len(invalid) > 0 || len(normalised) != 1 {
		return "", fmt.Errorf("imagefacts: licence %q is not a valid SPDX expression%s", expr, operatorHint(expr))
	}

	if normalised[0] != expr {
		return "", fmt.Errorf("imagefacts: licence %q is not the canonical spelling; write %q —"+
			" the value ships as an annotation consumers match on", expr, normalised[0])
	}

	return normalised[0], nil
}

// operatorHint recovers the one diagnosis the hand-written parser
// gave that a grammar failure alone does not. SPDX operators are
// case-SENSITIVE, so `MIT or Apache-2.0` is not a casing slip the
// normaliser can fix — it is a syntax error, and the library reports
// it as one. Without this, an operator typo and a genuinely
// malformed expression read identically, and the first is far more
// common.
func operatorHint(expr string) string {
	fixed := expr

	for _, op := range []string{"and", "or", "with"} {
		for _, spelling := range []string{" " + op + " ", " " + strings.ToUpper(op[:1]) + op[1:] + " "} {
			fixed = strings.ReplaceAll(fixed, spelling, " "+strings.ToUpper(op)+" ")
		}
	}

	if fixed == expr {
		return ""
	}

	if _, invalid := spdxexp.ValidateLicenses([]string{fixed}); len(invalid) > 0 {
		return ""
	}

	return " (operators are case-sensitive: AND, OR, WITH — try " + strconv.Quote(fixed) + ")"
}
