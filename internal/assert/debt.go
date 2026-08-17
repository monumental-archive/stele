// The debt file: human-declared evidence exceptions, one per line as
// `subject(assertion)` — the attestation-debt pattern. Parsing is the
// ONLY way a declared exception enters the walk (the report package's
// asymmetric-constructor law), and a malformed line is an error: the
// file is committed under review, and a line that parses as nothing
// excuses nothing silently.

package assert

import (
	"fmt"
	"strings"

	"github.com/monumental-archive/stele/internal/report"
)

// ParseDebt reads the committed debt file into declared exceptions.
// path is carried into each exception's origin so the report points
// at the reviewed line.
func ParseDebt(content []byte, path string) ([]report.Exception, error) {
	var out []report.Exception

	for i, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		open := strings.IndexByte(trimmed, '(')
		if open <= 0 || !strings.HasSuffix(trimmed, ")") {
			return nil, fmt.Errorf("assert: %s:%d: %q is not subject(assertion)", path, i+1, trimmed)
		}

		subject := trimmed[:open]
		assertion := trimmed[open+1 : len(trimmed)-1]

		if assertion == "" {
			return nil, fmt.Errorf("assert: %s:%d: the assertion is empty — a blanket excuse needs its own review",
				path, i+1)
		}

		out = append(out, report.Declared(subject, assertion, fmt.Sprintf("%s:%d", path, i+1)))
	}

	return out, nil
}
