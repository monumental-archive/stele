// The debt file: human-declared exceptions, one per line as
// `subject(assertion)` — the attestation-debt pattern. It lives HERE,
// not in one walk (#147): excusability is a property of judgment, so
// the file every judgment reads is parsed by the layer every finding
// passes through, and a walk cannot be written that forgets it.
//
// Parsing is the ONLY way a declared exception enters a run (the
// asymmetric-constructor law), and a malformed line is an error: the
// file is committed under review, and a line that parses as nothing
// excuses nothing silently. Both wildcards the engine can spell — a
// blank subject, a blank assertion — are refused here: a blanket
// excuse needs its own review, and a file cannot vote itself wider
// than the line a human read.

package report

import (
	"fmt"
	"strings"
)

// ParseDebt reads the committed debt file into declared exceptions.
// path is carried into each exception's origin so the report points
// at the reviewed line.
func ParseDebt(content []byte, path string) ([]Exception, error) {
	var out []Exception

	for i, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		open := strings.IndexByte(trimmed, '(')
		if open <= 0 || !strings.HasSuffix(trimmed, ")") {
			return nil, fmt.Errorf("report: %s:%d: %q is not subject(assertion)", path, i+1, trimmed)
		}

		subject := trimmed[:open]
		assertion := trimmed[open+1 : len(trimmed)-1]

		if assertion == "" {
			return nil, fmt.Errorf("report: %s:%d: the assertion is empty — a blanket excuse needs its own review",
				path, i+1)
		}

		out = append(out, Declared(subject, assertion, fmt.Sprintf("%s:%d", path, i+1)))
	}

	return out, nil
}
