// This file: the release decision (stele#399) — the record a commit
// point signs when every required proof succeeded, and the subjects
// it covers. It replaces the canon's shell assembly of the same
// record in its release and stream workflows: the proofs judged by
// name, the predicate built from them, the covered documents hashed
// into sha256sum lines. The type and conclusion are policy
// (trust.decision); the record is read back through the verifier's
// own decision reader before a byte is written, so a decision the
// release verdict would refuse cannot be emitted.

package emit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/intoto"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/policy"
	"github.com/monumental-archive/stele/internal/verify"
)

// proofSucceeded is the one result a required proof may carry: the
// job conclusion the orchestration reports for a proof that ran and
// passed. Every other value — failure, cancelled, skipped, empty —
// is a proof that did not happen.
const proofSucceeded = "success"

// alsoLineRE is one extra subject line: a sha256 digest, two spaces,
// and the name the reader is shown.
var alsoLineRE = regexp.MustCompile(`^[0-9a-f]{64} {2}\S.*$`)

// Proof is one required proof and the result its job reported.
type Proof struct {
	Name, Result string
}

// DecisionInputs is everything one release decision covers.
type DecisionInputs struct {
	// Tag is the release the decision opens; empty exactly when
	// Stream is set — a stream publishes with no version, and its
	// decision names none.
	Tag    string
	Stream bool
	// Classes is the evidence classes being published, recorded as
	// the caller states them.
	Classes string
	// Proofs is every required proof, in the order the record lists
	// them.
	Proofs []Proof
	// Covered is the directory of documents the decision covers.
	Covered string
	// Inventory, when set, is the one planned inventory this decision
	// is for: it covers that document and names nothing else.
	Inventory string
	// Also is further subject lines, `<sha256>  <name>`, covered
	// beside the documents — what a stranger starts from when the
	// documents themselves are not where they look (a stream's
	// per-architecture images).
	Also []string
}

// Decision is one emitted release decision: the predicate the signer
// signs, the subject lines it signs it over, and the predicate type
// the policy names for it.
type Decision struct {
	PredicateType string
	Predicate     []byte
	Subjects      []byte
}

// decisionDoc is the record's field set and order, the one
// docs/policy-schema.md's trust.decision describes and the verifier
// decodes: the tag (releases only), the classes, the conclusion, when
// it was decided, and every proof by name.
type decisionDoc struct {
	Tag        *string    `json:"tag,omitempty"`
	Classes    string     `json:"classes"`
	Conclusion string     `json:"conclusion"`
	DecidedAt  string     `json:"decidedAt"`
	Proofs     []proofDoc `json:"proofs"`
}

type proofDoc struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

// Decide assembles one release decision, or refuses it by name. A
// refusal is the commit point closing: nothing is written, and the
// caller's signer never runs.
func Decide(p *policy.Policy, in *DecisionInputs, now func() time.Time) (*Decision, error) {
	if p.Trust == nil || p.Trust.Decision == nil {
		return nil, errors.New("emit: the policy declares no trust.decision — there is no decision to emit")
	}

	if err := validateDecisionInputs(in); err != nil {
		return nil, err
	}

	lines, err := coveredLines(in)
	if err != nil {
		return nil, err
	}

	doc := decisionDoc{
		Classes:    in.Classes,
		Conclusion: *p.Trust.Decision.RequiredConclusion,
		DecidedAt:  now().UTC().Truncate(time.Second).Format(time.RFC3339),
		Proofs:     make([]proofDoc, 0, len(in.Proofs)),
	}

	if !in.Stream {
		doc.Tag = &in.Tag
	}

	for _, pr := range in.Proofs {
		doc.Proofs = append(doc.Proofs, proofDoc(pr))
	}

	pred, err := jsonx.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("emit: decision predicate: %w", err)
	}

	if err := readBack(p, in.Tag, pred, lines); err != nil {
		return nil, err
	}

	return &Decision{
		PredicateType: *p.Trust.Decision.PredicateType,
		Predicate:     append(pred, '\n'),
		Subjects:      []byte(strings.Join(lines, "\n") + "\n"),
	}, nil
}

// validateDecisionInputs refuses a decision that could not be honest:
// a subject that is neither a release nor a stream, unnamed classes,
// and any required proof that did not succeed — every failing proof
// named, not only the first.
func validateDecisionInputs(in *DecisionInputs) error {
	switch {
	case in.Stream && in.Tag != "":
		return errors.New("emit: a decision is for a release tag or for a stream, never both")
	case !in.Stream && in.Tag == "":
		return errors.New("emit: a decision names its subject: a release tag, or a stream")
	case strings.TrimSpace(in.Classes) == "":
		return errors.New("emit: a decision names the classes it publishes")
	case len(in.Proofs) == 0:
		return errors.New("emit: no required proof is named — absence of a proof is never a proof")
	}

	var refused []string

	seen := map[string]bool{}

	for _, pr := range in.Proofs {
		switch {
		case strings.TrimSpace(pr.Name) == "":
			return errors.New("emit: a required proof has no name")
		case seen[pr.Name]:
			return fmt.Errorf("emit: proof %q is named twice — one proof has one result", pr.Name)
		}

		seen[pr.Name] = true

		if pr.Result != proofSucceeded {
			refused = append(refused, fmt.Sprintf("%s is '%s' — absence of a proof is never a proof", pr.Name, pr.Result))
		}
	}

	if len(refused) > 0 {
		return fmt.Errorf("emit: the commit point stays closed: %s", strings.Join(refused, "; "))
	}

	return nil
}

// coveredLines hashes the covered documents into sha256sum lines —
// every regular file under the directory in path order, or the one
// planned inventory alone — and appends the extra lines. A walk that
// fails refuses: a listing that errored must never read as an empty
// covered set.
func coveredLines(in *DecisionInputs) ([]string, error) {
	files, err := coveredFiles(in.Covered)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("emit: the covered set %s is empty — a decision over nothing decides nothing",
			in.Covered)
	}

	if in.Inventory != "" {
		if files, err = selectInventory(files, in.Inventory); err != nil {
			return nil, err
		}
	}

	lines := make([]string, 0, len(files)+len(in.Also))

	for _, f := range files {
		sum, herr := fileSHA256(f)
		if herr != nil {
			return nil, herr
		}

		lines = append(lines, sum+"  "+filepath.Base(f))
	}

	for _, also := range in.Also {
		if !alsoLineRE.MatchString(also) {
			return nil, fmt.Errorf("emit: subject line %q is not `<sha256>  <name>`", also)
		}

		lines = append(lines, also)
	}

	return lines, nil
}

// coveredFiles lists every regular file under dir, sorted by path —
// the order the record has always listed them in.
func coveredFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}

		if d.Type().IsRegular() {
			files = append(files, path)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("emit: listing the covered set: %w", err)
	}

	slices.Sort(files)

	return files, nil
}

// selectInventory resolves the planned inventory by listing, never by
// building a path out of its name: a planned inventory decides for
// itself and names nothing else (stele#158).
func selectInventory(files []string, inventory string) ([]string, error) {
	var found []string

	for _, f := range files {
		if filepath.Base(f) == inventory {
			found = append(found, f)
		}
	}

	switch len(found) {
	case 0:
		return nil, fmt.Errorf("emit: the plan names %s but the covered set does not carry it", inventory)
	case 1:
		return found, nil
	default:
		return nil, fmt.Errorf("emit: the covered set carries %s %d times — which one the plan named is ambiguous",
			inventory, len(found))
	}
}

// fileSHA256 hashes one covered document.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a file the walk of the caller's covered set listed
	if err != nil {
		return "", fmt.Errorf("emit: covered document: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("emit: hashing %s: %w", path, err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// readBack wraps the predicate in the statement the signer will make
// of it and reads that through the verifier's own decision reader:
// the record must hold for this tag (or stream), and the subjects the
// reader recovers must be exactly the lines about to be written —
// checked by the reader, never by inverting this writer.
func readBack(p *policy.Policy, tag string, pred []byte, lines []string) error {
	subjects := make([]intoto.ResourceDescriptor, 0, len(lines))

	for _, line := range lines {
		digest, name, _ := strings.Cut(line, "  ")
		subjects = append(subjects, intoto.ResourceDescriptor{
			Name:   &name,
			Digest: map[string]string{intoto.AlgSHA256: digest},
		})
	}

	stype := intoto.StatementType
	stmt, err := jsonx.Marshal(intoto.Statement{
		Type:          &stype,
		Subject:       subjects,
		PredicateType: p.Trust.Decision.PredicateType,
		Predicate:     pred,
	})
	if err != nil {
		return fmt.Errorf("emit: decision statement: %w", err)
	}

	read, err := verify.ReadDecision(p, stmt, tag)
	if err != nil {
		return fmt.Errorf("emit: the decision does not read back as one the verdict accepts: %w", err)
	}

	if !slices.Equal(read, lines) {
		return errors.New("emit: the decision's subjects do not read back as the lines it covers")
	}

	return nil
}
