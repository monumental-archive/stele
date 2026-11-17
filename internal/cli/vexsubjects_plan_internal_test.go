// `derive vex-subjects` as a signing plan (stele#398): several
// decisions in one run, the store asked which it already holds, and
// the exit code carrying what the plan found — while the plan itself
// is always written whole.

package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gh"
	"github.com/monumental-archive/stele/internal/jsonx"
	"github.com/monumental-archive/stele/internal/vexsubjects"
)

// vexStoreForge is the replayed org plus an attestation store for the
// signed decisions, at acme/canon, whose control read and probes can
// each be made to fail.
type vexStoreForge struct {
	gh.Snapshot

	missing    bool
	controlErr error
	probeErr   error
}

//nolint:gocritic // unnamedResult: the forge's own DefaultBranch shape
func (f vexStoreForge) DefaultBranch(owner, repo string) (string, bool, error) {
	if owner != "acme" || repo != "canon" {
		return "", false, nil
	}

	if f.controlErr != nil {
		return "", false, f.controlErr
	}

	return "main", !f.missing, nil
}

func (f vexStoreForge) Attestations(owner, repo, digest string) ([]jsonx.Raw, error) {
	if owner == "acme" && repo == "canon" && f.probeErr != nil {
		return nil, f.probeErr
	}

	return f.Snapshot.Attestations(owner, repo, digest)
}

func swapVEXStoreForge(t *testing.T, f vexStoreForge) {
	t.Helper()

	orig := newForge
	newForge = func() gh.Forge { return f }

	t.Cleanup(func() { newForge = orig })
}

// holdDecision records, in the snapshot's acme/canon store, a signed
// statement whose predicate is the decision — under the derived set's
// first subject.
func holdDecision(t *testing.T, snap, decision string) {
	t.Helper()

	raw, err := os.ReadFile(decision) //nolint:gosec // a path this test wrote
	if err != nil {
		t.Fatal(err)
	}

	stmt := `{"_type":"https://in-toto.io/Statement/v1","subject":[],` +
		`"predicateType":"https://openvex.dev/ns/v0.2.0","predicate":` + string(raw) + `}`
	bundles := `[{"dsseEnvelope":{"payload":"` + base64.StdEncoding.EncodeToString([]byte(stmt)) + `"}}]`

	dir := filepath.Join(snap, "acme", "canon", "attestations")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	//nolint:gosec // G703: a path under this test's own temp directory
	if err := os.WriteFile(filepath.Join(dir, strings.Repeat("a", 64)+".json"), []byte(bundles), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readPlan decodes the plan a run wrote.
func readPlan(t *testing.T, path string) *vexsubjects.Plan {
	t.Helper()

	raw, err := os.ReadFile(path) //nolint:gosec // a path this test named
	if err != nil {
		t.Fatalf("the plan was not written: %v", err)
	}

	plan, err := jsonx.DecodeBytes[vexsubjects.Plan](raw)
	if err != nil {
		t.Fatalf("the plan does not decode: %v\n%s", err, raw)
	}

	return plan
}

// TestDeriveVEXSubjectsPlansSeveral: two decisions, one refused — the
// other is still planned, the plan is written whole, and the run exits
// 1 because something was refused.
func TestDeriveVEXSubjectsPlansSeveral(t *testing.T) {
	snap, policy, decision := vexSubjectsSnapshot(t)
	swapScanner(t, cliScanner{out: vexSubjectsScan})

	broken := filepath.Join(t.TempDir(), "broken.openvex.json")
	if err := os.WriteFile(broken, []byte(`{"statements": []}`), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "plan.json")

	var stdout, stderr bytes.Buffer

	code := Run([]string{
		"derive", "vex-subjects", "--org", "acme", "--policy", policy,
		"--decision", broken, "--decision", decision, "--snapshot", snap, "--out", out,
	}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, exitRefused, stdout.String(), stderr.String())
	}

	plan := readPlan(t, out)

	if len(plan.Refused) != 1 || plan.Refused[0].Reason != broken+" is not an OpenVEX document" {
		t.Errorf("refused = %+v, want the non-OpenVEX file named", plan.Refused)
	}

	if len(plan.Cells) != 1 || plan.Cells[0].Decision != decision {
		t.Errorf("cells = %+v, want the other decision still planned", plan.Cells)
	}
}

// TestDeriveVEXSubjectsUnsignedOnly: the store's answers through the
// verb — held is omitted, a 404 is a cell, a probe that fails is exit 4
// with the plan still written, and a store repository that cannot be
// read is exit 4 with no plan at all.
func TestDeriveVEXSubjectsUnsignedOnly(t *testing.T) {
	for _, tt := range []struct {
		name   string
		forge  vexStoreForge
		held   bool
		code   int
		cells  int
		heldN  int
		blind  bool
		noPlan bool
		says   string
	}{
		{name: "the store holds the decision", held: true, code: exitOK, heldN: 1},
		{name: "the store holds nothing (404 on both probes)", code: exitOK, cells: 1},
		{
			name:  "a probe answers 403",
			forge: vexStoreForge{probeErr: errors.New("gh: HTTP 403")},
			code:  exitBlind, blind: true,
			says: "the attestation store could not be read — refusing to read that as unsigned: gh: HTTP 403",
		},
		{
			name:  "a probe answers 502",
			forge: vexStoreForge{probeErr: errors.New("gh: HTTP 502")},
			code:  exitBlind, blind: true,
			says: "refusing to read that as unsigned: gh: HTTP 502",
		},
		{
			name:  "the store's repository answers 404",
			forge: vexStoreForge{missing: true},
			code:  exitBlind, noPlan: true,
			says: "the attestation store's repository is unreadable — refusing to read that as an empty store",
		},
		{
			name:  "the store's repository read fails",
			forge: vexStoreForge{controlErr: errors.New("gh: HTTP 503")},
			code:  exitBlind, noPlan: true,
			says: "gh: HTTP 503",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			snap, policy, decision := vexSubjectsSnapshot(t)
			swapScanner(t, cliScanner{out: vexSubjectsScan})

			if tt.held {
				holdDecision(t, snap, decision)
			}

			f := tt.forge
			f.Snapshot = gh.Snapshot{Dir: snap}
			swapVEXStoreForge(t, f)

			out := filepath.Join(t.TempDir(), "plan.json")

			var stdout, stderr bytes.Buffer

			code := Run([]string{
				"derive", "vex-subjects", "--org", "acme", "--policy", policy, "--decision", decision,
				"--unsigned-only", "--store", "acme/canon", "--out", out,
			}, &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("Run = %d, want %d\nstdout: %s\nstderr: %s", code, tt.code, stdout.String(), stderr.String())
			}

			if tt.says != "" && !strings.Contains(stdout.String()+stderr.String(), tt.says) {
				t.Errorf("the run does not say %q\nstdout: %s\nstderr: %s", tt.says, stdout.String(), stderr.String())
			}

			if tt.noPlan {
				if _, err := os.Stat(out); err == nil {
					t.Error("a plan was written over a store nobody could read")
				}

				return
			}

			plan := readPlan(t, out)
			if len(plan.Cells) != tt.cells || len(plan.Held) != tt.heldN || plan.Blind() != tt.blind {
				t.Errorf("plan = %+v", plan)
			}
		})
	}
}

// TestDeriveVEXSubjectsPlanUsage: the new flags' contradictions.
func TestDeriveVEXSubjectsPlanUsage(t *testing.T) {
	snap, policy, decision := vexSubjectsSnapshot(t)

	base := []string{"derive", "vex-subjects", "--org", "acme", "--policy", policy, "--decision", decision}

	for _, tt := range []struct {
		name string
		args []string
		code int
		says string
	}{
		{
			name: "unsigned-only with no store",
			args: append(append([]string{}, base...), "--unsigned-only"),
			code: exitUsage,
			says: "--unsigned-only needs --store owner/name",
		},
		{
			name: "a store that is not owner/name",
			args: append(append([]string{}, base...), "--unsigned-only", "--store", "canon"),
			code: exitUsage,
			says: "--unsigned-only needs --store owner/name",
		},
		{
			name: "a store with nothing to ask it",
			args: append(append([]string{}, base...), "--store", "acme/canon"),
			code: exitUsage,
			says: "--store is read only with --unsigned-only",
		},
		{
			name: "one decision named twice",
			args: append(append([]string{}, base...), "--decision", decision),
			code: exitUsage,
			says: "is named twice — one decision is planned once",
		},
		{
			// A replayed forge has no live store behind it.
			name: "unsigned-only against a replay",
			args: append(append([]string{}, base...), "--unsigned-only", "--store", "acme/canon", "--snapshot", snap),
			code: exitRefused,
			says: "--unsigned-only asks the live attestation store, and this forge cannot read one",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			swapScanner(t, cliScanner{out: vexSubjectsScan})

			var stdout, stderr bytes.Buffer

			if code := Run(tt.args, &stdout, &stderr); code != tt.code {
				t.Fatalf("Run = %d, want %d; stderr: %s", code, tt.code, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.says) {
				t.Errorf("stderr = %q, want it to say %q", stderr.String(), tt.says)
			}
		})
	}
}
