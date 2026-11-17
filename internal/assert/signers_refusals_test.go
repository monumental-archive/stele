package assert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/monumental-archive/stele/internal/report"
)

// Every way the watch refuses before it judges anything: an error,
// and the checkpoint exactly as it was found.
func TestSignerWatchRefusals(t *testing.T) {
	t.Parallel()

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		startAt uint64
		edit    func(h *harness)
		want    string
	}{
		{
			name: "a policy declaring no watch",
			edit: func(h *harness) { h.pol.SignerCertificates = nil },
			want: "the policy declares no signerCertificates section",
		},
		{
			name: "a population member this run could not look at",
			edit: func(h *harness) {
				h.pol = signersPolicyOver(h.t, h.log.url(), githubIssuer, oneSigner,
					`{"coverage": {"visibility": ["public"]}, "repositories": [{"repo": ".github"}, `+
						`{"repo": "vault", "visibility": "private"}]}`)
				h.listing = []string{".github"}
			},
			want: "population: vault is outside this run's declared enumeration coverage",
		},
		{
			name: "a tree head the log will not serve",
			edit: func(h *harness) {
				h.log.hook = func(w http.ResponseWriter, kind string, _ int) bool {
					if kind != "sth" {
						return false
					}

					http.NotFound(w, nil)

					return true
				}
			},
			want: "ctlog: get-sth: HTTP 404",
		},
		{
			name: "a tree head signed by a key the trusted root does not hold",
			edit: func(h *harness) {
				h.trusted = logSource{"other": {
					BaseURL: h.log.url(), ID: []byte("other"), PublicKey: otherKey.Public(),
				}}
			},
			want: fmt.Sprintf("the tree head of size %d is not signed by a key the trusted root holds", smallLog),
		},
		{
			name:    "a start beyond the head",
			startAt: smallLog + 1,
			want:    fmt.Sprintf("--start-at %d is beyond the log's tree size %d", smallLog+1, smallLog),
		},
		{
			name: "a founding the disk refuses",
			edit: func(h *harness) { h.cpPath = filepath.Join(h.t.TempDir(), "no-such-dir", "cp.json") },
			want: "ctlog: checkpoint:",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, fillerLeaves(smallLog))
			if tc.edit != nil {
				tc.edit(h)
			}

			rep, err := h.run(tc.startAt)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v (report %v), want it to say %q", err, rep, tc.want)
			}

			if len(entryRequests(h.log.seen())) != 0 {
				t.Fatalf("a refused run read entries: %q", h.log.seen())
			}
		})
	}
}

// A consistency proof the log will not serve is a refusal too: the
// head is not proven to extend the checkpoint's.
func TestSignerWatchRefusesAnUnprovenHead(t *testing.T) {
	t.Parallel()

	h := newHarness(t, fillerLeaves(1500))
	h.log.grow(1000)

	if _, err := h.run(1000); err != nil {
		t.Fatal(err)
	}

	h.log.grow(1500)
	h.log.hook = func(w http.ResponseWriter, kind string, _ int) bool {
		if kind != "consistency" {
			return false
		}

		http.Error(w, "no", http.StatusBadRequest)

		return true
	}

	if _, err := h.run(0); err == nil || !strings.Contains(err.Error(), "get-sth-consistency 1000..1500: HTTP 400") {
		t.Fatalf("err = %v, want the unserved proof named", err)
	}

	if h.lastSaved() != 1000 {
		t.Fatalf("the checkpoint moved to %d", h.lastSaved())
	}
}

// Stops partway, each a report and never a judgment of what was not
// done: a checkpoint the disk will not take, and a budget that ends
// with a match scanned but not reconciled.
func TestSignerWatchStopsPartway(t *testing.T) {
	t.Parallel()

	t.Run("a chunk's checkpoint the disk refuses", func(t *testing.T) {
		t.Parallel()

		h := reconcileHarness(t, releaseIndex)
		h.chunk = 10
		h.failSavesAfter = 1

		rep, err := h.run(0)
		if err != nil {
			t.Fatal(err)
		}

		// The certificate's chunk was judged and could not be recorded:
		// the next run judges it again, so this one reports nothing of
		// it — never a finding the checkpoint did not move past.
		if rep.Verdict() != report.VerdictCannotJudge || len(rep.Findings()) != 0 {
			t.Fatalf("verdict %s with findings %+v", rep.Verdict(), rep.Findings())
		}

		if got := fact(t, rep, "stopped"); got != "incomplete: writing the checkpoint: the disk is full" {
			t.Fatalf("stopped = %q", got)
		}

		if got := fact(t, rep, "outstanding"); got != fmt.Sprintf("0..%d", smallLog-1) {
			t.Fatalf("outstanding = %q", got)
		}
	})

	t.Run("the budget ends with a match scanned", func(t *testing.T) {
		t.Parallel()

		h := reconcileHarness(t, releaseIndex)
		h.chunk = 10
		h.budget = time.Minute
		h.log.onEntriesSent = func(uint64) { h.clock.Sleep(time.Hour) }

		rep, err := h.run(0)
		if err != nil {
			t.Fatal(err)
		}

		if rep.Verdict() != report.VerdictCannotJudge || h.lastSaved() != 0 {
			t.Fatalf("verdict %s, checkpoint %d — want CANNOT_JUDGE at 0", rep.Verdict(), h.lastSaved())
		}

		want := "budget: ctlog: the run's budget ended before the chunk's 1 match(es) were reconciled"
		if got := fact(t, rep, "stopped"); got != want {
			t.Fatalf("stopped = %q, want %q", got, want)
		}

		if len(h.forge.reads) != 0 {
			t.Fatalf("the forge was read past the budget: %q", h.forge.reads)
		}
	})
}
