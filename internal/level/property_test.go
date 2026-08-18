package level_test

import (
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/level"
)

func rev(id, subject string, parents int) level.Revision {
	return level.Revision{ID: id, Subject: subject, Parents: parents, Time: epoch}
}

func TestEvaluatorVocabularyIsClosed(t *testing.T) {
	t.Parallel()

	for _, name := range level.EvaluatorNames() {
		if _, ok := level.EvaluatorFor(name); !ok {
			t.Errorf("EvaluatorFor(%q) = _, false — the advertised vocabulary must resolve", name)
		}
	}

	// A typo must not resolve to something that quietly proves nothing:
	// an unknown evaluator is refused where it is used, and this is the
	// lookup that refuses it.
	if _, ok := level.EvaluatorFor("history-conformance"); ok {
		t.Error("EvaluatorFor resolved a name outside the built-in vocabulary")
	}
}

func TestLinearHistory(t *testing.T) {
	t.Parallel()

	ev, ok := level.EvaluatorFor("linear-history")
	if !ok {
		t.Fatal("linear-history is not registered")
	}

	for _, tt := range []struct {
		name string
		revs []level.Revision
		held bool
		why  string
	}{
		{
			name: "a squashed history holds",
			revs: []level.Revision{rev("aaaa", "feat: one", 1), rev("bbbb", "fix: two", 1)},
			held: true,
		},
		{
			// A root commit has no parents at all, which is one parent
			// fewer than a squash — never a merge.
			name: "a root commit holds",
			revs: []level.Revision{rev("aaaa", "feat: one", 0)},
			held: true,
		},
		{
			name: "a merge commit refutes",
			revs: []level.Revision{rev("aaaa", "feat: one", 1), rev("bbbbbbbbbbbb", "merge", 2)},
			held: false,
			why:  "bbbbbbbbbbbb",
		},
		{
			name: "an empty window holds vacuously",
			revs: nil,
			held: true,
		},
	} {
		held, why := ev.Evaluate(tt.revs)
		if held != tt.held {
			t.Errorf("%s: Evaluate = %v (%s), want %v", tt.name, held, why, tt.held)
		}

		if why == "" {
			t.Errorf("%s: Evaluate gave no reason — a proof that cannot say what it proved is not evidence", tt.name)
		}

		if tt.why != "" && !strings.Contains(why, tt.why) {
			t.Errorf("%s: reason %q does not name the offending revision", tt.name, why)
		}
	}
}

func TestConventionalHistory(t *testing.T) {
	t.Parallel()

	ev, ok := level.EvaluatorFor("conventional-history")
	if !ok {
		t.Fatal("conventional-history is not registered")
	}

	if held, why := ev.Evaluate([]level.Revision{rev("aaaa", "feat(cli): add the level verb", 1)}); !held {
		t.Errorf("Evaluate = false (%s), want a conventional subject to parse", why)
	}

	held, why := ev.Evaluate([]level.Revision{
		rev("aaaa", "feat: fine", 1),
		rev("bbbbbbbbbbbb", "just some words", 1),
	})
	if held {
		t.Error("Evaluate = true, want a non-conventional subject refuted")
	}

	if !strings.Contains(why, "bbbbbbbbbbbb") {
		t.Errorf("reason %q does not name the offending revision", why)
	}
}
