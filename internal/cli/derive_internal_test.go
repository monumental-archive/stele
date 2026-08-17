package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// stubHistory is the derive verb's history seam. Every read can be made
// to fail independently, because a guard that fires only when git is
// unhappy is the least exercised code here.
type stubHistory struct {
	tags       []string
	commits    []string
	messages   map[string]string
	tagsErr    error
	revsErr    error
	msgErr     error
	timeErr    error
	commitTime string
}

func (s *stubHistory) Tags(string) ([]string, error) { return s.tags, s.tagsErr }

func (s *stubHistory) Commits(_, _ string, _ ...string) ([]string, error) {
	return s.commits, s.revsErr
}

func (s *stubHistory) CommitTime(string) (string, error) {
	if s.timeErr != nil {
		return "", s.timeErr
	}

	return s.commitTime, nil
}

func (s *stubHistory) Message(rev string) (string, error) {
	if s.msgErr != nil {
		return "", s.msgErr
	}

	return s.messages[rev], nil
}

// withHistory swaps the seam for one test and restores it after.
func withHistory(t *testing.T, h deriveHistory, err error) {
	t.Helper()

	previous := openDeriveGit
	openDeriveGit = func(string) (deriveHistory, error) { return h, err }

	t.Cleanup(func() { openDeriveGit = previous })
}

func TestDeriveCmdUsage(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{name: "no mode", args: nil, want: exitUsage},
		{name: "unknown mode", args: []string{"nonsense"}, want: exitUsage},
		{name: "no git dir", args: []string{"version"}, want: exitUsage},
		{name: "unknown flag", args: []string{"version", "--nope"}, want: exitUsage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if got := deriveCmd(tc.args, &stdout, &stderr); got != tc.want {
				t.Errorf("deriveCmd(%v) = %d, want %d (stderr: %s)", tc.args, got, tc.want, stderr.String())
			}
		})
	}
}

// Every way the derivation can refuse. Each is a state a real repository
// reaches, and a refusal that does not fire looks exactly like a clean
// derivation.
func TestDeriveRefusals(t *testing.T) {
	sentinel := errors.New("git said no")

	for _, tc := range []struct {
		name  string
		args  []string
		hist  deriveHistory
		open  error
		match string
	}{
		{
			name: "the repository cannot be opened",
			open: sentinel, match: "git said no",
		},
		{
			name: "listing tags fails",
			hist: &stubHistory{tagsErr: sentinel}, match: "git said no",
		},
		{
			name: "listing commits fails",
			hist: &stubHistory{revsErr: sentinel}, match: "git said no",
		},
		{
			name: "reading a message fails",
			hist: &stubHistory{commits: []string{"abc"}, msgErr: sentinel}, match: "git said no",
		},
		{
			name: "a commit type votes twice",
			args: []string{"--minor-types", "feat", "--silent-types", "feat"},
			hist: &stubHistory{}, match: "listed twice",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHistory(t, tc.hist, tc.open)

			var stdout, stderr bytes.Buffer

			args := append([]string{"version", "--git-dir", "."}, tc.args...)
			if got := deriveCmd(args, &stdout, &stderr); got != exitRefused {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitRefused, stderr.String())
			}

			if !strings.Contains(stderr.String(), tc.match) {
				t.Errorf("stderr = %q, want it to mention %q", stderr.String(), tc.match)
			}
		})
	}
}

func TestDeriveVersionReports(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		hist     *stubHistory
		want     []string
		unwanted []string
	}{
		{
			name: "a first release when nothing is tagged",
			hist: &stubHistory{
				commits:  []string{"a"},
				messages: map[string]string{"a": "feat: the first thing"},
			},
			want: []string{"no release in the \"v\" namespace", "version=0.1.0", "tag=v0.1.0", "release=true"},
		},
		{
			name: "a patch on an existing release",
			hist: &stubHistory{
				tags:     []string{"v1.2.3"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "fix: repair it"},
			},
			want: []string{"base 1.2.3", "bump=patch", "version=1.2.4", "tag=v1.2.4"},
		},
		{
			name: "nothing to release",
			hist: &stubHistory{
				tags:     []string{"v1.2.3"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "chore: tidy"},
			},
			want:     []string{"release=false", "nothing to release"},
			unwanted: []string{"version="},
		},
		// The 0.x rule reports both bumps: a reader told only the applied
		// one would conclude nothing broke.
		{
			name: "a break below 1.0.0 states what it absorbed",
			hist: &stubHistory{
				tags:     []string{"v0.4.2"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "feat!: change the shape"},
			},
			want: []string{"bump=minor (requested major", "version=0.5.0"},
		},
		{
			name: "another component's namespace",
			args: []string{"--tag-prefix", "core-v"},
			hist: &stubHistory{
				tags:     []string{"v9.9.9", "core-v1.0.0"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "feat: a thing"},
			},
			want: []string{"base 1.0.0", "version=1.1.0", "tag=core-v1.1.0"},
		},
		// Both kinds of silence are named rather than dropped.
		{
			name: "debris in the namespace is reported",
			hist: &stubHistory{
				tags:     []string{"v0.9-pre-import", "v1.0.0"},
				commits:  []string{"a"},
				messages: map[string]string{"a": "fix: repair it"},
			},
			want: []string{`skipped "v0.9-pre-import"`, "version=1.0.1"},
		},
		{
			name: "unconventional commits are counted",
			hist: &stubHistory{
				tags:    []string{"v1.0.0"},
				commits: []string{"a", "b"},
				messages: map[string]string{
					"a": "Merge branch 'main' into topic",
					"b": "fix: repair it",
				},
			},
			want: []string{"1 commit(s) in the range are not conventional", "version=1.0.1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withHistory(t, tc.hist, nil)

			var stdout, stderr bytes.Buffer

			args := append([]string{"version", "--git-dir", "."}, tc.args...)
			if got := deriveCmd(args, &stdout, &stderr); got != exitOK {
				t.Fatalf("deriveCmd = %d, want %d (stderr: %s)", got, exitOK, stderr.String())
			}

			for _, want := range tc.want {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
				}
			}

			for _, unwanted := range tc.unwanted {
				if strings.Contains(stdout.String(), unwanted) {
					t.Errorf("stdout = %q, want it NOT to contain %q", stdout.String(), unwanted)
				}
			}
		})
	}
}

// A tool that fails to say what it derived must not report success.
func TestDeriveWriterFailure(t *testing.T) {
	withHistory(t, &stubHistory{
		commits:  []string{"a"},
		messages: map[string]string{"a": "feat: the first thing"},
	}, nil)

	var stderr bytes.Buffer

	if got := deriveCmd([]string{"version", "--git-dir", "."}, failWriterI{}, &stderr); got != exitIO {
		t.Errorf("deriveCmd = %d, want %d", got, exitIO)
	}
}

func TestSplitTypes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{in: "", want: 0},
		{in: "feat", want: 1},
		{in: "feat,fix", want: 2},
		{in: " feat , fix ", want: 2},
		{in: "feat,,fix,", want: 2},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := splitTypes(tc.in); len(got) != tc.want {
				t.Errorf("splitTypes(%q) = %v, want %d entries", tc.in, got, tc.want)
			}
		})
	}
}
