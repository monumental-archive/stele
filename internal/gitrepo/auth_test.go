package gitrepo_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/monumental-archive/stele/internal/gitrepo"
)

// tokenUnderTest is a made-up credential: the value these tests prove
// never reaches an argument list, a file, or a message.
const tokenUnderTest = "ghs_THE-TOKEN-UNDER-TEST" //nolint:gosec // G101: a made-up value, the one under test

// encodedToken is the token under test as the header carries it.
func encodedToken() string {
	return base64.StdEncoding.EncodeToString([]byte("x-access-token:" + tokenUnderTest))
}

// TestAFailedCloneNeverPrintsTheToken (stele#395): a fetch that fails
// prints its arguments — they are what makes it diagnosable — so no
// argument may carry the credential, raw or encoded.
func TestAFailedCloneNeverPrintsTheToken(t *testing.T) {
	t.Parallel()

	_, err := gitrepo.Clone(filepath.Join(t.TempDir(), "scratch"), "file:///nonexistent/remote.git", tokenUnderTest,
		"n", "e@example.com", "refs/heads/main", "refs/notes/commits")
	if err == nil {
		t.Fatal("Clone fetched from a remote that is not there")
	}

	for _, secret := range []string{tokenUnderTest, encodedToken()} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the refusal carries the credential:\n%v", err)
		}
	}

	// The arguments are still there: the refusal stays diagnosable.
	if !strings.Contains(err.Error(), "git fetch -q file:///nonexistent/remote.git +refs/heads/main:refs/heads/main") {
		t.Fatalf("the refusal lost the command it refuses:\n%v", err)
	}
}

// invocation is one recorded run of the stand-in git.
type invocation struct {
	args []string
	env  []string
}

// standInGit puts a git first on PATH that records every argument and
// the whole environment of each run, then hands over to the real git —
// so the commands under test still do their work, and the record is
// of exactly what each one was given. Not parallel: PATH is the
// process's.
func standInGit(t *testing.T) func() []invocation {
	t.Helper()

	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("no git on PATH: %v", err)
	}

	bin, record := t.TempDir(), t.TempDir()
	script := "#!/bin/sh\n" +
		"n=$(ls '" + record + "' | grep -c '\\.args$')\n" +
		"printf '%s\\n' \"$@\" > '" + record + "/'\"$n\".args\n" +
		"env > '" + record + "/'\"$n\".env\n" +
		"exec '" + realGit + "' \"$@\"\n"

	//nolint:gosec // G306: an executable by design, in the test's own directory
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	return func() []invocation {
		t.Helper()

		var out []invocation

		for n := 0; ; n++ {
			args, aerr := os.ReadFile(filepath.Join(record, strconv.Itoa(n)+".args")) //nolint:gosec // the test's own record
			if aerr != nil {
				return out
			}

			env, eerr := os.ReadFile(filepath.Join(record, strconv.Itoa(n)+".env")) //nolint:gosec // the test's own record
			if eerr != nil {
				t.Fatal(eerr)
			}

			out = append(out, invocation{
				args: strings.Split(strings.TrimRight(string(args), "\n"), "\n"),
				env:  strings.Split(strings.TrimRight(string(env), "\n"), "\n"),
			})
		}
	}
}

// emitWorld is a remote holding a branch and a ledger, and the commit
// a note is written on.
//
//nolint:gocritic // unnamedResult: the remote, then the commit
func emitWorld(t *testing.T) (string, string) {
	t.Helper()

	fx := repo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitCmd(t, fx.dir)("clone", "-q", "--bare", fx.dir, remote)
	gitCmd(t, remote)("fetch", "-q", fx.dir, "+refs/notes/*:refs/notes/*")

	return "file://" + remote, fx.tip
}

// TestTheTokenReachesGitOnlyThroughItsEnvironment (stele#395): every
// command emit sends to a remote — the clone's two fetches and its
// probe, the notes fetch, the push proof and the push — is given the
// credential as one environment pair and nowhere else: never an
// argument. With no token, no credential configuration is set at all.
func TestTheTokenReachesGitOnlyThroughItsEnvironment(t *testing.T) {
	remote, tip := emitWorld(t)
	recorded := standInGit(t)

	r, err := gitrepo.Clone(filepath.Join(t.TempDir(), "scratch"), remote, tokenUnderTest,
		"n", "e@example.com", "refs/heads/main", notesRef)
	if err != nil {
		t.Fatalf("Clone = %v", err)
	}

	// Bound as emit binds it: the ledger is policy, the clone is not.
	if err := r.SetNotesRef(notesRef); err != nil {
		t.Fatalf("SetNotesRef = %v", err)
	}

	if err := r.FetchNotes(remote, tokenUnderTest); err != nil {
		t.Fatalf("FetchNotes = %v", err)
	}

	if err := r.DryRunPushNotes(remote, tokenUnderTest, tip); err != nil {
		t.Fatalf("DryRunPushNotes = %v", err)
	}

	if err := r.AddNote(tip, []byte("a note to push")); err != nil {
		t.Fatalf("AddNote = %v", err)
	}

	if err := r.PushNotes(remote, tokenUnderTest); err != nil {
		t.Fatalf("PushNotes = %v", err)
	}

	runs := recorded()
	seen := map[string]int{}

	for _, run := range runs {
		for _, a := range run.args {
			if strings.Contains(a, tokenUnderTest) || strings.Contains(a, encodedToken()) {
				t.Fatalf("an argument carried the credential: %q", run.args)
			}
		}

		entry := emitEntry(run.args)
		if entry == "" {
			assertNoAuth(t, run)

			continue
		}

		seen[entry]++
		assertAuthPairOnly(t, entry, run)
	}

	// Every entry the issue names ran with the token: the clone's
	// branch fetch, its probe (remoteHasRef) and its ledger fetch; then
	// FetchNotes — the second ledger fetch — the push proof and the
	// push.
	for entry, want := range map[string]int{
		"Clone branch fetch": 1, "remoteHasRef": 1, "ledger fetch (Clone, FetchNotes)": 2,
		"DryRunPushNotes": 1, "PushNotes": 1,
	} {
		if seen[entry] != want {
			t.Errorf("%s ran %d time(s) with the token, want %d (seen %v)", entry, seen[entry], want, seen)
		}
	}
}

// TestAnAnonymousCallSetsNoCredentialConfig: an empty token — a
// file:// remote, a test — leaves the command exactly as it was.
func TestAnAnonymousCallSetsNoCredentialConfig(t *testing.T) {
	remote, tip := emitWorld(t)
	recorded := standInGit(t)

	r, err := gitrepo.Clone(filepath.Join(t.TempDir(), "scratch"), remote, "",
		"n", "e@example.com", "refs/heads/main", notesRef)
	if err != nil {
		t.Fatalf("Clone = %v", err)
	}

	if err := r.SetNotesRef(notesRef); err != nil {
		t.Fatalf("SetNotesRef = %v", err)
	}

	if err := r.FetchNotes(remote, ""); err != nil {
		t.Fatalf("FetchNotes = %v", err)
	}

	if err := r.DryRunPushNotes(remote, "", tip); err != nil {
		t.Fatalf("DryRunPushNotes = %v", err)
	}

	if err := r.PushNotes(remote, ""); err != nil {
		t.Fatalf("PushNotes = %v", err)
	}

	runs := recorded()
	if len(runs) == 0 {
		t.Fatal("the stand-in recorded nothing")
	}

	for _, run := range runs {
		assertNoAuth(t, run)
	}
}

// emitEntry names the emit entry one recorded network command belongs
// to, "" for a local command.
func emitEntry(args []string) string {
	switch {
	case slices.Contains(args, "ls-remote"):
		return "remoteHasRef"
	case slices.Contains(args, "push") && slices.Contains(args, "--dry-run"):
		return "DryRunPushNotes"
	case slices.Contains(args, "push"):
		return "PushNotes"
	case slices.Contains(args, "fetch") && slices.Contains(args, "+"+notesRef+":"+notesRef):
		return "ledger fetch (Clone, FetchNotes)"
	case slices.Contains(args, "fetch"):
		return "Clone branch fetch"
	default:
		return ""
	}
}

// assertAuthPairOnly holds one networked command to the contract: the
// encoded credential in exactly one environment value, keyed as the
// extra header, no raw token anywhere in the environment, and no
// credential helper or prompt left able to run.
func assertAuthPairOnly(t *testing.T, entry string, run invocation) {
	t.Helper()

	header := "AUTHORIZATION: basic " + encodedToken()

	var carriers []string

	for _, kv := range run.env {
		if strings.Contains(kv, tokenUnderTest) {
			t.Fatalf("%s: the raw token is in the environment: %q", entry, kv)
		}

		if strings.Contains(kv, encodedToken()) {
			carriers = append(carriers, kv)
		}
	}

	if len(carriers) != 1 || !strings.HasPrefix(carriers[0], "GIT_CONFIG_VALUE_") ||
		!strings.HasSuffix(carriers[0], "="+header) {
		t.Fatalf("%s: the credential is carried by %q, want one GIT_CONFIG_VALUE_n pair", entry, carriers)
	}

	n := strings.TrimPrefix(strings.SplitN(carriers[0], "=", 2)[0], "GIT_CONFIG_VALUE_")

	for _, want := range []string{
		"GIT_CONFIG_KEY_" + n + "=http.extraheader",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_TRACE_REDACT=1",
	} {
		if !slices.Contains(run.env, want) {
			t.Fatalf("%s: the environment lacks %q", entry, want)
		}
	}

	if !helperEmptied(run.env) {
		t.Fatalf("%s: no emptied credential.helper in the environment config", entry)
	}
}

// helperEmptied reports whether the environment config resets the
// credential helper list to empty.
func helperEmptied(env []string) bool {
	for _, kv := range env {
		key, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(key, "GIT_CONFIG_KEY_") || value != "credential.helper" {
			continue
		}

		n := strings.TrimPrefix(key, "GIT_CONFIG_KEY_")
		if slices.Contains(env, "GIT_CONFIG_VALUE_"+n+"=") {
			return true
		}
	}

	return false
}

// assertNoAuth holds a command that carries no credential to carrying
// no credential configuration either.
func assertNoAuth(t *testing.T, run invocation) {
	t.Helper()

	for _, kv := range run.env {
		if strings.Contains(kv, "extraheader") || strings.Contains(kv, encodedToken()) ||
			kv == "GIT_TERMINAL_PROMPT=0" {
			t.Fatalf("%q ran with credential configuration %q", run.args, kv)
		}
	}
}

// TestGitsOwnTraceCannotPrintTheToken: a refusal carries git's own
// words, and an operator's environment can ask git to trace its HTTP
// with redaction off. The credential's environment turns redaction
// back on, so even then the refusal holds no credential (measured:
// with GIT_CURL_VERBOSE=1 and GIT_TRACE_REDACT=0, git prints the
// header twice).
func TestGitsOwnTraceCannotPrintTheToken(t *testing.T) {
	t.Setenv("GIT_CURL_VERBOSE", "1")
	t.Setenv("GIT_TRACE_REDACT", "0")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	fx := repo(t)

	r, err := gitrepo.Open(fx.dir, notesRef)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}

	err = r.FetchNotes(srv.URL+"/acme/widget.git", tokenUnderTest)
	if err == nil {
		t.Fatal("FetchNotes fetched from a server that refuses everything")
	}

	for _, secret := range []string{tokenUnderTest, encodedToken()} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the refusal carries the credential:\n%v", err)
		}
	}

	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("the refusal lost git's own words:\n%v", err)
	}
}

// TestAuthEnv pins the one function a credential reaches git through:
// the header scoped to an HTTP remote's own origin, unscoped for a
// named remote whose URL the repository's config holds, and the
// no-helper, no-prompt, redacting settings either way.
func TestAuthEnv(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, remote, token, key string
	}{
		{
			name: "an https remote", remote: "https://github.com/acme/widget.git", token: "t",
			key: "http.https://github.com/.extraheader",
		},
		{
			name: "an http remote keeps its port", remote: "http://127.0.0.1:8080/acme/widget.git", token: "t",
			key: "http.http://127.0.0.1:8080/.extraheader",
		},
		{name: "a named remote", remote: "origin", token: "t", key: "http.extraheader"},
		{name: "a file remote", remote: "file:///srv/widget.git", token: "t", key: "http.extraheader"},
		{name: "an scp-like remote", remote: "git@github.com:acme/widget.git", token: "t", key: "http.extraheader"},
		{name: "no token", remote: "https://github.com/acme/widget.git"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := gitrepo.AuthEnv(tc.remote, tc.token)

			for _, want := range []string{
				"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=",
				"GIT_CONFIG_PARAMETERS=", "GIT_TRACE_REDACT=1",
			} {
				if !slices.Contains(env, want) {
					t.Fatalf("AuthEnv lacks %q: %q", want, env)
				}
			}

			if !helperEmptied(env) {
				t.Fatalf("AuthEnv leaves the credential helper list alone: %q", env)
			}

			if keyed := headerKeyIn(env); keyed != tc.key {
				t.Fatalf("header key = %q, want %q", keyed, tc.key)
			}

			if count := configPairs(env); !slices.Contains(env, "GIT_CONFIG_COUNT="+strconv.Itoa(count)) {
				t.Fatalf("GIT_CONFIG_COUNT does not count the %d pairs: %q", count, env)
			}
		})
	}
}

// headerKeyIn is the config key the environment sets the header under,
// "" when it sets none.
func headerKeyIn(env []string) string {
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_CONFIG_KEY_") && strings.HasSuffix(kv, "extraheader") {
			return strings.SplitN(kv, "=", 2)[1]
		}
	}

	return ""
}

// configPairs counts the environment's config keys.
func configPairs(env []string) int {
	count := 0

	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_CONFIG_KEY_") {
			count++
		}
	}

	return count
}
