package gitrepo

import (
	"encoding/base64"
	"net/url"
	"strconv"
)

// AuthEnv is the environment a git command that reaches a remote runs
// under, and the ONE way a credential reaches git in stele (stele#384,
// stele#395): emit's notes fetch and push and the walks' history fetch
// both take it from here, so there is no second spelling of it to
// drift.
//
// The credential travels as an http.extraheader through git's
// environment configuration (GIT_CONFIG_COUNT and its key/value
// pairs) — never an argument, which any process on the machine can
// read and which a failed command prints, and never a file. With it:
//
//   - no credential helper runs: the helper list is reset to empty,
//     because a git may read a helper from configuration this
//     package does not control (Apple's git reads its own built-in
//     osxkeychain even with the system config pinned away, measured
//     on stele#384);
//   - no prompt opens: no terminal prompt, no askpass program;
//   - no inherited `-c` setting rides along (GIT_CONFIG_PARAMETERS);
//   - git's own trace output redacts the header, so an operator who
//     turned HTTP tracing on with redaction off cannot have the
//     credential printed into a refusal (measured: with
//     GIT_CURL_VERBOSE=1 and GIT_TRACE_REDACT=0, git prints the header
//     twice).
//
// The header is scoped to an HTTP remote's own origin, so it goes to
// that host alone. A named remote's URL lives in the repository's
// config, so the header goes with whatever URL the name resolves to,
// unscoped — as `-c http.extraheader` always did. A transport that is
// not HTTP sends no header at all. token "" sets no header: the
// settings above still hold.
func AuthEnv(remote, token string) []string {
	cfg := [][2]string{
		{"credential.helper", ""},
		{"core.askPass", ""},
	}

	if token != "" {
		header := "AUTHORIZATION: basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
		cfg = append(cfg, [2]string{headerKey(remote), header})
	}

	env := []string{
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=", "GIT_CONFIG_PARAMETERS=", "GIT_TRACE_REDACT=1",
		"GIT_CONFIG_COUNT=" + strconv.Itoa(len(cfg)),
	}

	for i, kv := range cfg {
		env = append(env,
			"GIT_CONFIG_KEY_"+strconv.Itoa(i)+"="+kv[0],
			"GIT_CONFIG_VALUE_"+strconv.Itoa(i)+"="+kv[1])
	}

	return env
}

// headerKey is the config key the header is set under: scoped to an
// HTTP remote's origin, unscoped for anything else.
func headerKey(remote string) string {
	if u, err := url.Parse(remote); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		return "http." + u.Scheme + "://" + u.Host + "/.extraheader"
	}

	return "http.extraheader"
}
