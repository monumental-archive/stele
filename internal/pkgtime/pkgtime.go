// Package pkgtime answers when a dependency version was published.
//
// It exists for one requirement: the draft dependency track's secure
// ingestion policy, whose observable consequence is the interval
// between a version being published upstream and a producer taking it.
// A producer who ingests a version minutes after it appears is running
// no quarantine; one whose every dependency sat upstream for days
// plainly is. That interval is a fact about published artifacts, so it
// is evidence rather than a claim about configuration.
//
// Resolution is keyed by package URL type, because that is how the
// ecosystem already names which registry owns a package. A type with
// no resolver here answers "unknown" rather than guessing — the judge
// turns that into an unevaluated requirement, never into a pass.
package pkgtime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// httpTimeout bounds one registry call end to end; maxBody bounds one
// response, since a metadata document is small and an unbounded read
// of a hostile one is not.
const (
	httpTimeout = 30 * time.Second
	maxBody     = 1 << 20
	// maxASCII is the last code point the proxy's escaping is defined
	// over; beyond it there is no faithful encoding to apply.
	maxASCII = 127
)

// Resolver answers when one package version was published.
type Resolver interface {
	// Published reports the publication time of the version a package
	// URL names. ok=false means this resolver does not serve that
	// package's ecosystem, which is an answer and not an error.
	Published(purl string) (when time.Time, ok bool, err error)
}

// Client resolves publication times from public registries.
type Client struct {
	// GoProxy is the module proxy base; empty uses the public one,
	// which is the same checksummed proxy a Go build already fetches
	// through.
	GoProxy string
	HTTP    *http.Client
}

// New builds a client against the public registries.
func New() *Client {
	return &Client{
		GoProxy: "https://proxy.golang.org",
		HTTP:    &http.Client{Timeout: httpTimeout},
	}
}

// goInfo is the module proxy's version metadata document.
type goInfo struct {
	Version *string `json:"Version"` //nolint:tagliatelle // the proxy's own field names
	Time    *string `json:"Time"`    //nolint:tagliatelle // the proxy's own field names
}

// Published implements Resolver.
//
//nolint:gocritic // unnamedResult: when, ok, err — named on the interface
func (c *Client) Published(purl string) (time.Time, bool, error) {
	module, version, ok := parseGoPurl(purl)
	if !ok {
		// Another ecosystem's package. Saying so is the honest answer;
		// a guess here would become a level.
		return time.Time{}, false, nil
	}

	escaped, err := escapeModule(module)
	if err != nil {
		return time.Time{}, false, err
	}

	endpoint := fmt.Sprintf("%s/%s/@v/%s.info", c.GoProxy, escaped, url.PathEscape(version))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("pkgtime: %w", err)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("pkgtime: %s: %w", module, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only close

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, false, fmt.Errorf("pkgtime: %s@%s: proxy answered %s", module, version, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("pkgtime: %s@%s: %w", module, version, err)
	}

	info, err := jsonx.DecodeForeign[goInfo](body)
	if err != nil || info.Time == nil {
		return time.Time{}, false, fmt.Errorf("pkgtime: %s@%s: the proxy returned no publication time", module, version)
	}

	when, err := time.Parse(time.RFC3339, *info.Time)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("pkgtime: %s@%s: %w", module, version, err)
	}

	return when, true, nil
}

// parseGoPurl splits a Go module package URL into module and version.
//
//nolint:gocritic // unnamedResult: module, version, ok — the stdlib shape
func parseGoPurl(purl string) (string, string, bool) {
	const prefix = "pkg:golang/"

	rest, cut := strings.CutPrefix(purl, prefix)
	if !cut {
		return "", "", false
	}

	// Qualifiers and subpaths are not part of the module identity.
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")

	module, version, ok := strings.Cut(rest, "@")
	if !ok || module == "" || version == "" {
		return "", "", false
	}

	unescaped, err := url.PathUnescape(module)
	if err != nil {
		return "", "", false
	}

	return unescaped, version, true
}

// escapeModule applies the module proxy's case encoding: an uppercase
// letter becomes "!" plus its lowercase form, so that case-insensitive
// filesystems cannot collide two distinct modules.
func escapeModule(module string) (string, error) {
	var b strings.Builder

	for _, r := range module {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		case r > maxASCII:
			return "", fmt.Errorf("pkgtime: module path %q is not ASCII", module)
		default:
			b.WriteRune(r)
		}
	}

	return b.String(), nil
}
