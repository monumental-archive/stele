// The repository-metadata read surface (stele#40): the two facts a
// release's image annotations fall back to when the tree does not
// declare them — the licence the forge detects, and the repository
// description.
//
// Its own interface, like RulesReader and TagReader, and for the same
// reason: the facts resolver has no business being handed a seam that
// can list releases.

package gh

import (
	"fmt"
	"net/url"

	"github.com/monumental-archive/stele/internal/jsonx"
)

// MetaReader is the repository-metadata surface.
type MetaReader interface {
	// Licence returns the SPDX id the forge detects for a repository
	// at one ref. ok=false means the forge detected nothing usable —
	// an answer, not an error: a repository may genuinely carry no
	// recognised licence file, and the caller decides whether that is
	// fatal.
	Licence(owner, repo, ref string) (id string, ok bool, err error)
	// Description returns the repository's description, empty when it
	// has none.
	Description(owner, repo string) (string, error)
}

// licenceDoc is the forge's licence response. Foreign: the endpoint
// is somebody else's evolving schema.
type licenceDoc struct {
	License *struct {
		SPDXID *string `json:"spdx_id"`
	} `json:"license"`
}

// The values the forge uses for "no usable answer". Detection is a
// heuristic reading of one file, so it has several ways of saying it
// found nothing, and every one of them must mean absent rather than
// become a licence.
func unusableLicence(id string) bool {
	switch id {
	case "", "NOASSERTION", "NONE", "OTHER":
		return true
	default:
		return false
	}
}

// Licence implements MetaReader: the id, whether one was detected,
// and any error reading.
//
//nolint:gocritic // unnamedResult: named results are refused by nonamedreturns
func (c *Client) Licence(owner, repo, ref string) (string, bool, error) {
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/license"
	if ref != "" {
		path += "?ref=" + url.QueryEscape(ref)
	}

	body, ok, err := c.get(path, ghJSON)
	if err != nil {
		return "", false, err
	}

	if !ok {
		return "", false, nil
	}

	// Decoded from the captured body rather than read through a
	// server-side filter: the CLI this replaces printed the error body
	// to stdout on an HTTP error, so a failed request could be parsed
	// as a licence.
	doc, err := jsonx.DecodeForeign[licenceDoc](body)
	if err != nil {
		return "", false, fmt.Errorf("gh: %s: %w", path, err)
	}

	if doc.License == nil || doc.License.SPDXID == nil || unusableLicence(*doc.License.SPDXID) {
		return "", false, nil
	}

	return *doc.License.SPDXID, true, nil
}

// repoDoc carries the description.
type repoDoc struct {
	Description *string `json:"description"`
}

// Description implements MetaReader.
func (c *Client) Description(owner, repo string) (string, error) {
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo)

	body, ok, err := c.get(path, ghJSON)
	if err != nil {
		return "", err
	}

	if !ok {
		return "", nil
	}

	doc, err := jsonx.DecodeForeign[repoDoc](body)
	if err != nil {
		return "", fmt.Errorf("gh: %s: %w", path, err)
	}

	if doc.Description == nil {
		return "", nil
	}

	return *doc.Description, nil
}
