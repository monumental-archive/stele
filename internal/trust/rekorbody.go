// The Rekor canonicalized body a gitsign offline mint does not carry,
// rebuilt from the material it does (stele#182).
//
// `gitsign.rekorMode=offline` embeds the transparency-log entry as a
// CMS unsigned attribute but omits `canonicalizedBody`: that body is
// a function of the signature and the leaf certificate, both already
// present, so the mint does not carry a second copy of bytes the
// verifier already holds. sigstore-go's validator requires the field,
// so without this every offline-minted tag is refused for being
// exactly what its producer will always make it.
//
// Rebuilding IS the binding, and that is what makes it sound. The
// body is reconstructed from the signed-attribute blob's digest, the
// signature bytes and the leaf — the same three the seam invariant
// (cms.go) extracts byte-exact — and the entry's own
// countersignatures are then proven OVER the reconstruction: a signed
// entry timestamp covering some other body does not verify, and an
// inclusion proof over some other body does not reach its
// checkpoint's root. An entry whose body were merely asserted would
// prove nothing, and nothing here asserts one.
//
// The construction is Rekor's own (types.CanonicalizeEntry), never a
// hand-rolled rendering of the same JSON: the log canonicalized with
// this code, and a second spelling here would be a second definition
// of bytes that must be identical — the share-the-definition law.

package trust

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	hashedrekordv001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// rebuildRekorBody renders the canonicalized body of one entry that
// carries none, keyed by the kind and version the entry itself
// declares.
//
// The known set is closed on purpose. Each Rekor kind binds its
// signature to its subject differently, so a body built to the wrong
// shape would be a guess dressed as evidence — and one that could
// still verify against nothing. A kind outside the set refuses by
// name and says what it would have needed.
//
// Coverage note, deliberate: of the four error returns below, two are
// reachable and table-tested — the closed-set refusal, and the
// proposal refusal that fires when the material does not actually
// sign. The remaining two are fail-closed posture against library
// drift: a certificate that already parsed cannot fail to re-marshal,
// and an entry Rekor's own constructor accepted cannot then fail to
// version or canonicalize. Inducing them would mean faking the
// library, and a fake there proves nothing.
func rebuildRekorBody(kv *protorekor.KindVersion, leaf *x509.Certificate, pieces *cmsPieces) ([]byte, error) {
	kind, version := kv.GetKind(), kv.GetVersion()

	if kind != hashedrekord.KIND || version != hashedrekordv001.APIVERSION {
		return nil, fmt.Errorf(
			"trust: tag signature transparency-log entry carries no canonicalized body and declares kind %s/%s — "+
				"this tool rebuilds %s/%s only, and will not guess another entry shape",
			kind, version, hashedrekord.KIND, hashedrekordv001.APIVERSION)
	}

	leafPEM, err := cryptoutils.MarshalCertificateToPEM(leaf)
	if err != nil {
		return nil, fmt.Errorf("trust: tag signing certificate for the rebuilt transparency-log entry body: %w", err)
	}

	digest := pieces.signedBlobDigest()

	// Rekor's own constructor, which reverifies the signature over the
	// digest with this very certificate before it will render a body:
	// a rebuild from material that does not sign is refused here,
	// before anything is held against the log.
	proposed, err := types.NewProposedEntry(context.Background(), kind, version, types.ArtifactProperties{
		PKIFormat:      string(pki.X509),
		PublicKeyBytes: [][]byte{leafPEM},
		ArtifactHash:   hex.EncodeToString(digest[:]),
		SignatureBytes: pieces.signature,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"trust: rebuilding the %s/%s transparency-log entry body from the tag signature: %w", kind, version, err)
	}

	impl, err := types.CreateVersionedEntry(proposed)
	if err != nil {
		return nil, fmt.Errorf("trust: rebuilt %s/%s transparency-log entry body: %w", kind, version, err)
	}

	body, err := types.CanonicalizeEntry(context.Background(), impl)
	if err != nil {
		return nil, fmt.Errorf("trust: canonicalizing the rebuilt %s/%s transparency-log entry body: %w", kind, version, err)
	}

	return body, nil
}
