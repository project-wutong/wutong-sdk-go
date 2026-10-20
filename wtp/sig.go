// SPDX-License-Identifier: AGPL-3.0-only

package wtp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"regexp"
)

// Signing-input domain separation prefixes (WTP-STD-001 §8).
var (
	JCSPrefix  = []byte("WUTONG-SIG-V0.1\x00")
	CBORPrefix = []byte("WUTONG-CBOR-SIG-V0.1\x00")
)

// Encoding selects the canonical form that is signed.
type Encoding string

// Supported signature encodings.
const (
	EncodingJCS   Encoding = "jcs"
	EncodingDCBOR Encoding = "dcbor"
)

// SmallOrderPublicKeys lists weak Ed25519 public keys that must be rejected.
var SmallOrderPublicKeys = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
}

var nonceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// Auth is the envelope "auth" member.
type Auth struct {
	SignerID, KeyID, IssuedAt, Nonce string
}

// SigningInput returns prefix || canonical(envelope without "proof").
func SigningInput(envelope map[string]any, enc Encoding) ([]byte, error) {
	m := make(map[string]any, len(envelope))
	for k, v := range envelope {
		if k != "proof" {
			m[k] = v
		}
	}
	switch enc {
	case EncodingJCS, "":
		c, err := JCS(m)
		if err != nil {
			return nil, err
		}
		return append(append([]byte{}, JCSPrefix...), c...), nil
	case EncodingDCBOR:
		c, err := DCBOR(m)
		if err != nil {
			return nil, err
		}
		return append(append([]byte{}, CBORPrefix...), c...), nil
	default:
		return nil, errf(ErrSignature, "unsupported encoding %q", enc)
	}
}

// Sign adds auth and an Ed25519 proof to an unsigned envelope. When enc is
// EncodingDCBOR, proof.encoding is set to "dcbor".
func Sign(envelope map[string]any, key ed25519.PrivateKey, a Auth, enc Encoding) (map[string]any, error) {
	if _, ok := envelope["auth"]; ok {
		return nil, errf(ErrSignature, "already has auth")
	}
	if _, ok := envelope["proof"]; ok {
		return nil, errf(ErrSignature, "already has proof")
	}
	if !nonceRe.MatchString(a.Nonce) {
		return nil, errf(ErrSignature, "bad nonce")
	}
	out := make(map[string]any, len(envelope)+2)
	for k, v := range envelope {
		out[k] = v
	}
	out["auth"] = map[string]any{"signer_id": a.SignerID, "key_id": a.KeyID, "issued_at": a.IssuedAt, "nonce": a.Nonce}
	in, err := SigningInput(out, enc)
	if err != nil {
		return nil, err
	}
	proof := map[string]any{"alg": "Ed25519", "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, in))}
	if enc == EncodingDCBOR {
		proof["encoding"] = "dcbor"
	}
	out["proof"] = proof
	return out, nil
}

// ValidatePublicKey rejects malformed and small-order Ed25519 public keys.
func ValidatePublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errf(ErrSignature, "public key must be 32 bytes")
	}
	h := hex.EncodeToString(pub)
	for _, w := range SmallOrderPublicKeys {
		if h == w {
			return errf(ErrSignature, "weak or small-order public key rejected")
		}
	}
	return nil
}

// Verify checks the proof of a signed envelope (signature only: replay, clock-skew and
// key binding policy are the caller's responsibility).
func Verify(envelope map[string]any, pub ed25519.PublicKey) error {
	if err := ValidatePublicKey(pub); err != nil {
		return err
	}
	auth, ok := envelope["auth"].(map[string]any)
	if !ok {
		return errf(ErrSignature, "missing auth")
	}
	if n, _ := auth["nonce"].(string); !nonceRe.MatchString(n) {
		return errf(ErrSignature, "bad nonce")
	}
	proof, ok := envelope["proof"].(map[string]any)
	if !ok {
		return errf(ErrSignature, "missing proof")
	}
	if proof["alg"] != "Ed25519" {
		return errf(ErrSignature, "unsupported alg")
	}
	enc := EncodingJCS
	if e, present := proof["encoding"]; present {
		s, _ := e.(string)
		enc = Encoding(s)
	}
	s, _ := proof["sig"].(string)
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != s {
		return errf(ErrSignature, "non-canonical base64url signature")
	}
	in, err := SigningInput(envelope, enc)
	if err != nil {
		return err
	}
	// crypto/ed25519 rejects non-canonical S (S >= L).
	if !ed25519.Verify(pub, in, sig) {
		return errf(ErrSignature, "signature verification failed")
	}
	return nil
}
