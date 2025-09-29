package eddsa

import (
	"crypto/sha256"
	"encoding/base64"

    "crypto/rand"
    "errors"

    "github.com/cloudflare/circl/sign/ed448"
)

// GenerateEd448 returns raw public/private bytes (binary; not PEM).
func GenerateEd448() (pub, priv []byte, err error) {
    pb, sk, err := ed448.GenerateKey(rand.Reader)
    if err != nil { return nil, nil, err }
    return []byte(pb), []byte(sk), nil
}

// SignEd448 signs message bytes with an Ed448 private key (raw).
// Context is empty by default per RFC8032 allowance.
func SignEd448(priv []byte, msg []byte) ([]byte, string, error) {
    signature := ed448.Sign(ed448.PrivateKey(priv), msg, "")
    // Derive key ID from public key
    pk := ed448.PrivateKey(priv).Public().(ed448.PublicKey)
    kid := fmtKeyID([]byte(pk))
    return signature, kid, nil
}

func VerifyEd448(pub, msg, sig []byte) error {
    ok := ed448.Verify(ed448.PublicKey(pub), msg, sig, "")
    if !ok {
        return errors.New("invalid signature")
    }
    return nil
}

// fmtKeyID creates a short key id from public key bytes.
func fmtKeyID(pub []byte) string {
    // same approach as keyIDFromPub in main: base64(SHA256(pub))[:16]
    // we keep this local to avoid import cycles.
    // The main package will compute its own ID as needed; here we mirror the format.
    h := sha256.Sum256(pub)
	return base64.RawStdEncoding.EncodeToString(h[:])[:16]
}
