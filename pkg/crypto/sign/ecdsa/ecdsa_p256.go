package ecdsa

import (
    "bytes"
    "crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "encoding/asn1"
    "encoding/pem"
    "errors"
    "math/big"
)

func GenerateP256() (pub, priv []byte, err error) {
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { return nil, nil, err }
    der, err := x509.MarshalECPrivateKey(privKey)
    if err != nil { return nil, nil, err }
    priv = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
    pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
    if err != nil { return nil, nil, err }
    pub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
    return pub, priv, nil
}

func SignP256(privPem []byte, h crypto.Hash, digest []byte) ([]byte, error) {
    block, _ := pem.Decode(bytes.TrimSpace(privPem))
    sk, err := x509.ParseECPrivateKey(block.Bytes)
    if err != nil { return nil, err }
    r, s, err := ecdsa.Sign(rand.Reader, sk, digest)
    if err != nil { return nil, err }
    return asn1Encode(r, s)
}

func VerifyP256(pubPem []byte, h crypto.Hash, digest, sig []byte) error {
    block, _ := pem.Decode(bytes.TrimSpace(pubPem))
    keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil { return err }
    pk := keyAny.(*ecdsa.PublicKey)
    r, s, err := asn1Decode(sig)
    if err != nil { return err }
    if !ecdsa.Verify(pk, digest, r, s) {
        return errors.New("invalid signature")
    }
    return nil
}

func asn1Encode(r, s *big.Int) ([]byte, error) {
    return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}
func asn1Decode(b []byte) (*big.Int, *big.Int, error) {
    var v struct{ R, S *big.Int }
    _, err := asn1.Unmarshal(b, &v)
    return v.R, v.S, err
}

// PublicFromPrivate derives PEM SPKI public key from an EC private key (P-256).
func PublicFromPrivate(privPem []byte) []byte {
    block, _ := pem.Decode(bytes.TrimSpace(privPem))
    sk, err := x509.ParseECPrivateKey(block.Bytes)
    if err != nil { return nil }
    pubBytes, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
    if err != nil { return nil }
    return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
}
