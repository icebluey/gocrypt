package rsaenc

import (
    "bytes"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "fmt"
)

func GenerateRSA(bits int) (pub, priv []byte, err error) {
    sk, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil { return nil, nil, err }
    priv = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(sk)})
    pk := &sk.PublicKey
    pubBytes, err := x509.MarshalPKIXPublicKey(pk)
    if err != nil { return nil, nil, err }
    pub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
    return pub, priv, nil
}

func WrapOAEP(pubPEM, cek []byte) ([]byte, error) {
    pk, err := parsePub(pubPEM)
    if err != nil { return nil, err }
    ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, cek, nil)
    return ct, err
}

func UnwrapOAEP(privPEM, ct []byte) ([]byte, error) {
    sk, err := parsePriv(privPEM)
    if err != nil { return nil, err }
    return rsa.DecryptOAEP(sha256.New(), rand.Reader, sk, ct, nil)
}

func SignPSS(privPEM []byte, h crypto.Hash, digest []byte) ([]byte, error) {
    sk, err := parsePriv(privPEM)
    if err != nil { return nil, err }
    return rsa.SignPSS(rand.Reader, sk, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h})
}

func VerifyPSS(pubPEM []byte, h crypto.Hash, digest, sig []byte) error {
    pk, err := parsePub(pubPEM)
    if err != nil { return err }
    return rsa.VerifyPSS(pk, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h})
}

func PublicFromPrivate(privPEM []byte) []byte {
    sk, err := parsePriv(privPEM); if err != nil { return nil }
    pubBytes, _ := x509.MarshalPKIXPublicKey(&sk.PublicKey)
    return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
}

func parsePub(pemBytes []byte) (*rsa.PublicKey, error) {
    block, _ := pem.Decode(bytes.TrimSpace(pemBytes))
    if block == nil { return nil, fmt.Errorf("invalid public key") }
    key, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil { return nil, err }
    pk, ok := key.(*rsa.PublicKey)
    if !ok { return nil, fmt.Errorf("not an RSA public key") }
    return pk, nil
}
func parsePriv(pemBytes []byte) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode(bytes.TrimSpace(pemBytes))
    if block == nil { return nil, fmt.Errorf("invalid private key") }
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}
