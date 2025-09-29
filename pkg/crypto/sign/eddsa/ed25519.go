package eddsa

import (
    "bytes"
    "crypto/ed25519"
    "crypto/x509"
    "encoding/pem"
    "errors"
)

func GenerateEd25519() (pub, priv []byte, err error) {
    pubKey, privKey, err := ed25519.GenerateKey(nil)
    if err != nil { return nil, nil, err }
    // PKCS#8 private key
    pkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
    if err != nil { return nil, nil, err }
    priv = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
    // SPKI public key
    pubDer, err := x509.MarshalPKIXPublicKey(pubKey)
    if err != nil { return nil, nil, err }
    pub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
    return pub, priv, nil
}

// For Ed25519 we sign the provided bytes directly (caller decides hash policy).
func SignEd25519(privPem []byte, msg []byte) []byte {
    _, sk := ParseEd25519(privPem)
    return ed25519.Sign(sk, msg)
}

func VerifyEd25519(pubPem []byte, msg, sig []byte) error {
    pk := ParseEd25519Pub(pubPem)
    if !ed25519.Verify(pk, msg, sig) {
        return ErrVerify
    }
    return nil
}

func PublicFromPrivate(privPem []byte) []byte {
    pk, _ := ParseEd25519(privPem)
    der, _ := x509.MarshalPKIXPublicKey(pk)
    return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

var ErrVerify = errors.New("invalid signature")

func ParseEd25519(privPem []byte) (ed25519.PublicKey, ed25519.PrivateKey) {
    block, _ := pem.Decode(bytes.TrimSpace(privPem))
    keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return nil, nil
    }
    sk := keyAny.(ed25519.PrivateKey)
    return sk.Public().(ed25519.PublicKey), sk
}

func ParseEd25519Pub(pubPem []byte) ed25519.PublicKey {
    block, _ := pem.Decode(bytes.TrimSpace(pubPem))
    keyAny, _ := x509.ParsePKIXPublicKey(block.Bytes)
    return keyAny.(ed25519.PublicKey)
}
