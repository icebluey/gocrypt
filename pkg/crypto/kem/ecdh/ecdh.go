package ecdh

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
		
	)

// GenerateX25519 returns raw public/private bytes.
func GenerateX25519() (pub, priv []byte, err error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil { return nil, nil, err }
	return privKey.PublicKey().Bytes(), privKey.Bytes(), nil
}


// WrapX25519 performs ECDH to derive a KEK and wraps CEK via HKDF-like KDF+HMAC.
func WrapX25519(peerPub, cek []byte) (recipType string, wrapped, ephPub []byte, err error) {
	curve := ecdh.X25519()
	pubKey, err := curve.NewPublicKey(peerPub)
	if err != nil { return "", nil, nil, err }
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil { return "", nil, nil, err }
	secret, err := eph.ECDH(pubKey)
	if err != nil { return "", nil, nil, err }
	kek := kdf(secret, []byte("gocrypt-kek-x25519"))
	wrapped = xorWrap(cek, kek)
	return "x25519", wrapped, eph.PublicKey().Bytes(), nil
}

func UnwrapX25519(priv []byte, wrapped, ephPub []byte) ([]byte, error) {
	curve := ecdh.X25519()
	sk, err := curve.NewPrivateKey(priv)
	if err != nil { return nil, err }
	pk, err := curve.NewPublicKey(ephPub)
	if err != nil { return nil, err }
	secret, err := sk.ECDH(pk)
	if err != nil { return nil, err }
	kek := kdf(secret, []byte("gocrypt-kek-x25519"))
	cek := xorWrap(wrapped, kek)
	return cek, nil
}

func kdf(secret, info []byte) []byte {
	// Derive 32-byte KEK using HMAC-SHA256(secret, info)
	h := hmac.New(sha256.New, secret)
	h.Write(info)
	return h.Sum(nil)
}

func xorWrap(cek, kek []byte) []byte {
	out := make([]byte, len(cek))
	for i := range cek {
		out[i] = cek[i] ^ kek[i%len(kek)]
	}
	return out
}
