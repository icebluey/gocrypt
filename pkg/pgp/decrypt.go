package pgp

import (
	"bytes"
	"crypto/aes"
	"errors"

	pmocb "github.com/ProtonMail/go-crypto/ocb"
)

// DecryptSEIPDv2OCB decrypts a v2 SEIPD (Tag 18) body using the given session key (single-chunk variant).
func DecryptSEIPDv2OCB(body []byte, sessionKey []byte) ([]byte, error) {
	if len(body) < 4+32+16 { return nil, errors.New("short seipd") }
	version := body[0]; sym := body[1]; aead := body[2]; chunk := body[3]
	_ = version; _ = sym; _ = aead; _ = chunk
	salt := body[4:36]
	rest := body[36:]
	if len(rest) < 16 { return nil, errors.New("no ciphertext") }
	ct := rest[:len(rest)-16]
	finalTag := rest[len(rest)-16:]

	mk, iv7, err := kdfSEIPDv2HKDF(sessionKey, salt, version, sym, aead, chunk)
	if err != nil { return nil, err }
	block, err := aes.NewCipher(mk); if err != nil { return nil, err }
	aeadOCB, err := pmocb.NewOCB(block); if err != nil { return nil, err }
	aad := []byte{0xD2, version, sym, aead, chunk}

	nonce := make([]byte, 15)
	copy(nonce[:7], iv7)
	copy(nonce[7:], u64be(0))

	pt, err := aeadOCB.Open(nil, nonce, ct, aad)
	if err != nil { return nil, err }

	finalAAD := append(append([]byte{}, aad...), u64be(uint64(len(pt)))...)
	copy(nonce[:7], iv7)
	copy(nonce[7:], u64be(1))
	tag := aeadOCB.Seal(nil, nonce, nil, finalAAD)
	if !bytes.Equal(tag, finalTag) { return nil, errors.New("final tag mismatch") }
	return pt, nil
}

// DecryptOCBED decrypts a LibrePGP OCBED (Tag 20) body using the given CEK.
func DecryptOCBED(body []byte, cek []byte) ([]byte, error) {
	if len(body) < 4+15+16 { return nil, errors.New("short ocbed") }
	version := body[0]; sym := body[1]; mode := body[2]; chunk := body[3]
	_ = version; _ = sym; _ = mode; _ = chunk
	iv := body[4:19]
	rest := body[19:]
	if len(rest) < 16 { return nil, errors.New("no ciphertext") }
	ct := rest[:len(rest)-16]
	_ = rest[len(rest)-16:]
	block, err := aes.NewCipher(cek); if err != nil { return nil, err }
	aeadOCB, err := pmocb.NewOCB(block); if err != nil { return nil, err }
	aad := []byte{0xD4, version, sym, mode, chunk, 0,0,0,0,0,0,0,0}
	nonce := make([]byte, 15); copy(nonce, iv)
	pt, err := aeadOCB.Open(nil, nonce, ct, aad)
	if err != nil { return nil, err }
	return pt, nil
}
