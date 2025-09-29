package pgp

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	pmocb "github.com/ProtonMail/go-crypto/ocb"
)

const (
	AEAD_EAX = 1
	AEAD_OCB = 2
	AEAD_GCM = 3
)

const (
	SYM_AES128 = 7
	SYM_AES192 = 8
	SYM_AES256 = 9
)

// BuildSEIPDv2OCB builds a minimal SEIPD v2 (Tag 18) body per RFC 9580 (single-chunk variant).
func BuildSEIPDv2OCB(symAlg, chunkBits int, sessionKey, plaintext []byte) ([]byte, error) {
	if symAlg != SYM_AES192 && symAlg != SYM_AES256 && symAlg != SYM_AES128 {
		return nil, errors.New("unsupported sym alg")
	}
	if len(sessionKey) != 16 && len(sessionKey) != 24 && len(sessionKey) != 32 {
		return nil, errors.New("bad session key length")
	}
	version := byte(2)
	aeadAlg := byte(AEAD_OCB)
	chunkSize := byte(chunkBits & 0xFF)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil { return nil, err }

	mk, iv7, err := kdfSEIPDv2HKDF(sessionKey, salt, version, byte(symAlg), aeadAlg, chunkSize)
	if err != nil { return nil, err }
	aad := []byte{0xD2, version, byte(symAlg), aeadAlg, chunkSize}

	block, err := aes.NewCipher(mk)
	if err != nil { return nil, err }
	aead, err := pmocb.NewOCB(block)
	if err != nil { return nil, err }

	// single chunk (index = 0)
	nonce := make([]byte, 15)
	copy(nonce[:7], iv7)
	copy(nonce[7:], u64be(0))
	ct := aead.Seal(nil, nonce, plaintext, aad)

	// final tag with aad || u64be(totalLen), nonce index = 1
	finalAAD := append(append([]byte{}, aad...), u64be(uint64(len(plaintext)))...)
	copy(nonce[:7], iv7)
	copy(nonce[7:], u64be(1))
	finalTag := aead.Seal(nil, nonce, nil, finalAAD)

	body := make([]byte, 0, 4+32+len(ct)+len(finalTag))
	body = append(body, version, byte(symAlg), aeadAlg, chunkSize)
	body = append(body, salt...)
	body = append(body, ct...)
	body = append(body, finalTag...)
	return Packet(18, body), nil
}

// RFC 9580 HKDF (HMAC-SHA256): info = 0xD2 || version || sym || aead || chunkSize
// Returns (keyM, iv7).
func kdfSEIPDv2HKDF(ikm, salt []byte, version, sym, aead, chunkSize byte) (key []byte, iv []byte, err error) {
	info := []byte{0xD2, version, sym, aead, chunkSize}
	if len(salt) != 32 {
		tmp := make([]byte, 32)
		copy(tmp, salt)
		salt = tmp
	}
	// Extract
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	prk := h.Sum(nil)
	// Expand to 39 bytes (32 + 7)
	h = hmac.New(sha256.New, prk)
	h.Write(append(info, 0x01))
	t1 := h.Sum(nil)
	h = hmac.New(sha256.New, prk)
	h.Write(append(append(t1, info...), 0x02))
	t2 := h.Sum(nil)
	okm := append(t1, t2...)
	return okm[:32], okm[32:39], nil
}

func u64be(x uint64) []byte {
	return []byte{byte(x>>56),byte(x>>48),byte(x>>40),byte(x>>32),byte(x>>24),byte(x>>16),byte(x>>8),byte(x)}
}
