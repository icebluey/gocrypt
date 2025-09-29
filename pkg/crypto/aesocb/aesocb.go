package aesocb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/ocb"
)

// NewAEAD returns an AES-OCB3 AEAD and a fresh random nonce.
func NewAEAD(cipherName string, key []byte) (cipher.AEAD, []byte, error) {
	var want int
	switch cipherName {
	case "aes192":
		want = 24
	case "aes256":
		want = 32
	default:
		return nil, nil, fmt.Errorf("unsupported cipher: %s", cipherName)
	}
	if len(key) != want {
		return nil, nil, fmt.Errorf("bad key length: got %d want %d", len(key), want)
	}
	block, err := aes.NewCipher(key)
	if err != nil { return nil, nil, err }

	// OCB with 15-byte nonce, 16-byte tag.
	a, err := ocb.NewOCBWithNonceAndTagSize(block, 15, 16)
	if err != nil { return nil, nil, err }

	nonce := make([]byte, a.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return a, nonce, nil
}
