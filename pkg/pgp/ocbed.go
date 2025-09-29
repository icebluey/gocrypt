package pgp

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"

	pmocb "github.com/ProtonMail/go-crypto/ocb"
)

func BuildOCBED(symAlg, chunkBits int, cek, plaintext []byte) ([]byte, error) {
	if symAlg != SYM_AES192 && symAlg != SYM_AES256 && symAlg != SYM_AES128 {
		return nil, errors.New("unsupported sym alg")
	}
	if len(cek) != 16 && len(cek) != 24 && len(cek) != 32 {
		return nil, errors.New("bad key length")
	}
	version := byte(1)
	mode := byte(0x02) // OCB
	chunkSize := byte(chunkBits & 0xFF)
	iv := make([]byte, 15)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil { return nil, err }

	aad := []byte{0xD4, version, byte(symAlg), mode, chunkSize, 0,0,0,0,0,0,0,0}

	block, err := aes.NewCipher(cek)
	if err != nil { return nil, err }
	aead, err := pmocb.NewOCB(block)
	if err != nil { return nil, err }
	nonce := make([]byte, 15); copy(nonce, iv)

	ct := aead.Seal(nil, nonce, plaintext, aad)
	finalAAD := append(aad, u64be(uint64(len(plaintext)))...)
	finalTag := aead.Seal(nil, nonce, nil, finalAAD)

	body := make([]byte, 0, 4+15+len(ct)+len(finalTag))
	body = append(body, version, byte(symAlg), mode, chunkSize)
	body = append(body, iv...)
	body = append(body, ct...)
	body = append(body, finalTag...)
	return Packet(20, body), nil
}
