package pgp

import (
	"crypto/aes"
	"errors"
	"io"

	pmocb "github.com/ProtonMail/go-crypto/ocb"
)

// DecryptSEIPDv2OCBStream decrypts a v2 SEIPD (Tag 18) body and writes the
// plaintext to dst without buffering the entire ciphertext in memory.
func DecryptSEIPDv2OCBStream(dst io.Writer, body io.Reader, bodyLen int64, sessionKey []byte) error {
	if len(sessionKey) != 16 && len(sessionKey) != 24 && len(sessionKey) != 32 {
		return errors.New("bad session key length")
	}
	if bodyLen < 4+32+16 {
		return errors.New("short seipd")
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(body, header); err != nil {
		return err
	}
	version := header[0]
	sym := header[1]
	aeadAlg := header[2]
	bits := int(header[3])
	if bits <= 0 || bits > 30 {
		return errChunkBits
	}
	chunkSize := 1 << bits

	salt := make([]byte, 32)
	if _, err := io.ReadFull(body, salt); err != nil {
		return err
	}

	cipherLen := bodyLen - 4 - 32
	if cipherLen < 16 {
		return errors.New("short seipd ciphertext")
	}
	dataLen := cipherLen - 16

	mk, iv7, err := kdfSEIPDv2HKDF(sessionKey, salt, version, sym, aeadAlg, byte(bits))
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(mk)
	if err != nil {
		return err
	}
	aead, err := pmocb.NewOCB(block)
	if err != nil {
		return err
	}

	aad := []byte{0xD2, version, sym, aeadAlg, byte(bits)}

	nonce := make([]byte, 15)
	copy(nonce[:7], iv7)

	buf := make([]byte, chunkSize+16)
	dataReader := io.LimitReader(body, dataLen)

	var chunkIndex uint64
	var totalPlain uint64
	for remaining := dataLen; remaining > 0; {
		toRead := chunkSize + 16
		if int64(toRead) > remaining {
			toRead = int(remaining)
		}
		if toRead < 16 {
			return errors.New("seipd chunk too small")
		}
		n, err := io.ReadFull(dataReader, buf[:toRead])
		if err != nil {
			return err
		}
		chunk := buf[:n]
		copy(nonce[7:], u64be(chunkIndex))
		pt, err := aead.Open(nil, nonce, chunk, aad)
		if err != nil {
			return err
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
		totalPlain += uint64(len(pt))
		chunkIndex++
		remaining -= int64(n)
	}

	finalTag := make([]byte, 16)
	if _, err := io.ReadFull(body, finalTag); err != nil {
		return err
	}
	finalAAD := append(append([]byte{}, aad...), u64be(totalPlain)...)
	copy(nonce[:7], iv7)
	copy(nonce[7:], u64be(chunkIndex))
	expected := aead.Seal(nil, nonce, nil, finalAAD)
	if !bytesEqual(expected, finalTag) {
		return errors.New("final tag mismatch")
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
