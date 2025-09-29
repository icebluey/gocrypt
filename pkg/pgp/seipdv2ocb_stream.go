package pgp

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"

	pmocb "github.com/ProtonMail/go-crypto/ocb"
)

var errChunkBits = errors.New("pgp: invalid chunk bits")

// WriteSEIPDv2OCBStream writes a v2 SEIPD (Tag 18) body to dst encrypting
// plaintext read from src. The returned int64 is the number of bytes written to dst.
func WriteSEIPDv2OCBStream(dst io.Writer, symAlg, chunkBits int, sessionKey []byte, src io.Reader) (int64, error) {
	if symAlg != SYM_AES192 && symAlg != SYM_AES256 && symAlg != SYM_AES128 {
		return 0, errors.New("unsupported sym alg")
	}
	if len(sessionKey) != 16 && len(sessionKey) != 24 && len(sessionKey) != 32 {
		return 0, errors.New("bad session key length")
	}
	if chunkBits <= 0 || chunkBits > 30 {
		return 0, errChunkBits
	}
	chunkSize := 1 << chunkBits

	version := byte(2)
	aeadAlg := byte(AEAD_OCB)
	chunkSizeByte := byte(chunkBits & 0xFF)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return 0, err
	}

	mk, iv7, err := kdfSEIPDv2HKDF(sessionKey, salt, version, byte(symAlg), aeadAlg, chunkSizeByte)
	if err != nil {
		return 0, err
	}

	aad := []byte{0xD2, version, byte(symAlg), aeadAlg, chunkSizeByte}

	block, err := aes.NewCipher(mk)
	if err != nil {
		return 0, err
	}
	aead, err := pmocb.NewOCB(block)
	if err != nil {
		return 0, err
	}

	var written int64
	header := []byte{version, byte(symAlg), aeadAlg, chunkSizeByte}
	n, err := dst.Write(header)
	written += int64(n)
	if err != nil {
		return written, err
	}
	n, err = dst.Write(salt)
	written += int64(n)
	if err != nil {
		return written, err
	}

	buf := make([]byte, chunkSize)
	nonce := make([]byte, 15)
	copy(nonce[:7], iv7)

	var chunkIndex uint64
	var totalPlain uint64
	for {
		n, readErr := io.ReadAtLeast(src, buf, chunkSize)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return written, readErr
		}

		if readErr == io.ErrUnexpectedEOF {
			n = len(buf[:n])
		}
		if n == 0 {
			break
		}

		copy(nonce[7:], u64be(chunkIndex))
		ct := aead.Seal(nil, nonce, buf[:n], aad)
		totalPlain += uint64(n)
		chunkIndex++
		n2, err := dst.Write(ct)
		written += int64(n2)
		if err != nil {
			return written, err
		}

		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	finalAAD := append(append([]byte{}, aad...), u64be(totalPlain)...)
	copy(nonce[:7], iv7)
	copy(nonce[7:], u64be(chunkIndex))
	finalTag := aead.Seal(nil, nonce, nil, finalAAD)
	n, err = dst.Write(finalTag)
	written += int64(n)
	return written, err
}
