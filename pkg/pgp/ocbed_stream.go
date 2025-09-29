package pgp

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	pmocb "github.com/ProtonMail/go-crypto/ocb"
)

// WriteOCBEDStream writes a LibrePGP OCB Encrypted Data (Tag 20) body without buffering the plaintext.
func WriteOCBEDStream(dst io.Writer, symAlg, chunkBits int, cek []byte, src io.Reader) (int64, error) {
	if symAlg != SYM_AES192 && symAlg != SYM_AES256 && symAlg != SYM_AES128 {
		return 0, errors.New("unsupported sym alg")
	}
	if len(cek) != 16 && len(cek) != 24 && len(cek) != 32 {
		return 0, errors.New("bad key length")
	}
	if chunkBits <= 0 || chunkBits > 30 {
		return 0, errChunkBits
	}
	chunkSize := 1 << chunkBits

	version := byte(1)
	mode := byte(0x02)
	chunkByte := byte(chunkBits & 0xFF)

	iv := make([]byte, 15)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return 0, err
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return 0, err
	}
	aead, err := pmocb.NewOCB(block)
	if err != nil {
		return 0, err
	}

	header := []byte{version, byte(symAlg), mode, chunkByte}
	var written int64
	n, err := dst.Write(header)
	written += int64(n)
	if err != nil {
		return written, err
	}
	n, err = dst.Write(iv)
	written += int64(n)
	if err != nil {
		return written, err
	}

	aad := []byte{0xD4, version, byte(symAlg), mode, chunkByte, 0, 0, 0, 0, 0, 0, 0, 0}

	buf := make([]byte, chunkSize)
	nonce := make([]byte, 15)
	base := binary.BigEndian.Uint64(iv[7:])

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

		copy(nonce, iv)
		binary.BigEndian.PutUint64(nonce[7:], base+chunkIndex)
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

	copy(nonce, iv)
	binary.BigEndian.PutUint64(nonce[7:], base+chunkIndex)
	finalAAD := append(append([]byte{}, aad...), u64be(totalPlain)...)
	finalTag := aead.Seal(nil, nonce, nil, finalAAD)
	n, err = dst.Write(finalTag)
	written += int64(n)
	return written, err
}
