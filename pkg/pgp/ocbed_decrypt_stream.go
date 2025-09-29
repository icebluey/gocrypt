package pgp

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"io"

	pmocb "github.com/ProtonMail/go-crypto/ocb"
)

// DecryptOCBEDStream decrypts a Tag 20 body into dst without loading the full ciphertext in memory.
func DecryptOCBEDStream(dst io.Writer, body io.Reader, bodyLen int64, cek []byte) error {
	if len(cek) != 16 && len(cek) != 24 && len(cek) != 32 {
		return errors.New("bad key length")
	}
	if bodyLen < 4+15+16 {
		return errors.New("short ocbed")
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(body, header); err != nil {
		return err
	}
	version := header[0]
	sym := header[1]
	mode := header[2]
	bits := int(header[3])
	if bits <= 0 || bits > 30 {
		return errChunkBits
	}
	chunkSize := 1 << bits

	iv := make([]byte, 15)
	if _, err := io.ReadFull(body, iv); err != nil {
		return err
	}

	cipherLen := bodyLen - 4 - 15
	if cipherLen < 16 {
		return errors.New("short ocbed ciphertext")
	}
	dataLen := cipherLen - 16

	block, err := aes.NewCipher(cek)
	if err != nil {
		return err
	}
	aead, err := pmocb.NewOCB(block)
	if err != nil {
		return err
	}

	aad := []byte{0xD4, version, sym, mode, byte(bits), 0, 0, 0, 0, 0, 0, 0, 0}

	nonce := make([]byte, 15)
	base := binary.BigEndian.Uint64(iv[7:])

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
			return errors.New("ocbed chunk too small")
		}
		n, err := io.ReadFull(dataReader, buf[:toRead])
		if err != nil {
			return err
		}
		copy(nonce, iv)
		binary.BigEndian.PutUint64(nonce[7:], base+chunkIndex)
		pt, err := aead.Open(nil, nonce, buf[:n], aad)
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
	copy(nonce, iv)
	binary.BigEndian.PutUint64(nonce[7:], base+chunkIndex)
	expected := aead.Seal(nil, nonce, nil, finalAAD)
	if !bytesEqual(expected, finalTag) {
		return errors.New("final tag mismatch")
	}
	return nil
}
