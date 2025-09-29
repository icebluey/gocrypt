package aeskw

import (
	"crypto/aes"
	"errors"
)

// Wrap wraps plaintext using RFC 3394 AES Key Wrap with the default IV.
func Wrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext)%8 != 0 || len(plaintext) < 16 {
		return nil, errors.New("plain length must be multiple of 8 and >= 16")
	}
	block, err := aes.NewCipher(kek)
	if err != nil { return nil, err }
	iv := []byte{0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6}
	N := len(plaintext)/8
	A := make([]byte, 8)
	copy(A, iv)
	R := make([][]byte, N)
	for i:=0; i<N; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], plaintext[i*8:(i+1)*8])
	}
	buf := make([]byte, 16)
	for j:=0; j<6; j++ {
		for i:=0; i<N; i++ {
			copy(buf[:8], A)
			copy(buf[8:], R[i])
			block.Encrypt(buf, buf)
			// t = (n*j) + (i+1)
			t := uint64(N*j + (i+1))
			for k:=0; k<8; k++ {
				A[k] = buf[k] ^ byte(t>>(56-8*k))
			}
			copy(R[i], buf[8:])
		}
	}
	out := make([]byte, 8+8*N)
	copy(out[:8], A)
	for i:=0; i<N; i++ { copy(out[8+8*i:8+8*(i+1)], R[i]) }
	return out, nil
}

// Unwrap decrypts RFC 3394 AES Key Wrap with the default IV.
func Unwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped)%8 != 0 || len(wrapped) < 24 {
		return nil, errors.New("wrapped length must be multiple of 8 and >= 24")
	}
	block, err := aes.NewCipher(kek)
	if err != nil { return nil, err }
	iv := []byte{0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6}
	N := (len(wrapped)/8) - 1
	A := make([]byte, 8)
	copy(A, wrapped[:8])
	R := make([][]byte, N)
	for i:=0; i<N; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], wrapped[8+8*i:8+8*(i+1)])
	}
	buf := make([]byte, 16)
	for j:=5; j>=0; j-- {
		for i:=N-1; i>=0; i-- {
			// (A ^ t) | R[i]
			t := uint64(N*j + (i+1))
			for k:=0; k<8; k++ { buf[k] = A[k] ^ byte(t>>(56-8*k)) }
			copy(buf[8:], R[i])
			block.Decrypt(buf, buf)
			copy(A, buf[:8])
			copy(R[i], buf[8:])
		}
	}
	// verify IV
	for i:=0; i<8; i++ {
		if A[i] != iv[i] { return nil, errors.New("integrity check failed") }
	}
	out := make([]byte, 8*N)
	for i:=0; i<N; i++ { copy(out[8*i:8*(i+1)], R[i]) }
	return out, nil
}
