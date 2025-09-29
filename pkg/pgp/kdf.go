package pgp

import "crypto/sha256"

// kdfConcatSHA256 implements a minimal Concatenation KDF: Hash(0x00000001 || Z || params)
func kdfConcatSHA256(shared, params []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0,0,0,1})
	h.Write(shared)
	h.Write(params)
	return h.Sum(nil)
}
