package hash

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

func Digest(name string, data []byte) ([]byte, crypto.Hash, error) {
	switch name {
	case "sha256":
		h := sha256.Sum256(data)
		return h[:], crypto.SHA256, nil
	case "sha384":
		sum := sha512.Sum384(data)
		return sum[:], crypto.SHA384, nil
	case "sha512":
		sum := sha512.Sum512(data)
		return sum[:], crypto.SHA512, nil
	default:
		return nil, 0, fmt.Errorf("unsupported hash: %s", name)
	}
}
