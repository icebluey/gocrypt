package mlkem

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/cloudflare/circl/kem"
	mlkem1024 "github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func schemeByName(name string) (kem.Scheme, error) {
	switch name {
	case "mlkem768":
		return mlkem768.Scheme(), nil
	case "mlkem1024":
		return mlkem1024.Scheme(), nil
	default:
		return nil, fmt.Errorf("unknown scheme: %s", name)
	}
}

func hkdfLike(ss []byte, info []byte, n int) []byte {
	h := hmac.New(sha256.New, ss)
	h.Write(info)
	out := h.Sum(nil)
	if n <= len(out) {
		return out[:n]
	}
	// simple expand if >32 bytes
	buf := make([]byte, 0, n)
	t := out
	for len(buf) < n {
		h = hmac.New(sha256.New, ss)
		h.Write(t)
		h.Write(info)
		t = h.Sum(nil)
		buf = append(buf, t...)
	}
	return buf[:n]
}

// Wrap derives KEK from KEM shared secret and XOR-wraps CEK. Returns kemCT in third value.
func Wrap(name string, pub []byte, cek []byte) (recipType string, wrapped, kemCT []byte, err error) {
	s, err := schemeByName(name)
	if err != nil {
		return "", nil, nil, err
	}
	pk, err := s.UnmarshalBinaryPublicKey(pub)
	if err != nil {
		return "", nil, nil, err
	}
	ct, ss, err := s.Encapsulate(pk)
	if err != nil {
		return "", nil, nil, err
	}
	kek := hkdfLike(ss, []byte("gocrypt-kek-mlkem"), len(cek))
	wrapped = make([]byte, len(cek))
	for i := range cek {
		wrapped[i] = cek[i] ^ kek[i]
	}
	return name, wrapped, ct, nil
}

// Unwrap uses kemCT to recover CEK from XOR-wrapped bytes.
func Unwrap(name string, priv []byte, wrapped []byte, kemCT []byte) ([]byte, error) {
	s, err := schemeByName(name)
	if err != nil {
		return nil, err
	}
	sk, err := s.UnmarshalBinaryPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	ss, err := s.Decapsulate(sk, kemCT)
	if err != nil {
		return nil, err
	}
	kek := hkdfLike(ss, []byte("gocrypt-kek-mlkem"), len(wrapped))
	cek := make([]byte, len(wrapped))
	for i := range wrapped {
		cek[i] = wrapped[i] ^ kek[i]
	}
	return cek, nil
}

// Generate returns (public, private) raw bytes for the given ML-KEM scheme.
func Generate(name string) (pub, priv []byte, err error) {
	s, err := schemeByName(name)
	if err != nil {
		return nil, nil, err
	}
	pk, sk, err := s.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	bpk, _ := pk.MarshalBinary()
	bsk, _ := sk.MarshalBinary()
	return bpk, bsk, nil
}
