package pgp

import (
	"encoding/binary"
	"errors"
	"time"
)

// Algorithm IDs (RFC 9580 / IANA OpenPGP registry)
const (
	PKALG_RSA    = 1
	PKALG_ECDH   = 18
	PKALG_X25519 = 25
	PKALG_X448   = 26
)

// BuildPublicKeyV6 builds a minimal v6 Public-Key (Tag 6) packet body for X25519/X448.
// version(6) || created(4) || alg(1) || pubMatLen(4) || pubMat
func BuildPublicKeyV6(alg int, pub []byte) ([]byte, error) {
	var matLen int
	switch alg {
	case PKALG_X25519:
		if len(pub) != 32 { return nil, errors.New("X25519 pub must be 32 bytes") }
		matLen = 32
	case PKALG_X448:
		if len(pub) != 56 { return nil, errors.New("X448 pub must be 56 bytes") }
		matLen = 56
	default:
		return nil, errors.New("unsupported alg for v6 key")
	}
	b := make([]byte, 0, 1+4+1+4+matLen)
	b = append(b, 6) // version
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], uint32(time.Now().Unix()))
	b = append(b, t[:]...)
	b = append(b, byte(alg))
	binary.BigEndian.PutUint32(t[:], uint32(matLen))
	b = append(b, t[:]...)
	b = append(b, pub...)
	return Packet(6, b), nil
}

// BuildSecretKeyV6 builds a minimal v6 Secret-Key (Tag 5) packet body for X25519/X448 with S2K usage=0 (unencrypted).
// It embeds the v6 public-key fields first, then S2K usage octet 0, then the secret key material in native bytes.
func BuildSecretKeyV6(alg int, pub, priv []byte) ([]byte, error) {
	pubPkt, err := BuildPublicKeyV6(alg, pub)
	if err != nil { return nil, err }
	// strip the Tag6 header to keep only the Public Key packet body to embed
	_, pubBody, _, err := ReadPacket(pubPkt)
	if err != nil { return nil, err }
	var need int
	switch alg {
	case PKALG_X25519: need = 32
	case PKALG_X448: need = 56
	default: return nil, errors.New("unsupported alg for secret key")
	}
	if len(priv) != need { return nil, errors.New("bad secret size") }
	// Secret-Key packet: Public fields || s2k usage (0) || secret material
	body := make([]byte, 0, len(pubBody)+1+len(priv))
	body = append(body, pubBody...)
	body = append(body, 0) // s2k usage octet = 0 (no protection)
	body = append(body, priv...)
	return Packet(5, body), nil
}
