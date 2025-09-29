package pgp

import (
	"encoding/binary"
	"errors"
	"fmt"
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
		if len(pub) != 32 {
			return nil, errors.New("X25519 pub must be 32 bytes")
		}
		matLen = 32
	case PKALG_X448:
		if len(pub) != 56 {
			return nil, errors.New("X448 pub must be 56 bytes")
		}
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
	if err != nil {
		return nil, err
	}
	// strip the Tag6 header to keep only the Public Key packet body to embed
	_, pubBody, _, err := ReadPacket(pubPkt)
	if err != nil {
		return nil, err
	}
	var need int
	switch alg {
	case PKALG_X25519:
		need = 32
	case PKALG_X448:
		need = 56
	default:
		return nil, errors.New("unsupported alg for secret key")
	}
	if len(priv) != need {
		return nil, errors.New("bad secret size")
	}
	// Secret-Key packet: Public fields || s2k usage (0) || secret material
	body := make([]byte, 0, len(pubBody)+1+len(priv))
	body = append(body, pubBody...)
	body = append(body, 0) // s2k usage octet = 0 (no protection)
	body = append(body, priv...)
	return Packet(5, body), nil
}

// ParsePublicKeyV6 extracts the algorithm identifier and raw public key bytes from a
// minimal v6 Public-Key (Tag 6) packet produced by BuildPublicKeyV6 or equivalent.
func ParsePublicKeyV6(pkt []byte) (int, []byte, error) {
	tag, body, rest, err := ReadPacket(pkt)
	if err != nil {
		return 0, nil, err
	}
	if len(rest) != 0 {
		return 0, nil, errors.New("pgp: unexpected extra data after public key packet")
	}
	if tag != 6 {
		return 0, nil, errors.New("pgp: packet is not Tag 6 public key")
	}
	if len(body) < 1+4+1+4 {
		return 0, nil, errors.New("pgp: public key body too short")
	}
	if body[0] != 6 {
		return 0, nil, errors.New("pgp: unsupported public key version")
	}
	alg := int(body[1+4])
	pubLen := int(binary.BigEndian.Uint32(body[1+4+1 : 1+4+1+4]))
	off := 1 + 4 + 1 + 4
	if len(body) < off+pubLen {
		return 0, nil, errors.New("pgp: truncated public key material")
	}
	pub := body[off : off+pubLen]
	switch alg {
	case PKALG_X25519:
		if len(pub) != 32 {
			return 0, nil, fmt.Errorf("pgp: expected 32 byte X25519 key, got %d", len(pub))
		}
	case PKALG_X448:
		if len(pub) != 56 {
			return 0, nil, fmt.Errorf("pgp: expected 56 byte X448 key, got %d", len(pub))
		}
	default:
		return 0, nil, fmt.Errorf("pgp: unsupported public key algorithm %d", alg)
	}
	return alg, pub, nil
}

// ParseSecretKeyV6 extracts the algorithm identifier, public key bytes, and secret key
// bytes from a minimal v6 Secret-Key (Tag 5) packet produced by BuildSecretKeyV6 or equivalent.
func ParseSecretKeyV6(pkt []byte) (int, []byte, []byte, error) {
	tag, body, rest, err := ReadPacket(pkt)
	if err != nil {
		return 0, nil, nil, err
	}
	if len(rest) != 0 {
		return 0, nil, nil, errors.New("pgp: unexpected extra data after secret key packet")
	}
	if tag != 5 {
		return 0, nil, nil, errors.New("pgp: packet is not Tag 5 secret key")
	}
	if len(body) < 1+4+1+4+1 {
		return 0, nil, nil, errors.New("pgp: secret key body too short")
	}
	if body[0] != 6 {
		return 0, nil, nil, errors.New("pgp: unsupported secret key version")
	}
	alg := int(body[1+4])
	pubLen := int(binary.BigEndian.Uint32(body[1+4+1 : 1+4+1+4]))
	off := 1 + 4 + 1 + 4
	if len(body) < off+pubLen+1 {
		return 0, nil, nil, errors.New("pgp: truncated secret key material")
	}
	pub := body[off : off+pubLen]
	s2kUsage := body[off+pubLen]
	if s2kUsage != 0 {
		return 0, nil, nil, fmt.Errorf("pgp: unsupported s2k usage %d", s2kUsage)
	}
	priv := body[off+pubLen+1:]
	switch alg {
	case PKALG_X25519:
		if len(pub) != 32 || len(priv) != 32 {
			return 0, nil, nil, fmt.Errorf("pgp: expected 32 byte X25519 keys, got pub=%d priv=%d", len(pub), len(priv))
		}
	case PKALG_X448:
		if len(pub) != 56 || len(priv) != 56 {
			return 0, nil, nil, fmt.Errorf("pgp: expected 56 byte X448 keys, got pub=%d priv=%d", len(pub), len(priv))
		}
	default:
		return 0, nil, nil, fmt.Errorf("pgp: unsupported secret key algorithm %d", alg)
	}
	return alg, pub, priv, nil
}
