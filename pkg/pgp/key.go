package pgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"crypto/sha256"
)

// Algorithm IDs (RFC 9580 / IANA OpenPGP registry and LibrePGP §14 composites)
const (
	PKALG_RSA             = 1
	PKALG_ECDH            = 18
	PKALG_X25519          = 25
	PKALG_X448            = 26
	PKALG_MLKEM768_X25519 = 29
	PKALG_MLKEM1024_X448  = 30
	PKALG_MLKEM768_P256   = 31
	PKALG_MLKEM1024_P384  = 32
	PKALG_MLKEM768_BP256  = 33
	PKALG_MLKEM1024_BP384 = 34
)

// PublicKey describes the algorithm-specific material extracted from a v6
// Public-Key packet.  Composite schemes carry both an ECC point and an ML-KEM
// public key along with the key fingerprint required by LibrePGP §14.
type PublicKey struct {
	Algorithm   int
	Fingerprint [32]byte
	ECCPublic   []byte
	MLKEMPublic []byte
}

// SecretKey describes the key material extracted from a v6 Secret-Key packet.
// It embeds the public key information and adds the ECC and ML-KEM secrets when
// present.
type SecretKey struct {
	PublicKey
	ECCPrivate   []byte
	MLKEMPrivate []byte
}

type compositeSpec struct {
	curveOID     []byte
	eccLen       int
	mlkemPubLen  int
	mlkemPrivLen int
}

func compositeSpecForAlgorithm(alg int) (compositeSpec, error) {
	switch alg {
	case PKALG_MLKEM768_X25519:
		return compositeSpec{
			curveOID:     []byte{0x2B, 0x65, 0x6E}, // 1.3.101.110 (Curve25519 alternative OID)
			eccLen:       32,
			mlkemPubLen:  1184,
			mlkemPrivLen: 2400,
		}, nil
	case PKALG_MLKEM1024_X448:
		return compositeSpec{
			curveOID:     []byte{0x2B, 0x65, 0x6F}, // 1.3.101.111 (X448)
			eccLen:       56,
			mlkemPubLen:  1568,
			mlkemPrivLen: 3168,
		}, nil
	case PKALG_MLKEM768_P256, PKALG_MLKEM1024_P384, PKALG_MLKEM768_BP256, PKALG_MLKEM1024_BP384:
		return compositeSpec{}, fmt.Errorf("pgp: composite algorithm %d not implemented", alg)
	default:
		return compositeSpec{}, fmt.Errorf("pgp: unsupported composite algorithm %d", alg)
	}
}

// CompositeKeySizes returns the expected byte lengths for the ECC and ML-KEM
// components of the supported LibrePGP hybrid algorithms.
func CompositeKeySizes(alg int) (eccLen, mlkemPubLen, mlkemPrivLen int, err error) {
	spec, err := compositeSpecForAlgorithm(alg)
	if err != nil {
		return 0, 0, 0, err
	}
	return spec.eccLen, spec.mlkemPubLen, spec.mlkemPrivLen, nil
}

// ComputeCompositeFingerprint deterministically derives the v6 fingerprint for
// a composite ML-KEM + ECC public key using a fixed creation time of zero. This
// allows callers that only possess the raw algorithm-specific material to
// obtain a stable fingerprint suitable for LibrePGP hybrid PKESK processing.
func ComputeCompositeFingerprint(alg int, eccPub, mlkemPub []byte) ([32]byte, error) {
	var zero [32]byte
	spec, err := compositeSpecForAlgorithm(alg)
	if err != nil {
		return zero, err
	}
	if len(eccPub) != spec.eccLen {
		return zero, fmt.Errorf("pgp: ecc public key length %d mismatch (want %d)", len(eccPub), spec.eccLen)
	}
	if len(mlkemPub) != spec.mlkemPubLen {
		return zero, fmt.Errorf("pgp: ml-kem public key length %d mismatch (want %d)", len(mlkemPub), spec.mlkemPubLen)
	}

	pubMatLen := 1 + len(spec.curveOID) + 1 + spec.eccLen + 4 + spec.mlkemPubLen
	body := make([]byte, 0, 1+4+1+4+pubMatLen)
	body = append(body, 6)
	body = append(body, 0, 0, 0, 0) // fixed creation time for deterministic fingerprinting
	body = append(body, byte(alg))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(pubMatLen))
	body = append(body, lenBuf[:]...)
	body = append(body, byte(len(spec.curveOID)))
	body = append(body, spec.curveOID...)
	body = append(body, 0x40)
	body = append(body, eccPub...)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(spec.mlkemPubLen))
	body = append(body, lenBuf[:]...)
	body = append(body, mlkemPub...)

	fp := computeV6Fingerprint(body)
	return fp, nil
}

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

// BuildCompositePublicKeyV6 builds a minimal v6 Public-Key packet for the
// LibrePGP ML-KEM + ECC composite algorithms supported by this PoC.
func BuildCompositePublicKeyV6(alg int, eccPub, mlkemPub []byte) ([]byte, error) {
	spec, err := compositeSpecForAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	if len(eccPub) != spec.eccLen {
		return nil, fmt.Errorf("ecc pub length %d mismatch (want %d)", len(eccPub), spec.eccLen)
	}
	if len(mlkemPub) != spec.mlkemPubLen {
		return nil, fmt.Errorf("ml-kem pub length %d mismatch (want %d)", len(mlkemPub), spec.mlkemPubLen)
	}
	pubMatLen := 1 + len(spec.curveOID) + 1 + spec.eccLen + 4 + len(mlkemPub)
	b := make([]byte, 0, 1+4+1+4+pubMatLen)
	b = append(b, 6)
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], uint32(time.Now().Unix()))
	b = append(b, t[:]...)
	b = append(b, byte(alg))
	binary.BigEndian.PutUint32(t[:], uint32(pubMatLen))
	b = append(b, t[:]...)
	b = append(b, byte(len(spec.curveOID)))
	b = append(b, spec.curveOID...)
	b = append(b, 0x40)
	b = append(b, eccPub...)
	binary.BigEndian.PutUint32(t[:], uint32(len(mlkemPub)))
	b = append(b, t[:]...)
	b = append(b, mlkemPub...)
	return Packet(6, b), nil
}

// BuildCompositeSecretKeyV6 emits a minimal v6 Secret-Key packet for composite
// algorithms with S2K usage 0 (unencrypted secret data).
func BuildCompositeSecretKeyV6(alg int, eccPub, eccPriv, mlkemPub, mlkemPriv []byte) ([]byte, error) {
	spec, err := compositeSpecForAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	if len(eccPriv) != spec.eccLen {
		return nil, fmt.Errorf("ecc priv length %d mismatch (want %d)", len(eccPriv), spec.eccLen)
	}
	if len(mlkemPriv) != spec.mlkemPrivLen {
		return nil, fmt.Errorf("ml-kem priv length %d mismatch (want %d)", len(mlkemPriv), spec.mlkemPrivLen)
	}
	pubPkt, err := BuildCompositePublicKeyV6(alg, eccPub, mlkemPub)
	if err != nil {
		return nil, err
	}
	_, pubBody, _, err := ReadPacket(pubPkt)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, len(pubBody)+1+1+spec.eccLen+4+len(mlkemPriv))
	body = append(body, pubBody...)
	body = append(body, 0) // s2k usage octet = 0 (no protection)
	body = append(body, 0x40)
	body = append(body, eccPriv...)
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], uint32(len(mlkemPriv)))
	body = append(body, t[:]...)
	body = append(body, mlkemPriv...)
	return Packet(5, body), nil
}

func computeV6Fingerprint(body []byte) [32]byte {
	// The fingerprint is SHA2-256 over 0x9B || len(body) || body
	h := sha256.New()
	h.Write([]byte{0x9B})
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(body)))
	h.Write(l[:])
	h.Write(body)
	var fp [32]byte
	copy(fp[:], h.Sum(nil))
	return fp
}

func parseCompositePublic(mat []byte, alg int, spec compositeSpec) (*PublicKey, error) {
	if len(mat) < 1 {
		return nil, errors.New("pgp: composite public key missing curve OID length")
	}
	curveLen := int(mat[0])
	if curveLen == 0 || curveLen == 0xFF {
		return nil, errors.New("pgp: composite public key invalid curve length")
	}
	if len(mat) < 1+curveLen {
		return nil, errors.New("pgp: composite public key truncated curve OID")
	}
	curveOID := mat[1 : 1+curveLen]
	if len(spec.curveOID) != 0 && !equalBytes(curveOID, spec.curveOID) {
		return nil, fmt.Errorf("pgp: unexpected curve OID %x for alg %d", curveOID, alg)
	}
	rest := mat[1+curveLen:]
	eccSize := spec.eccLen + 1 // SOS prefix 0x40 + coordinate
	if len(rest) < eccSize {
		return nil, errors.New("pgp: composite public key truncated ECC point")
	}
	eccSOS := rest[:eccSize]
	if eccSOS[0] != 0x40 {
		return nil, errors.New("pgp: composite public key missing SOS prefix")
	}
	eccPub := append([]byte(nil), eccSOS[1:]...)
	rest = rest[eccSize:]
	if len(rest) < 4 {
		return nil, errors.New("pgp: composite public key missing ML-KEM length")
	}
	mlkemLen := int(binary.BigEndian.Uint32(rest[:4]))
	rest = rest[4:]
	if mlkemLen != len(rest) {
		return nil, errors.New("pgp: composite public key ML-KEM length mismatch")
	}
	if mlkemLen != spec.mlkemPubLen {
		return nil, fmt.Errorf("pgp: composite public key expected ML-KEM len %d got %d", spec.mlkemPubLen, mlkemLen)
	}
	mlkemPub := append([]byte(nil), rest...)
	return &PublicKey{Algorithm: alg, ECCPublic: eccPub, MLKEMPublic: mlkemPub}, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parsePublicKeyBody(body []byte) (*PublicKey, int, error) {
	if len(body) < 1+4+1+4 {
		return nil, 0, errors.New("pgp: public key body too short")
	}
	if body[0] != 6 {
		return nil, 0, errors.New("pgp: unsupported public key version")
	}
	alg := int(body[1+4])
	pubLen := int(binary.BigEndian.Uint32(body[1+4+1 : 1+4+1+4]))
	off := 1 + 4 + 1 + 4
	if len(body) < off+pubLen {
		return nil, 0, errors.New("pgp: truncated public key material")
	}
	mat := body[off : off+pubLen]
	var pk *PublicKey
	switch alg {
	case PKALG_X25519:
		if len(mat) != 32 {
			return nil, 0, fmt.Errorf("pgp: expected 32 byte X25519 key, got %d", len(mat))
		}
		pk = &PublicKey{Algorithm: alg, ECCPublic: append([]byte(nil), mat...)}
	case PKALG_X448:
		if len(mat) != 56 {
			return nil, 0, fmt.Errorf("pgp: expected 56 byte X448 key, got %d", len(mat))
		}
		pk = &PublicKey{Algorithm: alg, ECCPublic: append([]byte(nil), mat...)}
	case PKALG_MLKEM768_X25519, PKALG_MLKEM1024_X448:
		spec, err := compositeSpecForAlgorithm(alg)
		if err != nil {
			return nil, 0, err
		}
		var errParse error
		pk, errParse = parseCompositePublic(mat, alg, spec)
		if errParse != nil {
			return nil, 0, errParse
		}
	default:
		return nil, 0, fmt.Errorf("pgp: unsupported public key algorithm %d", alg)
	}
	pk.Fingerprint = computeV6Fingerprint(body[:off+pubLen])
	return pk, off + pubLen, nil
}

// ParsePublicKeyV6 extracts the algorithm identifier and algorithm-specific material
// from a v6 Public-Key (Tag 6) packet produced by BuildPublicKeyV6 or its composite
// counterparts.
func ParsePublicKeyV6(pkt []byte) (*PublicKey, error) {
	tag, body, rest, err := ReadPacket(pkt)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("pgp: unexpected extra data after public key packet")
	}
	if tag != 6 {
		return nil, errors.New("pgp: packet is not Tag 6 public key")
	}
	pk, _, err := parsePublicKeyBody(body)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// ParseSecretKeyV6 extracts the algorithm identifier, public and secret key bytes from a
// v6 Secret-Key (Tag 5) packet produced by BuildSecretKeyV6 or the composite builders.
func ParseSecretKeyV6(pkt []byte) (*SecretKey, error) {
	tag, body, rest, err := ReadPacket(pkt)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("pgp: unexpected extra data after secret key packet")
	}
	if tag != 5 {
		return nil, errors.New("pgp: packet is not Tag 5 secret key")
	}
	if len(body) < 1+4+1+4+1 {
		return nil, errors.New("pgp: secret key body too short")
	}
	if body[0] != 6 {
		return nil, errors.New("pgp: unsupported secret key version")
	}
	pk, consumed, err := parsePublicKeyBody(body)
	if err != nil {
		return nil, err
	}
	if len(body) < consumed+1 {
		return nil, errors.New("pgp: truncated secret key material")
	}
	s2kUsage := body[consumed]
	if s2kUsage != 0 {
		return nil, fmt.Errorf("pgp: unsupported s2k usage %d", s2kUsage)
	}
	priv := body[consumed+1:]
	sk := &SecretKey{PublicKey: *pk}
	switch pk.Algorithm {
	case PKALG_X25519:
		if len(priv) != 32 {
			return nil, fmt.Errorf("pgp: expected 32 byte X25519 secret key, got %d", len(priv))
		}
		sk.ECCPrivate = append([]byte(nil), priv...)
	case PKALG_X448:
		if len(priv) != 56 {
			return nil, fmt.Errorf("pgp: expected 56 byte X448 secret key, got %d", len(priv))
		}
		sk.ECCPrivate = append([]byte(nil), priv...)
	case PKALG_MLKEM768_X25519, PKALG_MLKEM1024_X448:
		spec, errSpec := compositeSpecForAlgorithm(pk.Algorithm)
		if errSpec != nil {
			return nil, errSpec
		}
		eccSize := spec.eccLen + 1
		if len(priv) < eccSize {
			return nil, errors.New("pgp: composite secret key truncated ECC scalar")
		}
		if priv[0] != 0x40 {
			return nil, errors.New("pgp: composite secret key missing SOS prefix")
		}
		sk.ECCPrivate = append([]byte(nil), priv[1:1+spec.eccLen]...)
		rest := priv[eccSize:]
		if len(rest) < 4 {
			return nil, errors.New("pgp: composite secret key missing ML-KEM length")
		}
		mlLen := int(binary.BigEndian.Uint32(rest[:4]))
		rest = rest[4:]
		if mlLen != len(rest) {
			return nil, errors.New("pgp: composite secret key ML-KEM length mismatch")
		}
		if mlLen != spec.mlkemPrivLen {
			return nil, fmt.Errorf("pgp: composite secret key expected ML-KEM len %d got %d", spec.mlkemPrivLen, mlLen)
		}
		sk.MLKEMPrivate = append([]byte(nil), rest...)
	default:
		return nil, fmt.Errorf("pgp: unsupported secret key algorithm %d", pk.Algorithm)
	}
	return sk, nil
}
