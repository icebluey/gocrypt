package pgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"example.com/gocrypt/pkg/crypto/aeskw"
	"example.com/gocrypt/pkg/crypto/kem/mlkem"
	"example.com/gocrypt/pkg/crypto/kem/xkem"
	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
)

// DecodePKESK_X unwraps session key from a v6 PKESK body for X25519/X448 using recipient private key bytes.
func DecodePKESK_X(pkesk []byte, pkAlg string, recipientPriv []byte) ([]byte, error) {
	if len(pkesk) < 4 {
		return nil, errors.New("pkesk too short")
	}
	if pkesk[0] != 6 {
		return nil, errors.New("not v6")
	}
	alg := int(pkesk[1])
	_ = alg
	pfLen := int(pkesk[2])
	off := 3
	if len(pkesk) < off+pfLen+1 {
		return nil, errors.New("pkesk fields")
	}
	pubFields := pkesk[off : off+pfLen]
	off += pfLen
	wrapLen := int(pkesk[off])
	off++
	if len(pkesk) < off+wrapLen {
		return nil, errors.New("pkesk enc too short")
	}
	wrapped := pkesk[off : off+wrapLen]

	if len(pubFields) < 3 {
		return nil, errors.New("pubFields short")
	}
	bitlen := int(binary.BigEndian.Uint16(pubFields[:2]))
	_ = bitlen
	mp := pubFields[2:]
	if len(mp) < 1 || mp[0] != 0x40 {
		return nil, errors.New("bad mpi prefix")
	}
	ephPub := mp[1:]

	switch strings.ToLower(pkAlg) {
	case "x25519":
		if len(recipientPriv) != 32 || len(ephPub) != 32 {
			return nil, errors.New("bad key sizes")
		}
		var sk x25519.Key
		copy(sk[:], recipientPriv)
		var ep x25519.Key
		copy(ep[:], ephPub)
		var sh x25519.Key
		ok := x25519.Shared(&sh, &sk, &ep)
		if !ok {
			return nil, errors.New("shared failed")
		}
		kek := kdfConcatSHA256(sh[:], buildECDHParams(PKALG_X25519))[:32]
		m, err := aeskw.Unwrap(kek, wrapped)
		if err != nil {
			return nil, err
		}
		// drop PKCS#7
		if len(m) == 0 {
			return nil, errors.New("unwrap empty")
		}
		pad := int(m[len(m)-1])
		if pad == 0 || pad > len(m) {
			return nil, errors.New("bad padding")
		}
		m = m[:len(m)-pad]
		if len(m) < 2 {
			return nil, errors.New("no checksum")
		}
		return m[:len(m)-2], nil
	case "x448":
		if len(recipientPriv) != 56 || len(ephPub) != 56 {
			return nil, errors.New("bad key sizes")
		}
		var sk x448.Key
		copy(sk[:], recipientPriv)
		var ep x448.Key
		copy(ep[:], ephPub)
		var sh x448.Key
		ok := x448.Shared(&sh, &sk, &ep)
		if !ok {
			return nil, errors.New("shared failed")
		}
		kek := kdfConcatSHA256(sh[:], buildECDHParams(PKALG_X448))[:32]
		m, err := aeskw.Unwrap(kek, wrapped)
		if err != nil {
			return nil, err
		}
		pad := int(m[len(m)-1])
		if pad == 0 || pad > len(m) {
			return nil, errors.New("bad padding")
		}
		m = m[:len(m)-pad]
		if len(m) < 2 {
			return nil, errors.New("no checksum")
		}
		return m[:len(m)-2], nil
	default:
		return nil, errors.New("unsupported pkalg")
	}
}

// DecodePKESK_MLKEMHybrid unwraps a composite ML-KEM+ECC PKESK body using the
// recipient's secret key material.
func DecodePKESK_MLKEMHybrid(body []byte, secret *SecretKey) ([]byte, int, error) {
	if secret == nil {
		return nil, 0, errors.New("pgp: nil secret key")
	}
	var curve xkem.Curve
	var mlkemName string
	switch secret.Algorithm {
	case PKALG_MLKEM768_X25519:
		curve = xkem.CurveX25519
		mlkemName = "mlkem768"
	case PKALG_MLKEM1024_X448:
		curve = xkem.CurveX448
		mlkemName = "mlkem1024"
	default:
		return nil, 0, fmt.Errorf("pgp: unsupported hybrid algorithm %d", secret.Algorithm)
	}
	if len(body) < 2+2+1+1 {
		return nil, 0, errors.New("pgp: pkesk body too short")
	}
	if body[0] != 6 {
		return nil, 0, errors.New("pgp: pkesk is not v6")
	}
	alg := int(body[1])
	if alg != secret.Algorithm {
		return nil, 0, fmt.Errorf("pgp: pkesk alg %d mismatch secret alg %d", alg, secret.Algorithm)
	}
	off := 2
	if len(body) < off+2 {
		return nil, 0, errors.New("pgp: pkesk missing pubfields length")
	}
	pfLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if len(body) < off+pfLen+2 {
		return nil, 0, errors.New("pgp: pkesk truncated fields")
	}
	pubFields := body[off : off+pfLen]
	off += pfLen
	symID := int(body[off])
	off++
	wrapLen := int(body[off])
	off++
	if len(body) < off+wrapLen {
		return nil, 0, errors.New("pgp: pkesk wrapped key truncated")
	}
	wrapped := body[off : off+wrapLen]
	off += wrapLen
	if off != len(body) {
		return nil, 0, errors.New("pgp: unexpected trailing data in pkesk")
	}

	if len(pubFields) < 2 {
		return nil, 0, errors.New("pgp: pkesk pubfields too short")
	}
	bitLen := int(binary.BigEndian.Uint16(pubFields[:2]))
	eccBytes := (bitLen + 7) / 8
	if len(pubFields) < 2+eccBytes+4 {
		return nil, 0, errors.New("pgp: pkesk ecc ciphertext truncated")
	}
	eccCipher := pubFields[2 : 2+eccBytes]
	if len(eccCipher) == 0 || eccCipher[0] != 0x40 {
		return nil, 0, errors.New("pgp: pkesk ecc ciphertext missing SOS prefix")
	}
	eccRaw := eccCipher[1:]
	rest := pubFields[2+eccBytes:]
	mlkemLen := int(binary.BigEndian.Uint32(rest[:4]))
	rest = rest[4:]
	if mlkemLen != len(rest) {
		return nil, 0, errors.New("pgp: pkesk mlkem ciphertext truncated")
	}
	mlkemCipher := rest

	eccShare, err := xkem.Decaps(curve, secret.ECCPrivate, secret.ECCPublic, eccRaw)
	if err != nil {
		return nil, 0, err
	}
	mlkemShare, err := mlkem.DecapsulateShared(mlkemName, secret.MLKEMPrivate, mlkemCipher)
	if err != nil {
		return nil, 0, err
	}
	fixedInfo := make([]byte, 1+len(secret.Fingerprint))
	fixedInfo[0] = byte(symID)
	copy(fixedInfo[1:], secret.Fingerprint[:])
	kek, err := multiKeyCombine(eccShare, eccCipher, mlkemShare, mlkemCipher, fixedInfo, 256)
	if err != nil {
		return nil, 0, err
	}
	sessionKey, err := aeskw.Unwrap(kek, wrapped)
	if err != nil {
		return nil, 0, err
	}
	return sessionKey, symID, nil
}
