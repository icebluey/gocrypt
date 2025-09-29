package pgp

import (
	"encoding/binary"
	"errors"
	"strings"

	"example.com/gocrypt/pkg/crypto/aeskw"
	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
)

// DecodePKESK_X unwraps session key from a v6 PKESK body for X25519/X448 using recipient private key bytes.
func DecodePKESK_X(pkesk []byte, pkAlg string, recipientPriv []byte) ([]byte, error) {
	if len(pkesk) < 4 { return nil, errors.New("pkesk too short") }
	if pkesk[0] != 6 { return nil, errors.New("not v6") }
	alg := int(pkesk[1]); _ = alg
	pfLen := int(pkesk[2])
	off := 3
	if len(pkesk) < off+pfLen+1 { return nil, errors.New("pkesk fields") }
	pubFields := pkesk[off:off+pfLen]; off += pfLen
	wrapLen := int(pkesk[off]); off++
	if len(pkesk) < off+wrapLen { return nil, errors.New("pkesk enc too short") }
	wrapped := pkesk[off:off+wrapLen]

	if len(pubFields) < 3 { return nil, errors.New("pubFields short") }
	bitlen := int(binary.BigEndian.Uint16(pubFields[:2]))
	_ = bitlen
	mp := pubFields[2:]
	if len(mp) < 1 || mp[0] != 0x40 { return nil, errors.New("bad mpi prefix") }
	ephPub := mp[1:]

	switch strings.ToLower(pkAlg) {
	case "x25519":
		if len(recipientPriv) != 32 || len(ephPub) != 32 { return nil, errors.New("bad key sizes") }
		var sk x25519.Key; copy(sk[:], recipientPriv)
		var ep x25519.Key; copy(ep[:], ephPub)
		var sh x25519.Key
		ok := x25519.Shared(&sh, &sk, &ep); if !ok { return nil, errors.New("shared failed") }
		kek := kdfConcatSHA256(sh[:], buildECDHParams(PKALG_X25519))[:32]
		m, err := aeskw.Unwrap(kek, wrapped); if err != nil { return nil, err }
		// drop PKCS#7
		if len(m) == 0 { return nil, errors.New("unwrap empty") }
		pad := int(m[len(m)-1])
		if pad == 0 || pad > len(m) { return nil, errors.New("bad padding") }
		m = m[:len(m)-pad]
		if len(m) < 2 { return nil, errors.New("no checksum") }
		return m[:len(m)-2], nil
	case "x448":
		if len(recipientPriv) != 56 || len(ephPub) != 56 { return nil, errors.New("bad key sizes") }
		var sk x448.Key; copy(sk[:], recipientPriv)
		var ep x448.Key; copy(ep[:], ephPub)
		var sh x448.Key
		ok := x448.Shared(&sh, &sk, &ep); if !ok { return nil, errors.New("shared failed") }
		kek := kdfConcatSHA256(sh[:], buildECDHParams(PKALG_X448))[:32]
		m, err := aeskw.Unwrap(kek, wrapped); if err != nil { return nil, err }
		pad := int(m[len(m)-1])
		if pad == 0 || pad > len(m) { return nil, errors.New("bad padding") }
		m = m[:len(m)-pad]
		if len(m) < 2 { return nil, errors.New("no checksum") }
		return m[:len(m)-2], nil
	default:
		return nil, errors.New("unsupported pkalg")
	}
}

