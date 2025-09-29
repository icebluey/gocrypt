package pgp

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
	"example.com/gocrypt/pkg/crypto/aeskw"
)


// BuildPKESKv6_X builds a minimal v6 PKESK for X25519/X448 recipient and wraps sessionKey via AES-KW.
func BuildPKESKv6_X(recipientAlg int, recipientPub []byte, sessionKey []byte) ([]byte, error) {
	var ephPub, shared []byte
	var err error
	switch recipientAlg {
	case PKALG_X25519:
		if len(recipientPub) != x25519.Size { return nil, errors.New("bad X25519 pub") }
		var eph x25519.Key
		if _, err = rand.Read(eph[:]); err != nil { return nil, err }
		var ephPk x25519.Key
		x25519.KeyGen(&ephPk, &eph)
		ephPub = append([]byte(nil), ephPk[:]...)
		var rpk x25519.Key
		copy(rpk[:], recipientPub)
		var sh x25519.Key
		ok := x25519.Shared(&sh, &eph, &rpk)
		if !ok { return nil, errors.New("x25519 shared failed") }
		shared = append([]byte(nil), sh[:]...)
	case PKALG_X448:
		if len(recipientPub) != x448.Size { return nil, errors.New("bad X448 pub") }
		var eph x448.Key
		if _, err = rand.Read(eph[:]); err != nil { return nil, err }
		var ephPk x448.Key
		x448.KeyGen(&ephPk, &eph)
		ephPub = append([]byte(nil), ephPk[:]...)
		var rpk x448.Key
		copy(rpk[:], recipientPub)
		var sh x448.Key
		ok := x448.Shared(&sh, &eph, &rpk)
		if !ok { return nil, errors.New("x448 shared failed") }
		shared = append([]byte(nil), sh[:]...)
	default:
		return nil, errors.New("unsupported recipient alg")
	}
	params := buildECDHParams(recipientAlg)
	mb := kdfConcatSHA256(shared, params)
	kek := mb[:32]

	// session key wrapping: append checksum then PKCS#7 to 8 byte multiple
	chk := uint16(0)
	for _, b := range sessionKey { chk = (chk + uint16(b)) & 0xFFFF }
	plain := append([]byte{}, sessionKey...)
	plain = append(plain, byte(chk>>8), byte(chk))
	pad := 8 - (len(plain) % 8)
	if pad == 0 { pad = 8 }
	for i:=0; i<pad; i++ { plain = append(plain, byte(pad)) }
	wrapped, err := aeskw.Wrap(kek, plain)
	if err != nil { return nil, err }

	var pubFields bytes.Buffer
	pref := append([]byte{0x40}, ephPub...)
	bitlen := uint16(len(pref)*8)
	pubFields.WriteByte(byte(bitlen>>8)); pubFields.WriteByte(byte(bitlen))
	pubFields.Write(pref)

	var body bytes.Buffer
	body.WriteByte(6) // v6
	body.WriteByte(byte(recipientAlg))
	body.WriteByte(byte(pubFields.Len()))
	body.Write(pubFields.Bytes())
	body.WriteByte(byte(len(wrapped)))
	body.Write(wrapped)

	return Packet(1, body.Bytes()), nil
}

// minimal ECDH params with "Anonymous Sender" constant; PoC only.
func buildECDHParams(recipientAlg int) []byte {
	anon := []byte("Anonymous Sender    ") // 20 bytes
	var b bytes.Buffer
	b.WriteByte(1); b.WriteByte(0) // fake curve OID size+oid
	b.WriteByte(byte(recipientAlg)) // alg id
	b.WriteByte(3); b.WriteByte(0x01); b.WriteByte(8); b.WriteByte(9) // KDF params: 0x01, SHA256(8), AES-256(9)
	b.Write(anon)
	return b.Bytes()
}

