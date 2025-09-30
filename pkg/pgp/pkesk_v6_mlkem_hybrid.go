package pgp

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"

	"example.com/gocrypt/pkg/crypto/aeskw"
	"example.com/gocrypt/pkg/crypto/kem/mlkem"
	"example.com/gocrypt/pkg/crypto/kem/xkem"
)

func BuildPKESKv6_MLKEMHybrid(pub *PublicKey, symAlg int, sessionKey []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("pgp: nil public key")
	}
	var curve xkem.Curve
	var mlkemName string
	switch pub.Algorithm {
	case PKALG_MLKEM768_X25519:
		curve = xkem.CurveX25519
		mlkemName = "mlkem768"
	case PKALG_MLKEM1024_X448:
		curve = xkem.CurveX448
		mlkemName = "mlkem1024"
	default:
		return nil, fmt.Errorf("pgp: unsupported hybrid algorithm %d", pub.Algorithm)
	}
	spec, err := compositeSpecForAlgorithm(pub.Algorithm)
	if err != nil {
		return nil, err
	}
	if len(pub.ECCPublic) != spec.eccLen {
		return nil, fmt.Errorf("pgp: ecc public key length %d mismatch (want %d)", len(pub.ECCPublic), spec.eccLen)
	}
	if len(pub.MLKEMPublic) != spec.mlkemPubLen {
		return nil, fmt.Errorf("pgp: ml-kem public key length %d mismatch (want %d)", len(pub.MLKEMPublic), spec.mlkemPubLen)
	}
	if len(sessionKey) == 0 || len(sessionKey)%8 != 0 {
		return nil, errors.New("pgp: session key must be non-empty and multiple of 8 bytes")
	}
	if symAlg != SYM_AES128 && symAlg != SYM_AES192 && symAlg != SYM_AES256 {
		return nil, fmt.Errorf("pgp: unsupported symmetric algorithm %d", symAlg)
	}
	if pub.Fingerprint == ([32]byte{}) {
		return nil, errors.New("pgp: composite public key missing fingerprint")
	}

	eccCipher, eccShare, err := xkem.Encaps(curve, pub.ECCPublic)
	if err != nil {
		return nil, err
	}
	eccCipherEnc := append([]byte{0x40}, eccCipher...)

	mlkemCipher, mlkemShare, err := mlkem.Encapsulate(mlkemName, pub.MLKEMPublic)
	if err != nil {
		return nil, err
	}

	fixedInfo := make([]byte, 1+len(pub.Fingerprint))
	fixedInfo[0] = byte(symAlg)
	copy(fixedInfo[1:], pub.Fingerprint[:])

	kek, err := multiKeyCombine(eccShare, eccCipherEnc, mlkemShare, mlkemCipher, fixedInfo, 256)
	if err != nil {
		return nil, err
	}
	wrapped, err := aeskw.Wrap(kek, sessionKey)
	if err != nil {
		return nil, err
	}

	pubFields := make([]byte, 0, 2+len(eccCipherEnc)+4+len(mlkemCipher))
	bitLen := uint16(len(eccCipherEnc) * 8)
	pubFields = append(pubFields, byte(bitLen>>8), byte(bitLen))
	pubFields = append(pubFields, eccCipherEnc...)
	var mlLen [4]byte
	binary.BigEndian.PutUint32(mlLen[:], uint32(len(mlkemCipher)))
	pubFields = append(pubFields, mlLen[:]...)
	pubFields = append(pubFields, mlkemCipher...)

	body := make([]byte, 0, 2+2+len(pubFields)+1+1+len(wrapped))
	body = append(body, 6)
	body = append(body, byte(pub.Algorithm))
	var pfLen [2]byte
	binary.BigEndian.PutUint16(pfLen[:], uint16(len(pubFields)))
	body = append(body, pfLen[:]...)
	body = append(body, pubFields...)
	body = append(body, byte(symAlg))
	if len(wrapped) > 255 {
		return nil, errors.New("pgp: wrapped session key too large")
	}
	body = append(body, byte(len(wrapped)))
	body = append(body, wrapped...)

	return Packet(1, body), nil
}

func multiKeyCombine(eccKeyShare, eccCipherText, mlkemKeyShare, mlkemCipherText, fixedInfo []byte, oBits int) ([]byte, error) {
	if oBits%8 != 0 {
		return nil, errors.New("pgp: multiKeyCombine requires byte-aligned output")
	}
	counter := []byte{0, 0, 0, 1}
	encData := make([]byte, 0, len(counter)+len(eccKeyShare)+len(eccCipherText)+len(mlkemKeyShare)+len(mlkemCipherText)+len(fixedInfo))
	encData = append(encData, counter...)
	encData = append(encData, eccKeyShare...)
	encData = append(encData, eccCipherText...)
	encData = append(encData, mlkemKeyShare...)
	encData = append(encData, mlkemCipherText...)
	encData = append(encData, fixedInfo...)
	return kmac256([]byte("OpenPGPCompositeKeyDerivationFunction"), encData, oBits, "KDF")
}

func kmac256(key, data []byte, oBits int, customization string) ([]byte, error) {
	if oBits%8 != 0 {
		return nil, errors.New("kmac: output bits must be multiple of 8")
	}
	encodedKey := encodeString(key)
	const rate = 136
	bp := bytepad(encodedKey, rate)
	right := rightEncode(uint64(oBits))
	shake := sha3.NewCShake256(nil, []byte(customization))
	if _, err := shake.Write(bp); err != nil {
		return nil, err
	}
	if _, err := shake.Write(data); err != nil {
		return nil, err
	}
	if _, err := shake.Write(right); err != nil {
		return nil, err
	}
	out := make([]byte, oBits/8)
	if _, err := shake.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func leftEncode(x uint64) []byte {
	buf := make([]byte, 9)
	n := byte(1)
	for v := x; v>>8 != 0; v >>= 8 {
		n++
	}
	buf[0] = n
	for i := byte(0); i < n; i++ {
		shift := (n - i - 1) * 8
		buf[i+1] = byte(x >> shift)
	}
	return buf[:n+1]
}

func rightEncode(x uint64) []byte {
	buf := make([]byte, 9)
	n := byte(1)
	for v := x; v>>8 != 0; v >>= 8 {
		n++
	}
	for i := byte(0); i < n; i++ {
		shift := (n - i - 1) * 8
		buf[i] = byte(x >> shift)
	}
	buf[n] = n
	return buf[:n+1]
}

func encodeString(in []byte) []byte {
	enc := leftEncode(uint64(len(in) * 8))
	enc = append(enc, in...)
	return enc
}

func bytepad(in []byte, w int) []byte {
	result := leftEncode(uint64(w))
	result = append(result, in...)
	for len(result)%w != 0 {
		result = append(result, 0)
	}
	return result
}
