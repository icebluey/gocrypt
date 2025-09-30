package pgp

import (
	"bytes"
	"crypto/rand"
	"testing"

	"example.com/gocrypt/pkg/crypto/kem/mlkem"
	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
)

func TestHybridPKESK_MLKEM768_X25519(t *testing.T) {
	var priv x25519.Key
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var pub x25519.Key
	x25519.KeyGen(&pub, &priv)

	mlPub, mlPriv, err := mlkem.Generate("mlkem768")
	if err != nil {
		t.Fatalf("mlkem gen: %v", err)
	}
	pubPkt, err := BuildCompositePublicKeyV6(PKALG_MLKEM768_X25519, pub[:], mlPub)
	if err != nil {
		t.Fatalf("BuildCompositePublicKeyV6: %v", err)
	}
	secPkt, err := BuildCompositeSecretKeyV6(PKALG_MLKEM768_X25519, pub[:], priv[:], mlPub, mlPriv)
	if err != nil {
		t.Fatalf("BuildCompositeSecretKeyV6: %v", err)
	}
	pubKey, err := ParsePublicKeyV6(pubPkt)
	if err != nil {
		t.Fatalf("ParsePublicKeyV6: %v", err)
	}
	secKey, err := ParseSecretKeyV6(secPkt)
	if err != nil {
		t.Fatalf("ParseSecretKeyV6: %v", err)
	}

	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("rand cek: %v", err)
	}
	pkeskPkt, err := BuildPKESKv6_MLKEMHybrid(pubKey, SYM_AES256, cek)
	if err != nil {
		t.Fatalf("BuildPKESKv6_MLKEMHybrid: %v", err)
	}
	_, pkeskBody, _, err := ReadPacket(pkeskPkt)
	if err != nil {
		t.Fatalf("ReadPacket pkesk: %v", err)
	}
	recovered, symID, err := DecodePKESK_MLKEMHybrid(pkeskBody, secKey)
	if err != nil {
		t.Fatalf("DecodePKESK_MLKEMHybrid: %v", err)
	}
	if symID != SYM_AES256 {
		t.Fatalf("expected sym id %d got %d", SYM_AES256, symID)
	}
	if !bytes.Equal(recovered, cek) {
		t.Fatalf("recovered cek mismatch")
	}

	plaintext := []byte("librepgp hybrid 768")
	ocbedPkt, err := BuildOCBED(SYM_AES256, 22, cek, plaintext)
	if err != nil {
		t.Fatalf("BuildOCBED: %v", err)
	}
	_, ocbedBody, _, err := ReadPacket(ocbedPkt)
	if err != nil {
		t.Fatalf("ReadPacket ocbed: %v", err)
	}
	gotPlain, err := DecryptOCBED(ocbedBody, cek)
	if err != nil {
		t.Fatalf("DecryptOCBED: %v", err)
	}
	if !bytes.Equal(gotPlain, plaintext) {
		t.Fatalf("OCBED round-trip mismatch")
	}
}

func TestHybridPKESK_MLKEM1024_X448(t *testing.T) {
	var priv x448.Key
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var pub x448.Key
	x448.KeyGen(&pub, &priv)

	mlPub, mlPriv, err := mlkem.Generate("mlkem1024")
	if err != nil {
		t.Fatalf("mlkem gen: %v", err)
	}
	pubPkt, err := BuildCompositePublicKeyV6(PKALG_MLKEM1024_X448, pub[:], mlPub)
	if err != nil {
		t.Fatalf("BuildCompositePublicKeyV6: %v", err)
	}
	secPkt, err := BuildCompositeSecretKeyV6(PKALG_MLKEM1024_X448, pub[:], priv[:], mlPub, mlPriv)
	if err != nil {
		t.Fatalf("BuildCompositeSecretKeyV6: %v", err)
	}
	pubKey, err := ParsePublicKeyV6(pubPkt)
	if err != nil {
		t.Fatalf("ParsePublicKeyV6: %v", err)
	}
	secKey, err := ParseSecretKeyV6(secPkt)
	if err != nil {
		t.Fatalf("ParseSecretKeyV6: %v", err)
	}

	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("rand cek: %v", err)
	}
	pkeskPkt, err := BuildPKESKv6_MLKEMHybrid(pubKey, SYM_AES256, cek)
	if err != nil {
		t.Fatalf("BuildPKESKv6_MLKEMHybrid: %v", err)
	}
	_, pkeskBody, _, err := ReadPacket(pkeskPkt)
	if err != nil {
		t.Fatalf("ReadPacket pkesk: %v", err)
	}
	recovered, symID, err := DecodePKESK_MLKEMHybrid(pkeskBody, secKey)
	if err != nil {
		t.Fatalf("DecodePKESK_MLKEMHybrid: %v", err)
	}
	if symID != SYM_AES256 {
		t.Fatalf("expected sym id %d got %d", SYM_AES256, symID)
	}
	if !bytes.Equal(recovered, cek) {
		t.Fatalf("recovered cek mismatch")
	}

	plaintext := []byte("librepgp hybrid 1024")
	ocbedPkt, err := BuildOCBED(SYM_AES256, 22, cek, plaintext)
	if err != nil {
		t.Fatalf("BuildOCBED: %v", err)
	}
	_, ocbedBody, _, err := ReadPacket(ocbedPkt)
	if err != nil {
		t.Fatalf("ReadPacket ocbed: %v", err)
	}
	gotPlain, err := DecryptOCBED(ocbedBody, cek)
	if err != nil {
		t.Fatalf("DecryptOCBED: %v", err)
	}
	if !bytes.Equal(gotPlain, plaintext) {
		t.Fatalf("OCBED round-trip mismatch")
	}
}
