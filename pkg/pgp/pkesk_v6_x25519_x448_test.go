package pgp

import (
	"encoding/base64"
	"testing"

	"github.com/cloudflare/circl/dh/x25519"
)

func TestBuildAndDecodePKESKv6X25519(t *testing.T) {
	var sk, pk x25519.Key
	copy(sk[:], []byte{
		0x14, 0x55, 0x5e, 0x8f, 0xc2, 0x9b, 0x32, 0xa7,
		0x5d, 0x8e, 0x9d, 0x1a, 0x42, 0xa1, 0x8c, 0x4e,
		0xf3, 0xd0, 0x51, 0x74, 0x44, 0x29, 0x44, 0xea,
		0x76, 0x9d, 0xce, 0x39, 0x31, 0x65, 0x4c, 0x6b,
	})
	x25519.KeyGen(&pk, &sk)

	cek := []byte("0123456789ABCDEF0123456789ABCDEF")
	pkt, err := BuildPKESKv6_X(PKALG_X25519, pk[:], cek)
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	tag, body, rest, err := ReadPacket(pkt)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if tag != 1 {
		t.Fatalf("expected PKESK tag, got %d", tag)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing bytes: %d", len(rest))
	}
	if body[0] != 6 {
		t.Fatalf("expected version 6, got %d", body[0])
	}

	got, err := DecodePKESK_X(body, "x25519", sk[:])
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if base64.StdEncoding.EncodeToString(got) != base64.StdEncoding.EncodeToString(cek) {
		t.Fatalf("session key mismatch")
	}
}
