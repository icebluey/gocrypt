package pgp

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestBuildSEIPDv2OCBLayout(t *testing.T) {
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	body, err := BuildSEIPDv2OCB(SYM_AES256, 22, cek, []byte("test plaintext"))
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}
	tag, payload, rest, err := ReadPacket(body)
	if err != nil {
		t.Fatalf("read packet: %v", err)
	}
	if tag != 18 {
		t.Fatalf("expected tag 18, got %d", tag)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected trailing data")
	}
	if len(payload) < 4+32+16 {
		t.Fatalf("payload too short: %d", len(payload))
	}
	if payload[0] != 2 {
		t.Fatalf("expected version 2, got %d", payload[0])
	}
	if payload[1] != byte(SYM_AES256) {
		t.Fatalf("expected sym id %d got %d", SYM_AES256, payload[1])
	}
	if payload[2] != AEAD_OCB {
		t.Fatalf("expected AEAD OCB, got %d", payload[2])
	}
	salt := payload[4:36]
	if bytes.Equal(salt, make([]byte, len(salt))) {
		t.Fatalf("salt must be non-zero")
	}
}
