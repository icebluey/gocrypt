package pgp

import "testing"

func TestParsePublicKeyV6(t *testing.T) {
	var sk, pk [56]byte
	for i := range sk {
		sk[i] = byte(i + 1)
	}
	for i := range pk {
		pk[i] = byte(200 - i)
	}

	pkt, err := BuildPublicKeyV6(PKALG_X448, pk[:])
	if err != nil {
		t.Fatalf("BuildPublicKeyV6: %v", err)
	}

    parsed, err := ParsePublicKeyV6(pkt)
    if err != nil {
            t.Fatalf("ParsePublicKeyV6: %v", err)
    }
    if parsed.Algorithm != PKALG_X448 {
            t.Fatalf("ParsePublicKeyV6 alg = %d", parsed.Algorithm)
    }
    gotPub := parsed.ECCPublic
    if len(gotPub) != len(pk) || gotPub[0] != pk[0] || gotPub[len(pk)-1] != pk[len(pk)-1] {
            t.Fatalf("ParsePublicKeyV6 unexpected pub bytes")
    }

	// ensure mismatch sizes are caught
	badPkt, err := BuildPublicKeyV6(PKALG_X25519, sk[:32])
	if err != nil {
		t.Fatalf("BuildPublicKeyV6(x25519): %v", err)
	}
	badPkt = append(badPkt, 0x00) // extra data triggers error
    if _, err := ParsePublicKeyV6(badPkt); err == nil {
            t.Fatalf("ParsePublicKeyV6 should reject trailing data")
    }
}

func TestParseSecretKeyV6(t *testing.T) {
	var sk, pk [56]byte
	for i := range sk {
		sk[i] = byte(i + 1)
	}
	for i := range pk {
		pk[i] = byte(200 - i)
	}

	pkt, err := BuildSecretKeyV6(PKALG_X448, pk[:], sk[:])
	if err != nil {
		t.Fatalf("BuildSecretKeyV6: %v", err)
	}

    parsed, err := ParseSecretKeyV6(pkt)
    if err != nil {
            t.Fatalf("ParseSecretKeyV6: %v", err)
    }
    if parsed.Algorithm != PKALG_X448 {
            t.Fatalf("ParseSecretKeyV6 alg = %d", parsed.Algorithm)
    }
    pub := parsed.ECCPublic
    priv := parsed.ECCPrivate
    if len(pub) != len(pk) || len(priv) != len(sk) {
            t.Fatalf("ParseSecretKeyV6 unexpected lengths")
    }
	if pub[0] != pk[0] || priv[0] != sk[0] {
		t.Fatalf("ParseSecretKeyV6 mismatched contents")
	}

	// tamper with S2K usage byte
	tampered := make([]byte, len(pkt))
	copy(tampered, pkt)
	tampered[len(tampered)-len(sk)-1] = 42
    if _, err := ParseSecretKeyV6(tampered); err == nil {
            t.Fatalf("ParseSecretKeyV6 should reject unsupported s2k usage")
    }
}
