package pgp

import "testing"

func TestMultiKeyCombineDeterministic(t *testing.T) {
	eccShare := []byte{0x01, 0x02, 0x03}
	eccCipher := []byte{0x04, 0x05}
	mlkemShare := []byte{0x06}
	mlkemCipher := []byte{0x07, 0x08, 0x09}
	fixedInfo := []byte{0x0A, 0x0B}

	got, err := multiKeyCombine(eccShare, eccCipher, mlkemShare, mlkemCipher, fixedInfo, 128)
	if err != nil {
		t.Fatalf("multiKeyCombine: %v", err)
	}
	want := []byte{0x9e, 0x67, 0xc6, 0x76, 0x8e, 0xaf, 0x94, 0x6a, 0xfc, 0x09, 0x83, 0x4f, 0xb9, 0x26, 0x1b, 0x9b}
	if len(got) != len(want) {
		t.Fatalf("unexpected length: got %d want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("multiKeyCombine mismatch at %d: got %02x want %02x", i, got[i], want[i])
		}
	}
}

func TestMultiKeyCombineBadBits(t *testing.T) {
	_, err := multiKeyCombine(nil, nil, nil, nil, nil, 7)
	if err == nil {
		t.Fatalf("expected error for non byte-aligned output")
	}
}
