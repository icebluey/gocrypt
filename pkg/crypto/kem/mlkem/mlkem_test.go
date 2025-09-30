package mlkem

import "testing"

func TestWrapUnwrapRoundTrip(t *testing.T) {
	pub, priv, err := Generate("mlkem768")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cek := []byte("example session key 123456")
	recip, wrapped, ct, err := Wrap("mlkem768", pub, cek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if recip != "mlkem768" {
		t.Fatalf("unexpected recipient id: %s", recip)
	}
	out, err := Unwrap("mlkem768", priv, wrapped, ct)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(out) != string(cek) {
		t.Fatalf("session key mismatch")
	}
}

func TestUnknownScheme(t *testing.T) {
	if _, _, err := Generate("nope"); err == nil {
		t.Fatalf("expected error for unknown scheme")
	}
	if _, _, _, err := Wrap("nope", nil, nil); err == nil {
		t.Fatalf("expected wrap error")
	}
	if _, err := Unwrap("nope", nil, nil, nil); err == nil {
		t.Fatalf("expected unwrap error")
	}
}
