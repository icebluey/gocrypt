package container

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const magic = "GOC1"

type Recipient struct {
	Type         string `json:"type"` // rsa-oaep-sha256|x25519|x448|mlkem768|mlkem1024
	KeyID        string `json:"key_id"`
	Encapsulated []byte `json:"enc"`
	EphemeralPub []byte `json:"eph,omitempty"`
}

type SignerInfo struct {
	Algorithm string `json:"algo"`
	Hash      string `json:"hash"`
	KeyID     string `json:"key_id"`
	Signature []byte `json:"sig"`
}

type Header struct {
	Version     int          `json:"v"`
	Created     time.Time    `json:"t"`
	Compression string       `json:"c"`
	Cipher      string       `json:"sym"` // aes-ocb
	Nonce       []byte       `json:"n"`
	Recipients  []Recipient  `json:"rcp"`
	Signer      *SignerInfo  `json:"sig,omitempty"`
}

func (h *Header) AssociatedData() []byte {
	// JSON without Nonce to avoid circular dependency (still binds recipients etc.)
	tmp := *h
	tmp.Nonce = nil
	b, _ := json.Marshal(tmp)
	return b
}

func Write(w io.Writer, h *Header, ciphertext []byte) error {
	hb, err := json.Marshal(h)
	if err != nil { return err }
	if _, err = io.WriteString(w, magic); err != nil { return err }
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(hb)))
	if _, err = w.Write(lenBuf[:]); err != nil { return err }
	if _, err = w.Write(hb); err != nil { return err }
	_, err = w.Write(ciphertext)
	return err
}

func Read(r io.Reader) (*Header, []byte, error) {
	var m [4]byte
	if _, err := io.ReadFull(r, m[:]); err != nil { return nil, nil, err }
	if string(m[:]) != magic {
		return nil, nil, fmt.Errorf("bad magic")
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil { return nil, nil, err }
	n := binary.BigEndian.Uint32(lenBuf[:])
	hb := make([]byte, n)
	if _, err := io.ReadFull(r, hb); err != nil { return nil, nil, err }
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil { return nil, nil, err }
	ct, err := io.ReadAll(r)
	if err != nil { return nil, nil, err }
	return &h, ct, nil
}

// Helpers for testing round-trip
func RoundTrip(h *Header, ct []byte) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := Write(buf, h, ct); err != nil { return nil, err }
	_, out, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil { return nil, err }
	return out, nil
}
