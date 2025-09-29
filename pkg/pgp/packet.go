package pgp

import (
	"bytes"
	"errors"
	"io"
)

var errShortHeader = errors.New("pgp: short packet header")

// writeNewFormatHeader builds a RFC 9580 new-format packet header.
func writeNewFormatHeader(tag byte, bodyLen int) []byte {
	first := 0xC0 | int(tag&0x3F)
	var hdr bytes.Buffer
	hdr.WriteByte(byte(first))
	if bodyLen < 192 {
		hdr.WriteByte(byte(bodyLen))
	} else if bodyLen <= 8383 {
		bodyLen -= 192
		hdr.WriteByte(byte(192 + (bodyLen >> 8)))
		hdr.WriteByte(byte(bodyLen & 0xFF))
	} else {
		hdr.WriteByte(0xFF)
		hdr.WriteByte(byte(bodyLen >> 24))
		hdr.WriteByte(byte((bodyLen >> 16) & 0xFF))
		hdr.WriteByte(byte((bodyLen >> 8) & 0xFF))
		hdr.WriteByte(byte(bodyLen & 0xFF))
	}
	return hdr.Bytes()
}

func Packet(tag byte, body []byte) []byte {
	h := writeNewFormatHeader(tag, len(body))
	out := make([]byte, 0, len(h)+len(body))
	out = append(out, h...)
	out = append(out, body...)
	return out
}

// WritePacketHeader writes a new-format packet header for the given tag/bodyLen.
func WritePacketHeader(w io.Writer, tag byte, bodyLen int) error {
	hdr := writeNewFormatHeader(tag, bodyLen)
	_, err := w.Write(hdr)
	return err
}

// ReadPacketHeader reads a new-format packet header from r and returns the tag and body length.
func ReadPacketHeader(r io.Reader) (tag byte, bodyLen int, err error) {
	var first [1]byte
	if _, err = io.ReadFull(r, first[:]); err != nil {
		if err == io.EOF {
			return 0, 0, errShortHeader
		}
		return 0, 0, err
	}
	h := first[0]
	if (h & 0xC0) != 0xC0 {
		return 0, 0, ErrPacket
	}
	tag = h & 0x3F

	var lenByte [1]byte
	if _, err = io.ReadFull(r, lenByte[:]); err != nil {
		if err == io.EOF {
			return 0, 0, errShortHeader
		}
		return 0, 0, err
	}
	b := lenByte[0]
	switch {
	case b < 192:
		bodyLen = int(b)
	case b <= 223:
		var next [1]byte
		if _, err = io.ReadFull(r, next[:]); err != nil {
			return 0, 0, err
		}
		bodyLen = (int(b)-192)<<8 + int(next[0]) + 192
	case b == 255:
		var buf [4]byte
		if _, err = io.ReadFull(r, buf[:]); err != nil {
			return 0, 0, err
		}
		bodyLen = int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	default:
		return 0, 0, ErrPacket
	}
	return tag, bodyLen, nil
}

// ReadPacket parses a single new-format packet and returns (tag, body, rest).
func ReadPacket(b []byte) (byte, []byte, []byte, error) {
	if len(b) < 2 {
		return 0, nil, nil, ErrPacket
	}
	h := b[0]
	if (h & 0xC0) != 0xC0 {
		return 0, nil, nil, ErrPacket
	}
	tag := h & 0x3F
	b = b[1:]
	var n int
	if b[0] < 192 {
		n = int(b[0])
		b = b[1:]
	} else if b[0] <= 223 {
		if len(b) < 2 {
			return 0, nil, nil, ErrPacket
		}
		n = int(b[0]-192)<<8 + int(b[1]) + 192
		b = b[2:]
	} else if b[0] == 255 {
		if len(b) < 5 {
			return 0, nil, nil, ErrPacket
		}
		n = int(b[1])<<24 | int(b[2])<<16 | int(b[3])<<8 | int(b[4])
		b = b[5:]
	} else {
		return 0, nil, nil, ErrPacket
	}
	if len(b) < n {
		return 0, nil, nil, ErrPacket
	}
	return tag, b[:n], b[n:], nil
}
