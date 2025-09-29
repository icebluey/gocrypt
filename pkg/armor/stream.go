package armor

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
)

// MessageWriter streams ASCII armor output for PGP MESSAGE blocks.
type MessageWriter struct {
	blockType  string
	w          *bufio.Writer
	enc        io.WriteCloser
	breaker    *lineBreaker
	includeCRC bool
	crc        uint32
	wroteData  bool
	closed     bool
}

// NewMessageWriter initializes a streaming ASCII armor writer.
func NewMessageWriter(w io.Writer, blockType string, headers map[string]string, includeCRC bool) (*MessageWriter, error) {
	if blockType == "" {
		return nil, errors.New("armor: block type required")
	}
	bw := bufio.NewWriterSize(w, 32*1024)
	mw := &MessageWriter{
		blockType:  blockType,
		w:          bw,
		includeCRC: includeCRC,
		crc:        0xB704CE,
	}

	if _, err := fmt.Fprintf(bw, "-----BEGIN %s-----\n", blockType); err != nil {
		return nil, err
	}
	if len(headers) > 0 {
		keys := make([]string, 0, len(headers))
		for k := range headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, err := fmt.Fprintf(bw, "%s: %s\n", k, headers[k]); err != nil {
				return nil, err
			}
		}
	}
	if _, err := io.WriteString(bw, "\n"); err != nil {
		return nil, err
	}

	mw.breaker = &lineBreaker{w: bw}
	mw.enc = base64.NewEncoder(base64.StdEncoding, mw.breaker)
	return mw, nil
}

// NewPGPMessageWriter returns a MessageWriter for "PGP MESSAGE" blocks.
func NewPGPMessageWriter(w io.Writer, headers map[string]string, includeCRC bool) (*MessageWriter, error) {
	return NewMessageWriter(w, "PGP MESSAGE", headers, includeCRC)
}

// Write streams data into the armor encoder.
func (mw *MessageWriter) Write(p []byte) (int, error) {
	if mw.closed {
		return 0, errors.New("armor: write on closed message writer")
	}
	if mw.includeCRC {
		for _, b := range p {
			mw.crc = crc24UpdateByte(mw.crc, b)
		}
	}
	if len(p) > 0 {
		mw.wroteData = true
	}
	return mw.enc.Write(p)
}

// Close flushes base64 output and writes the footer.
func (mw *MessageWriter) Close() error {
	if mw.closed {
		return nil
	}
	mw.closed = true
	if err := mw.enc.Close(); err != nil {
		return err
	}
	if err := mw.breaker.Close(); err != nil {
		return err
	}

	if mw.includeCRC {
		crc := mw.crc & 0xFFFFFF
		crcBytes := []byte{byte((crc >> 16) & 0xFF), byte((crc >> 8) & 0xFF), byte(crc & 0xFF)}
		buf := make([]byte, base64.StdEncoding.EncodedLen(len(crcBytes)))
		base64.StdEncoding.Encode(buf, crcBytes)
		if _, err := fmt.Fprintf(mw.w, "=%s\n", string(buf)); err != nil {
			return err
		}
	} else if !mw.wroteData {
		if _, err := io.WriteString(mw.w, "\n"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(mw.w, "-----END %s-----\n", mw.blockType); err != nil {
		return err
	}
	return mw.w.Flush()
}

type lineBreaker struct {
	w   io.Writer
	col int
}

func (lb *lineBreaker) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if lb.col == 64 {
			if err := lb.writeNewline(); err != nil {
				return written, err
			}
		}
		remaining := 64 - lb.col
		if remaining == 0 {
			continue
		}
		n := len(p)
		if n > remaining {
			n = remaining
		}
		m, err := lb.w.Write(p[:n])
		written += m
		lb.col += m
		if err != nil {
			return written, err
		}
		if m < n {
			return written, io.ErrShortWrite
		}
		p = p[n:]
	}
	return written, nil
}

func (lb *lineBreaker) Close() error {
	if lb.col > 0 {
		return lb.writeNewline()
	}
	return nil
}

func (lb *lineBreaker) writeNewline() error {
	if bw, ok := lb.w.(interface{ WriteByte(byte) error }); ok {
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	} else {
		if _, err := lb.w.Write([]byte{'\n'}); err != nil {
			return err
		}
	}
	lb.col = 0
	return nil
}

func crc24UpdateByte(crc uint32, b byte) uint32 {
	crc ^= uint32(b) << 16
	for i := 0; i < 8; i++ {
		crc <<= 1
		if (crc & 0x1000000) != 0 {
			crc ^= 0x1864CF
		}
	}
	return crc & 0xFFFFFF
}
