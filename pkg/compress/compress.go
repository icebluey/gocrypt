package compress

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"io"

	dbz2 "github.com/dsnet/compress/bzip2"
)

type Codec interface {
	Compress([]byte) ([]byte, error)
	Decompress([]byte) ([]byte, error)
}

func Get(name string) (Codec, error) {
	switch name {
	case "none":
		return noop{}, nil
	case "zip":
		return deflateCodec{}, nil
	case "zlib":
		return zlibCodec{}, nil
	case "bzip2":
		return bzip2Codec{}, nil
	default:
		return noop{}, nil
	}
}

type noop struct{}
func (noop) Compress(b []byte) ([]byte, error)   { return b, nil }
func (noop) Decompress(b []byte) ([]byte, error) { return b, nil }

type deflateCodec struct{}
func (deflateCodec) Compress(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	if _, err := w.Write(b); err != nil { return nil, err }
	_ = w.Close()
	return buf.Bytes(), nil
}
func (deflateCodec) Decompress(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	return io.ReadAll(r)
}

type zlibCodec struct{}
func (zlibCodec) Compress(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if _, err := w.Write(b); err != nil { return nil, err }
	_ = w.Close()
	return buf.Bytes(), nil
}
func (zlibCodec) Decompress(b []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil { return nil, err }
	defer r.Close()
	return io.ReadAll(r)
}

type bzip2Codec struct{}
func (bzip2Codec) Compress(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := dbz2.NewWriter(&buf, &dbz2.WriterConfig{Level: dbz2.BestCompression})
	if err != nil { return nil, err }
	if _, err := w.Write(b); err != nil { return nil, err }
	_ = w.Close()
	return buf.Bytes(), nil
}
func (bzip2Codec) Decompress(b []byte) ([]byte, error) {
	// stdlib only supports reader without writer, but dsnet also supports reader:
	r, err := dbz2.NewReader(bytes.NewReader(b), &dbz2.ReaderConfig{})
	if err != nil { return nil, err }
	defer r.Close()
	return io.ReadAll(r)
}
