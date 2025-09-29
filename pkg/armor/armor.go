package armor

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

// CRC-24 (poly 0x1864CF, init 0xB704CE) compatible with OpenPGP armor.
func crc24(data []byte) uint32 {
	crc := uint32(0xB704CE)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if (crc & 0x1000000) != 0 {
				crc ^= 0x1864CF
			}
		}
	}
	return crc & 0xFFFFFF
}

// ArmorPGPMessage encodes raw bytes as an ASCII-armored PGP MESSAGE block.
func ArmorPGPMessage(raw []byte, headers map[string]string) []byte {
	return ArmorEncode("PGP MESSAGE", raw, headers)
}

// ArmorPGPMessageNoCRC encodes without CRC footer (RFC 9580 §6.1 discourages CRC; §6.2 forbids it for v2 SEIPD sequences).
func ArmorPGPMessageNoCRC(raw []byte, headers map[string]string) []byte {
	return ArmorEncodeNoCRC("PGP MESSAGE", raw, headers)
}

// ArmorEncodeNoCRC is like ArmorEncode but omits the CRC24 footer.
func ArmorEncodeNoCRC(blockType string, raw []byte, headers map[string]string) []byte {
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(b64, raw)

	var buf bytes.Buffer
	buf.WriteString("-----BEGIN " + blockType + "-----\n")
	if headers != nil {
		for k, v := range headers {
			buf.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	buf.WriteString("\n")
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) { end = len(b64) }
		buf.Write(b64[i:end])
		buf.WriteByte('\n')
	}
	buf.WriteString("-----END " + blockType + "-----\n")
	return buf.Bytes()
}

// ArmorEncode encodes raw bytes into an ASCII armored block with the given type,
// e.g. "PGP MESSAGE", "PGP SIGNATURE", "PGP PUBLIC KEY BLOCK", "PGP PRIVATE KEY BLOCK".
func ArmorEncode(blockType string, raw []byte, headers map[string]string) []byte {
	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(b64, raw)

	var buf bytes.Buffer
	buf.WriteString("-----BEGIN " + blockType + "-----\n")
	if headers != nil {
		for k, v := range headers {
			buf.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	// blank line before data section (even if no headers)
	buf.WriteString("\n")

	// wrap base64 at 64 columns
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) { end = len(b64) }
		buf.Write(b64[i:end])
		buf.WriteByte('\n')
	}
	// CRC-24 checksum line
	crc := crc24(raw)
	crcBytes := []byte{ byte((crc>>16)&0xFF), byte((crc>>8)&0xFF), byte(crc&0xFF) }
	crcB64 := make([]byte, base64.StdEncoding.EncodedLen(3))
	base64.StdEncoding.Encode(crcB64, crcBytes)
	buf.WriteString("=")
	buf.Write(crcB64)
	buf.WriteByte('\n')

	buf.WriteString("-----END " + blockType + "-----\n")
	return buf.Bytes()
}

// ArmorDecode parses any OpenPGP-style armored block and returns (type, headers, raw, ok).
// CRC line (if present) is verified; if absent, ok is still true.
func ArmorDecode(in []byte) (string, map[string]string, []byte, bool) {
	beginPrefix := []byte("-----BEGIN ")
	start := bytes.Index(in, beginPrefix)
	if start < 0 { return "", nil, nil, false }
	in = in[start+len(beginPrefix):]
	endType := bytes.Index(in, []byte("-----"))
	if endType < 0 { return "", nil, nil, false }
	blockType := string(in[:endType])
	in = in[endType+len("-----"):]

	endMarker := []byte("-----END " + blockType + "-----")
	end := bytes.Index(in, endMarker)
	if end < 0 { return "", nil, nil, false }
	body := in[:end]

	// split into lines and trim CR
	lines := bytes.Split(body, []byte{'\n'})
	for i := range lines { lines[i] = bytes.TrimRight(lines[i], "\r") }

	// parse headers until blank line
	hdrs := map[string]string{}
	dataStart := 0
	for i, ln := range lines {
		if len(bytes.TrimSpace(ln)) == 0 {
			dataStart = i + 1
			break
		}
		kv := bytes.SplitN(ln, []byte{':'}, 2)
		if len(kv) == 2 {
			k := string(bytes.TrimSpace(kv[0]))
			v := string(bytes.TrimSpace(kv[1]))
			hdrs[k] = v
		}
	}
	// if no blank line was found, there were no headers
	if dataStart == 0 { dataStart = 0 }

	// collect non-empty data lines
	dataLines := make([][]byte, 0, len(lines)-dataStart)
	for _, ln := range lines[dataStart:] {
		if len(bytes.TrimSpace(ln)) == 0 { continue }
		dataLines = append(dataLines, ln)
	}
	if len(dataLines) == 0 { return "", nil, nil, false }

	// last line may be CRC if it begins with '='
	var crcGiven []byte
	last := dataLines[len(dataLines)-1]
	if len(last) > 0 && last[0] == '=' {
		crcB64 := bytes.TrimSpace(last[1:])
		crcGiven = make([]byte, base64.StdEncoding.DecodedLen(len(crcB64)))
		n, err := base64.StdEncoding.Decode(crcGiven, crcB64)
		if err == nil { crcGiven = crcGiven[:n] } else { crcGiven = nil }
		dataLines = dataLines[:len(dataLines)-1]
	}
	if len(dataLines) == 0 { return "", nil, nil, false }

	b64 := bytes.Join(dataLines, nil)
	out := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(out, b64)
	if err != nil { return "", nil, nil, false }
	out = out[:n]

	if len(crcGiven) == 3 {
		crc := crc24(out)
		if byte((crc>>16)&0xFF) != crcGiven[0] || byte((crc>>8)&0xFF) != crcGiven[1] || byte(crc&0xFF) != crcGiven[2] {
			return "", nil, nil, false
		}
	}
	return blockType, hdrs, out, true
}

// DecodePGPMessage extracts a PGP MESSAGE armored block.
func DecodePGPMessage(in []byte) ([]byte, bool) {
	bt, _, raw, ok := ArmorDecode(in)
	if !ok || bt != "PGP MESSAGE" { return nil, false }
	return raw, true
}
