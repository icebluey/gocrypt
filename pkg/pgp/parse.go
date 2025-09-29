package pgp

import (
    "encoding/binary"
    "fmt"
)

type PacketView struct {
    Tag  byte
    Body []byte
}

// ParseNewFormatPackets splits a stream into packets with new-format headers.
func ParseNewFormatPackets(buf []byte) ([]PacketView, error) {
    var out []PacketView
    i := 0
    for i < len(buf) {
        if i >= len(buf) { break }
        oct := buf[i]
        if (oct & 0xC0) != 0xC0 {
            return nil, fmt.Errorf("not a new-format header at %d", i)
        }
        tag := oct & 0x3F
        i++
        if i >= len(buf) { return nil, fmt.Errorf("truncated length") }
        l1 := buf[i]; i++
        var bodyLen int
        if l1 < 192 {
            bodyLen = int(l1)
        } else if l1 <= 223 {
            if i >= len(buf) { return nil, fmt.Errorf("truncated 2-oct len") }
            l2 := buf[i]; i++
            bodyLen = int(((int(l1)-192)<<8) + int(l2) + 192)
        } else {
            if i+4 > len(buf) { return nil, fmt.Errorf("truncated 5-oct len") }
            bodyLen = int(binary.BigEndian.Uint32(buf[i:i+4]))
            i += 4
        }
        if i+bodyLen > len(buf) { return nil, fmt.Errorf("truncated body") }
        out = append(out, PacketView{Tag: tag, Body: buf[i:i+bodyLen]})
        i += bodyLen
    }
    return out, nil
}
