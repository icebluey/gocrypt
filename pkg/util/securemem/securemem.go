package securemem

import (
	"github.com/awnumar/memguard"
)

// Secret wraps a memguard locked buffer.
type Secret struct {
	buf *memguard.LockedBuffer
}

func NewRandom(n int) *Secret {
	return &Secret{buf: memguard.NewBufferRandom(n)}
}
func New(b []byte) *Secret {
	return &Secret{buf: memguard.NewBufferFromBytes(b)}
}
func (s *Secret) Bytes() []byte { return s.buf.Bytes() }
func (s *Secret) Destroy()      { s.buf.Destroy() }
