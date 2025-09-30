package xkem

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/sha3"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/dh/x448"
)

// Curve selects which Montgomery curve to use for the XKem construction.
type Curve int

const (
	CurveX25519 Curve = iota
	CurveX448
)

// Encaps runs the LibrePGP §14.1.1 XKem encapsulation and returns the
// ephemeral public key (without SOS prefix) and hashed key share.
func Encaps(curve Curve, recipientPub []byte) ([]byte, []byte, error) {
	switch curve {
	case CurveX25519:
		if len(recipientPub) != x25519.Size {
			return nil, nil, errors.New("xkem: bad x25519 public key length")
		}
		var ephSecret x25519.Key
		if _, err := rand.Read(ephSecret[:]); err != nil {
			return nil, nil, err
		}
		var ephPub x25519.Key
		x25519.KeyGen(&ephPub, &ephSecret)
		var recip x25519.Key
		copy(recip[:], recipientPub)
		var shared x25519.Key
		if ok := x25519.Shared(&shared, &ephSecret, &recip); !ok {
			return nil, nil, errors.New("xkem: shared secret failure")
		}
		buf := make([]byte, 0, len(shared)+len(ephPub)+len(recipientPub))
		buf = append(buf, shared[:]...)
		buf = append(buf, ephPub[:]...)
		buf = append(buf, recipientPub...)
		digest := sha3.Sum256(buf)
		keyShare := make([]byte, len(digest))
		copy(keyShare, digest[:])
		return append([]byte(nil), ephPub[:]...), keyShare, nil
	case CurveX448:
		if len(recipientPub) != x448.Size {
			return nil, nil, errors.New("xkem: bad x448 public key length")
		}
		var ephSecret x448.Key
		if _, err := rand.Read(ephSecret[:]); err != nil {
			return nil, nil, err
		}
		var ephPub x448.Key
		x448.KeyGen(&ephPub, &ephSecret)
		var recip x448.Key
		copy(recip[:], recipientPub)
		var shared x448.Key
		if ok := x448.Shared(&shared, &ephSecret, &recip); !ok {
			return nil, nil, errors.New("xkem: shared secret failure")
		}
		buf := make([]byte, 0, len(shared)+len(ephPub)+len(recipientPub))
		buf = append(buf, shared[:]...)
		buf = append(buf, ephPub[:]...)
		buf = append(buf, recipientPub...)
		digest := sha3.Sum512(buf)
		out := make([]byte, len(digest))
		copy(out, digest[:])
		return append([]byte(nil), ephPub[:]...), out, nil
	default:
		return nil, nil, errors.New("xkem: unsupported curve")
	}
}

// Decaps runs the LibrePGP §14.1.1 XKem decapsulation for the given curve and
// returns the hashed key share.
func Decaps(curve Curve, recipientPriv, recipientPub, ciphertext []byte) ([]byte, error) {
	switch curve {
	case CurveX25519:
		if len(recipientPriv) != x25519.Size || len(recipientPub) != x25519.Size || len(ciphertext) != x25519.Size {
			return nil, errors.New("xkem: bad x25519 key length")
		}
		var priv x25519.Key
		copy(priv[:], recipientPriv)
		var recip x25519.Key
		copy(recip[:], recipientPub)
		var eph x25519.Key
		copy(eph[:], ciphertext)
		var shared x25519.Key
		if ok := x25519.Shared(&shared, &priv, &eph); !ok {
			return nil, errors.New("xkem: shared secret failure")
		}
		buf := make([]byte, 0, len(shared)+len(ciphertext)+len(recipientPub))
		buf = append(buf, shared[:]...)
		buf = append(buf, ciphertext...)
		buf = append(buf, recipientPub...)
		digest := sha3.Sum256(buf)
		out := make([]byte, len(digest))
		copy(out, digest[:])
		return out, nil
	case CurveX448:
		if len(recipientPriv) != x448.Size || len(recipientPub) != x448.Size || len(ciphertext) != x448.Size {
			return nil, errors.New("xkem: bad x448 key length")
		}
		var priv x448.Key
		copy(priv[:], recipientPriv)
		var recip x448.Key
		copy(recip[:], recipientPub)
		var eph x448.Key
		copy(eph[:], ciphertext)
		var shared x448.Key
		if ok := x448.Shared(&shared, &priv, &eph); !ok {
			return nil, errors.New("xkem: shared secret failure")
		}
		buf := make([]byte, 0, len(shared)+len(ciphertext)+len(recipientPub))
		buf = append(buf, shared[:]...)
		buf = append(buf, ciphertext...)
		buf = append(buf, recipientPub...)
		digest := sha3.Sum512(buf)
		out := make([]byte, len(digest))
		copy(out, digest[:])
		return out, nil
	default:
		return nil, errors.New("xkem: unsupported curve")
	}
}
