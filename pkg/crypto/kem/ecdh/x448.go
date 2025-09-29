package ecdh

import (
    "crypto/rand"
    "errors"
    "io"

    "github.com/cloudflare/circl/dh/x448"
)

// GenerateX448 returns raw public/private bytes using CIRCL x448.
func GenerateX448() (pub, priv []byte, err error) {
    var sk, pk x448.Key
    if _, err = io.ReadFull(rand.Reader, sk[:]); err != nil { return nil, nil, err }
    x448.KeyGen(&pk, &sk)
    return pk[:], sk[:], nil
}

// WrapX448 performs ECDH(X448) using ephemeral secret and wraps CEK via kdf() + xorWrap().
func WrapX448(peerPub, cek []byte) (recipType string, wrapped, ephPub []byte, err error) {
    if len(peerPub) != x448.Size {
        return "", nil, nil, errors.New("bad x448 public key length")
    }
    var pk x448.Key
    copy(pk[:], peerPub)

    // Ephemeral key pair
    var ephSk, ephPk x448.Key
    if _, err = io.ReadFull(rand.Reader, ephSk[:]); err != nil { return "", nil, nil, err }
    x448.KeyGen(&ephPk, &ephSk)

    // Shared secret
    var shared x448.Key
    ok := x448.Shared(&shared, &ephSk, &pk)
    if !ok {
        return "", nil, nil, errors.New("x448 shared secret failed (low-order point?)")
    }
    kek := kdf(shared[:], []byte("gocrypt-kek-x448"))
    wrapped = xorWrap(cek, kek)
    return "x448", wrapped, ephPk[:], nil
}

func UnwrapX448(priv []byte, wrapped, ephPub []byte) ([]byte, error) {
    if len(priv) != x448.Size || len(ephPub) != x448.Size {
        return nil, errors.New("bad x448 key length")
    }
    var sk, ep, shared x448.Key
    copy(sk[:], priv)
    copy(ep[:], ephPub)
    ok := x448.Shared(&shared, &sk, &ep)
    if !ok {
        return nil, errors.New("x448 shared secret failed (low-order point?)")
    }
    kek := kdf(shared[:], []byte("gocrypt-kek-x448"))
    return xorWrap(wrapped, kek), nil
}
