# gocrypt (PoC)

A minimal proof of concept showing how to emit OpenPGP-encrypted messages compatible with **RFC 9580 (IETF, v6)** and with the **LibrePGP draft (Tag 20 OCBED)**. This PoC focuses on encryption and ASCII armor. It supports:

- v6 PKESK with X25519 or X448 (Concat-KDF + AES-KW)
- LibrePGP §14 hybrid PKESK with ML-KEM768+X25519 or ML-KEM1024+X448
- v2 SEIPD (Tag 18) using AEAD=OCB
- LibrePGP OCBED (Tag 20) using AEAD=OCB
- Armor (`--armor`) enabled by default

> ⚠️ This is a teaching-oriented PoC. It does **not** implement full key/cert parsing, signature verification, recipient preference negotiation, multi-chunk AEAD, or full KDF parameter encoding. See code comments for what to harden next before production use.

## Build

```bash
cd gocrypt
go mod tidy
go build ./cmd/gocrypt
```

## Usage

### Generate a key pair

```bash
./gocrypt keygen -pkalg=x448 -armor -out keys/x448
```

This creates `keys/x448.pub.asc` and `keys/x448.key.asc`. The `.asc` files are
OpenPGP-armored Tag 6/Tag 5 packets that carry the raw X448 material expected
by the CLI.

### Encrypt using a public key file

```bash
echo 'hello' | ./gocrypt \
  -format=rfc9580 \
  -sym=aes256 \
  -pubfile=keys/x448.pub.asc \
  -out msg.asc
```

`-pubfile` accepts either the armored output shown above or the raw base64
(`keys/x448.pub`) produced when `-armor` is omitted. The tool automatically
detects whether the key is X25519/X448 or one of the ML-KEM hybrids (1216 or
1624 byte raw blobs); use `-pkalg` only if you need to override detection.

### Decrypt using the matching private key

```bash
./gocrypt decrypt \
  -keyfile=keys/x448.key.asc \
  -out plaintext.txt \
  msg.asc
```

`-keyfile` mirrors `-pubfile` and supports `.key.asc` as well as the raw
`keys/x448.key` file (including 2432/3224 byte ML-KEM hybrid dumps). The
command writes the decrypted message to `stdout` when `-out` is omitted.

If you already have the raw base64 strings, the original `-pk=<BASE64>` flag is
still available for both encryption (public key) and `decrypt` (private key).
Supply the 32- or 56-byte ECC share for X25519/X448, or concatenate it with the
ML-KEM payload (32+1184 or 56+1568 bytes for the public key; 32+2400 or
56+3168 bytes for the private key) when working with the hybrid algorithms, and
confirm the choice with `-pkalg=mlkem768+x25519` or `-pkalg=mlkem1024+x448`.
The `gocrypt hybrid` helper shown below performs this concatenation for you.

### Work with ML-KEM helper routines

The CLI exposes experimental helpers that exercise the ML-KEM wrappers used by
the hybrid LibrePGP design:

```bash
# Generate a ML-KEM-768 key pair (omit -out to print base64 to stdout)
./gocrypt kemgen -scheme=mlkem768 -out kem/mlkem768

# Wrap a freshly generated 32-byte CEK for that recipient
./gocrypt kemwrap \
  -scheme=mlkem768 \
  -pubfile=kem/mlkem768.pub \
  -ceksize=32

# Recover the CEK from the base64 WRAPPED/KEMCT values printed above
./gocrypt kemunwrap \
  -scheme=mlkem768 \
  -privfile=kem/mlkem768.key \
  -wrapped="<WRAPPED from kemwrap>" \
  -kemct="<KEMCT from kemwrap>"
```

`kemwrap` accepts `-cek` when you want to supply the CEK bytes yourself and the
`-pub`/`-pubfile` flags mirror the public key handling used by `encrypt`.  The
`kemunwrap` command likewise supports inline base64 or files via `-priv`/`-privfile`,
`-wrapped`/`-wrappedfile`, and `-kemct`/`-kemctfile`.

### Encrypt with a ML-KEM + X25519 composite key

The PoC can emit and consume the LibrePGP §14 hybrid PKESK format.  The CLI now
accepts both full Tag 6/Tag 5 packets **and** the raw hybrid blobs described
above, so you can mix and match depending on your workflow.  Generate the raw
X25519/X448 and ML-KEM material (for example via `keygen` and `kemgen`), then use
`gocrypt hybrid` to merge the byte slices into the base64 blobs expected by
`-pk`/`-pkalg` and `decrypt -pk`.

#### Example: ML-KEM768 + X25519 via raw base64

```bash
# 1. produce the ECC and ML-KEM material
./gocrypt keygen -pkalg=x25519 -out keys/mlkem768_x25519
./gocrypt kemgen -scheme=mlkem768 -out kem/mlkem768

# 2. combine the ECC and ML-KEM shares with the CLI helper
./gocrypt hybrid \
  -mode=pub \
  -eccfile=keys/mlkem768_x25519.pub \
  -mlkemfile=kem/mlkem768.pub \
  -out keys/mlkem768_x25519_hybrid.pub
./gocrypt hybrid \
  -mode=priv \
  -eccfile=keys/mlkem768_x25519.key \
  -mlkemfile=kem/mlkem768.key \
  -out keys/mlkem768_x25519_hybrid.key
PUB=$(tr -d '\n' < keys/mlkem768_x25519_hybrid.pub)
PRIV=$(tr -d '\n' < keys/mlkem768_x25519_hybrid.key)

# 3. encrypt with the hybrid algorithm (1216-byte public material)
echo 'mlkem768 hybrid hello' | ./gocrypt \
  -format=librepgp \
  -sym=aes256 \
  -pk="$PUB" \
  -pkalg=mlkem768+x25519 \
  -out hybrid768.msg

# 4. decrypt using the matching composite private key (2432 bytes)
./gocrypt decrypt \
  -pk="$PRIV" \
  -pkalg=mlkem768+x25519 \
  -out hybrid768.txt \
  hybrid768.msg
```

#### Example: ML-KEM1024 + X448 via raw base64

```bash
./gocrypt keygen -pkalg=x448 -out keys/mlkem1024_x448
./gocrypt kemgen -scheme=mlkem1024 -out kem/mlkem1024

./gocrypt hybrid \
  -mode=pub \
  -eccfile=keys/mlkem1024_x448.pub \
  -mlkemfile=kem/mlkem1024.pub \
  -out keys/mlkem1024_x448_hybrid.pub
./gocrypt hybrid \
  -mode=priv \
  -eccfile=keys/mlkem1024_x448.key \
  -mlkemfile=kem/mlkem1024.key \
  -out keys/mlkem1024_x448_hybrid.key

PUB=$(tr -d '\n' < keys/mlkem1024_x448_hybrid.pub)
PRIV=$(tr -d '\n' < keys/mlkem1024_x448_hybrid.key)

echo 'mlkem1024 hybrid hello' | ./gocrypt \
  -format=librepgp \
  -sym=aes256 \
  -pk="$PUB" \
  -pkalg=mlkem1024+x448 \
  -out hybrid1024.msg

./gocrypt decrypt \
  -pk="$PRIV" \
  -pkalg=mlkem1024+x448 \
  -out hybrid1024.txt \
  hybrid1024.msg
```

#### Using armored hybrid key packets

You can still build OpenPGP packets with the helper builders when you want
armored key material. After running the snippet you will have
`keys/hybrid.pub.asc` and `keys/hybrid.key.asc` that the CLI can use directly:

```bash
echo 'hybrid hello' | ./gocrypt \
  -format=librepgp \
  -sym=aes256 \
  -pubfile=keys/hybrid.pub.asc \
  -out hybrid.msg

./gocrypt decrypt \
  -keyfile=keys/hybrid.key.asc \
  -out hybrid.txt \
  hybrid.msg
```

The same flow works for the ML-KEM1024+X448 combination—switch the snippet to
use `mlkem.Generate("mlkem1024")` and the corresponding
`pgp.PKALG_MLKEM1024_X448` constant when you want the higher security level.

## Notes

- RFC 9580 references:
  - v6 PKESK, ECDH KDF and AES-KW (§5.1, §11.4, §11.5).
  - v2 SEIPD (AEAD-OCB) with HKDF, salt, chunk size, and final tag on empty string (§5.13.2).
- LibrePGP draft references:
  - OCB Encrypted Data Packet (Tag 20), AAD layout and final tag (§5.16).
