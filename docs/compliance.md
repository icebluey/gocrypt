# gocrypt RFC 9580 & LibrePGP Compatibility Notes

This document summarizes how the gocrypt proof of concept aligns with the
OpenPGP specification published as [RFC 9580] and the LibrePGP draft
([draft-koch-librepgp-04]).  It is intended to record an engineering audit of
the repository so that future contributors can understand which mandatory
structures of the specifications are already covered and which areas still
need further work.

## Scope

The CLI focuses exclusively on encrypting data streams and ASCII armoring the
result.  Key material is generated for learning purposes only and is not a
complete OpenPGP certificate.  The PoC does **not** attempt to cover policy
preferences, signature verification, multi-chunk AEAD, or revocation data.

## Version 6 Keys (Tag 6 / Tag 5)

* Section 5.5 of RFC 9580 defines the layout of version 6 public keys, and the
  repository constructs them via `BuildPublicKeyV6`, which injects version 6,
  timestamp, algorithm identifier, and the algorithm-specific key material in a
  4-octet length-prefixed field.【F:pkg/pgp/key.go†L11-L39】
* Secret keys embed the entire public key body followed by an S2K usage octet
  per RFC 9580 §5.6.  The PoC only supports the “usage 0” (no protection)
  variant to keep the example compact.【F:pkg/pgp/key.go†L41-L77】
* The CLI’s `keygen` command uses these helpers to emit either X25519 or X448
  material in Tag 6 / Tag 5 packets, with optional ASCII armor wrappers.  The
  key parser mirrors the same constraints so encrypted messages can be
  decrypted with material that originated from other tooling, as long as it
  embeds the same raw curve bytes.【F:cmd/gocrypt/main.go†L238-L315】【F:pkg/pgp/key.go†L79-L132】

The implementation therefore matches the v6 key structure requirements for the
curves that this PoC supports.  Extending the code to cover additional
algorithms would only require adding new `Build…` variants that encode the
corresponding algorithm-specific material before delegating to the shared
packet framing helpers.

## Version 6 PKESK (Tag 1) and SEIPD v2 (Tag 18)

* RFC 9580 §5.1 requires version 6 PKESK packets to wrap the session key with
  AES Key Wrap after producing an ECDH shared secret via X25519 or X448.  The
  implementation follows exactly that recipe: it generates an ephemeral key, it
  derives a key-encryption key with the RFC 6637 Concat-KDF inputs, and it wraps
  the symmetric key with the AES Key Wrap routine before emitting Tag 1 and its
  length-prefixed algorithm specific fields.【F:pkg/pgp/pkesk_v6_x25519_x448.go†L14-L69】
* The decryptor performs the reverse operation and is used by the CLI to unwrap
  the PKESK body before decrypting the payload.【F:pkg/pgp/pkesk_decode.go†L9-L66】【F:cmd/gocrypt/main.go†L361-L417】
* Section 5.13.2 of RFC 9580 mandates AEAD=OCB for v2 SEIPD packets.  The PoC
  only instantiates that combination, derives the chunk IV using the HKDF
  construction defined in §5.13.2, and emits the single-chunk variant together
  with the final authentication tag over the octet count.  The chunk size flag is
  exposed so that the stream helper can reuse the same framing logic.【F:pkg/pgp/seipdv2ocb.go†L23-L81】
* The streaming helpers called by the CLI always select AEAD=OCB and the v2
  packet body.  As a result, any encrypted message produced by the tool is
  forced to comply with the AEAD requirements listed in RFC 9580 §5.13.2 and the
  LibrePGP draft §5.16 when emitting Tag 20 packets.【F:cmd/gocrypt/main.go†L292-L344】【F:pkg/pgp/seipdv2ocb_stream.go†L9-L104】【F:pkg/pgp/ocbed_stream.go†L10-L107】

## AEAD and OCB3 Usage

Both RFC 9580 §5.13.2 and the LibrePGP draft §5.16 require OCB as the mandatory
AEAD mode for version 6 session encryption.  The PoC uses ProtonMail’s Go OCB
implementation, instantiating it with AES-128/192/256 keys and computing both the
chunk ciphertext and the final tag over the encoded length, which mirrors the
OCBED behaviour described in the LibrePGP draft.【F:pkg/pgp/seipdv2ocb.go†L33-L78】【F:pkg/pgp/ocbed.go†L14-L66】

## ML-KEM 768 / 1024 Helpers

LibrePGP §14 introduces post-quantum hybrid encryption that combines an ECC-KEM
with ML-KEM-768 or ML-KEM-1024.  The repository already hosts utility functions
that wrap a randomly generated content-encryption key using Cloudflare CIRCL’s
ML-KEM primitives, returning the ciphertext and the XOR-protected session key.
This functionality is exercised in the unit tests that accompany this change so
that future work can wire it into the packet builders when the composite
algorithm IDs are finalized.【F:pkg/crypto/kem/mlkem/mlkem.go†L12-L79】

## Remaining Work

* **Version 6 signatures:** this PoC focuses on encryption.  A complete
  implementation still needs routines to produce and verify version 6 Signature
  packets, including hashed and unhashed subpacket management and EdDSA/ECDSA
  MPI encoding.
* **Composite ML-KEM PKESK:** the helper wraps and unwraps ML-KEM ciphertexts,
  but the packet builders still need to combine the ECC and ML-KEM shares and
  feed them through the KMAC-based key combiner defined in LibrePGP §14.1.4.
* **Passphrase recipients (v6 SKESK):** the CLI only emits PKESK packets today.
  Adding v6 SKESK construction would make it possible to encrypt to passwords in
  addition to public keys while staying on the modern AEAD v2 container.

[RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html
[draft-koch-librepgp-04]: https://www.ietf.org/archive/id/draft-koch-librepgp-04.txt
