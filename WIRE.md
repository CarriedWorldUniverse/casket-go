# casket at-rest envelope — wire format (cross-implementation parity)

This document enumerates the EXACT constants and byte layouts a port
(`casket-ts`, `casket-dotnet`, future `casket-go` versions) MUST match
byte-for-byte. The envelope is a cross-implementation wire format: an off-by-one
or width/endianness mistake is interop-fatal. Implementations MUST agree on every
value below.

The committed Known-Answer Tests (KATs) are the canonical conformance vectors:

- single-shot: `katVectors` in `envelope_test.go` (`TestKnownAnswerVectors`)
- framed/STREAM: `framedKATVectors` in `envelope_framed_test.go`
  (`TestFramedKnownAnswerVectors`)

A port is conformant iff it reproduces these blobs byte-for-byte (deterministic
seal, given the same key / keyref / nonce-or-salt+prefix / inputs) AND opens them.

All multi-byte integers on the wire are **big-endian**.

---

## Versions, suites, key types

| Field            | Value | Notes                                            |
|------------------|-------|--------------------------------------------------|
| version          | `0x01`| `envelopeVersion`; Open rejects any other value  |
| suite AES-256-GCM| `0x01`| 12-byte nonce, 16-byte tag                        |
| suite ChaCha20-Poly1305 (IETF) | `0x02` | 12-byte nonce, 16-byte tag          |
| suite XChaCha20-Poly1305 | `0x03` | 24-byte nonce, 16-byte tag (default suite) |
| keytype derived-repo | `0x01` | metadata only; authenticated, not interpreted |
| keytype byok-repo    | `0x02` | metadata only                                |
| keytype aspect-identity | `0x03` | metadata only                             |

Key length: **32 bytes** for all three suites (`envelopeKeySize`).
AEAD tag (Poly1305 / GCM): **16 bytes** for all three suites.

Nonce sizes come from the AEAD `NonceSize()`:
AES-GCM = 12, ChaCha20 = 12, XChaCha20 = 24.

---

## Descriptor (fixed 20 bytes, suite-first)

`descriptorSize = 20`. Field offsets:

| Offset (bytes) | Width | Field   | Const                       |
|----------------|-------|---------|-----------------------------|
| `[0]`          | 1     | suite   | `descOffSuite = 0`          |
| `[1]`          | 1     | version | `descOffVersion = 1`        |
| `[2]`          | 1     | keytype | `descOffKeyType = 2`        |
| `[3..18]`      | 16    | keyref  | `descOffKeyRef = 3`, `keyRefSize = 16` |
| `[19]`         | 1     | flags   | `descOffFlags = keyRefSize+3 = 19` |

`keyref` is a 16-byte opaque key identifier supplied by the caller (assigned by
nexus). It is stored in cleartext and MUST NOT be derived from secret key
material. It is copied verbatim into `[3..18]`.

`flags`: `0x00` = single-shot. `bit0` (`flagFramed = 0x01`) = framed/STREAM.
Single-shot Open rejects any non-zero flags (and gives a specific error for the
framed bit). Framed Open requires `bit0` set and rejects any other bits.

Total: `1+1+1+16+1 = 20`. (keyref ends at offset 18 inclusive; flags at 19.)

---

## Single-shot body

```
blob = DESCRIPTOR(20) || BODY
BODY = nonce(nonceSize) || ciphertext || tag(16)
```

Body byte-order is `nonce || AEAD.Seal(...)`, where `AEAD.Seal` appends the
16-byte tag to the ciphertext, i.e. `nonce || ciphertext || tag`.

Open slicing: `body = blob[20:]`; require `len(body) >= nonceSize` then
`len(body) - nonceSize >= 16` (tag); `nonce = body[:nonceSize]`,
`ciphertext = body[nonceSize:]` (the trailing 16 bytes are the tag, passed to the
AEAD as part of the ciphertext+tag input).

### Single-shot AAD (length-prefixed, big-endian)

```
AAD = descriptor(20)
   || uint16be(len(repoIdentity)) || repoIdentity
   || uint16be(len(objectPath))   || objectPath
```

Length prefixes are **2-byte big-endian** (`uint16be`). Each of `repoIdentity`
and `objectPath` MUST be `<= 0xFFFF (65535)` bytes; a longer field is rejected
(`maxU16Field = 0xFFFF`) so the length cannot silently wrap and defeat the
re-split ambiguity protection.

---

## Framed / STREAM format (flags bit0 set)

```
blob = DESCRIPTOR(20, bit0 set) || SALT(32)
    || noncePrefix(nonceSize - 5) || block_0 || block_1 || ... || block_last
block_i = AEAD.Seal(segment_i) = ciphertext_i || tag_i   (tag = 16 bytes)
```

Constants:

| Name                | Value                | Notes                                     |
|---------------------|----------------------|-------------------------------------------|
| salt size           | `32`                 | `framedSaltSize`; on wire right after the 20-byte descriptor, before the nonce prefix |
| segment size        | `65536` (64 KiB)     | `framedSegSize`; fixed format parameter, authenticated in the framed AAD |
| nonce prefix length | `nonceSize - 5`      | `noncePrefixLen`; AES-GCM/ChaCha20 → 7, XChaCha20 → 19 |
| nonce counter width | `4` (uint32be)       | `framedCounterSize`                         |
| nonce final-flag    | `1` byte             | `framedFlagSize`; `0x00` non-final, `0x01` final |
| nonce suffix        | `5` = counter(4) + flag(1) | `framedSuffixSize`                    |

### Per-stream key derivation (HKDF)

```
framedKey = HKDF-SHA256(secret = key, salt = SALT(32 random),
                        info = "casket-envelope-framed-v1") -> 32 bytes
```

HKDF info string is the exact ASCII bytes `casket-envelope-framed-v1` (25 bytes,
no NUL, no version suffix beyond `-v1`). Salt is the 32 on-wire bytes. Output
length is 32. The suite AEAD is then built from `framedKey`. A fresh random salt
per stream makes cross-stream nonce collisions infeasible for all suites.

### Per-segment nonce

```
nonce_i = noncePrefix || uint32be(i) || finalFlag
          \_ nonceSize-5 _/  \__ 4 __/  \__ 1 __/
```

`i` is the segment index, a **uint32 big-endian** counter starting at 0.
`finalFlag` = `0x01` for the final segment, `0x00` for every non-final segment.
The full nonce length equals the suite `nonceSize` (prefix + 4 + 1).

Segment-index limit: a framed stream may contain AT MOST `2^32` segments —
indices `0 .. 2^32-1` (= `math.MaxUint32`), the last marked final. No index may
repeat or wrap. A non-final segment at index `MaxUint32` is refused (the next
index would wrap to 0 and reuse a nonce); a final segment at `MaxUint32` is
legitimate. (In `casket-go`, a sticky `exhausted` flag makes index reuse
structurally impossible.)

### Framed AAD (same for every segment)

```
framedAAD = descriptor(20)
   || uint16be(len(repoIdentity)) || repoIdentity
   || uint16be(len(objectPath))   || objectPath
   || uint32be(framedSegSize)
```

i.e. the single-shot AAD followed by a **4-byte big-endian** segment size. The
same `framedAAD` is authenticated for all segments; segment position is bound by
the nonce counter and stream termination by the nonce final-flag, so the AAD does
not vary per segment. Binding `framedSegSize` turns a seal/open size mismatch into
an AEAD verification failure instead of a silent mis-parse.

### Segmentation rules (identical seal and open)

Let `S = framedSegSize`, `L = len(plaintext)`:

- `L == 0` → exactly one 0-byte final segment (block = just the 16-byte tag).
- `L > 0`, `L % S == 0` → `L/S` segments; the last is a full S-byte segment
  marked final (NO trailing empty segment).
- otherwise → `ceil(L/S)` segments; the last holds the remainder, marked final.

Only the last segment is final.

### Open block-boundary rule

With `blockSize = framedSegSize + 16` (tag): read up to `blockSize` bytes per
block. A full `blockSize` read is a (possibly non-final) block; a short non-empty
read is the final remainder block; a clean zero-byte read is end-of-stream. A full
block is final iff no bytes follow it (peek). The exact-multiple case is
unambiguous: a trailing block of exactly `blockSize` that is followed by EOF is
the final full block. A remainder block shorter than 16 bytes (no room for a tag)
is an error. Truncation, reorder, duplication, and splice all surface as AEAD
verification failures.

---

## Multi-recipient format (leading magic `0xCA`)

Age-style hybrid encryption: a fresh random 32-byte DEK seals the body as a
complete **single-shot envelope** (see above — identical descriptor, body, and
AAD semantics), and the DEK is wrapped once per recipient via ephemeral-X25519
ECDH + HKDF + the suite AEAD. Any single recipient private key opens the blob.

```
blob = MULTIHEADER(4) || WRAPS || BODY
MULTIHEADER = magic(0xCA) || version(0x01) || suite(1) || count(1)
WRAPS = count × ( ephemeralPub(32) || keyid(8) || nonce(nonceSize) || wrappedDEK(48) )
BODY = a complete single-shot envelope sealed under the DEK
     = DESCRIPTOR(20) || nonce(nonceSize) || ciphertext || tag(16)
```

Constants:

| Name            | Value  | Notes                                              |
|-----------------|--------|----------------------------------------------------|
| magic           | `0xCA` | `multiMagic`; distinct from every suite byte (0x01–0x03), so a multi blob can never be misparsed as a descriptor-first envelope |
| version         | `0x01` | `multiVersion`; Open rejects any other value        |
| suite           | same values as the descriptor suite | governs BOTH the DEK-wrap AEAD and the body envelope; the inner descriptor suite MUST equal the header suite (Open enforces) |
| count           | uint8, `1..255` | `0` is invalid; one wrap entry per recipient, in the order recipients were supplied to seal |
| ephemeralPub    | 32 bytes | raw X25519 public key, fresh per recipient per seal |
| keyid           | 8 bytes  | `SHA-256(recipientPub)[:8]`, cleartext recipient identifier |
| nonce           | suite `nonceSize` (12 / 12 / 24) | random, per wrap entry        |
| wrappedDEK      | 48 bytes | `AEAD.Seal(DEK)` = ciphertext(32) ‖ tag(16)        |
| DEK             | 32 bytes | random per seal; the body envelope's key            |
| recipient keys  | 32 bytes | raw X25519 (private scalar / public key)            |

### Per-recipient DEK wrap

```
shared  = X25519(ephemeralPriv, recipientPub)
wrapKey = HKDF-SHA256(secret = shared, salt = empty,
                      info = "casket-multi-v1" || ephemeralPub || recipientPub) -> 32 bytes
wrappedDEK = AEAD(suite, wrapKey).Seal(nonce = random, plaintext = DEK, aad = empty)
```

HKDF info is the exact ASCII bytes `casket-multi-v1` (15 bytes, no NUL)
followed by the raw 32-byte ephemeral public key, then the raw 32-byte
recipient public key (79 bytes total). The wrap AEAD uses no AAD; the wrap key
itself is bound to both ECDH ends via the info string.

### Open rules

- Reject: wrong magic, wrong version, unknown suite, `count == 0`, blob shorter
  than `4 + count·entrySize + 20` (entrySize = `32 + 8 + nonceSize + 48`).
- Derive the public key from the supplied private key; `keyid =
  SHA-256(pub)[:8]`; try matching entries **in order** (truncated-hash
  collisions between recipients are resolved by trying every matching entry).
- Unwrap the DEK, then open BODY exactly as a single-shot envelope (same
  caller-supplied `repoIdentity` / `objectPath` AAD binding), and require the
  inner descriptor suite to equal the header suite.

The header and wrap entries are **not** separately authenticated: each wrap is
self-authenticating (AEAD under a key bound to `ephemeralPub` + `recipientPub`),
and the body authenticates the descriptor + repo identity + object path under
the DEK. Corrupting a wrap entry only denies that recipient; it cannot alter
what any recipient decrypts.

---

## Endianness summary

| Quantity                       | Encoding   |
|--------------------------------|------------|
| AAD field length prefixes      | uint16 big-endian |
| framed AAD segment size        | uint32 big-endian |
| framed per-segment nonce counter | uint32 big-endian |
| descriptor fields              | raw bytes (no integers wider than 1 byte) |

No little-endian fields exist anywhere in the envelope wire format.
