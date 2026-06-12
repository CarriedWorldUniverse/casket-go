// Package casket — multi-recipient at-rest envelope.
//
// The multi-recipient envelope seals a blob so that ANY ONE of a set of
// recipients can open it (age-style hybrid encryption): a fresh random 32-byte
// DEK seals the body via the existing single-shot envelope path (Seal/Open —
// same suite and AAD semantics, binding repoIdentity + objectPath), and the DEK
// is wrapped once per recipient under a key derived from an ephemeral X25519
// ECDH exchange with that recipient's public key.
//
// First consumers: satchel (file-per-secret credential store, `.recipients`
// sets) and porter backups. See the satchel design, §4 (multi-recipient
// envelope as a casket primitive).
//
// See the SealMulti doc comment for the exact wire format.
package casket

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Multi-recipient format constants.
const (
	// multiMagic is the leading marker byte of a multi-recipient envelope. It is
	// deliberately distinct from every Suite value (0x01–0x03), so a
	// multi-recipient blob can never be misparsed as a descriptor-first
	// (single-shot or framed) envelope, and vice versa.
	multiMagic   byte = 0xCA
	multiVersion byte = 0x01

	multiHeaderSize = 4 // magic(1) + version(1) + suite(1) + count(1)

	multiOffMagic   = 0
	multiOffVersion = 1
	multiOffSuite   = 2
	multiOffCount   = 3

	// multiKeyIDSize is the recipient key identifier width: SHA-256(pubkey)[:8].
	multiKeyIDSize = 8

	// multiDEKSize is the body data-encryption-key length (32 bytes, matching
	// envelopeKeySize — all suites use a 256-bit key).
	multiDEKSize = envelopeKeySize

	// multiWrapSize is the wrapped-DEK length: DEK(32) + AEAD tag(16).
	multiWrapSize = multiDEKSize + 16

	// multiRecipientKeySize is the X25519 public/private key length.
	multiRecipientKeySize = 32

	// multiMaxRecipients is the largest recipient set: count is a single byte
	// and zero recipients is meaningless, so valid counts are 1..255.
	multiMaxRecipients = 255
)

// multiHKDFInfoPrefix domain-separates the per-recipient DEK-wrap key
// derivation. The full HKDF info is the prefix || ephemeralPub || recipientPub,
// binding the wrap key to both ends of the ECDH exchange.
const multiHKDFInfoPrefix = "casket-multi-v1"

// ErrNoRecipient reports that OpenMulti's private key matches no recipient
// entry in the blob (or every matching entry failed to unwrap). It is wrapped
// together with ErrEnvelopeOpen — both errors.Is checks succeed.
var ErrNoRecipient = errors.New("no matching recipient")

// suiteNonceSize returns the AEAD nonce length for a suite without
// instantiating the AEAD (needed to parse wrap entries before any key exists).
func suiteNonceSize(suite Suite) (int, error) {
	switch suite {
	case SuiteAESGCM, SuiteChaCha20:
		return 12, nil
	case SuiteXChaCha20:
		return 24, nil
	default:
		return 0, fmt.Errorf("unknown suite 0x%02x", byte(suite))
	}
}

// multiKeyID derives the deterministic recipient key identifier:
// SHA-256(recipient public key), truncated to 8 bytes. The keyid is stored in
// cleartext on the untrusted backing store; it identifies which wrap entry
// belongs to which recipient (restore-tooling UX) and intentionally reveals
// recipient-set membership to anyone holding the public keys — same posture as
// age's recipient stanzas.
func multiKeyID(recipientPub []byte) [multiKeyIDSize]byte {
	sum := sha256.Sum256(recipientPub)
	var id [multiKeyIDSize]byte
	copy(id[:], sum[:multiKeyIDSize])
	return id
}

// deriveWrapKey derives the 32-byte DEK-wrap key from an X25519 shared secret:
//
//	wrapKey = HKDF-SHA256(secret=shared, salt=nil,
//	                      info="casket-multi-v1" || ephemeralPub || recipientPub)
func deriveWrapKey(shared, ephemeralPub, recipientPub []byte) ([]byte, error) {
	info := make([]byte, 0, len(multiHKDFInfoPrefix)+len(ephemeralPub)+len(recipientPub))
	info = append(info, multiHKDFInfoPrefix...)
	info = append(info, ephemeralPub...)
	info = append(info, recipientPub...)
	r := hkdf.New(sha256.New, shared, nil, info)
	key := make([]byte, envelopeKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}
	return key, nil
}

// GenerateRecipientKey generates a fresh X25519 recipient keypair.
// Both the private and public key are 32 raw bytes.
//
// The private key is the recipient's long-term unwrap secret; the public key is
// what senders pass to SealMulti.
func GenerateRecipientKey() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// SealMulti encrypts plaintext into a multi-recipient at-rest envelope that any
// single recipient private key can open.
//
// A fresh random 32-byte DEK is generated; the body is the EXISTING single-shot
// envelope (Seal) under the DEK, so suite and AAD semantics — binding
// opts.RepoIdentity and opts.ObjectPath — are identical to Seal/Open. For each
// recipient public key (raw 32-byte X25519), a fresh ephemeral X25519 keypair
// is generated, shared = ECDH(ephemeralPriv, recipientPub), and the DEK is
// AEAD-sealed (suite AEAD, random nonce, no AAD) under
//
//	wrapKey = HKDF-SHA256(secret=shared, salt=nil,
//	                      info="casket-multi-v1" || ephemeralPub || recipientPub)
//
// A zero opts.Suite defaults to XChaCha20-Poly1305; the same suite is used for
// both the DEK wraps and the body.
//
// Wire format (multi-recipient, all integers big-endian):
//
//	blob = MULTIHEADER(4 bytes) || WRAPS || BODY
//
//	MULTIHEADER:
//	  [0] magic   (0xCA — distinct from every Suite value, so a multi blob can
//	               never be misparsed as a descriptor-first envelope)
//	  [1] version (0x01)
//	  [2] suite   (same Suite values as the Descriptor: 0x01 AES-256-GCM,
//	               0x02 ChaCha20-Poly1305, 0x03 XChaCha20-Poly1305; governs both
//	               the DEK-wrap AEAD and the body envelope — they MUST match)
//	  [3] count   (uint8 recipient count, 1..255; 0 is invalid)
//
//	WRAPS = count entries, each (in the order recipients were supplied):
//	  ephemeralPub(32) || keyid(8) || nonce(suite nonce length) || wrappedDEK(48)
//
//	  keyid      = SHA-256(recipientPub)[:8]  (cleartext recipient identifier)
//	  wrappedDEK = AEAD.Seal(DEK) = ciphertext(32) || tag(16) under wrapKey
//
//	BODY = a complete single-shot envelope sealed under the DEK:
//	  descriptor(20) || nonce || ciphertext || tag  (see envelope.go)
//
// The header and wrap entries are not separately authenticated: each wrap is
// self-authenticating (AEAD under a key bound to ephemeralPub + recipientPub
// via the HKDF info), and the body authenticates suite, descriptor, repo
// identity, and object path under the DEK. Stripping or corrupting a wrap entry
// only denies that recipient — it cannot alter what any recipient decrypts.
func SealMulti(plaintext []byte, recipients [][]byte, opts SealOptions) ([]byte, error) {
	suite := opts.Suite
	if suite == 0 {
		suite = defaultSuite
	}
	nonceSize, err := suiteNonceSize(suite)
	if err != nil {
		return nil, sealError(err.Error())
	}
	if len(recipients) == 0 {
		return nil, sealError("at least one recipient required")
	}
	if len(recipients) > multiMaxRecipients {
		return nil, sealError(fmt.Sprintf("too many recipients: %d (max %d)", len(recipients), multiMaxRecipients))
	}
	for i, pub := range recipients {
		if len(pub) != multiRecipientKeySize {
			return nil, sealError(fmt.Sprintf("recipient %d public key must be %d bytes, got %d", i, multiRecipientKeySize, len(pub)))
		}
	}

	dek := make([]byte, multiDEKSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, sealError(fmt.Sprintf("generating DEK: %v", err))
	}

	// Body first: the existing single-shot path under the DEK (same AAD
	// semantics — descriptor + repoIdentity + objectPath).
	bodyOpts := opts
	bodyOpts.Suite = suite
	body, err := Seal(dek, plaintext, bodyOpts)
	if err != nil {
		return nil, err
	}

	entrySize := multiRecipientKeySize + multiKeyIDSize + nonceSize + multiWrapSize
	blob := make([]byte, 0, multiHeaderSize+len(recipients)*entrySize+len(body))
	blob = append(blob, multiMagic, multiVersion, byte(suite), byte(len(recipients)))

	curve := ecdh.X25519()
	for i, recipientPub := range recipients {
		ephPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, sealError(fmt.Sprintf("recipient %d: generating ephemeral key: %v", i, err))
		}
		recipKey, err := curve.NewPublicKey(recipientPub)
		if err != nil {
			return nil, sealError(fmt.Sprintf("recipient %d: invalid X25519 public key: %v", i, err))
		}
		shared, err := ephPriv.ECDH(recipKey)
		if err != nil {
			return nil, sealError(fmt.Sprintf("recipient %d: ECDH: %v", i, err))
		}
		ephPub := ephPriv.PublicKey().Bytes()
		wrapKey, err := deriveWrapKey(shared, ephPub, recipientPub)
		if err != nil {
			return nil, sealError(fmt.Sprintf("recipient %d: %v", i, err))
		}
		aead, err := newAEAD(suite, wrapKey)
		if err != nil {
			return nil, sealError(fmt.Sprintf("recipient %d: %v", i, err))
		}
		nonce := make([]byte, nonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, sealError(fmt.Sprintf("recipient %d: generating wrap nonce: %v", i, err))
		}
		keyID := multiKeyID(recipientPub)

		blob = append(blob, ephPub...)
		blob = append(blob, keyID[:]...)
		blob = append(blob, nonce...)
		blob = aead.Seal(blob, nonce, dek, nil) // appends wrappedDEK (32+16)
	}

	blob = append(blob, body...)
	return blob, nil
}

// multiWrapEntry is one parsed per-recipient DEK wrap.
type multiWrapEntry struct {
	ephemeralPub []byte
	keyID        []byte
	nonce        []byte
	wrappedDEK   []byte
}

// parseMulti parses and bounds-checks the multi-recipient header and wrap
// entries, returning the entries, the body, and the suite. Malformed input
// never panics — every read is length-checked first.
func parseMulti(blob []byte) (Suite, []multiWrapEntry, []byte, error) {
	if len(blob) < multiHeaderSize {
		return 0, nil, nil, openError(fmt.Sprintf("blob too short for multi-recipient header: have %d, need %d", len(blob), multiHeaderSize))
	}
	if blob[multiOffMagic] != multiMagic {
		return 0, nil, nil, openError(fmt.Sprintf("not a multi-recipient envelope: leading byte 0x%02x, want 0x%02x", blob[multiOffMagic], multiMagic))
	}
	if blob[multiOffVersion] != multiVersion {
		return 0, nil, nil, openError(fmt.Sprintf("unsupported multi-recipient version 0x%02x", blob[multiOffVersion]))
	}
	suite := Suite(blob[multiOffSuite])
	nonceSize, err := suiteNonceSize(suite)
	if err != nil {
		return 0, nil, nil, openError(err.Error())
	}
	count := int(blob[multiOffCount])
	if count == 0 {
		return 0, nil, nil, openError("recipient count is zero")
	}

	entrySize := multiRecipientKeySize + multiKeyIDSize + nonceSize + multiWrapSize
	rest := blob[multiHeaderSize:]
	if len(rest) < count*entrySize {
		return 0, nil, nil, openError(fmt.Sprintf("blob too short for %d wrap entries: have %d, need %d", count, len(rest), count*entrySize))
	}
	entries := make([]multiWrapEntry, count)
	for i := range entries {
		e := rest[i*entrySize : (i+1)*entrySize]
		off := 0
		entries[i].ephemeralPub = e[off : off+multiRecipientKeySize]
		off += multiRecipientKeySize
		entries[i].keyID = e[off : off+multiKeyIDSize]
		off += multiKeyIDSize
		entries[i].nonce = e[off : off+nonceSize]
		off += nonceSize
		entries[i].wrappedDEK = e[off : off+multiWrapSize]
	}
	body := rest[count*entrySize:]
	if len(body) < descriptorSize {
		return 0, nil, nil, openError(fmt.Sprintf("blob too short for body envelope: have %d, need at least %d", len(body), descriptorSize))
	}
	return suite, entries, body, nil
}

// OpenMulti opens a multi-recipient envelope with ONE recipient private key
// (raw 32-byte X25519). It works with any single key from the sealed recipient
// set.
//
// The recipient public key is derived from privKey; wrap entries whose keyid
// matches SHA-256(pub)[:8] are tried in order (so a truncated-hash collision
// between two recipients still resolves), the DEK is unwrapped, and the body is
// opened via the existing single-shot Open path with the caller-supplied
// repoIdentity and objectPath (AAD must match what was sealed).
//
// A key that matches no entry (or whose every matching entry fails to unwrap)
// yields an error satisfying both errors.Is(err, ErrEnvelopeOpen) and
// errors.Is(err, ErrNoRecipient). Tampered bodies and AAD mismatches yield
// ErrEnvelopeOpen. Malformed input never panics.
func OpenMulti(privKey, blob, repoIdentity, objectPath []byte) ([]byte, error) {
	suite, entries, body, err := parseMulti(blob)
	if err != nil {
		return nil, err
	}

	priv, err := ecdh.X25519().NewPrivateKey(privKey)
	if err != nil {
		return nil, openError(fmt.Sprintf("invalid X25519 private key: %v", err))
	}
	pub := priv.PublicKey().Bytes()
	myID := multiKeyID(pub)

	matched := false
	for _, e := range entries {
		if !bytes.Equal(e.keyID, myID[:]) {
			continue
		}
		matched = true
		ephPub, err := ecdh.X25519().NewPublicKey(e.ephemeralPub)
		if err != nil {
			continue // corrupt entry; another matching entry may still work
		}
		shared, err := priv.ECDH(ephPub)
		if err != nil {
			continue
		}
		wrapKey, err := deriveWrapKey(shared, e.ephemeralPub, pub)
		if err != nil {
			continue
		}
		aead, err := newAEAD(suite, wrapKey)
		if err != nil {
			continue
		}
		dek, err := aead.Open(nil, e.nonce, e.wrappedDEK, nil)
		if err != nil {
			continue // tampered wrap or keyid collision with another recipient
		}
		pt, desc, err := Open(dek, body, repoIdentity, objectPath)
		if err != nil {
			return nil, err
		}
		if desc.Suite != suite {
			return nil, openError(fmt.Sprintf("body suite 0x%02x does not match header suite 0x%02x", byte(desc.Suite), byte(suite)))
		}
		return pt, nil
	}
	if matched {
		return nil, fmt.Errorf("%w: %w: DEK unwrap failed for every matching entry (tampered wrap or wrong key)", ErrEnvelopeOpen, ErrNoRecipient)
	}
	return nil, fmt.Errorf("%w: %w: key is not in this envelope's recipient set", ErrEnvelopeOpen, ErrNoRecipient)
}

// RecipientIDs lists the cleartext recipient key identifiers
// (SHA-256(recipientPub)[:8], 8 bytes each) of a multi-recipient envelope, in
// wrap-entry order. It requires no key material — restore tooling uses it to
// show which recipients can open a blob.
func RecipientIDs(blob []byte) ([][]byte, error) {
	_, entries, _, err := parseMulti(blob)
	if err != nil {
		return nil, err
	}
	ids := make([][]byte, len(entries))
	for i, e := range entries {
		ids[i] = append([]byte(nil), e.keyID...)
	}
	return ids, nil
}
