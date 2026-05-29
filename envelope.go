// Package casket — at-rest AEAD envelope.
//
// The envelope seals a blob (e.g. a cairn object or porter chunk) for storage on
// an untrusted backing store (S3 etc.). It is independent of the Frame-to-Frame
// channel layer: the symmetric key is supplied by the caller (resolved by nexus
// from the descriptor's keyref fingerprint).
//
// Wire format (single-shot):
//
//	blob = DESCRIPTOR(20 bytes) || BODY
//	BODY = nonce(suite nonce length) || ciphertext || tag
//
// The body byte-order (nonce || ciphertext || tag) matches channel.go's
// EncryptBody: Go's AEAD.Seal appends the 16-byte tag to the ciphertext, so
// nonce || AEAD.Seal(...) yields nonce || ciphertext || tag.
//
// Descriptor (20 bytes, fixed-width, suite-first):
//
//	[0]      suite   (0x01 AES-256-GCM, 0x02 ChaCha20-Poly1305, 0x03 XChaCha20-Poly1305)
//	[1]      version (0x01)
//	[2]      keytype (0x01 derived-repo, 0x02 byok-repo, 0x03 aspect-identity; metadata)
//	[3..18]  keyref  (16-byte casket key fingerprint)
//	[19]     flags   (0x00 single-shot; bit0 = framed/STREAM, see envelope_framed.go)
//
// AAD (authenticated, not encrypted) — length-prefixed so the two caller-supplied
// fields cannot be ambiguously re-split:
//
//	AAD = descriptor(20B)
//	   || uint16be(len(repoIdentity)) || repoIdentity
//	   || uint16be(len(objectPath))   || objectPath
//
// Binding the full descriptor (incl. suite + keyref) plus repo identity and object
// path prevents header-strip, suite/keyref swap, and cross-repo/cross-object
// ciphertext substitution.
package casket

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Suite identifies the AEAD construction used to seal an envelope body.
type Suite byte

// KeyType is descriptor metadata describing how the key was provisioned.
// It is authenticated (part of the descriptor → AAD) but not otherwise interpreted
// by Seal/Open; the caller and nexus give it meaning.
type KeyType byte

// Suite values.
const (
	SuiteAESGCM    Suite = 0x01 // AES-256-GCM, 12-byte nonce
	SuiteChaCha20  Suite = 0x02 // ChaCha20-Poly1305 (IETF), 12-byte nonce
	SuiteXChaCha20 Suite = 0x03 // XChaCha20-Poly1305, 24-byte nonce
	defaultSuite         = SuiteXChaCha20
)

// KeyType values.
const (
	KeyTypeDerivedRepo    KeyType = 0x01
	KeyTypeBYOKRepo       KeyType = 0x02
	KeyTypeAspectIdentity KeyType = 0x03
)

// Envelope format constants.
const (
	envelopeVersion byte = 0x01

	descriptorSize  = 20 // suite(1) + version(1) + keytype(1) + keyref(16) + flags(1)
	keyRefSize      = 16
	envelopeKeySize = 32 // all three suites use a 256-bit key

	descOffSuite   = 0
	descOffVersion = 1
	descOffKeyType = 2
	descOffKeyRef  = 3              // [3..18]
	descOffFlags   = keyRefSize + 3 // 19

	// flagFramed (bit0) marks a framed/STREAM envelope (see envelope_framed.go).
	// Single-shot envelopes set flags == 0x00; single-shot Open rejects flagFramed
	// and framed Open rejects flags without it.
	flagFramed byte = 0x01
)

// fingerprintDomain domain-separates the keyref hash from any other hash of the
// key, so a keyref can never be confused with a raw SHA-256 of the key material.
var fingerprintDomain = []byte("casket-envelope-keyref-v1")

// Sentinel errors — use errors.Is to test.
var (
	ErrEnvelopeSeal = errors.New("envelope seal error")
	ErrEnvelopeOpen = errors.New("envelope open error")
)

func sealError(msg string) error { return fmt.Errorf("%w: %s", ErrEnvelopeSeal, msg) }
func openError(msg string) error { return fmt.Errorf("%w: %s", ErrEnvelopeOpen, msg) }

// Descriptor is the fixed-width, suite-first envelope header.
type Descriptor struct {
	Suite   Suite
	Version byte
	KeyType KeyType
	KeyRef  [16]byte
	Flags   byte
}

// Fingerprint computes a domain-separated 16-byte casket keyref for key:
// SHA-256("casket-envelope-keyref-v1" || key) truncated to the first 16 bytes.
func Fingerprint(key []byte) [16]byte {
	h := sha256.New()
	h.Write(fingerprintDomain)
	h.Write(key)
	sum := h.Sum(nil)
	var fp [16]byte
	copy(fp[:], sum[:keyRefSize])
	return fp
}

// encode serialises the descriptor to its fixed 20-byte wire form.
func (d Descriptor) encode() []byte {
	b := make([]byte, descriptorSize)
	b[descOffSuite] = byte(d.Suite)
	b[descOffVersion] = d.Version
	b[descOffKeyType] = byte(d.KeyType)
	copy(b[descOffKeyRef:descOffKeyRef+keyRefSize], d.KeyRef[:])
	b[descOffFlags] = d.Flags
	return b
}

// decodeDescriptor parses the first 20 bytes of b. It does not validate field
// semantics (caller does) — it only bounds-checks length.
func decodeDescriptor(b []byte) (Descriptor, error) {
	if len(b) < descriptorSize {
		return Descriptor{}, openError(fmt.Sprintf("blob too short for descriptor: have %d, need %d", len(b), descriptorSize))
	}
	var d Descriptor
	d.Suite = Suite(b[descOffSuite])
	d.Version = b[descOffVersion]
	d.KeyType = KeyType(b[descOffKeyType])
	copy(d.KeyRef[:], b[descOffKeyRef:descOffKeyRef+keyRefSize])
	d.Flags = b[descOffFlags]
	return d, nil
}

// newAEAD constructs the AEAD for a suite, after validating the key length.
func newAEAD(suite Suite, key []byte) (cipher.AEAD, error) {
	if len(key) != envelopeKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", envelopeKeySize, len(key))
	}
	switch suite {
	case SuiteAESGCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("creating AES cipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("creating GCM: %w", err)
		}
		return gcm, nil
	case SuiteChaCha20:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("creating ChaCha20-Poly1305: %w", err)
		}
		return aead, nil
	case SuiteXChaCha20:
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, fmt.Errorf("creating XChaCha20-Poly1305: %w", err)
		}
		return aead, nil
	default:
		return nil, fmt.Errorf("unknown suite 0x%02x", byte(suite))
	}
}

// buildAAD constructs the length-prefixed additional authenticated data.
// AAD = descriptor || uint16be(len(repo)) || repo || uint16be(len(path)) || path.
func buildAAD(descriptor, repoIdentity, objectPath []byte) []byte {
	aad := make([]byte, 0, len(descriptor)+2+len(repoIdentity)+2+len(objectPath))
	aad = append(aad, descriptor...)
	aad = appendU16Prefixed(aad, repoIdentity)
	aad = appendU16Prefixed(aad, objectPath)
	return aad
}

func appendU16Prefixed(dst, field []byte) []byte {
	var lp [2]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(field)))
	dst = append(dst, lp[:]...)
	dst = append(dst, field...)
	return dst
}

// maxU16Field is the largest length a u16-prefixed AAD field may have. Beyond
// this, uint16(len(field)) would wrap silently and defeat the length-prefix
// ambiguity protection, so we reject such fields explicitly.
const maxU16Field = 0xFFFF

// validateAADFields guards the two caller-supplied AAD fields against u16
// length-prefix overflow. It returns a *raw* error message; callers wrap it with
// sealError or openError as appropriate.
func validateAADFields(repoIdentity, objectPath []byte) error {
	if len(repoIdentity) > maxU16Field {
		return fmt.Errorf("repo identity exceeds %d bytes", maxU16Field)
	}
	if len(objectPath) > maxU16Field {
		return fmt.Errorf("object path exceeds %d bytes", maxU16Field)
	}
	return nil
}

// SealOptions configures a Seal call.
// A zero-value Suite defaults to XChaCha20-Poly1305 (0x03).
type SealOptions struct {
	Suite        Suite
	KeyType      KeyType
	KeyRef       [16]byte
	RepoIdentity []byte
	ObjectPath   []byte
}

// Seal encrypts plaintext into a single-shot at-rest envelope.
//
// It validates the key length (32 bytes for all suites), builds the descriptor,
// generates a fresh random nonce of the suite's nonce length via crypto/rand, and
// AEAD-seals binding the AAD (descriptor + repo identity + object path).
//
// Returns descriptor || nonce || ciphertext || tag. The KeyRef in opts is caller-
// supplied; use Fingerprint(key) to derive a conventional keyref.
func Seal(key, plaintext []byte, opts SealOptions) ([]byte, error) {
	suite := opts.Suite
	if suite == 0 {
		suite = defaultSuite
	}
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, sealError(err.Error())
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, sealError(fmt.Sprintf("generating nonce: %v", err))
	}
	return sealCommon(aead, suite, nonce, plaintext, opts)
}

// sealWithNonce is a test-only seam: it seals with a caller-supplied nonce so KAT
// vectors can be regenerated deterministically. The public Seal always uses a
// fresh random nonce.
func sealWithNonce(key, plaintext []byte, opts SealOptions, nonce []byte) ([]byte, error) {
	suite := opts.Suite
	if suite == 0 {
		suite = defaultSuite
	}
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, sealError(err.Error())
	}
	if len(nonce) != aead.NonceSize() {
		return nil, sealError(fmt.Sprintf("nonce must be %d bytes for suite 0x%02x, got %d", aead.NonceSize(), byte(suite), len(nonce)))
	}
	return sealCommon(aead, suite, nonce, plaintext, opts)
}

func sealCommon(aead cipher.AEAD, suite Suite, nonce, plaintext []byte, opts SealOptions) ([]byte, error) {
	if err := validateAADFields(opts.RepoIdentity, opts.ObjectPath); err != nil {
		return nil, sealError(err.Error())
	}
	desc := Descriptor{
		Suite:   suite,
		Version: envelopeVersion,
		KeyType: opts.KeyType,
		KeyRef:  opts.KeyRef,
		Flags:   0x00, // single-shot
	}
	descBytes := desc.encode()
	aad := buildAAD(descBytes, opts.RepoIdentity, opts.ObjectPath)

	// AEAD.Seal appends ciphertext||tag → body = nonce || ciphertext || tag.
	body := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	body = append(body, nonce...)
	body = aead.Seal(body, nonce, plaintext, aad)

	blob := make([]byte, 0, len(descBytes)+len(body))
	blob = append(blob, descBytes...)
	blob = append(blob, body...)
	return blob, nil
}

// Open parses and verifies a single-shot envelope blob, returning the plaintext
// and the parsed descriptor.
//
// It validates version, suite, and flags (rejecting any non-zero flags for now),
// reconstructs the AAD from the parsed descriptor plus the caller-supplied
// repoIdentity and objectPath, and AEAD-opens. Any tamper, wrong key, or mismatch
// (repo identity / object path) yields ErrEnvelopeOpen. Malformed input never
// panics — every read is bounds-checked.
func Open(key, blob, repoIdentity, objectPath []byte) (plaintext []byte, desc Descriptor, err error) {
	desc, err = decodeDescriptor(blob)
	if err != nil {
		return nil, Descriptor{}, err
	}
	if desc.Version != envelopeVersion {
		return nil, Descriptor{}, openError(fmt.Sprintf("unsupported version 0x%02x", desc.Version))
	}
	if desc.Flags != 0x00 {
		if desc.Flags&flagFramed != 0 {
			return nil, Descriptor{}, openError("framed envelope passed to single-shot Open; use OpenFramed / NewOpenReader")
		}
		return nil, Descriptor{}, openError(fmt.Sprintf("unsupported flags 0x%02x", desc.Flags))
	}

	if err := validateAADFields(repoIdentity, objectPath); err != nil {
		return nil, Descriptor{}, openError(err.Error())
	}

	aead, err := newAEAD(desc.Suite, key)
	if err != nil {
		return nil, Descriptor{}, openError(err.Error())
	}

	body := blob[descriptorSize:]
	nsize := aead.NonceSize()
	if len(body) < nsize {
		return nil, Descriptor{}, openError(fmt.Sprintf("blob too short for nonce: body has %d, need %d", len(body), nsize))
	}
	if len(body)-nsize < aead.Overhead() {
		return nil, Descriptor{}, openError("blob too short for AEAD tag")
	}
	nonce := body[:nsize]
	ciphertext := body[nsize:]

	descBytes := blob[:descriptorSize]
	aad := buildAAD(descBytes, repoIdentity, objectPath)

	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, Descriptor{}, openError("decryption failed — wrong key, tampered blob, or repo/object mismatch")
	}
	return pt, desc, nil
}
