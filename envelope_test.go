package casket

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// --- helpers ---

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

var allSuites = []Suite{SuiteAESGCM, SuiteChaCha20, SuiteXChaCha20}

func suiteName(s Suite) string {
	switch s {
	case SuiteAESGCM:
		return "AES-256-GCM"
	case SuiteChaCha20:
		return "ChaCha20-Poly1305"
	case SuiteXChaCha20:
		return "XChaCha20-Poly1305"
	default:
		return "unknown"
	}
}

// --- 1. round-trip per suite ---

func TestSealOpenRoundTripAllSuites(t *testing.T) {
	key := testKey()
	repo := []byte("cairn/repo-1")
	path := []byte("objects/foo.bin")
	pt := []byte("hello at-rest world")

	for _, suite := range allSuites {
		t.Run(suiteName(suite), func(t *testing.T) {
			fp := Fingerprint(key)
			blob, err := Seal(key, pt, SealOptions{
				Suite:        suite,
				KeyType:      KeyTypeBYOKRepo,
				KeyRef:       fp,
				RepoIdentity: repo,
				ObjectPath:   path,
			})
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			got, desc, err := Open(key, blob, repo, path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("plaintext mismatch: got %q want %q", got, pt)
			}
			if desc.Suite != suite {
				t.Errorf("desc.Suite = 0x%02x want 0x%02x", byte(desc.Suite), byte(suite))
			}
			if desc.Version != envelopeVersion {
				t.Errorf("desc.Version = 0x%02x want 0x%02x", desc.Version, envelopeVersion)
			}
			if desc.KeyType != KeyTypeBYOKRepo {
				t.Errorf("desc.KeyType = 0x%02x want 0x%02x", byte(desc.KeyType), byte(KeyTypeBYOKRepo))
			}
			if desc.KeyRef != fp {
				t.Errorf("desc.KeyRef mismatch")
			}
			if desc.Flags != 0x00 {
				t.Errorf("desc.Flags = 0x%02x want 0x00", desc.Flags)
			}
		})
	}
}

func TestSealDefaultSuiteIsXChaCha(t *testing.T) {
	key := testKey()
	blob, err := Seal(key, []byte("x"), SealOptions{
		// Suite left zero — must default to XChaCha20.
		KeyRef:       Fingerprint(key),
		RepoIdentity: []byte("r"),
		ObjectPath:   []byte("p"),
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if Suite(blob[descOffSuite]) != SuiteXChaCha20 {
		t.Fatalf("default suite = 0x%02x want 0x%02x (XChaCha20)", blob[descOffSuite], byte(SuiteXChaCha20))
	}
}

// --- 2. AAD binding / tamper rejection ---

func sealForTamper(t *testing.T, suite Suite) (key, blob, repo, path, pt []byte) {
	t.Helper()
	key = testKey()
	repo = []byte("cairn/repo-1")
	path = []byte("objects/foo.bin")
	pt = []byte("secret payload")
	b, err := Seal(key, pt, SealOptions{
		Suite:        suite,
		KeyRef:       Fingerprint(key),
		RepoIdentity: repo,
		ObjectPath:   path,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return key, b, repo, path, pt
}

func TestTamperCiphertextRejected(t *testing.T) {
	for _, suite := range allSuites {
		t.Run(suiteName(suite), func(t *testing.T) {
			key, blob, repo, path, _ := sealForTamper(t, suite)
			// First byte after descriptor+nonce is ciphertext. Flip a ciphertext byte.
			// Pick a byte safely in the middle of the body's ciphertext region.
			tampered := append([]byte(nil), blob...)
			ctStart := descriptorSize // somewhere in body; flip a byte well past nonce
			// flip a byte near the end (within ciphertext, before/at tag — any flip must fail)
			idx := len(tampered) - 20
			if idx <= ctStart {
				idx = len(tampered) - 1
			}
			tampered[idx] ^= 0xFF
			if _, _, err := Open(key, tampered, repo, path); err == nil {
				t.Fatal("Open accepted tampered ciphertext")
			} else if !errors.Is(err, ErrEnvelopeOpen) {
				t.Fatalf("wrong error type: %v", err)
			}
		})
	}
}

func TestTamperTagRejected(t *testing.T) {
	for _, suite := range allSuites {
		t.Run(suiteName(suite), func(t *testing.T) {
			key, blob, repo, path, _ := sealForTamper(t, suite)
			tampered := append([]byte(nil), blob...)
			tampered[len(tampered)-1] ^= 0xFF // last byte is in the 16-byte tag
			if _, _, err := Open(key, tampered, repo, path); err == nil {
				t.Fatal("Open accepted tampered tag")
			}
		})
	}
}

func TestTamperDescriptorSuiteRejected(t *testing.T) {
	key, blob, repo, path, _ := sealForTamper(t, SuiteXChaCha20)
	tampered := append([]byte(nil), blob...)
	// Flip suite to AES-GCM. Even though the new suite is "known", the descriptor
	// is part of the AAD, so Open must fail (and nonce length now mismatches too).
	tampered[descOffSuite] = byte(SuiteAESGCM)
	if _, _, err := Open(key, tampered, repo, path); err == nil {
		t.Fatal("Open accepted suite-swapped descriptor")
	}
}

func TestTamperDescriptorKeyRefRejected(t *testing.T) {
	key, blob, repo, path, _ := sealForTamper(t, SuiteXChaCha20)
	tampered := append([]byte(nil), blob...)
	tampered[descOffKeyRef] ^= 0xFF // flip a keyref byte — bound via AAD
	if _, _, err := Open(key, tampered, repo, path); err == nil {
		t.Fatal("Open accepted keyref-swapped descriptor")
	}
}

func TestWrongRepoIdentityRejected(t *testing.T) {
	key, blob, _, path, _ := sealForTamper(t, SuiteXChaCha20)
	if _, _, err := Open(key, blob, []byte("cairn/repo-OTHER"), path); err == nil {
		t.Fatal("Open accepted wrong repoIdentity")
	}
}

func TestWrongObjectPathRejected(t *testing.T) {
	key, blob, repo, _, _ := sealForTamper(t, SuiteXChaCha20)
	if _, _, err := Open(key, blob, repo, []byte("objects/other.bin")); err == nil {
		t.Fatal("Open accepted wrong objectPath")
	}
}

// The ambiguity test: length-prefixing must prevent re-splitting the two fields.
func TestAADLengthPrefixAmbiguity(t *testing.T) {
	key := testKey()
	blob, err := Seal(key, []byte("payload"), SealOptions{
		Suite:        SuiteXChaCha20,
		KeyRef:       Fingerprint(key),
		RepoIdentity: []byte("ab"),
		ObjectPath:   []byte("c"),
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Without length-prefixing, "ab"+"c" == "a"+"bc" == "abc". With it, they differ.
	if _, _, err := Open(key, blob, []byte("a"), []byte("bc")); err == nil {
		t.Fatal("Open accepted ambiguous re-split repo/path (length-prefixing broken)")
	}
	// Sanity: the correct split still opens.
	if _, _, err := Open(key, blob, []byte("ab"), []byte("c")); err != nil {
		t.Fatalf("correct split failed to open: %v", err)
	}
}

// A >64KiB AAD field must be rejected (not silently u16-wrapped) by both
// Seal and Open. Without the guard, uint16(len) wraps and the AAD ambiguity
// protection collapses.
func TestAADFieldOverflowRejected(t *testing.T) {
	key := testKey()
	big := make([]byte, maxU16Field+1) // 65536 bytes — wraps to 0 under uint16

	// Seal rejects an oversized repo identity.
	if _, err := Seal(key, []byte("x"), SealOptions{
		Suite:        SuiteXChaCha20,
		KeyRef:       Fingerprint(key),
		RepoIdentity: big,
		ObjectPath:   []byte("p"),
	}); err == nil {
		t.Fatal("Seal accepted >64KiB repo identity")
	} else if !errors.Is(err, ErrEnvelopeSeal) {
		t.Fatalf("wrong error type: %v", err)
	}

	// Seal rejects an oversized object path.
	if _, err := Seal(key, []byte("x"), SealOptions{
		Suite:        SuiteXChaCha20,
		KeyRef:       Fingerprint(key),
		RepoIdentity: []byte("r"),
		ObjectPath:   big,
	}); err == nil {
		t.Fatal("Seal accepted >64KiB object path")
	} else if !errors.Is(err, ErrEnvelopeSeal) {
		t.Fatalf("wrong error type: %v", err)
	}

	// Open rejects oversized fields too (before AAD reconstruction).
	blob, err := Seal(key, []byte("x"), SealOptions{
		Suite:        SuiteXChaCha20,
		KeyRef:       Fingerprint(key),
		RepoIdentity: []byte("r"),
		ObjectPath:   []byte("p"),
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, _, err := Open(key, blob, big, []byte("p")); err == nil {
		t.Fatal("Open accepted >64KiB repo identity")
	} else if !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("wrong error type: %v", err)
	}
	if _, _, err := Open(key, blob, []byte("r"), big); err == nil {
		t.Fatal("Open accepted >64KiB object path")
	} else if !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("wrong error type: %v", err)
	}
}

// --- 3. descriptor parse ---

func TestDescriptorEncodeDecodeRoundTrip(t *testing.T) {
	d := Descriptor{
		Suite:   SuiteChaCha20,
		Version: envelopeVersion,
		KeyType: KeyTypeAspectIdentity,
		Flags:   0x00,
	}
	for i := range d.KeyRef {
		d.KeyRef[i] = byte(i * 7)
	}
	enc := d.encode()
	if len(enc) != descriptorSize {
		t.Fatalf("encoded length = %d want %d", len(enc), descriptorSize)
	}
	got, err := decodeDescriptor(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != d {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, d)
	}
}

func TestOpenRejectsUnknownSuite(t *testing.T) {
	key := testKey()
	blob, _ := Seal(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, RepoIdentity: []byte("r"), ObjectPath: []byte("p")})
	bad := append([]byte(nil), blob...)
	bad[descOffSuite] = 0x7F // unknown suite
	if _, _, err := Open(key, bad, []byte("r"), []byte("p")); err == nil {
		t.Fatal("Open accepted unknown suite")
	} else if !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("wrong error type: %v", err)
	}
}

func TestOpenRejectsWrongVersion(t *testing.T) {
	key := testKey()
	blob, _ := Seal(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, RepoIdentity: []byte("r"), ObjectPath: []byte("p")})
	bad := append([]byte(nil), blob...)
	bad[descOffVersion] = 0x02
	if _, _, err := Open(key, bad, []byte("r"), []byte("p")); err == nil {
		t.Fatal("Open accepted wrong version")
	}
}

func TestOpenRejectsNonZeroFlags(t *testing.T) {
	key := testKey()
	blob, _ := Seal(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, RepoIdentity: []byte("r"), ObjectPath: []byte("p")})

	// framed bit (bit0) — must give the specific framed-not-supported error.
	framed := append([]byte(nil), blob...)
	framed[descOffFlags] = flagFramed
	if _, _, err := Open(key, framed, []byte("r"), []byte("p")); err == nil {
		t.Fatal("Open accepted framed flag")
	} else if !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("wrong error type: %v", err)
	}

	// any other non-zero flags — also rejected.
	other := append([]byte(nil), blob...)
	other[descOffFlags] = 0x80
	if _, _, err := Open(key, other, []byte("r"), []byte("p")); err == nil {
		t.Fatal("Open accepted non-zero flags")
	}
}

func TestOpenRejectsTruncatedBlobNoPanic(t *testing.T) {
	key := testKey()
	blob, _ := Seal(key, []byte("payload data"), SealOptions{Suite: SuiteXChaCha20, RepoIdentity: []byte("r"), ObjectPath: []byte("p")})

	cases := map[string][]byte{
		"empty":            {},
		"len<20":           blob[:10],
		"exactly20-noBody": blob[:descriptorSize],
		"len<20+nonce":     blob[:descriptorSize+5], // XChaCha needs 24-byte nonce
		"nonce-but-no-tag": blob[:descriptorSize+24],
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			// Must not panic; must return an error.
			_, _, err := Open(key, b, []byte("r"), []byte("p"))
			if err == nil {
				t.Fatalf("Open accepted truncated blob (%s)", name)
			}
			if !errors.Is(err, ErrEnvelopeOpen) {
				t.Fatalf("wrong error type for %s: %v", name, err)
			}
		})
	}
}

// --- 4. fingerprint ---

func TestFingerprintDeterministicAndDomainSeparated(t *testing.T) {
	key := testKey()
	a := Fingerprint(key)
	b := Fingerprint(key)
	if a != b {
		t.Fatal("Fingerprint not deterministic")
	}
	if len(a) != 16 {
		t.Fatalf("Fingerprint length = %d want 16", len(a))
	}
	// Must differ from raw SHA-256(key)[:16] (domain separation).
	raw := sha256.Sum256(key)
	if bytes.Equal(a[:], raw[:16]) {
		t.Fatal("Fingerprint equals raw SHA-256(key)[:16] — domain separation missing")
	}
	// Different keys → different fingerprints.
	key2 := testKey()
	key2[0] ^= 0xFF
	if Fingerprint(key2) == a {
		t.Fatal("Fingerprint collision for different keys")
	}
}

// --- 5. wrong key / wrong key length ---

func TestOpenWrongKeyFails(t *testing.T) {
	key := testKey()
	repo, path := []byte("r"), []byte("p")
	blob, err := Seal(key, []byte("secret"), SealOptions{Suite: SuiteXChaCha20, RepoIdentity: repo, ObjectPath: path})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	wrong := testKey()
	wrong[31] ^= 0x01
	if _, _, err := Open(wrong, blob, repo, path); err == nil {
		t.Fatal("Open accepted wrong key")
	}
}

func TestSealWrongKeyLengthFails(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		key := make([]byte, n)
		_, err := Seal(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, RepoIdentity: []byte("r"), ObjectPath: []byte("p")})
		if err == nil {
			t.Fatalf("Seal accepted %d-byte key", n)
		}
		if !errors.Is(err, ErrEnvelopeSeal) {
			t.Fatalf("wrong error type for %d-byte key: %v", n, err)
		}
	}
}

func TestOpenWrongKeyLengthFails(t *testing.T) {
	key := testKey()
	blob, _ := Seal(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, RepoIdentity: []byte("r"), ObjectPath: []byte("p")})
	short := make([]byte, 16)
	if _, _, err := Open(short, blob, []byte("r"), []byte("p")); err == nil {
		t.Fatal("Open accepted 16-byte key")
	}
}

// --- 6. Known-Answer Tests (lock the wire format forever) ---

type kat struct {
	name     string
	suite    Suite
	keyHex   string
	keyrefHx string
	nonceHex string
	repo     string
	path     string
	pt       string
	blobHex  string
}

// Vectors generated via sealWithNonce (deterministic). key = bytes 0x00..0x1f;
// keyref = Fingerprint(key); KeyType = KeyTypeDerivedRepo (0x01).
var katVectors = []kat{
	{
		name:     "XChaCha20-Poly1305 (default suite)",
		suite:    SuiteXChaCha20,
		keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		keyrefHx: "5a1bcc51a25aae05d215e40ce89fd5a6",
		nonceHex: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
		repo:     "cairn/repo-42",
		path:     "objects/ab/cdef.bin",
		pt:       "the quick brown fox jumps over the lazy dog",
		blobHex:  "0301015a1bcc51a25aae05d215e40ce89fd5a600b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c71c3e1c779886ae568f96b66accb1908223e21239cc9e4e816333de69a6003583f3d0c41754dac3c07815aab0c5b0e557d8773ef81adb931bbf6dfd",
	},
	{
		name:     "AES-256-GCM",
		suite:    SuiteAESGCM,
		keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		keyrefHx: "5a1bcc51a25aae05d215e40ce89fd5a6",
		nonceHex: "a0a1a2a3a4a5a6a7a8a9aaab",
		repo:     "cairn/repo-42",
		path:     "objects/ab/cdef.bin",
		pt:       "the quick brown fox jumps over the lazy dog",
		blobHex:  "0101015a1bcc51a25aae05d215e40ce89fd5a600a0a1a2a3a4a5a6a7a8a9aaab9270190d34be6bdc0945e5a1680daefe16c32130f8c22f1cef2e49f01ad95575ba136793ce582a1d3bf363b8dfcebdf0b87be206c7f6cefdbe9fb1",
	},
	{
		name:     "ChaCha20-Poly1305 IETF",
		suite:    SuiteChaCha20,
		keyHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		keyrefHx: "5a1bcc51a25aae05d215e40ce89fd5a6",
		nonceHex: "a0a1a2a3a4a5a6a7a8a9aaab",
		repo:     "cairn/repo-42",
		path:     "objects/ab/cdef.bin",
		pt:       "the quick brown fox jumps over the lazy dog",
		blobHex:  "0201015a1bcc51a25aae05d215e40ce89fd5a600a0a1a2a3a4a5a6a7a8a9aaab78c31d7f3c93abcecb2f9166938d93dbfb31ab9f291f0dd3c7f8b4c71410e37804e536e6cfb386aaa2a39264d44e498dca02d82efe93210541bec8",
	},
}

func TestKnownAnswerVectors(t *testing.T) {
	for _, v := range katVectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustHex(t, v.keyHex)
			nonce := mustHex(t, v.nonceHex)
			expectedBlob := mustHex(t, v.blobHex)

			// keyref in the vector must equal Fingerprint(key).
			fp := Fingerprint(key)
			if hex.EncodeToString(fp[:]) != v.keyrefHx {
				t.Fatalf("keyref mismatch: Fingerprint=%s vector=%s", hex.EncodeToString(fp[:]), v.keyrefHx)
			}

			opts := SealOptions{
				Suite:        v.suite,
				KeyType:      KeyTypeDerivedRepo,
				KeyRef:       fp,
				RepoIdentity: []byte(v.repo),
				ObjectPath:   []byte(v.path),
			}

			// (a) Deterministic re-seal must reproduce the exact blob.
			got, err := sealWithNonce(key, []byte(v.pt), opts, nonce)
			if err != nil {
				t.Fatalf("sealWithNonce: %v", err)
			}
			if !bytes.Equal(got, expectedBlob) {
				t.Fatalf("blob mismatch:\n got %s\nwant %s", hex.EncodeToString(got), v.blobHex)
			}

			// (b) Open(expected_blob) must recover the plaintext.
			pt, desc, err := Open(key, expectedBlob, []byte(v.repo), []byte(v.path))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if string(pt) != v.pt {
				t.Fatalf("plaintext mismatch: got %q want %q", pt, v.pt)
			}
			if desc.Suite != v.suite {
				t.Errorf("desc.Suite = 0x%02x want 0x%02x", byte(desc.Suite), byte(v.suite))
			}
			if desc.KeyType != KeyTypeDerivedRepo {
				t.Errorf("desc.KeyType = 0x%02x want 0x01", byte(desc.KeyType))
			}
		})
	}
}
