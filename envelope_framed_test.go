package casket

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

// withSegSize sets framedSegSize for the duration of the test and restores it.
func withSegSize(t *testing.T, s int) {
	t.Helper()
	old := framedSegSize
	framedSegSize = s
	t.Cleanup(func() { framedSegSize = old })
}

func framedRepoPath() (repo, path []byte) {
	return []byte("cairn/repo-framed"), []byte("objects/large/blob.bin")
}

// deterministicPlaintext returns n bytes with a recognisable pattern so reorder /
// corruption is easy to detect on inspection if a test fails.
func deterministicPlaintext(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

// --- 1. round-trip per suite across segment-boundary sizes ---

func TestFramedRoundTripAllSuitesSizes(t *testing.T) {
	const S = 16
	withSegSize(t, S)
	key := testKey()
	repo, path := framedRepoPath()

	sizes := []int{0, 1, S - 1, S, S + 1, 2 * S, 2*S + 1, 3*S + 7}

	for _, suite := range allSuites {
		for _, L := range sizes {
			suite, L := suite, L
			t.Run(suiteName(suite)+"/L="+itoa(L), func(t *testing.T) {
				pt := deterministicPlaintext(L)
				blob, err := SealFramed(key, pt, SealOptions{
					Suite:        suite,
					KeyType:      KeyTypeBYOKRepo,
					KeyRef:       Fingerprint(key),
					RepoIdentity: repo,
					ObjectPath:   path,
				})
				if err != nil {
					t.Fatalf("SealFramed: %v", err)
				}

				// Descriptor must carry the framed flag and the right suite.
				if blob[descOffFlags]&flagFramed == 0 {
					t.Fatalf("framed flag not set in descriptor")
				}
				if Suite(blob[descOffSuite]) != suite {
					t.Fatalf("suite = 0x%02x want 0x%02x", blob[descOffSuite], byte(suite))
				}

				// OpenFramed buffer path.
				got, desc, err := OpenFramed(key, blob, repo, path)
				if err != nil {
					t.Fatalf("OpenFramed: %v", err)
				}
				if !bytes.Equal(got, pt) {
					t.Fatalf("OpenFramed plaintext mismatch (L=%d): got %d bytes want %d", L, len(got), len(pt))
				}
				if desc.Suite != suite || desc.Flags&flagFramed == 0 {
					t.Fatalf("OpenFramed descriptor wrong: %+v", desc)
				}

				// Streaming reader path must yield identical bytes.
				r, err := NewOpenReader(bytes.NewReader(blob), key, repo, path)
				if err != nil {
					t.Fatalf("NewOpenReader: %v", err)
				}
				streamed, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("stream ReadAll: %v", err)
				}
				if !bytes.Equal(streamed, pt) {
					t.Fatalf("streamed plaintext mismatch (L=%d)", L)
				}
			})
		}
	}
}

// itoa avoids strconv import churn in subtest names.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// blockSizeFor returns framedSegSize + AEAD overhead for a suite (test helper).
func blockSizeFor(t *testing.T, suite Suite) int {
	t.Helper()
	aead, err := newAEAD(suite, testKey())
	if err != nil {
		t.Fatalf("newAEAD: %v", err)
	}
	return framedSegSize + aead.Overhead()
}

func prefixLenFor(t *testing.T, suite Suite) int {
	t.Helper()
	aead, err := newAEAD(suite, testKey())
	if err != nil {
		t.Fatalf("newAEAD: %v", err)
	}
	pl, err := noncePrefixLen(aead)
	if err != nil {
		t.Fatalf("noncePrefixLen: %v", err)
	}
	return pl
}

// --- 2. truncation: drop the final block ---

func TestFramedTruncationRejected(t *testing.T) {
	const S = 16
	withSegSize(t, S)
	key := testKey()
	repo, path := framedRepoPath()

	for _, suite := range allSuites {
		t.Run(suiteName(suite), func(t *testing.T) {
			// 3 segments worth of plaintext (2 full + remainder).
			pt := deterministicPlaintext(2*S + 5)
			blob, err := SealFramed(key, pt, SealOptions{Suite: suite, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
			if err != nil {
				t.Fatalf("SealFramed: %v", err)
			}
			bs := blockSizeFor(t, suite)
			// Header = descriptor + prefix.
			hdr := descriptorSize + prefixLenFor(t, suite)
			// Body = 2 full blocks (bs each) + final remainder block.
			// Drop the final block entirely → stream ends without a final-flagged
			// segment, and the now-last full block can't verify as final.
			truncated := blob[:hdr+2*bs]
			if _, _, err := OpenFramed(key, truncated, repo, path); err == nil {
				t.Fatal("OpenFramed accepted truncated stream (final block dropped)")
			} else if !errors.Is(err, ErrEnvelopeOpen) {
				t.Fatalf("wrong error type: %v", err)
			}

			// Also drop just the final block's tag bytes (partial final block).
			partial := blob[:len(blob)-3]
			if _, _, err := OpenFramed(key, partial, repo, path); err == nil {
				t.Fatal("OpenFramed accepted truncated final block")
			}
		})
	}
}

// --- 3. reorder: swap two non-final blocks ---

func TestFramedReorderRejected(t *testing.T) {
	const S = 16
	withSegSize(t, S)
	key := testKey()
	repo, path := framedRepoPath()

	for _, suite := range allSuites {
		t.Run(suiteName(suite), func(t *testing.T) {
			// 3 full segments + remainder → at least 3 non-final blocks.
			pt := deterministicPlaintext(3*S + 4)
			blob, err := SealFramed(key, pt, SealOptions{Suite: suite, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
			if err != nil {
				t.Fatalf("SealFramed: %v", err)
			}
			bs := blockSizeFor(t, suite)
			hdr := descriptorSize + prefixLenFor(t, suite)
			swapped := append([]byte(nil), blob...)
			// Swap block 0 and block 1 (both non-final, both full bs).
			b0 := swapped[hdr : hdr+bs]
			b1 := swapped[hdr+bs : hdr+2*bs]
			tmp := append([]byte(nil), b0...)
			copy(b0, b1)
			copy(b1, tmp)
			if _, _, err := OpenFramed(key, swapped, repo, path); err == nil {
				t.Fatal("OpenFramed accepted reordered blocks (nonce counter mismatch not caught)")
			} else if !errors.Is(err, ErrEnvelopeOpen) {
				t.Fatalf("wrong error type: %v", err)
			}
		})
	}
}

// --- 4. segment tamper (middle segment ciphertext / a tag byte) ---

func TestFramedSegmentTamperRejected(t *testing.T) {
	const S = 16
	withSegSize(t, S)
	key := testKey()
	repo, path := framedRepoPath()

	for _, suite := range allSuites {
		t.Run(suiteName(suite), func(t *testing.T) {
			pt := deterministicPlaintext(3*S + 1)
			blob, err := SealFramed(key, pt, SealOptions{Suite: suite, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
			if err != nil {
				t.Fatalf("SealFramed: %v", err)
			}
			bs := blockSizeFor(t, suite)
			hdr := descriptorSize + prefixLenFor(t, suite)

			// Flip a ciphertext byte in the middle (second) block.
			ctTamper := append([]byte(nil), blob...)
			ctTamper[hdr+bs+3] ^= 0xFF
			if _, _, err := OpenFramed(key, ctTamper, repo, path); err == nil {
				t.Fatal("OpenFramed accepted tampered middle ciphertext")
			}

			// Flip a tag byte in the first block (last byte of block 0).
			tagTamper := append([]byte(nil), blob...)
			tagTamper[hdr+bs-1] ^= 0xFF
			if _, _, err := OpenFramed(key, tagTamper, repo, path); err == nil {
				t.Fatal("OpenFramed accepted tampered tag")
			}
		})
	}
}

// --- 5. descriptor binding + repo/path + u16 ambiguity (framed) ---

func TestFramedDescriptorBindingRejected(t *testing.T) {
	const S = 16
	withSegSize(t, S)
	key := testKey()
	repo, path := framedRepoPath()
	pt := deterministicPlaintext(2*S + 3)

	blob, err := SealFramed(key, pt, SealOptions{Suite: SuiteXChaCha20, KeyType: KeyTypeDerivedRepo, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
	if err != nil {
		t.Fatalf("SealFramed: %v", err)
	}

	// Flip suite byte (descriptor is AAD; also nonce length changes → reject).
	suiteFlip := append([]byte(nil), blob...)
	suiteFlip[descOffSuite] = byte(SuiteAESGCM)
	if _, _, err := OpenFramed(key, suiteFlip, repo, path); err == nil {
		t.Fatal("OpenFramed accepted suite-swapped descriptor")
	}

	// Flip a keyref byte.
	keyrefFlip := append([]byte(nil), blob...)
	keyrefFlip[descOffKeyRef] ^= 0xFF
	if _, _, err := OpenFramed(key, keyrefFlip, repo, path); err == nil {
		t.Fatal("OpenFramed accepted keyref-swapped descriptor")
	}

	// Wrong repo / path.
	if _, _, err := OpenFramed(key, blob, []byte("cairn/OTHER"), path); err == nil {
		t.Fatal("OpenFramed accepted wrong repoIdentity")
	}
	if _, _, err := OpenFramed(key, blob, repo, []byte("objects/other")); err == nil {
		t.Fatal("OpenFramed accepted wrong objectPath")
	}
}

func TestFramedAADAmbiguityRejected(t *testing.T) {
	withSegSize(t, 16)
	key := testKey()
	blob, err := SealFramed(key, deterministicPlaintext(40), SealOptions{
		Suite:        SuiteXChaCha20,
		KeyRef:       Fingerprint(key),
		RepoIdentity: []byte("ab"),
		ObjectPath:   []byte("c"),
	})
	if err != nil {
		t.Fatalf("SealFramed: %v", err)
	}
	// "ab"+"c" must not re-split as "a"+"bc".
	if _, _, err := OpenFramed(key, blob, []byte("a"), []byte("bc")); err == nil {
		t.Fatal("OpenFramed accepted ambiguous repo/path re-split")
	}
	if _, _, err := OpenFramed(key, blob, []byte("ab"), []byte("c")); err != nil {
		t.Fatalf("correct split failed: %v", err)
	}
}

func TestFramedAADFieldOverflowRejected(t *testing.T) {
	key := testKey()
	big := make([]byte, maxU16Field+1)
	// Seal path.
	if _, err := SealFramed(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: big, ObjectPath: []byte("p")}); err == nil {
		t.Fatal("SealFramed accepted >64KiB repo identity")
	} else if !errors.Is(err, ErrEnvelopeSeal) {
		t.Fatalf("wrong error type: %v", err)
	}
	// Open path.
	blob, err := SealFramed(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: []byte("r"), ObjectPath: []byte("p")})
	if err != nil {
		t.Fatalf("SealFramed: %v", err)
	}
	if _, _, err := OpenFramed(key, blob, big, []byte("p")); err == nil {
		t.Fatal("OpenFramed accepted >64KiB repo identity")
	} else if !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("wrong error type: %v", err)
	}
}

// --- 6. cross-mode rejection ---

func TestCrossModeRejection(t *testing.T) {
	withSegSize(t, 16)
	key := testKey()
	repo, path := []byte("r"), []byte("p")

	// Single-shot Open must reject a framed blob.
	framedBlob, err := SealFramed(key, deterministicPlaintext(40), SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
	if err != nil {
		t.Fatalf("SealFramed: %v", err)
	}
	if _, _, err := Open(key, framedBlob, repo, path); err == nil {
		t.Fatal("single-shot Open accepted framed blob")
	} else if !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("wrong error type: %v", err)
	}

	// Framed Open must reject a single-shot blob.
	ssBlob, err := Seal(key, []byte("hi"), SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, _, err := OpenFramed(key, ssBlob, repo, path); err == nil {
		t.Fatal("OpenFramed accepted single-shot blob")
	} else if !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("wrong error type: %v", err)
	}
}

// --- 7. streaming API: many unaligned writes; large multi-segment input ---

func TestFramedStreamingUnalignedWrites(t *testing.T) {
	const S = 16
	withSegSize(t, S)
	key := testKey()
	repo, path := framedRepoPath()

	pt := deterministicPlaintext(5*S + 9)
	var buf bytes.Buffer
	w, err := NewSealWriter(&buf, key, SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
	if err != nil {
		t.Fatalf("NewSealWriter: %v", err)
	}
	// Write in odd-sized chunks that never align to S.
	chunks := []int{1, 7, 3, 13, 5, 11, 2, 9}
	off := 0
	ci := 0
	for off < len(pt) {
		n := chunks[ci%len(chunks)]
		ci++
		if off+n > len(pt) {
			n = len(pt) - off
		}
		if _, err := w.Write(pt[off : off+n]); err != nil {
			t.Fatalf("Write: %v", err)
		}
		off += n
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Double close → error.
	if err := w.Close(); err == nil {
		t.Fatal("second Close did not error")
	}
	// Write after close → error.
	if _, err := w.Write([]byte("x")); err == nil {
		t.Fatal("Write after close did not error")
	}

	r, err := NewOpenReader(bytes.NewReader(buf.Bytes()), key, repo, path)
	if err != nil {
		t.Fatalf("NewOpenReader: %v", err)
	}
	// Read in tiny chunks to exercise pending buffering.
	got, err := readAllSmall(r, 3)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("streamed mismatch: got %d bytes want %d", len(got), len(pt))
	}
}

// readAllSmall reads via fixed small buffers to stress the reader's chunking.
func readAllSmall(r io.Reader, sz int) ([]byte, error) {
	var out []byte
	buf := make([]byte, sz)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

// True multi-segment streaming with a realistic segment size.
func TestFramedStreamingRealSegmentSize(t *testing.T) {
	// Use the shipped default framedSegSize (65536); 5*S exercises multiple full
	// segments + nothing-special remainder semantics at production scale.
	key := testKey()
	repo, path := framedRepoPath()
	S := framedSegSize
	pt := deterministicPlaintext(5 * S) // exact multiple → last full segment is final

	blob, err := SealFramed(key, pt, SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
	if err != nil {
		t.Fatalf("SealFramed: %v", err)
	}
	got, _, err := OpenFramed(key, blob, repo, path)
	if err != nil {
		t.Fatalf("OpenFramed: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("plaintext mismatch at real segment size")
	}
	// Also via streaming reader.
	r, err := NewOpenReader(bytes.NewReader(blob), key, repo, path)
	if err != nil {
		t.Fatalf("NewOpenReader: %v", err)
	}
	streamed, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(streamed, pt) {
		t.Fatalf("streamed mismatch at real segment size")
	}
}

// --- 8. framed KAT (locks the framed wire format) ---

// Framed KAT for the default suite (XChaCha20). Generated via
// sealFramedWithPrefix with a deterministic 19-byte nonce prefix and a small
// framedSegSize so the vector spans multiple segments. Regenerate by running
// with -update-framed-kat... (manual: print got below).
type framedKAT struct {
	prefixHex string
	segSize   int
	repo      string
	path      string
	ptHex     string
	blobHex   string
}

var framedKATVector = framedKAT{
	// prefix length for XChaCha20 = 24 - 5 = 19 bytes.
	prefixHex: "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2",
	segSize:   16,
	repo:      "cairn/repo-42",
	path:      "objects/ab/cdef.bin",
	// 35 bytes → 2 full 16-byte segments + 3-byte final remainder (3 segments).
	ptHex:   "00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef012345",
	blobHex: "0301015a1bcc51a25aae05d215e40ce89fd5a601d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e22d8a0dfd32734ef89ff571c090e772ee08c1f87b0224193ecb5730bf39eb218a4357edfec005098a1e2e38998d67a86e13e790bedd790fe6f82df53e446f64ea5de1a85def99c19a3a953fd509b83516d50860",
}

func TestFramedKnownAnswerVector(t *testing.T) {
	v := framedKATVector
	withSegSize(t, v.segSize)
	key := testKey()
	fp := Fingerprint(key)
	prefix := mustHex(t, v.prefixHex)
	pt := mustHex(t, v.ptHex)

	opts := SealOptions{
		Suite:        SuiteXChaCha20,
		KeyType:      KeyTypeDerivedRepo,
		KeyRef:       fp,
		RepoIdentity: []byte(v.repo),
		ObjectPath:   []byte(v.path),
	}
	got, err := sealFramedWithPrefix(key, pt, opts, prefix)
	if err != nil {
		t.Fatalf("sealFramedWithPrefix: %v", err)
	}

	if v.blobHex == "" {
		t.Fatalf("framed KAT blob not yet committed; generated blob =\n%s", hex.EncodeToString(got))
	}
	want := mustHex(t, v.blobHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("framed KAT mismatch:\n got %s\nwant %s", hex.EncodeToString(got), v.blobHex)
	}

	// And it must open back to the plaintext.
	rt, desc, err := OpenFramed(key, want, []byte(v.repo), []byte(v.path))
	if err != nil {
		t.Fatalf("OpenFramed(KAT): %v", err)
	}
	if !bytes.Equal(rt, pt) {
		t.Fatalf("framed KAT did not round-trip")
	}
	if desc.Flags&flagFramed == 0 || desc.Suite != SuiteXChaCha20 {
		t.Fatalf("framed KAT descriptor wrong: %+v", desc)
	}
}

// --- 9. wrong key / wrong key length on framed ---

func TestFramedWrongKeyRejected(t *testing.T) {
	withSegSize(t, 16)
	key := testKey()
	repo, path := framedRepoPath()
	blob, err := SealFramed(key, deterministicPlaintext(40), SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
	if err != nil {
		t.Fatalf("SealFramed: %v", err)
	}
	wrong := testKey()
	wrong[0] ^= 0x01
	if _, _, err := OpenFramed(wrong, blob, repo, path); err == nil {
		t.Fatal("OpenFramed accepted wrong key")
	} else if !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("wrong error type: %v", err)
	}
}

func TestFramedWrongKeyLengthRejected(t *testing.T) {
	withSegSize(t, 16)
	key := testKey()
	repo, path := framedRepoPath()
	// Seal with short key.
	for _, n := range []int{0, 16, 31, 33} {
		short := make([]byte, n)
		if _, err := SealFramed(short, []byte("x"), SealOptions{Suite: SuiteXChaCha20, RepoIdentity: repo, ObjectPath: path}); err == nil {
			t.Fatalf("SealFramed accepted %d-byte key", n)
		} else if !errors.Is(err, ErrEnvelopeSeal) {
			t.Fatalf("wrong error type for %d-byte seal key: %v", n, err)
		}
	}
	// Open with short key.
	blob, err := SealFramed(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
	if err != nil {
		t.Fatalf("SealFramed: %v", err)
	}
	if _, _, err := OpenFramed(make([]byte, 16), blob, repo, path); err == nil {
		t.Fatal("OpenFramed accepted 16-byte key")
	} else if !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("wrong error type: %v", err)
	}
}

// Malformed framed input must never panic.
func TestFramedMalformedNoPanic(t *testing.T) {
	withSegSize(t, 16)
	key := testKey()
	repo, path := framedRepoPath()
	cases := map[string][]byte{
		"empty":            {},
		"short-descriptor": make([]byte, 5),
		"descriptor-only": func() []byte {
			b, _ := SealFramed(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
			return b[:descriptorSize]
		}(),
		"desc-but-no-body": func() []byte {
			b, _ := SealFramed(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
			return b[:descriptorSize+5]
		}(),
		"header-but-noblock": func() []byte {
			b, _ := SealFramed(key, []byte("x"), SealOptions{Suite: SuiteXChaCha20, KeyRef: Fingerprint(key), RepoIdentity: repo, ObjectPath: path})
			return b[:descriptorSize+prefixLenFor(t, SuiteXChaCha20)]
		}(),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := OpenFramed(key, b, repo, path); err == nil {
				t.Fatalf("OpenFramed accepted malformed input (%s)", name)
			} else if !errors.Is(err, ErrEnvelopeOpen) {
				t.Fatalf("wrong error type for %s: %v", name, err)
			}
		})
	}
}
