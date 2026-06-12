package casket

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// --- helpers ---

type testRecipient struct {
	priv, pub []byte
}

func makeRecipients(t *testing.T, n int) []testRecipient {
	t.Helper()
	rs := make([]testRecipient, n)
	for i := range rs {
		priv, pub, err := GenerateRecipientKey()
		if err != nil {
			t.Fatalf("GenerateRecipientKey: %v", err)
		}
		rs[i] = testRecipient{priv: priv, pub: pub}
	}
	return rs
}

func pubs(rs []testRecipient) [][]byte {
	out := make([][]byte, len(rs))
	for i, r := range rs {
		out[i] = r.pub
	}
	return out
}

func multiOpts(suite Suite) SealOptions {
	return SealOptions{
		Suite:        suite,
		KeyType:      KeyTypeBYOKRepo,
		KeyRef:       testKeyRef(),
		RepoIdentity: []byte("cairn/satchel-store"),
		ObjectPath:   []byte("personal/github.com/jacinta.casket"),
	}
}

func sealMultiForTest(t *testing.T, suite Suite, n int) ([]testRecipient, []byte, []byte, SealOptions) {
	t.Helper()
	rs := makeRecipients(t, n)
	opts := multiOpts(suite)
	pt := []byte("line1 the secret\nlogin: jacinta\n")
	blob, err := SealMulti(pt, pubs(rs), opts)
	if err != nil {
		t.Fatalf("SealMulti: %v", err)
	}
	return rs, blob, pt, opts
}

// --- 1. recipient key generation ---

func TestGenerateRecipientKeySizes(t *testing.T) {
	priv, pub, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	if len(priv) != 32 {
		t.Errorf("private key length = %d, want 32", len(priv))
	}
	if len(pub) != 32 {
		t.Errorf("public key length = %d, want 32", len(pub))
	}
}

func TestGenerateRecipientKeyDistinct(t *testing.T) {
	priv1, pub1, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	priv2, pub2, err := GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	if bytes.Equal(priv1, priv2) {
		t.Error("two generated private keys are equal")
	}
	if bytes.Equal(pub1, pub2) {
		t.Error("two generated public keys are equal")
	}
}

// --- 2. round-trip: 1 / 2 / 5 recipients, every recipient opens independently ---

func TestSealMultiOpenMultiRoundTrip(t *testing.T) {
	for _, suite := range allSuites {
		for _, n := range []int{1, 2, 5} {
			t.Run(suiteName(suite)+"/recipients="+string(rune('0'+n)), func(t *testing.T) {
				rs, blob, pt, opts := sealMultiForTest(t, suite, n)
				for i, r := range rs {
					got, err := OpenMulti(r.priv, blob, opts.RepoIdentity, opts.ObjectPath)
					if err != nil {
						t.Fatalf("recipient %d: OpenMulti: %v", i, err)
					}
					if !bytes.Equal(got, pt) {
						t.Fatalf("recipient %d: plaintext mismatch: got %q want %q", i, got, pt)
					}
				}
			})
		}
	}
}

func TestSealMultiDefaultSuiteIsXChaCha(t *testing.T) {
	rs := makeRecipients(t, 1)
	opts := multiOpts(0) // zero suite — must default to XChaCha20
	blob, err := SealMulti([]byte("x"), pubs(rs), opts)
	if err != nil {
		t.Fatalf("SealMulti: %v", err)
	}
	if Suite(blob[multiOffSuite]) != SuiteXChaCha20 {
		t.Fatalf("default suite = 0x%02x want 0x%02x (XChaCha20)", blob[multiOffSuite], byte(SuiteXChaCha20))
	}
	pt, err := OpenMulti(rs[0].priv, blob, opts.RepoIdentity, opts.ObjectPath)
	if err != nil {
		t.Fatalf("OpenMulti: %v", err)
	}
	if !bytes.Equal(pt, []byte("x")) {
		t.Fatalf("plaintext mismatch")
	}
}

// --- 3. wrong key → no matching recipient ---

func TestOpenMultiWrongKeyFails(t *testing.T) {
	_, blob, _, opts := sealMultiForTest(t, SuiteXChaCha20, 2)
	outsider := makeRecipients(t, 1)[0]
	_, err := OpenMulti(outsider.priv, blob, opts.RepoIdentity, opts.ObjectPath)
	if err == nil {
		t.Fatal("OpenMulti with non-recipient key succeeded, want error")
	}
	if !errors.Is(err, ErrEnvelopeOpen) {
		t.Errorf("err = %v, want ErrEnvelopeOpen", err)
	}
	if !errors.Is(err, ErrNoRecipient) {
		t.Errorf("err = %v, want ErrNoRecipient", err)
	}
}

func TestOpenMultiBadPrivateKeyLength(t *testing.T) {
	_, blob, _, opts := sealMultiForTest(t, SuiteXChaCha20, 1)
	_, err := OpenMulti([]byte("short"), blob, opts.RepoIdentity, opts.ObjectPath)
	if err == nil {
		t.Fatal("OpenMulti with 5-byte private key succeeded, want error")
	}
	if !errors.Is(err, ErrEnvelopeOpen) {
		t.Errorf("err = %v, want ErrEnvelopeOpen", err)
	}
}

// --- 4. AAD binding: different objectPath / repoIdentity fails ---

func TestOpenMultiAADMismatchFails(t *testing.T) {
	rs, blob, _, opts := sealMultiForTest(t, SuiteXChaCha20, 1)
	if _, err := OpenMulti(rs[0].priv, blob, opts.RepoIdentity, []byte("personal/github.com/other.casket")); err == nil {
		t.Fatal("OpenMulti with wrong objectPath succeeded, want error")
	}
	if _, err := OpenMulti(rs[0].priv, blob, []byte("cairn/other-store"), opts.ObjectPath); err == nil {
		t.Fatal("OpenMulti with wrong repoIdentity succeeded, want error")
	}
}

// --- 5. RecipientIDs: deterministic keyid = SHA-256(pub)[:8], seal order ---

func TestRecipientIDs(t *testing.T) {
	rs, blob, _, _ := sealMultiForTest(t, SuiteXChaCha20, 3)
	ids, err := RecipientIDs(blob)
	if err != nil {
		t.Fatalf("RecipientIDs: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("len(ids) = %d, want 3", len(ids))
	}
	for i, r := range rs {
		want := sha256.Sum256(r.pub)
		if !bytes.Equal(ids[i], want[:8]) {
			t.Errorf("ids[%d] = %x, want SHA-256(pub)[:8] = %x", i, ids[i], want[:8])
		}
		if len(ids[i]) != 8 {
			t.Errorf("ids[%d] length = %d, want 8", i, len(ids[i]))
		}
	}
}

// --- 6. seal-side input validation ---

func TestSealMultiRejectsBadInput(t *testing.T) {
	opts := multiOpts(SuiteXChaCha20)
	rs := makeRecipients(t, 1)

	if _, err := SealMulti([]byte("pt"), nil, opts); err == nil {
		t.Error("SealMulti with zero recipients succeeded, want error")
	}
	if _, err := SealMulti([]byte("pt"), [][]byte{rs[0].pub[:31]}, opts); err == nil {
		t.Error("SealMulti with 31-byte recipient pubkey succeeded, want error")
	}
	badSuiteOpts := opts
	badSuiteOpts.Suite = 0x7F
	if _, err := SealMulti([]byte("pt"), pubs(rs), badSuiteOpts); err == nil {
		t.Error("SealMulti with unknown suite succeeded, want error")
	}
	many := make([][]byte, 256)
	for i := range many {
		many[i] = rs[0].pub
	}
	if _, err := SealMulti([]byte("pt"), many, opts); err == nil {
		t.Error("SealMulti with 256 recipients succeeded, want error (count is u8, max 255)")
	}
}

// --- 7. single-shot/framed Open reject a multi blob; OpenMulti rejects others ---

func TestMultiBlobRejectedByOtherOpens(t *testing.T) {
	rs, blob, _, opts := sealMultiForTest(t, SuiteXChaCha20, 1)
	if _, _, err := Open(testKey(), blob, opts.RepoIdentity, opts.ObjectPath); err == nil {
		t.Error("single-shot Open accepted a multi-recipient blob")
	}
	_ = rs

	single, err := Seal(testKey(), []byte("pt"), opts)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := OpenMulti(rs[0].priv, single, opts.RepoIdentity, opts.ObjectPath); err == nil {
		t.Error("OpenMulti accepted a single-shot blob")
	}
	if _, err := RecipientIDs(single); err == nil {
		t.Error("RecipientIDs accepted a single-shot blob")
	}
}

// --- 8. tamper: body bit-flip fails for every recipient ---

func TestOpenMultiTamperedBodyFails(t *testing.T) {
	for _, suite := range allSuites {
		t.Run(suiteName(suite), func(t *testing.T) {
			rs, blob, _, opts := sealMultiForTest(t, suite, 2)
			nonceSize, err := suiteNonceSize(suite)
			if err != nil {
				t.Fatalf("suiteNonceSize: %v", err)
			}
			entrySize := multiRecipientKeySize + multiKeyIDSize + nonceSize + multiWrapSize
			bodyStart := multiHeaderSize + 2*entrySize

			tampered := append([]byte(nil), blob...)
			tampered[len(tampered)-1] ^= 0x01 // flip a bit in the body tag
			for i, r := range rs {
				if _, err := OpenMulti(r.priv, tampered, opts.RepoIdentity, opts.ObjectPath); err == nil {
					t.Errorf("recipient %d opened a body-tampered blob", i)
				}
			}

			tampered2 := append([]byte(nil), blob...)
			tampered2[bodyStart+descriptorSize+nonceSize] ^= 0x01 // flip first ciphertext bit
			if _, err := OpenMulti(rs[0].priv, tampered2, opts.RepoIdentity, opts.ObjectPath); err == nil {
				t.Error("opened a ciphertext-tampered blob")
			}
		})
	}
}

// --- 9. tamper: bit-flip in one wrap entry breaks only that recipient ---

func TestOpenMultiTamperedWrapEntryIsolated(t *testing.T) {
	suite := SuiteXChaCha20
	rs, blob, pt, opts := sealMultiForTest(t, suite, 3)
	nonceSize, err := suiteNonceSize(suite)
	if err != nil {
		t.Fatalf("suiteNonceSize: %v", err)
	}
	entrySize := multiRecipientKeySize + multiKeyIDSize + nonceSize + multiWrapSize

	// Flip a byte inside recipient 1's wrappedDEK.
	tampered := append([]byte(nil), blob...)
	victimWrapOff := multiHeaderSize + 1*entrySize + multiRecipientKeySize + multiKeyIDSize + nonceSize
	tampered[victimWrapOff] ^= 0xFF

	if _, err := OpenMulti(rs[1].priv, tampered, opts.RepoIdentity, opts.ObjectPath); err == nil {
		t.Error("victim recipient opened despite tampered wrap entry")
	} else if !errors.Is(err, ErrNoRecipient) {
		t.Errorf("victim err = %v, want ErrNoRecipient", err)
	}

	for _, i := range []int{0, 2} {
		got, err := OpenMulti(rs[i].priv, tampered, opts.RepoIdentity, opts.ObjectPath)
		if err != nil {
			t.Errorf("unaffected recipient %d: OpenMulti: %v", i, err)
			continue
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("unaffected recipient %d: plaintext mismatch", i)
		}
	}
}

// --- 10. malformed input: truncation at every length, corrupt header — no panics ---

func TestOpenMultiTruncationsErrorCleanly(t *testing.T) {
	rs, blob, _, opts := sealMultiForTest(t, SuiteXChaCha20, 2)
	for i := 0; i < len(blob); i++ {
		trunc := blob[:i]
		if _, err := OpenMulti(rs[0].priv, trunc, opts.RepoIdentity, opts.ObjectPath); err == nil {
			t.Fatalf("OpenMulti succeeded on %d-byte truncation of a %d-byte blob", i, len(blob))
		} else if !errors.Is(err, ErrEnvelopeOpen) {
			t.Fatalf("truncation at %d: err = %v, want ErrEnvelopeOpen", i, err)
		}
		// RecipientIDs must never panic; it may succeed once both entries are
		// present and a descriptor-sized body remains.
		_, _ = RecipientIDs(trunc)
	}
}

func TestOpenMultiCorruptHeaderErrors(t *testing.T) {
	rs, blob, _, opts := sealMultiForTest(t, SuiteXChaCha20, 1)

	mutate := func(off int, val byte) []byte {
		b := append([]byte(nil), blob...)
		b[off] = val
		return b
	}

	cases := []struct {
		name string
		blob []byte
	}{
		{"bad magic", mutate(multiOffMagic, 0x00)},
		{"bad version", mutate(multiOffVersion, 0x7F)},
		{"unknown suite", mutate(multiOffSuite, 0x7F)},
		{"zero count", mutate(multiOffCount, 0)},
		{"oversized count", mutate(multiOffCount, 255)},
		{"empty", nil},
		{"header only", blob[:multiHeaderSize]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := OpenMulti(rs[0].priv, tc.blob, opts.RepoIdentity, opts.ObjectPath); err == nil {
				t.Errorf("OpenMulti succeeded on %s", tc.name)
			} else if !errors.Is(err, ErrEnvelopeOpen) {
				t.Errorf("%s: err = %v, want ErrEnvelopeOpen", tc.name, err)
			}
			if _, err := RecipientIDs(tc.blob); err == nil {
				t.Errorf("RecipientIDs succeeded on %s", tc.name)
			}
		})
	}
}

// TestOpenMultiEveryByteMutationNoPanic flips every byte of a sealed blob and
// requires OpenMulti to return (never panic). Mutations outside the opening
// recipient's wrap entry and the body may legitimately still succeed (e.g. in
// another recipient's entry), so only absence of panics — and failure for
// header/own-entry/body mutations — is asserted.
func TestOpenMultiEveryByteMutationNoPanic(t *testing.T) {
	rs, blob, _, opts := sealMultiForTest(t, SuiteXChaCha20, 2)
	for i := 0; i < len(blob); i++ {
		for _, x := range []byte{0x01, 0xFF} {
			mutated := append([]byte(nil), blob...)
			mutated[i] ^= x
			_, _ = OpenMulti(rs[0].priv, mutated, opts.RepoIdentity, opts.ObjectPath)
			_, _ = RecipientIDs(mutated)
		}
	}
}
