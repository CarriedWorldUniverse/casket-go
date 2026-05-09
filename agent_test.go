package casket

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDeriveAgentKey_Deterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, 32)

	priv1, pub1, err := DeriveAgentKey(seed, "plumb")
	if err != nil {
		t.Fatalf("first derivation: %v", err)
	}
	priv2, pub2, err := DeriveAgentKey(seed, "plumb")
	if err != nil {
		t.Fatalf("second derivation: %v", err)
	}

	if !bytes.Equal(priv1, priv2) {
		t.Errorf("private keys differ across calls: %x vs %x", priv1, priv2)
	}
	if !bytes.Equal(pub1, pub2) {
		t.Errorf("public keys differ across calls: %x vs %x", pub1, pub2)
	}
}

func TestDeriveAgentKey_DifferentSlugsIndependent(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, 32)

	_, pubPlumb, err := DeriveAgentKey(seed, "plumb")
	if err != nil {
		t.Fatal(err)
	}
	_, pubAnvil, err := DeriveAgentKey(seed, "anvil")
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(pubPlumb, pubAnvil) {
		t.Error("different slugs produced identical public keys")
	}
}

func TestDeriveAgentKey_DifferentSeedsIndependent(t *testing.T) {
	seedA := bytes.Repeat([]byte{0xaa}, 32)
	seedB := bytes.Repeat([]byte{0xbb}, 32)

	_, pubA, err := DeriveAgentKey(seedA, "plumb")
	if err != nil {
		t.Fatal(err)
	}
	_, pubB, err := DeriveAgentKey(seedB, "plumb")
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(pubA, pubB) {
		t.Error("different seeds produced identical public keys for same slug")
	}
}

func TestDeriveAgentKey_KnownVector(t *testing.T) {
	// Known vector to detect accidental algorithm changes.
	// seed = 32 bytes of 0xab, slug = "plumb"
	// Expected pubkey is computed once and frozen here.
	seed := bytes.Repeat([]byte{0xab}, 32)
	expectedPubHex := "f234195fe908f1f6cf7ccfae9a1b5bce9d0ba3af249269bd113c43916d3b5652"

	_, pub, err := DeriveAgentKey(seed, "plumb")
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(pub)

	if expectedPubHex == "FROZEN_AT_FIRST_PASSING_RUN" {
		// First-pass: print the value and fail so the developer freezes it.
		t.Logf("seed=%x slug=%s -> pubkey=%s", seed, "plumb", got)
		t.Fatalf("freeze the expected pubkey above into expectedPubHex")
	}
	if got != expectedPubHex {
		t.Errorf("pubkey changed; got %s want %s", got, expectedPubHex)
	}
}

func TestDeriveAgentKey_RejectsEmptySeed(t *testing.T) {
	_, _, err := DeriveAgentKey([]byte{}, "plumb")
	if err == nil {
		t.Error("expected error for empty seed")
	}
}

func TestDeriveAgentKey_RejectsEmptySlug(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, 32)
	_, _, err := DeriveAgentKey(seed, "")
	if err == nil {
		t.Error("expected error for empty slug")
	}
}

func TestDeriveAgentKey_PrivateKeyIsValidEd25519(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, 32)
	priv, _, err := DeriveAgentKey(seed, "plumb")
	if err != nil {
		t.Fatal(err)
	}
	// Ed25519 private keys are 64 bytes (32-byte seed + 32-byte public key).
	if len(priv) != 64 {
		t.Errorf("private key length: got %d want 64", len(priv))
	}
}
