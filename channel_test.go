package casket_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	casket "github.com/nexus-cw/casket-go"
)

// memStorage is an in-process ChannelStorage backed by a map.
type memStorage struct {
	m map[string]string
}

func newMemStorage() *memStorage {
	return &memStorage{m: make(map[string]string)}
}

func (s *memStorage) Get(_ context.Context, k string) (string, error) {
	return s.m[k], nil
}
func (s *memStorage) Put(_ context.Context, k, v string) error {
	s.m[k] = v
	return nil
}
func (s *memStorage) Delete(_ context.Context, k string) error {
	delete(s.m, k)
	return nil
}

// makePair creates two channels and pairs them using the default alg.
func makePair(t *testing.T, alg casket.DhAlgorithm) (a, b *casket.Channel, pa, pb *casket.PairedChannel) {
	t.Helper()
	ctx := context.Background()
	var err error
	a, err = casket.Load(ctx, "nexus-a", newMemStorage(), alg)
	if err != nil {
		t.Fatalf("Load nexus-a: %v", err)
	}
	b, err = casket.Load(ctx, "nexus-b", newMemStorage(), alg)
	if err != nil {
		t.Fatalf("Load nexus-b: %v", err)
	}
	tokA := a.MakePairingToken("https://relay-a.example.com")
	tokB := b.MakePairingToken("https://relay-b.example.com")
	pa, err = a.Pair(ctx, tokB, 86400)
	if err != nil {
		t.Fatalf("a.Pair: %v", err)
	}
	pb, err = b.Pair(ctx, tokA, 86400)
	if err != nil {
		t.Fatalf("b.Pair: %v", err)
	}
	return
}

func isBase64URL(s string) bool {
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && !strings.ContainsAny(s, "+/=")
}

// --- Channel.Load ---

func TestLoad_GeneratesED25519AndP256KeysOnFirstRun(t *testing.T) {
	ctx := context.Background()
	ch, err := casket.Load(ctx, "nexus-a", newMemStorage(), casket.P256)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.PublicKeyBytes()) != 32 {
		t.Errorf("Ed25519 public key: want 32 bytes, got %d", len(ch.PublicKeyBytes()))
	}
	if !isBase64URL(ch.PublicKeyB64u()) {
		t.Errorf("PublicKeyB64u is not valid base64url: %s", ch.PublicKeyB64u())
	}
	if len(ch.DHPublicKeyBytes()) != 65 {
		t.Errorf("P-256 DH public key: want 65 bytes (uncompressed), got %d", len(ch.DHPublicKeyBytes()))
	}
	if ch.DHAlg() != casket.P256 {
		t.Errorf("DHAlg: want P-256, got %s", ch.DHAlg())
	}
}

func TestLoad_GeneratesX25519KeyWhenRequested(t *testing.T) {
	ctx := context.Background()
	ch, err := casket.Load(ctx, "nexus-a", newMemStorage(), casket.X25519)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.PublicKeyBytes()) != 32 {
		t.Errorf("Ed25519 public key: want 32 bytes, got %d", len(ch.PublicKeyBytes()))
	}
	if len(ch.DHPublicKeyBytes()) != 32 {
		t.Errorf("X25519 DH public key: want 32 bytes, got %d", len(ch.DHPublicKeyBytes()))
	}
	if ch.DHAlg() != casket.X25519 {
		t.Errorf("DHAlg: want X25519, got %s", ch.DHAlg())
	}
}

func TestLoad_ReloadsKeysFromStorage_P256(t *testing.T) {
	ctx := context.Background()
	stor := newMemStorage()
	ch1, err := casket.Load(ctx, "nexus-a", stor, casket.P256)
	if err != nil {
		t.Fatal(err)
	}
	pub1, dhPub1 := ch1.PublicKeyB64u(), ch1.DHPublicKeyB64u()

	ch2, err := casket.Load(ctx, "nexus-a", stor, casket.P256)
	if err != nil {
		t.Fatal(err)
	}
	if ch2.PublicKeyB64u() != pub1 {
		t.Error("Ed25519 public key changed on reload")
	}
	if ch2.DHPublicKeyB64u() != dhPub1 {
		t.Error("DH public key changed on reload")
	}
	if ch2.DHAlg() != casket.P256 {
		t.Errorf("DHAlg changed on reload: got %s", ch2.DHAlg())
	}
}

func TestLoad_StoredAlgWinsOnReload(t *testing.T) {
	ctx := context.Background()
	stor := newMemStorage()
	ch1, err := casket.Load(ctx, "nexus-a", stor, casket.X25519)
	if err != nil {
		t.Fatal(err)
	}
	pub1, dhPub1 := ch1.PublicKeyB64u(), ch1.DHPublicKeyB64u()

	// Request P-256 on reload — stored X25519 must win.
	ch2, err := casket.Load(ctx, "nexus-a", stor, casket.P256)
	if err != nil {
		t.Fatal(err)
	}
	if ch2.DHAlg() != casket.X25519 {
		t.Errorf("stored alg should win on reload: want X25519, got %s", ch2.DHAlg())
	}
	if ch2.PublicKeyB64u() != pub1 {
		t.Error("Ed25519 public key changed on reload")
	}
	if ch2.DHPublicKeyB64u() != dhPub1 {
		t.Error("DH public key changed on reload")
	}
}

// --- MakePairingToken ---

func TestMakePairingToken_Fields(t *testing.T) {
	ctx := context.Background()
	ch, _ := casket.Load(ctx, "nexus-a", newMemStorage(), casket.P256)
	tok := ch.MakePairingToken("https://relay-a.example.com")

	if tok.V != 1 {
		t.Errorf("V: want 1, got %d", tok.V)
	}
	if tok.NexusID != "nexus-a" {
		t.Errorf("NexusID: want nexus-a, got %s", tok.NexusID)
	}
	if tok.SigAlg != "ed25519" {
		t.Errorf("SigAlg: want ed25519, got %s", tok.SigAlg)
	}
	if tok.DhAlg != casket.P256 {
		t.Errorf("DhAlg: want P-256, got %s", tok.DhAlg)
	}
	if tok.Pubkey != ch.PublicKeyB64u() {
		t.Error("Pubkey does not match PublicKeyB64u()")
	}
	if tok.DhPubkey != ch.DHPublicKeyB64u() {
		t.Error("DhPubkey does not match DHPublicKeyB64u()")
	}
	if tok.Endpoint != "https://relay-a.example.com" {
		t.Errorf("Endpoint: want https://relay-a.example.com, got %s", tok.Endpoint)
	}
	if len(tok.Nonce) == 0 {
		t.Error("Nonce is empty")
	}
	if tok.Ts <= 0 {
		t.Error("Ts is not set")
	}
}

func TestMakePairingToken_X25519CarriesDhAlg(t *testing.T) {
	ctx := context.Background()
	ch, _ := casket.Load(ctx, "nexus-a", newMemStorage(), casket.X25519)
	tok := ch.MakePairingToken("https://relay-a.example.com")
	if tok.DhAlg != casket.X25519 {
		t.Errorf("DhAlg: want X25519, got %s", tok.DhAlg)
	}
}

// --- Pair ---

func TestPair_ProducesConsistentPathID(t *testing.T) {
	_, _, pa, pb := makePair(t, casket.P256)
	if pa.PathID() != pb.PathID() {
		t.Errorf("pathIDs differ: %s vs %s", pa.PathID(), pb.PathID())
	}
	if !strings.HasPrefix(pa.PathID(), "nxc_") {
		t.Errorf("pathID missing nxc_ prefix: %s", pa.PathID())
	}
}

func TestPair_PathIDIsSymmetric(t *testing.T) {
	ctx := context.Background()
	chA, _ := casket.Load(ctx, "nexus-a", newMemStorage(), casket.P256)
	chB, _ := casket.Load(ctx, "nexus-b", newMemStorage(), casket.P256)
	tokA := chA.MakePairingToken("https://relay-a.example.com")
	tokB := chB.MakePairingToken("https://relay-b.example.com")

	pbFirst, _ := chB.Pair(ctx, tokA, 86400)
	paFirst, _ := chA.Pair(ctx, tokB, 86400)
	if paFirst.PathID() != pbFirst.PathID() {
		t.Errorf("pathIDs differ when pairing order reversed: %s vs %s", paFirst.PathID(), pbFirst.PathID())
	}
}

func TestPair_RejectsStaleToken(t *testing.T) {
	ctx := context.Background()
	chA, _ := casket.Load(ctx, "nexus-a", newMemStorage(), casket.P256)
	chB, _ := casket.Load(ctx, "nexus-b", newMemStorage(), casket.P256)
	stale := chB.MakePairingToken("https://relay-b.example.com")
	stale.Ts = stale.Ts - 9999

	_, err := chA.Pair(ctx, stale, 3600)
	if err == nil || !errors.Is(err, casket.ErrChannelPair) {
		t.Errorf("expected ErrChannelPair for stale token, got %v", err)
	}
}

func TestPair_RejectsBadED25519PubkeyLength(t *testing.T) {
	ctx := context.Background()
	chA, _ := casket.Load(ctx, "nexus-a", newMemStorage(), casket.P256)
	bad := casket.PairingToken{
		V:        1,
		NexusID:  "nexus-b",
		SigAlg:   "ed25519",
		DhAlg:    casket.P256,
		Pubkey:   "aGVsbG8", // "hello" — not 32 bytes
		DhPubkey: "aGVsbG8",
		Endpoint: "https://x.example.com",
		Nonce:    "abc",
		Ts:       casket.UnixNowForTest(),
	}
	_, err := chA.Pair(ctx, bad, 86400)
	if err == nil || !errors.Is(err, casket.ErrChannelPair) {
		t.Errorf("expected ErrChannelPair for bad pubkey length, got %v", err)
	}
}

func TestPair_RejectsMismatchedDhAlg(t *testing.T) {
	ctx := context.Background()
	chA, _ := casket.Load(ctx, "nexus-a", newMemStorage(), casket.P256)
	chB, _ := casket.Load(ctx, "nexus-b", newMemStorage(), casket.X25519)
	tokB := chB.MakePairingToken("https://relay-b.example.com")

	_, err := chA.Pair(ctx, tokB, 86400)
	if err == nil || !errors.Is(err, casket.ErrChannelPair) {
		t.Errorf("expected ErrChannelPair for alg mismatch, got %v", err)
	}
}

// --- GetPaired ---

func TestGetPaired_NilForUnknownPeer(t *testing.T) {
	ctx := context.Background()
	ch, _ := casket.Load(ctx, "nexus-a", newMemStorage(), casket.P256)
	p, err := ch.GetPaired(ctx, "nexus-b")
	if err != nil {
		t.Fatalf("GetPaired: %v", err)
	}
	if p != nil {
		t.Error("expected nil for unknown peer")
	}
}

func TestGetPaired_ReturnsSamePathIDAfterPairing(t *testing.T) {
	ctx := context.Background()
	chA, _, pa, _ := makePair(t, casket.P256)

	reloaded, err := chA.GetPaired(ctx, "nexus-b")
	if err != nil {
		t.Fatalf("GetPaired: %v", err)
	}
	if reloaded == nil {
		t.Fatal("expected non-nil PairedChannel from GetPaired")
	}
	if reloaded.PathID() != pa.PathID() {
		t.Errorf("pathID mismatch after reload: got %s, want %s", reloaded.PathID(), pa.PathID())
	}
}

// --- Revoke ---

func TestRevoke_RemovesPeerSoGetPairedReturnsNil(t *testing.T) {
	ctx := context.Background()
	chA, _, _, _ := makePair(t, casket.P256)

	if err := chA.Revoke(ctx, "nexus-b"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	p, _ := chA.GetPaired(ctx, "nexus-b")
	if p != nil {
		t.Error("expected nil after revoke")
	}
}

// --- Sign / Verify ---

func TestSignVerify_RoundTrip(t *testing.T) {
	_, _, pa, pb := makePair(t, casket.P256)
	msg := []byte(`{"msg_id":"abc","ts":1234567890}`)

	sig, err := pa.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := pb.Verify(sig, msg); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerify_TamperedMessage(t *testing.T) {
	_, _, pa, pb := makePair(t, casket.P256)
	sig, _ := pa.Sign([]byte(`{"msg_id":"abc"}`))
	err := pb.Verify(sig, []byte(`{"msg_id":"xyz"}`))
	if err == nil || !errors.Is(err, casket.ErrChannelVerify) {
		t.Errorf("expected ErrChannelVerify for tampered message, got %v", err)
	}
}

func TestVerify_BadSignature(t *testing.T) {
	_, _, _, pb := makePair(t, casket.P256)
	badSig := make([]byte, 64)
	err := pb.Verify(badSig, []byte("hello"))
	if err == nil || !errors.Is(err, casket.ErrChannelVerify) {
		t.Errorf("expected ErrChannelVerify for bad signature, got %v", err)
	}
}

// --- EncryptBody / DecryptBody ---

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	_, _, pa, pb := makePair(t, casket.P256)
	plaintext := []byte("Hello, @keel-nexus — here is the spec proposal.")

	ct, err := pa.EncryptBody(plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptBody: %v", err)
	}
	recovered, err := pb.DecryptBody(ct, nil)
	if err != nil {
		t.Fatalf("DecryptBody: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Errorf("decrypted text mismatch: got %q, want %q", recovered, plaintext)
	}
}

func TestEncryptDecrypt_BothDirections(t *testing.T) {
	_, _, pa, pb := makePair(t, casket.P256)
	msg := []byte("reply from B")
	ct, _ := pb.EncryptBody(msg, nil)
	pt, err := pa.DecryptBody(ct, nil)
	if err != nil {
		t.Fatalf("DecryptBody: %v", err)
	}
	if string(pt) != string(msg) {
		t.Errorf("decrypted: got %q, want %q", pt, msg)
	}
}

func TestEncryptBody_RandomNonce(t *testing.T) {
	_, _, pa, _ := makePair(t, casket.P256)
	msg := []byte("same message")
	ct1, _ := pa.EncryptBody(msg, nil)
	ct2, _ := pa.EncryptBody(msg, nil)
	if string(ct1) == string(ct2) {
		t.Error("two encryptions of same plaintext produced identical output — nonce is not random")
	}
}

func TestDecryptBody_TamperedCiphertext(t *testing.T) {
	_, _, pa, pb := makePair(t, casket.P256)
	ct, _ := pa.EncryptBody([]byte("secret"), nil)
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[15] ^= 0xff // flip a byte in the ciphertext region (after 12-byte nonce)

	_, err := pb.DecryptBody(tampered, nil)
	if err == nil || !errors.Is(err, casket.ErrChannelDecrypt) {
		t.Errorf("expected ErrChannelDecrypt for tampered ciphertext, got %v", err)
	}
}

func TestDecryptBody_WrongChannel(t *testing.T) {
	ctx := context.Background()
	_, _, pa, _ := makePair(t, casket.P256)

	// Third frame — different shared key
	chC, _ := casket.Load(ctx, "nexus-c", newMemStorage(), casket.P256)
	chA2, _ := casket.Load(ctx, "nexus-a-2", newMemStorage(), casket.P256)
	tokC := chC.MakePairingToken("https://relay-c.example.com")
	tokA2 := chA2.MakePairingToken("https://relay-a2.example.com")
	pairedC, _ := chC.Pair(ctx, tokA2, 86400)
	chA2.Pair(ctx, tokC, 86400) //nolint:errcheck

	ct, _ := pa.EncryptBody([]byte("top secret"), nil)
	_, err := pairedC.DecryptBody(ct, nil)
	if err == nil || !errors.Is(err, casket.ErrChannelDecrypt) {
		t.Errorf("expected ErrChannelDecrypt for wrong channel, got %v", err)
	}
}

func TestDecryptBody_AADMismatch(t *testing.T) {
	_, _, pa, pb := makePair(t, casket.P256)
	aadA := []byte("envelope-header-bytes")
	aadB := []byte("different-header-bytes")
	ct, _ := pa.EncryptBody([]byte("body"), aadA)
	_, err := pb.DecryptBody(ct, aadB)
	if err == nil || !errors.Is(err, casket.ErrChannelDecrypt) {
		t.Errorf("expected ErrChannelDecrypt for AAD mismatch, got %v", err)
	}
}

func TestDecryptBody_TooShort(t *testing.T) {
	_, _, _, pb := makePair(t, casket.P256)
	_, err := pb.DecryptBody([]byte("abc"), nil)
	if err == nil || !errors.Is(err, casket.ErrChannelDecrypt) {
		t.Errorf("expected ErrChannelDecrypt for too-short input, got %v", err)
	}
}

func TestEncryptDecrypt_X25519RoundTrip(t *testing.T) {
	_, _, pa, pb := makePair(t, casket.X25519)
	plaintext := []byte("Hello via X25519")
	ct, err := pa.EncryptBody(plaintext, nil)
	if err != nil {
		t.Fatalf("EncryptBody: %v", err)
	}
	recovered, err := pb.DecryptBody(ct, nil)
	if err != nil {
		t.Fatalf("DecryptBody: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Errorf("X25519 decrypted: got %q, want %q", recovered, plaintext)
	}
}
