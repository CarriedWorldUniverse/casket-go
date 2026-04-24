package casket_test

// Interop tests: verify that casket-go and casket-ts produce byte-identical
// pathIds and can encrypt/decrypt across the language boundary.
//
// Requires:
//   - Node.js in PATH
//   - casket-ts built: dist/esm/channel.js (run 'npm run build' in casket-ts)
//
// Set CASKET_TS_DIST to override the default casket-ts dist path.
// Set CASKET_FIXTURE_SCRIPT to override the default gen-fixture.mjs path.
//
// Tests skip (not fail) if node or casket-ts dist are unavailable.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	casket "github.com/nexus-cw/casket-go"
)

type interopChannelData struct {
	Token      casket.PairingToken `json:"token"`
	SigPubKey  string              `json:"sigPubKey"`
	DhPubKey   string              `json:"dhPubKey"`
	DhPrivKeyRaw string            `json:"dhPrivKeyRaw"` // base64url raw DH private scalar
}

type interopFixture struct {
	Alg            string             `json:"alg"`
	ChannelA       interopChannelData `json:"channelA"`
	ChannelB       interopChannelData `json:"channelB"`
	ExpectedPathID string             `json:"expectedPathId"`
	EncryptedByA   string             `json:"encryptedByA"` // TS A encrypted → B (Go) must decrypt
	EncryptedByB   string             `json:"encryptedByB"` // TS B encrypted → A (Go) must decrypt
	AAD            string             `json:"aad"`          // base64url raw AAD bytes
	Plaintext      string             `json:"plaintext"`
}

func defaultCasketTsDist() string {
	if v := os.Getenv("CASKET_TS_DIST"); v != "" {
		return v
	}
	_, thisFile, _, _ := runtime.Caller(0)
	casketGoDir := filepath.Dir(thisFile)
	return filepath.Join(casketGoDir, "..", "casket-ts", "dist", "esm", "channel.js")
}

func defaultFixtureScript() string {
	if v := os.Getenv("CASKET_FIXTURE_SCRIPT"); v != "" {
		return v
	}
	_, thisFile, _, _ := runtime.Caller(0)
	casketGoDir := filepath.Dir(thisFile)
	return filepath.Join(casketGoDir, "testdata", "interop", "gen-fixture.mjs")
}

func generateFixture(t *testing.T, alg string) *interopFixture {
	t.Helper()

	nodeCmd, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not in PATH — skipping interop test")
	}

	scriptPath := defaultFixtureScript()
	distPath := defaultCasketTsDist()

	if _, err := os.Stat(distPath); errors.Is(err, os.ErrNotExist) {
		t.Skipf("casket-ts dist not found at %s — run 'npm run build' in casket-ts", distPath)
	}

	cmd := exec.Command(nodeCmd, scriptPath, distPath, alg)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("gen-fixture.mjs failed: %v", err)
	}

	var fix interopFixture
	if err := json.Unmarshal(out, &fix); err != nil {
		t.Fatalf("unmarshalling fixture JSON: %v\noutput: %s", err, out)
	}
	return &fix
}

// pathIDFromB64u replicates the pathId formula from channel.go using only raw
// bytes — verifies the formula independently of the package implementation.
func pathIDFromB64u(t *testing.T, pubAB64u, pubBB64u string) string {
	t.Helper()
	pubA, err := base64.RawURLEncoding.DecodeString(pubAB64u)
	if err != nil {
		t.Fatalf("decoding pubA: %v", err)
	}
	pubB, err := base64.RawURLEncoding.DecodeString(pubBB64u)
	if err != nil {
		t.Fatalf("decoding pubB: %v", err)
	}

	first, second := pubA, pubB
	for i := 0; i < len(first) && i < len(second); i++ {
		if first[i] > second[i] {
			first, second = pubB, pubA
			break
		} else if first[i] < second[i] {
			break
		}
	}

	combined := append(append([]byte(nil), first...), second...)
	digest := sha256.Sum256(combined)
	return "nxc_" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func b64uDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode of %q: %v", s, err)
	}
	return b
}

func runInteropTest(t *testing.T, alg casket.DhAlgorithm) {
	t.Helper()

	fix := generateFixture(t, string(alg))
	ctx := context.Background()

	aadBytes := b64uDecode(t, fix.AAD)
	expectedPlaintext := fix.Plaintext

	// --- 1. pathId formula verification ---
	// Go independently computes the same pathId from the TS pubkeys.
	goPathID := pathIDFromB64u(t, fix.ChannelA.SigPubKey, fix.ChannelB.SigPubKey)
	if goPathID != fix.ExpectedPathID {
		t.Errorf("pathId formula mismatch:\n  got:  %s\n  want: %s", goPathID, fix.ExpectedPathID)
	}

	// --- 2. TS encrypts → Go decrypts (full cross-language decrypt) ---
	// Reconstruct the TS channel B's paired state using fixture private keys.
	// "Go acting as B" uses B's DH private key + A's DH public key.
	goAsB, err := casket.PairedChannelFromRawKeys(
		"nexus-ts-b",
		nil, // sig priv not needed for decrypt
		b64uDecode(t, fix.ChannelB.DhPrivKeyRaw),
		b64uDecode(t, fix.ChannelB.SigPubKey),
		b64uDecode(t, fix.ChannelA.DhPubKey), // peer DH pub = A's DH pub
		alg,
		fix.ExpectedPathID,
		"nexus-ts-a",
	)
	if err != nil {
		t.Fatalf("PairedChannelFromRawKeys (Go as B): %v", err)
	}

	encByABytes := b64uDecode(t, fix.EncryptedByA)
	decByGoB, err := goAsB.DecryptBody(encByABytes, aadBytes)
	if err != nil {
		t.Fatalf("TS-A-encrypted → Go-as-B DecryptBody: %v", err)
	}
	if string(decByGoB) != expectedPlaintext {
		t.Errorf("TS→Go decrypt mismatch:\n  got:  %q\n  want: %q", decByGoB, expectedPlaintext)
	}

	// "Go acting as A" uses A's DH private key + B's DH public key.
	goAsA, err := casket.PairedChannelFromRawKeys(
		"nexus-ts-a",
		nil,
		b64uDecode(t, fix.ChannelA.DhPrivKeyRaw),
		b64uDecode(t, fix.ChannelA.SigPubKey),
		b64uDecode(t, fix.ChannelB.DhPubKey),
		alg,
		fix.ExpectedPathID,
		"nexus-ts-b",
	)
	if err != nil {
		t.Fatalf("PairedChannelFromRawKeys (Go as A): %v", err)
	}

	encByBBytes := b64uDecode(t, fix.EncryptedByB)
	decByGoA, err := goAsA.DecryptBody(encByBBytes, aadBytes)
	if err != nil {
		t.Fatalf("TS-B-encrypted → Go-as-A DecryptBody: %v", err)
	}
	if string(decByGoA) != expectedPlaintext {
		t.Errorf("TS→Go decrypt mismatch (B→A):\n  got:  %q\n  want: %q", decByGoA, expectedPlaintext)
	}

	// --- 3. Go encrypts → Go decrypts (using keys derived from TS material) ---
	goReCT, err := goAsB.EncryptBody([]byte("reply from Go"), aadBytes)
	if err != nil {
		t.Fatalf("Go re-encrypt: %v", err)
	}
	// The symmetric shared key is the same on both sides — goAsA can decrypt what goAsB encrypted.
	goReDec, err := goAsA.DecryptBody(goReCT, aadBytes)
	if err != nil {
		t.Fatalf("Go re-decrypt: %v", err)
	}
	if string(goReDec) != "reply from Go" {
		t.Errorf("Go re-decrypt: got %q, want %q", goReDec, "reply from Go")
	}

	// --- 4. Pair a fresh Go channel with TS token and verify pathId ---
	goCh, err := casket.Load(ctx, "nexus-go-peer", newMemStorage(), alg)
	if err != nil {
		t.Fatalf("casket.Load: %v", err)
	}
	tokA := fix.ChannelA.Token
	tokA.Ts = time.Now().Unix() // refresh ts so Pair() doesn't reject stale fixture token
	goPaired, err := goCh.Pair(ctx, tokA, 86400)
	if err != nil {
		t.Fatalf("goCh.Pair with TS channelA token: %v", err)
	}
	expectedGoPairPathID := pathIDFromB64u(t, goCh.PublicKeyB64u(), fix.ChannelA.Token.Pubkey)
	if goPaired.PathID() != expectedGoPairPathID {
		t.Errorf("fresh Go pair pathId:\n  got:  %s\n  want: %s", goPaired.PathID(), expectedGoPairPathID)
	}

	t.Logf("alg=%s TS-pathId=%s TS→Go-decrypt=OK Go→Go-decrypt=OK fresh-pair-pathId=%s",
		alg, fix.ExpectedPathID, goPaired.PathID())
}

func TestInterop_P256_FullRoundTrip(t *testing.T) {
	runInteropTest(t, casket.P256)
}

func TestInterop_X25519_FullRoundTrip(t *testing.T) {
	runInteropTest(t, casket.X25519)
}

// TestInterop_SignatureFormat verifies Ed25519 signatures are 64 bytes and
// base64url-encode to 86 chars — matching the TS wire format.
func TestInterop_SignatureFormat(t *testing.T) {
	_, _, pa, _ := makePair(t, casket.P256)
	msg := []byte("test envelope bytes")
	sig, err := pa.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("Ed25519 signature: want 64 bytes, got %d", len(sig))
	}
	b64u := base64.RawURLEncoding.EncodeToString(sig)
	if len(b64u) != 86 {
		t.Errorf("base64url sig: want 86 chars, got %d", len(b64u))
	}
	if strings.ContainsAny(b64u, "+/=") {
		t.Error("base64url sig contains non-base64url characters")
	}
}

// TestInterop_PairingTokenJSONShape verifies the Go PairingToken JSON has
// exactly the field names casket-ts expects on the wire.
func TestInterop_PairingTokenJSONShape(t *testing.T) {
	ctx := context.Background()
	ch, _ := casket.Load(ctx, "nexus-a", newMemStorage(), casket.P256)
	tok := ch.MakePairingToken("https://relay-a.example.com")

	b, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	required := []string{"v", "nexus_id", "sig_alg", "dh_alg", "pubkey", "dh_pubkey", "endpoint", "nonce", "ts"}
	for _, field := range required {
		if _, ok := m[field]; !ok {
			t.Errorf("PairingToken JSON missing field: %s", field)
		}
	}
	if v, ok := m["v"].(float64); !ok || v != 1 {
		t.Errorf("v: want 1, got %v", m["v"])
	}
	if m["sig_alg"] != "ed25519" {
		t.Errorf("sig_alg: want ed25519, got %v", m["sig_alg"])
	}
	if m["dh_alg"] != "P-256" {
		t.Errorf("dh_alg: want P-256, got %v", m["dh_alg"])
	}
	if fmt.Sprint(m["nexus_id"]) != "nexus-a" {
		t.Errorf("nexus_id: want nexus-a, got %v", m["nexus_id"])
	}
}
