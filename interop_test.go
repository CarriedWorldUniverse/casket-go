package casket_test

// Interop tests: verify that casket-go and casket-ts produce byte-identical
// pathIds and share the same wire format.
//
// Requires:
//   - Node.js in PATH
//   - casket-ts built: C:\src\nexus-cw\casket-ts\dist\esm\channel.js
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

type interopFixture struct {
	Alg      string `json:"alg"`
	ChannelA struct {
		Token     casket.PairingToken `json:"token"`
		SigPubKey string              `json:"sigPubKey"`
		DhPubKey  string              `json:"dhPubKey"`
	} `json:"channelA"`
	ChannelB struct {
		Token     casket.PairingToken `json:"token"`
		SigPubKey string              `json:"sigPubKey"`
		DhPubKey  string              `json:"dhPubKey"`
	} `json:"channelB"`
	ExpectedPathID string `json:"expectedPathId"`
	EncryptedByA   string `json:"encryptedByA"` // base64url nonce||ct+tag from TS channelA
	AAD            string `json:"aad"`           // base64url raw AAD bytes
	Plaintext      string `json:"plaintext"`
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
		t.Skipf("casket-ts dist not found at %s — run 'npm run build' in casket-ts first", distPath)
	}

	cmd := exec.Command(nodeCmd, scriptPath, distPath, alg)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("gen-fixture.mjs failed: %v", err)
	}

	var fix interopFixture
	if err := json.Unmarshal(out, &fix); err != nil {
		t.Fatalf("unmarshalling fixture JSON: %v", err)
	}
	return &fix
}

// pathIDFromB64u replicates the pathId formula from channel.go using
// only raw bytes — verifies the formula independently of the implementation.
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

func runInteropTest(t *testing.T, alg casket.DhAlgorithm) {
	t.Helper()

	fix := generateFixture(t, string(alg))
	ctx := context.Background()

	// 1. Verify Go independently computes the same pathId from the TS pubkeys.
	goPathID := pathIDFromB64u(t, fix.ChannelA.SigPubKey, fix.ChannelB.SigPubKey)
	if goPathID != fix.ExpectedPathID {
		t.Errorf("Go pathId formula mismatch:\n  got:  %s\n  want: %s", goPathID, fix.ExpectedPathID)
	}

	// 2. Create a fresh Go channel (nexus-go-b) and pair it with TS channelA's token.
	//    This exercises the full ECDH + HKDF + AES-GCM path against TS keys.
	goCh, err := casket.Load(ctx, "nexus-go-b", newMemStorage(), alg)
	if err != nil {
		t.Fatalf("casket.Load: %v", err)
	}

	// Use a refreshed ts so Pair() doesn't reject the fixture token as stale.
	tokA := fix.ChannelA.Token
	tokA.Ts = time.Now().Unix()

	goPaired, err := goCh.Pair(ctx, tokA, 86400)
	if err != nil {
		t.Fatalf("goCh.Pair with TS channelA token: %v", err)
	}

	// 3. Verify Go's pathId for this pair matches independent formula.
	expectedGoPathID := pathIDFromB64u(t, goCh.PublicKeyB64u(), fix.ChannelA.Token.Pubkey)
	if goPaired.PathID() != expectedGoPathID {
		t.Errorf("goPaired.PathID() mismatch:\n  got:  %s\n  want: %s", goPaired.PathID(), expectedGoPathID)
	}

	// 4. Go encrypts with the Go↔TSA shared key and verifies self-decrypt.
	aadBytes, err := base64.RawURLEncoding.DecodeString(fix.AAD)
	if err != nil {
		t.Fatalf("decoding AAD: %v", err)
	}
	plaintext := []byte("Hello from casket-go — interop check")

	goCT, err := goPaired.EncryptBody(plaintext, aadBytes)
	if err != nil {
		t.Fatalf("EncryptBody: %v", err)
	}
	goDecrypted, err := goPaired.DecryptBody(goCT, aadBytes)
	if err != nil {
		t.Fatalf("DecryptBody (Go self-decrypt): %v", err)
	}
	if string(goDecrypted) != string(plaintext) {
		t.Errorf("Go self-decrypt: got %q, want %q", goDecrypted, plaintext)
	}

	// 5. Ciphertext layout sanity: nonce (12) || ciphertext+tag (≥ 16+len(plaintext)).
	const nonceSize, tagSize = 12, 16
	if len(goCT) < nonceSize+tagSize+len(plaintext) {
		t.Errorf("ciphertext too short: %d bytes", len(goCT))
	}

	t.Logf("alg=%s pathId=%s goPairedPathId=%s ct=%d bytes — OK",
		alg, fix.ExpectedPathID, goPaired.PathID(), len(goCT))
}

func TestInterop_P256_PathIDAndEncrypt(t *testing.T) {
	runInteropTest(t, casket.P256)
}

func TestInterop_X25519_PathIDAndEncrypt(t *testing.T) {
	runInteropTest(t, casket.X25519)
}

// TestInterop_SignatureFormat verifies Ed25519 signatures are 64 bytes
// and base64url-encode to 86 chars with no +/= chars — matching TS wire format.
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

// TestInterop_PairingTokenJSONShape verifies the Go PairingToken JSON
// has exactly the field names casket-ts expects.
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
