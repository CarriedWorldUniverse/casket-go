// Package casket provides Ed25519 + ECDH channel identity for Frame-to-Frame relay.
//
// Each Frame holds two keypairs:
//   - Ed25519 (signing/verification) — non-repudiation on outer envelope
//   - ECDH (P-256 or X25519) — derives a shared symmetric key for body encryption
//
// Wire format and JSON shapes are byte-identical to casket-ts/src/channel.ts so a
// Go Frame and a TS Frame can pair through the interchange and interop byte-for-byte.
package casket

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"golang.org/x/crypto/hkdf"
)

// DhAlgorithm is the ECDH curve used for key exchange.
type DhAlgorithm string

const (
	P256   DhAlgorithm = "P-256"
	X25519 DhAlgorithm = "X25519"
)

// ChannelStorage is the persistence interface injected into a Channel.
// Returning ("", nil) from Get signals key-not-found.
type ChannelStorage interface {
	Get(ctx context.Context, key string) (string, error)
	Put(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
}

// PairingToken is exchanged out-of-band between two Frame operators to initiate pairing.
// JSON field names match casket-ts exactly for wire compatibility.
type PairingToken struct {
	V        int         `json:"v"`         // always 1
	NexusID  string      `json:"nexus_id"`
	SigAlg   string      `json:"sig_alg"`   // always "ed25519"
	DhAlg    DhAlgorithm `json:"dh_alg"`
	Pubkey   string      `json:"pubkey"`    // base64url Ed25519 public key (32 bytes)
	DhPubkey string      `json:"dh_pubkey"` // base64url ECDH public key (65 bytes P-256 / 32 bytes X25519)
	Endpoint string      `json:"endpoint"`  // https URL of the relay endpoint
	Nonce    string      `json:"nonce"`     // base64url 16 random bytes
	Ts       int64       `json:"ts"`        // unix seconds
}

// PeerRecord is stored in ChannelStorage for each paired peer.
type PeerRecord struct {
	NexusID  string      `json:"nexus_id"`
	Pubkey   string      `json:"pubkey"`
	DhAlg    DhAlgorithm `json:"dh_alg"`
	DhPubkey string      `json:"dh_pubkey"`
	Endpoint string      `json:"endpoint"`
	PathID   string      `json:"path_id"`
	PairedAt int64       `json:"paired_at"`
}

// Sentinel errors — use errors.Is to test.
var (
	ErrChannelPair    = errors.New("channel pair error")
	ErrChannelVerify  = errors.New("channel verify error")
	ErrChannelDecrypt = errors.New("channel decrypt error")
)

func pairError(msg string) error    { return fmt.Errorf("%w: %s", ErrChannelPair, msg) }
func verifyError(msg string) error  { return fmt.Errorf("%w: %s", ErrChannelVerify, msg) }
func decryptError(msg string) error { return fmt.Errorf("%w: %s", ErrChannelDecrypt, msg) }

// Storage keys — match casket-ts constants.
const (
	keyPrivate   = "casket:channel:private_key"
	keyPublic    = "casket:channel:public_key"
	keyDhPrivate = "casket:channel:dh_private_key"
	keyDhPublic  = "casket:channel:dh_public_key"
	keyDhAlg     = "casket:channel:dh_alg"
	peerPrefix   = "casket:peers:"
)

const (
	nonceSize = 12
	tagSize   = 16
)

// hkdfInfo must match casket-ts: new TextEncoder().encode('nexus-casket-channel-v1')
var hkdfInfo = []byte("nexus-casket-channel-v1")

// --- base64url helpers ---

func b64uEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64uDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// --- pathId derivation ---

// computePathID derives the symmetric path identifier from both Ed25519 signing pubkeys.
// Wire format: raw 32-byte ed25519 keys, sorted ascending, concatenated, SHA-256 hashed.
// Matches casket-ts computePathId exactly.
func computePathID(pubA, pubB []byte) string {
	keys := [][]byte{pubA, pubB}
	sort.Slice(keys, func(i, j int) bool {
		return compareBytes(keys[i], keys[j]) < 0
	})
	combined := append(append([]byte(nil), keys[0]...), keys[1]...)
	digest := sha256.Sum256(combined)
	return "nxc_" + b64uEncode(digest[:])
}

func compareBytes(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return int(a[i]) - int(b[i])
		}
	}
	return len(a) - len(b)
}

// --- ECDH helpers ---

func dhCurve(alg DhAlgorithm) (ecdh.Curve, error) {
	switch alg {
	case P256:
		return ecdh.P256(), nil
	case X25519:
		return ecdh.X25519(), nil
	default:
		return nil, fmt.Errorf("unsupported dh_alg: %s", alg)
	}
}

func dhPubKeyExpectedBytes(alg DhAlgorithm) int {
	if alg == P256 {
		return 65 // uncompressed SEC1 point: 0x04 || 32 || 32
	}
	return 32 // X25519 raw public key
}

// deriveSharedKey performs ECDH + HKDF-SHA256 → 32-byte AES-256-GCM key.
// HKDF salt = 32 zero bytes, info = hkdfInfo — must match casket-ts exactly.
func deriveSharedKey(alg DhAlgorithm, localPriv *ecdh.PrivateKey, peerPubBytes []byte) ([]byte, error) {
	curve, err := dhCurve(alg)
	if err != nil {
		return nil, err
	}
	peerPub, err := curve.NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("importing peer DH public key: %w", err)
	}
	rawSecret, err := localPriv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	salt := make([]byte, 32) // 32 zero bytes — matches casket-ts: new Uint8Array(32)
	r := hkdf.New(sha256.New, rawSecret, salt, hkdfInfo)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("HKDF expand: %w", err)
	}
	return key, nil
}

// --- Channel ---

// Channel is a Frame's local identity. One per Nexus instance.
// Call Load on every cold start — generates keys on first run, reloads on subsequent runs.
type Channel struct {
	nexusID     string
	sigPriv     ed25519.PrivateKey
	sigPubBytes []byte
	dhPriv      *ecdh.PrivateKey
	dhPubBytes  []byte
	dhAlg       DhAlgorithm
	storage     ChannelStorage
}

// Load initialises the Channel from storage, generating keys on first run.
// dhAlg is ignored on reload — the stored algorithm is authoritative.
func Load(ctx context.Context, nexusID string, storage ChannelStorage, dhAlg DhAlgorithm) (*Channel, error) {
	storedSigPriv, _ := storage.Get(ctx, keyPrivate)
	storedSigPub, _  := storage.Get(ctx, keyPublic)
	storedDhPriv, _  := storage.Get(ctx, keyDhPrivate)
	storedDhPub, _   := storage.Get(ctx, keyDhPublic)
	storedDhAlg, _   := storage.Get(ctx, keyDhAlg)

	if storedSigPriv != "" && storedSigPub != "" && storedDhPriv != "" && storedDhPub != "" && storedDhAlg != "" {
		sigPrivBytes, err := b64uDecode(storedSigPriv)
		if err != nil {
			return nil, fmt.Errorf("decoding stored sig private key: %w", err)
		}
		sigPubBytes, err := b64uDecode(storedSigPub)
		if err != nil {
			return nil, fmt.Errorf("decoding stored sig public key: %w", err)
		}
		dhPrivBytes, err := b64uDecode(storedDhPriv)
		if err != nil {
			return nil, fmt.Errorf("decoding stored dh private key: %w", err)
		}
		dhPubBytes, err := b64uDecode(storedDhPub)
		if err != nil {
			return nil, fmt.Errorf("decoding stored dh public key: %w", err)
		}
		storedAlg := DhAlgorithm(storedDhAlg)
		curve, err := dhCurve(storedAlg)
		if err != nil {
			return nil, err
		}
		dhPriv, err := curve.NewPrivateKey(dhPrivBytes)
		if err != nil {
			return nil, fmt.Errorf("importing stored dh private key: %w", err)
		}
		return &Channel{
			nexusID:     nexusID,
			sigPriv:     ed25519.PrivateKey(sigPrivBytes),
			sigPubBytes: sigPubBytes,
			dhPriv:      dhPriv,
			dhPubBytes:  dhPubBytes,
			dhAlg:       storedAlg,
			storage:     storage,
		}, nil
	}

	// First run — generate both keypairs.
	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 keypair: %w", err)
	}

	curve, err := dhCurve(dhAlg)
	if err != nil {
		return nil, err
	}
	dhPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDH keypair: %w", err)
	}
	dhPubBytes := dhPriv.PublicKey().Bytes()
	// For ECDH, PrivateKey.Bytes() returns the scalar bytes (32 for both P-256 and X25519).
	// On reload we use curve.NewPrivateKey(scalar) which reconstructs the full key.
	dhPrivBytes := dhPriv.Bytes()

	sigPubBytes := []byte(sigPub)
	sigPrivBytes := []byte(sigPriv) // ed25519.PrivateKey = seed || pubkey (64 bytes)

	if err := storage.Put(ctx, keyPrivate, b64uEncode(sigPrivBytes)); err != nil {
		return nil, err
	}
	if err := storage.Put(ctx, keyPublic, b64uEncode(sigPubBytes)); err != nil {
		return nil, err
	}
	if err := storage.Put(ctx, keyDhPrivate, b64uEncode(dhPrivBytes)); err != nil {
		return nil, err
	}
	if err := storage.Put(ctx, keyDhPublic, b64uEncode(dhPubBytes)); err != nil {
		return nil, err
	}
	if err := storage.Put(ctx, keyDhAlg, string(dhAlg)); err != nil {
		return nil, err
	}

	return &Channel{
		nexusID:     nexusID,
		sigPriv:     sigPriv,
		sigPubBytes: sigPubBytes,
		dhPriv:      dhPriv,
		dhPubBytes:  dhPubBytes,
		dhAlg:       dhAlg,
		storage:     storage,
	}, nil
}

func (c *Channel) PublicKeyBytes() []byte    { return c.sigPubBytes }
func (c *Channel) PublicKeyB64u() string     { return b64uEncode(c.sigPubBytes) }
func (c *Channel) DHPublicKeyBytes() []byte  { return c.dhPubBytes }
func (c *Channel) DHPublicKeyB64u() string   { return b64uEncode(c.dhPubBytes) }
func (c *Channel) DHAlg() DhAlgorithm        { return c.dhAlg }

// MakePairingToken builds a PairingToken to exchange OOB with the peer operator.
func (c *Channel) MakePairingToken(endpoint string) PairingToken {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(fmt.Sprintf("casket: rand.Read: %v", err))
	}
	return PairingToken{
		V:        1,
		NexusID:  c.nexusID,
		SigAlg:   "ed25519",
		DhAlg:    c.dhAlg,
		Pubkey:   c.PublicKeyB64u(),
		DhPubkey: c.DHPublicKeyB64u(),
		Endpoint: endpoint,
		Nonce:    b64uEncode(nonce),
		Ts:       time.Now().Unix(),
	}
}

// Pair completes pairing from the peer's PairingToken.
// Derives the shared AEAD key via ECDH and stores the peer record.
// Returns ErrChannelPair if the token is stale, malformed, or uses a mismatched algorithm.
func (c *Channel) Pair(ctx context.Context, token PairingToken, maxAgeSec int64) (*PairedChannel, error) {
	age := time.Now().Unix() - token.Ts
	if age > maxAgeSec || age < -300 {
		return nil, pairError(fmt.Sprintf("pairing token is too old or from the future (age=%ds)", age))
	}

	peerSigPubBytes, err := b64uDecode(token.Pubkey)
	if err != nil {
		return nil, pairError("invalid base64url in pubkey")
	}
	if len(peerSigPubBytes) != ed25519.PublicKeySize {
		return nil, pairError(fmt.Sprintf("peer Ed25519 public key must be 32 bytes, got %d", len(peerSigPubBytes)))
	}

	peerDhAlg := token.DhAlg
	if peerDhAlg == "" {
		peerDhAlg = P256 // tolerate tokens from pre-dh_alg casket
	}
	if peerDhAlg != c.dhAlg {
		return nil, pairError(fmt.Sprintf(
			"DH algorithm mismatch: local=%s, peer=%s. Both sides must use the same curve.",
			c.dhAlg, peerDhAlg,
		))
	}

	peerDhPubBytes, err := b64uDecode(token.DhPubkey)
	if err != nil {
		return nil, pairError("invalid base64url in dh_pubkey")
	}
	expectedDhBytes := dhPubKeyExpectedBytes(peerDhAlg)
	if len(peerDhPubBytes) != expectedDhBytes {
		return nil, pairError(fmt.Sprintf(
			"peer %s public key must be %d bytes, got %d",
			peerDhAlg, expectedDhBytes, len(peerDhPubBytes),
		))
	}

	pathID := computePathID(c.sigPubBytes, peerSigPubBytes)
	sharedKey, err := deriveSharedKey(c.dhAlg, c.dhPriv, peerDhPubBytes)
	if err != nil {
		return nil, pairError(fmt.Sprintf("deriving shared key: %v", err))
	}

	record := PeerRecord{
		NexusID:  token.NexusID,
		Pubkey:   token.Pubkey,
		DhAlg:    peerDhAlg,
		DhPubkey: token.DhPubkey,
		Endpoint: token.Endpoint,
		PathID:   pathID,
		PairedAt: time.Now().Unix(),
	}
	recJSON, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if err := c.storage.Put(ctx, peerPrefix+token.NexusID, string(recJSON)); err != nil {
		return nil, err
	}

	return &PairedChannel{
		localNexusID: c.nexusID,
		sigPriv:      c.sigPriv,
		peer:         record,
		peerSigPub:   ed25519.PublicKey(peerSigPubBytes),
		sharedKey:    sharedKey,
	}, nil
}

// GetPaired reloads an existing PairedChannel from storage.
// Returns nil, nil if the peer is not found.
func (c *Channel) GetPaired(ctx context.Context, peerID string) (*PairedChannel, error) {
	raw, err := c.storage.Get(ctx, peerPrefix+peerID)
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}

	var record PeerRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return nil, fmt.Errorf("unmarshalling peer record: %w", err)
	}

	peerSigPubBytes, err := b64uDecode(record.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("decoding peer sig pubkey from record: %w", err)
	}
	peerDhPubBytes, err := b64uDecode(record.DhPubkey)
	if err != nil {
		return nil, fmt.Errorf("decoding peer dh pubkey from record: %w", err)
	}
	peerDhAlg := record.DhAlg
	if peerDhAlg == "" {
		peerDhAlg = P256
	}

	sharedKey, err := deriveSharedKey(peerDhAlg, c.dhPriv, peerDhPubBytes)
	if err != nil {
		return nil, fmt.Errorf("deriving shared key on reload: %w", err)
	}

	return &PairedChannel{
		localNexusID: c.nexusID,
		sigPriv:      c.sigPriv,
		peer:         record,
		peerSigPub:   ed25519.PublicKey(peerSigPubBytes),
		sharedKey:    sharedKey,
	}, nil
}

// Revoke removes a peer from storage. A fresh Pair after revocation produces a new pathID.
func (c *Channel) Revoke(ctx context.Context, peerID string) error {
	return c.storage.Delete(ctx, peerPrefix+peerID)
}

// --- PairedChannel ---

// PairedChannel is an active channel to a specific peer.
// Obtained from Channel.Pair or Channel.GetPaired.
type PairedChannel struct {
	localNexusID string
	sigPriv      ed25519.PrivateKey
	peer         PeerRecord
	peerSigPub   ed25519.PublicKey
	sharedKey    []byte
}

func (p *PairedChannel) PathID() string        { return p.peer.PathID }
func (p *PairedChannel) PeerID() string        { return p.peer.NexusID }
func (p *PairedChannel) PeerEndpoint() string  { return p.peer.Endpoint }
func (p *PairedChannel) PeerRecord() PeerRecord { return p.peer }

// Sign signs arbitrary bytes for the outer envelope using the local Ed25519 key.
// Returns the raw 64-byte signature.
func (p *PairedChannel) Sign(data []byte) ([]byte, error) {
	sig := ed25519.Sign(p.sigPriv, data)
	return sig, nil
}

// Verify verifies a signature from the peer.
// Returns ErrChannelVerify if the signature is invalid.
func (p *PairedChannel) Verify(sig, data []byte) error {
	if !ed25519.Verify(p.peerSigPub, data, sig) {
		return verifyError("signature verification failed")
	}
	return nil
}

// EncryptBody encrypts the message body (inner layer) with AES-256-GCM.
// Returns nonce (12 bytes) || ciphertext+GCM-tag as raw bytes.
// aad is optional additional authenticated data.
// Output format matches casket-ts encryptBody exactly.
func (p *PairedChannel) EncryptBody(plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.sharedKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// gcm.Seal appends ciphertext+tag to nil → returns ciphertext||tag
	ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, aad)

	result := make([]byte, nonceSize+len(ciphertextWithTag))
	copy(result, nonce)
	copy(result[nonceSize:], ciphertextWithTag)
	return result, nil
}

// DecryptBody decrypts a blob produced by EncryptBody.
// blob layout: nonce (12 bytes) || ciphertext+GCM-tag.
// Returns ErrChannelDecrypt if authentication fails or blob is too short.
func (p *PairedChannel) DecryptBody(blob, aad []byte) ([]byte, error) {
	if len(blob) < nonceSize+tagSize {
		return nil, decryptError("ciphertext too short")
	}

	block, err := aes.NewCipher(p.sharedKey)
	if err != nil {
		return nil, decryptError(fmt.Sprintf("creating AES cipher: %v", err))
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, decryptError(fmt.Sprintf("creating GCM: %v", err))
	}

	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, decryptError("body decryption failed — wrong key or tampered ciphertext")
	}
	return plaintext, nil
}
