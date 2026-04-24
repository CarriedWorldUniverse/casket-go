package casket

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
	"time"
)

// UnixNowForTest exposes the current unix timestamp for use in test fixtures.
func UnixNowForTest() int64 {
	return time.Now().Unix()
}

// PairedChannelFromRawKeys constructs a PairedChannel from raw key material.
// Used only in interop tests to reconstruct a TS channel's paired state from
// exported fixture data (ephemeral test keys — never used with real key material).
//
// Parameters:
//   localNexusID  — identity string for this side
//   localSigPriv  — 64-byte ed25519 private key (seed || pubkey)
//   localDhPrivRaw — raw DH private scalar (32 bytes for both P-256 and X25519)
//   peerSigPub    — 32-byte ed25519 public key
//   peerDhPub     — raw DH public key bytes (65 for P-256, 32 for X25519)
//   alg            — DhAlgorithm
//   pathID         — precomputed path ID
//   peerNexusID    — identity string for the peer
func PairedChannelFromRawKeys(
	localNexusID string,
	localSigPriv []byte,
	localDhPrivRaw []byte,
	peerSigPub []byte,
	peerDhPub []byte,
	alg DhAlgorithm,
	pathID string,
	peerNexusID string,
) (*PairedChannel, error) {
	curve, err := dhCurve(alg)
	if err != nil {
		return nil, err
	}
	localDhPriv, err := curve.NewPrivateKey(localDhPrivRaw)
	if err != nil {
		return nil, fmt.Errorf("importing local DH private key: %w", err)
	}
	sharedKey, err := deriveSharedKey(alg, localDhPriv, peerDhPub)
	if err != nil {
		return nil, fmt.Errorf("deriving shared key: %w", err)
	}

	// Validate peer DH public key parses correctly under the given alg.
	if _, err := curve.NewPublicKey(peerDhPub); err != nil {
		return nil, fmt.Errorf("importing peer DH public key: %w", err)
	}

	_ = ecdh.P256() // ensure import used

	return &PairedChannel{
		localNexusID: localNexusID,
		sigPriv:      ed25519.PrivateKey(localSigPriv),
		peer: PeerRecord{
			NexusID:  peerNexusID,
			Pubkey:   b64uEncode(peerSigPub),
			DhAlg:    alg,
			DhPubkey: b64uEncode(peerDhPub),
			PathID:   pathID,
		},
		peerSigPub: ed25519.PublicKey(peerSigPub),
		sharedKey:  sharedKey,
	}, nil
}
