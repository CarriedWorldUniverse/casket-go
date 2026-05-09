// Package casket — agent identity derivation.
//
// DeriveAgentKey produces a deterministic Ed25519 keypair from an owner's
// identity seed and an agent slug. Same (seed, slug) always produces the
// same keypair, on any machine. Different slugs produce independent keys.
//
// The derivation uses HKDF-SHA256 with info string "cairn-agent-v1:" + slug,
// length 32 bytes (Ed25519's seed size). The HKDF output is fed into
// ed25519.NewKeyFromSeed to produce the keypair.
//
// Reference: docs/cairn/specs/2026-05-09-cairn-foundation-design.md §6
// in the Cairn repo.

package casket

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const agentKeyInfoPrefix = "cairn-agent-v1:"

// DeriveAgentKey derives a deterministic Ed25519 keypair from an owner's
// identity seed and an agent slug. See package doc for details.
//
// Errors: returns an error if seed is empty or slug is empty.
func DeriveAgentKey(seed []byte, slug string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(seed) == 0 {
		return nil, nil, errors.New("casket: seed must not be empty")
	}
	if slug == "" {
		return nil, nil, errors.New("casket: slug must not be empty")
	}

	info := []byte(agentKeyInfoPrefix + slug)
	r := hkdf.New(sha256.New, seed, nil, info)

	derivedSeed := make([]byte, ed25519.SeedSize) // 32 bytes
	if _, err := io.ReadFull(r, derivedSeed); err != nil {
		return nil, nil, err
	}

	priv := ed25519.NewKeyFromSeed(derivedSeed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}
