// Package casket — framed (streaming) at-rest envelope.
//
// The framed mode seals an arbitrarily large blob without holding the whole
// plaintext (or ciphertext) in memory. It uses the Tink-style streaming-AEAD
// construction (STREAM of Hoang–Reyhanitabar–Rogaway–Vizár, with a per-stream
// derived key as in Google Tink): a fresh random 32-byte salt is generated per
// stream and the long-term key is HKDF-expanded into a per-stream subkey; the
// plaintext is then split into fixed-size segments, each segment AEAD-sealed
// under the per-stream subkey with a per-segment nonce derived from a random
// prefix plus a 32-bit counter, and the final segment marked with a distinct
// nonce flag byte. This binds segment order (the counter) and stream termination
// (the final flag) into the nonce, so reorder, truncation, duplication, and
// splice are all rejected by AEAD verification — no separately-authenticated
// length field is needed.
//
// Per-stream key derivation:
//
//	framedKey = HKDF-SHA256(secret=key, salt=salt(32B random),
//	                        info="casket-envelope-framed-v1") → 32 bytes
//
// Because each stream uses a distinct random salt, the AEAD subkey differs per
// stream; cross-stream nonce collisions are therefore infeasible for ALL suites,
// including the 12-byte-nonce suites whose ~7-byte random prefix would otherwise
// risk a birthday collision across many streams under one long-term key.
//
// Wire format (framed):
//
//	blob = DESCRIPTOR(20 bytes, flags bit0 set) || SALT(32 bytes)
//	    || noncePrefix(nonceSize-5 bytes) || block_0 || block_1 || ... || block_last
//	block_i = AEAD.Seal(segment_i) = ciphertext_i || tag_i   (tag is 16 bytes)
//
// Per-segment nonce (length = suite nonceSize):
//
//	nonce_i = noncePrefix || uint32be(i) || finalFlag
//	          \__ nonceSize-5 __/  \_ 4 _/  \__ 1 __/
//
//	finalFlag = 0x00 for every non-final segment, 0x01 for the final segment.
//	prefix length is nonceSize-5: AES-GCM / ChaCha20 (12B nonce) → 7;
//	XChaCha20 (24B nonce) → 19.
//
// AAD: the *same* message-level framed AAD is authenticated for every segment:
//
//	framedAAD = descriptor(20B)
//	   || uint16be(len(repoIdentity)) || repoIdentity
//	   || uint16be(len(objectPath))   || objectPath
//	   || uint32be(framedSegSize)
//
// (= buildAAD || uint32be(framedSegSize)). Binding the segment size means a
// seal/open size mismatch fails as an AEAD verification error rather than
// silently mis-parsing the block boundaries. Segment position is bound by the
// nonce counter and stream termination by the final flag, so the AAD need not
// vary per segment.
//
// Segmentation rules (identical between seal and open):
//
//   - Plaintext is split into framedSegSize-byte segments; the last is the
//     remainder. L==0 → exactly one 0-byte (final) segment. L>0 and L%S==0 →
//     L/S segments, the last a full S-byte segment marked final (no trailing
//     empty segment). Otherwise ceil(L/S) segments. Only the last is final.
//   - A framed stream may contain AT MOST 2^32 segments: the segment index is a
//     uint32, so valid indices are 0..2^32-1 (= math.MaxUint32), 2^32 distinct
//     values. The last segment is marked final. No index may repeat or wrap. A
//     non-final segment at index math.MaxUint32 is refused, because emitting the
//     next (non-final or final) segment would require index 2^32, which wraps the
//     uint32 back to 0 and would reuse a nonce. A final segment AT index
//     math.MaxUint32 is legitimate (it is the last, so no further index is
//     needed). Nonce-index reuse is made structurally impossible by a sticky
//     "exhausted" flag (see sealWriter.flushSegment).
//
// Open derives the per-stream framedKey from the descriptor's keyref-identified
// long-term key plus the on-wire salt, then derives boundaries from the body
// length: with blockSize = framedSegSize+16,
// consume full blockSize blocks (finalFlag=0) while the remaining bytes exceed
// blockSize; the remainder (≤ blockSize) is the final block (finalFlag=1). This
// makes the exact-multiple case unambiguous: a trailing remainder of exactly
// blockSize is the final full block. A remainder < 16 (no room for tag) is an
// error, and there must be nothing left after the final block.
package casket

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/hkdf"
)

// framedSegSize is the fixed plaintext segment size. Canonical value is 65536
// (64 KiB) — a fixed format parameter all implementations MUST use; it is
// authenticated via the framed AAD, so a seal/open size mismatch fails as an AEAD
// error rather than silently mis-parsing. The package var exists only so tests
// can shrink it (it is an unexported var, not a const); production code MUST NOT
// mutate it.
var framedSegSize = 65536

// framed nonce layout: ...prefix... || uint32be(counter) || finalFlag(1 byte).
const (
	framedCounterSize = 4 // uint32 big-endian segment index
	framedFlagSize    = 1 // final-segment flag
	framedSuffixSize  = framedCounterSize + framedFlagSize

	framedFinalFlag    byte = 0x01
	framedNonFinalFlag byte = 0x00

	// framedSaltSize is the per-stream HKDF salt length (32 bytes), written on
	// the wire immediately after the descriptor and before the nonce prefix.
	framedSaltSize = 32
)

// framedHKDFInfo domain-separates the per-stream framed-subkey derivation from
// any other use of the long-term key (e.g. the channel layer's hkdfInfo).
var framedHKDFInfo = []byte("casket-envelope-framed-v1")

// deriveFramedKey expands the long-term key into a 32-byte per-stream subkey via
// HKDF-SHA256(secret=key, salt=salt, info="casket-envelope-framed-v1"). The
// random per-stream salt makes cross-stream nonce collisions infeasible for all
// suites.
func deriveFramedKey(key, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, key, salt, framedHKDFInfo)
	out := make([]byte, envelopeKeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("HKDF expand framed subkey: %w", err)
	}
	return out, nil
}

// buildFramedAAD appends the authenticated segment size to the message-level AAD:
// framedAAD = buildAAD(...) || uint32be(framedSegSize). Binding the segment size
// turns a seal/open size mismatch into an AEAD verification failure.
func buildFramedAAD(descriptor, repoIdentity, objectPath []byte, segSize int) []byte {
	aad := buildAAD(descriptor, repoIdentity, objectPath)
	var sz [4]byte
	binary.BigEndian.PutUint32(sz[:], uint32(segSize))
	return append(aad, sz[:]...)
}

// noncePrefixLen returns the random nonce-prefix length for a suite's AEAD:
// nonceSize - 5 (4-byte counter + 1-byte final flag).
func noncePrefixLen(aead cipher.AEAD) (int, error) {
	n := aead.NonceSize()
	if n <= framedSuffixSize {
		return 0, fmt.Errorf("suite nonce size %d too small for STREAM suffix %d", n, framedSuffixSize)
	}
	return n - framedSuffixSize, nil
}

// segmentNonce builds the per-segment nonce: prefix || uint32be(index) || flag.
// The returned slice has length aead.NonceSize(); prefix must be exactly
// nonceSize-5 bytes.
func segmentNonce(prefix []byte, index uint32, final bool) []byte {
	nonce := make([]byte, len(prefix)+framedSuffixSize)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[len(prefix):], index)
	if final {
		nonce[len(prefix)+framedCounterSize] = framedFinalFlag
	} else {
		nonce[len(prefix)+framedCounterSize] = framedNonFinalFlag
	}
	return nonce
}

// framedDescriptor builds the framed-mode descriptor (flags bit0 set).
func framedDescriptor(suite Suite, opts SealOptions) Descriptor {
	return Descriptor{
		Suite:   suite,
		Version: envelopeVersion,
		KeyType: opts.KeyType,
		KeyRef:  opts.KeyRef,
		Flags:   flagFramed,
	}
}

// --- streaming seal ---

type sealWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	salt   []byte // per-stream HKDF salt (framedSaltSize bytes)
	prefix []byte // nonce prefix (nonceSize-5 bytes)
	aad    []byte // message-level framed AAD (constant across segments)

	buf     []byte // pending plaintext, < framedSegSize once a segment is flushed
	index   uint32 // next segment index to emit
	started bool   // header (descriptor + salt + prefix) written
	closed  bool
	// exhausted becomes true once a segment is sealed at index math.MaxUint32
	// (the last legitimately usable index). Any further flush attempt would have
	// to reuse or wrap the index — and thus reuse a nonce — so it is refused.
	// This makes nonce-index reuse structurally impossible rather than implied by
	// control flow.
	exhausted bool
	err       error // sticky error
}

// NewSealWriter returns an io.WriteCloser that seals everything written to it as
// a framed envelope written to w, using the per-stream-keyed STREAM construction.
// A fresh random 32-byte salt and the long-term key are HKDF-expanded into the
// per-stream AEAD subkey. The descriptor (framed flag set), salt, and random
// nonce prefix are written on the first flush. Each time the internal buffer
// fills to framedSegSize a non-final segment is sealed and written; Close seals
// the remaining buffer as the final segment (handling empty and exact-multiple
// inputs per the segmentation rules). Close is idempotent-safe in that a second
// call returns an error rather than corrupting output. Key length and AAD fields
// are validated up front.
func NewSealWriter(w io.Writer, key []byte, opts SealOptions) (io.WriteCloser, error) {
	suite := opts.Suite
	if suite == 0 {
		suite = defaultSuite
	}
	if err := validateAADFields(opts.RepoIdentity, opts.ObjectPath); err != nil {
		return nil, sealError(err.Error())
	}
	salt := make([]byte, framedSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, sealError(fmt.Sprintf("generating framed salt: %v", err))
	}
	aead, err := newFramedAEAD(suite, key, salt)
	if err != nil {
		return nil, sealError(err.Error())
	}
	prefixLen, err := noncePrefixLen(aead)
	if err != nil {
		return nil, sealError(err.Error())
	}
	prefix := make([]byte, prefixLen)
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return nil, sealError(fmt.Sprintf("generating nonce prefix: %v", err))
	}
	return newSealWriterWithSaltPrefix(w, aead, suite, salt, prefix, opts)
}

// newFramedAEAD validates the long-term key length, derives the per-stream subkey
// via HKDF(key, salt), and builds the suite AEAD from that subkey.
func newFramedAEAD(suite Suite, key, salt []byte) (cipher.AEAD, error) {
	if len(key) != envelopeKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", envelopeKeySize, len(key))
	}
	framedKey, err := deriveFramedKey(key, salt)
	if err != nil {
		return nil, err
	}
	return newAEAD(suite, framedKey)
}

// newSealWriterWithSaltPrefix is the deterministic seam used by NewSealWriter and
// by KAT helpers: it takes a caller-supplied salt and nonce prefix instead of
// random ones. aead must already be built from the per-stream subkey for salt.
func newSealWriterWithSaltPrefix(w io.Writer, aead cipher.AEAD, suite Suite, salt, prefix []byte, opts SealOptions) (io.WriteCloser, error) {
	if err := validateAADFields(opts.RepoIdentity, opts.ObjectPath); err != nil {
		return nil, sealError(err.Error())
	}
	if len(salt) != framedSaltSize {
		return nil, sealError(fmt.Sprintf("framed salt must be %d bytes, got %d", framedSaltSize, len(salt)))
	}
	prefixLen, err := noncePrefixLen(aead)
	if err != nil {
		return nil, sealError(err.Error())
	}
	if len(prefix) != prefixLen {
		return nil, sealError(fmt.Sprintf("nonce prefix must be %d bytes for suite 0x%02x, got %d", prefixLen, byte(suite), len(prefix)))
	}
	desc := framedDescriptor(suite, opts)
	aad := buildFramedAAD(desc.encode(), opts.RepoIdentity, opts.ObjectPath, framedSegSize)
	return &sealWriter{
		w:      w,
		aead:   aead,
		salt:   append([]byte(nil), salt...),
		prefix: append([]byte(nil), prefix...),
		aad:    aad,
		buf:    make([]byte, 0, framedSegSize),
	}, nil
}

// writeHeader emits descriptor + salt + nonce prefix on first use. The descriptor
// bytes are exactly the first descriptorSize bytes of the AAD, so they are reused
// here to guarantee the on-wire header and the authenticated descriptor are
// identical.
func (sw *sealWriter) writeHeader() error {
	if sw.started {
		return nil
	}
	header := make([]byte, 0, descriptorSize+len(sw.salt)+len(sw.prefix))
	header = append(header, sw.aad[:descriptorSize]...)
	header = append(header, sw.salt...)
	header = append(header, sw.prefix...)
	if _, err := sw.w.Write(header); err != nil {
		return sealError(fmt.Sprintf("writing framed header: %v", err))
	}
	sw.started = true
	return nil
}

func (sw *sealWriter) Write(p []byte) (int, error) {
	if sw.err != nil {
		return 0, sw.err
	}
	if sw.closed {
		sw.err = sealError("write after close")
		return 0, sw.err
	}
	written := 0
	for len(p) > 0 {
		// A full buffer with more data still to come (this Write has bytes left)
		// is definitely a NON-final segment: flush it before buffering more.
		// Deferring the flush until we know there is more data is what lets Close
		// mark the trailing buffer final, including the exact-multiple case.
		if len(sw.buf) == framedSegSize {
			if err := sw.flushSegment(false); err != nil {
				sw.err = err
				return written, err
			}
		}
		space := framedSegSize - len(sw.buf)
		take := len(p)
		if take > space {
			take = space
		}
		sw.buf = append(sw.buf, p[:take]...)
		p = p[take:]
		written += take
	}
	return written, nil
}

// flushSegment seals sw.buf as one segment with the given final flag and resets
// the buffer. It writes the header first if needed.
func (sw *sealWriter) flushSegment(final bool) error {
	if err := sw.writeHeader(); err != nil {
		return err
	}
	// No-wrap invariant. Once a segment has been sealed at index math.MaxUint32
	// (the last usable index), the stream is exhausted: any further flush would
	// reuse index 0 (uint32 wrap) and therefore reuse a per-segment nonce. Refuse
	// it unconditionally — this guards both the final and non-final paths and
	// makes nonce-index reuse structurally impossible.
	if sw.exhausted {
		return sealError("framed stream exhausted: a segment was already sealed at index math.MaxUint32; emitting another would wrap the uint32 index and reuse a nonce")
	}
	if sw.index == math.MaxUint32 && !final {
		// A framed stream may contain at most 2^32 segments (indices 0..2^32-1 =
		// math.MaxUint32). A non-final segment at index math.MaxUint32 is refused
		// because the next index would wrap the uint32 back to 0 and reuse a
		// nonce. (A FINAL segment at index math.MaxUint32 is legitimate — it is the
		// last, so no further index is needed.)
		return sealError("framed stream may contain at most 2^32 segments (indices 0..2^32-1 = math.MaxUint32); a non-final segment at index math.MaxUint32 is refused because the next index would wrap")
	}
	nonce := segmentNonce(sw.prefix, sw.index, final)
	block := sw.aead.Seal(nil, nonce, sw.buf, sw.aad)
	if _, err := sw.w.Write(block); err != nil {
		return sealError(fmt.Sprintf("writing framed segment %d: %v", sw.index, err))
	}
	if sw.index == math.MaxUint32 {
		// We just sealed the last legitimately usable index (this is necessarily a
		// final segment, given the non-final guard above). Mark the stream
		// exhausted so no subsequent flush can reuse/wrap the index.
		sw.exhausted = true
	}
	sw.index++
	sw.buf = sw.buf[:0]
	return nil
}

func (sw *sealWriter) Close() error {
	if sw.err != nil {
		return sw.err
	}
	if sw.closed {
		return sealError("double close")
	}
	// Seal whatever is buffered as the FINAL segment. Per the rules:
	//   - empty input: buf is empty, index 0 → one 0-byte final segment.
	//   - exact multiple: the last full buffer was deferred (never flushed with
	//     more data following), so buf holds a full framedSegSize segment now →
	//     marked final (no trailing empty segment).
	//   - otherwise: buf holds the remainder → final.
	if err := sw.flushSegment(true); err != nil {
		sw.err = err
		return err
	}
	sw.closed = true
	return nil
}

// --- streaming open ---

type openReader struct {
	r      io.Reader
	aead   cipher.AEAD
	prefix []byte
	aad    []byte

	index uint32

	// pending holds decrypted plaintext not yet handed to the caller.
	pending []byte
	// next holds the next ciphertext block read ahead (to detect EOF / final).
	next    []byte
	haveNxt bool
	done    bool // final segment already decrypted
	err     error
}

// NewOpenReader parses the framed descriptor and nonce prefix from r, then
// returns an io.Reader that streams the decrypted plaintext. It rejects
// single-shot / unknown-flag blobs. Decryption uses a one-block read-ahead so it
// can mark the correct segment final (the block after which the stream EOFs).
// Truncation (stream ends without a final-flagged segment that verifies),
// reorder, duplication, and tamper all surface as ErrEnvelopeOpen. Malformed
// input never panics.
func NewOpenReader(r io.Reader, key, repoIdentity, objectPath []byte) (io.Reader, error) {
	if err := validateAADFields(repoIdentity, objectPath); err != nil {
		return nil, openError(err.Error())
	}
	// Read and parse the descriptor.
	descBytes := make([]byte, descriptorSize)
	if _, err := io.ReadFull(r, descBytes); err != nil {
		return nil, openError(fmt.Sprintf("reading descriptor: %v", err))
	}
	desc, err := decodeDescriptor(descBytes)
	if err != nil {
		return nil, err
	}
	if desc.Version != envelopeVersion {
		return nil, openError(fmt.Sprintf("unsupported version 0x%02x", desc.Version))
	}
	if desc.Flags&flagFramed == 0 {
		return nil, openError("not a framed envelope (flags bit0 not set); use Open for single-shot")
	}
	if desc.Flags&^flagFramed != 0 {
		return nil, openError(fmt.Sprintf("unsupported flags 0x%02x", desc.Flags))
	}

	// Read the per-stream salt, then derive the framed subkey from the long-term
	// key. The keyref in the descriptor still identifies the long-term key.
	salt := make([]byte, framedSaltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, openError(fmt.Sprintf("reading framed salt: %v", err))
	}
	aead, err := newFramedAEAD(desc.Suite, key, salt)
	if err != nil {
		return nil, openError(err.Error())
	}
	prefixLen, err := noncePrefixLen(aead)
	if err != nil {
		return nil, openError(err.Error())
	}
	prefix := make([]byte, prefixLen)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, openError(fmt.Sprintf("reading nonce prefix: %v", err))
	}

	aad := buildFramedAAD(descBytes, repoIdentity, objectPath, framedSegSize)
	or := &openReader{
		r:      r,
		aead:   aead,
		prefix: prefix,
		aad:    aad,
	}
	// Prime the read-ahead with the first block. A framed stream always has at
	// least one block (even empty plaintext → one final block of tag length), so
	// an empty stream here is truncation.
	if err := or.fill(); err != nil {
		return nil, err
	}
	if !or.haveNxt {
		return nil, openError("truncated framed stream: no segments present")
	}
	return or, nil
}

// blockSize is framedSegSize + tag overhead.
func (or *openReader) blockSize() int { return framedSegSize + or.aead.Overhead() }

// fill ensures or.next holds the next ciphertext block, if one remains. It reads
// up to blockSize bytes: a full read is a (possibly non-final) block; a short
// non-empty read is the final (remainder) block; a clean EOF (zero bytes) means
// the stream is exhausted and leaves haveNxt false. fill does not itself decide
// truncation — callers interpret an empty result in context.
func (or *openReader) fill() error {
	if or.haveNxt {
		return nil
	}
	buf := make([]byte, or.blockSize())
	n, err := io.ReadFull(or.r, buf)
	switch {
	case err == nil:
		// Full block read.
		or.next = buf[:n]
		or.haveNxt = true
		return nil
	case errors.Is(err, io.ErrUnexpectedEOF):
		// Short, non-empty read → final (remainder) block.
		or.next = buf[:n]
		or.haveNxt = true
		return nil
	case errors.Is(err, io.EOF):
		// Clean EOF, zero bytes: stream exhausted. haveNxt stays false.
		return nil
	default:
		return openError(fmt.Sprintf("reading framed segment: %v", err))
	}
}

// decryptNext consumes or.next, decrypting it under the correct index and final
// flag. Finality is decided by read-ahead: a short block is final; a full block
// is final iff no further bytes follow.
func (or *openReader) decryptNext() error {
	if !or.haveNxt {
		return openError("internal: no block to decrypt")
	}
	block := or.next
	or.next = nil
	or.haveNxt = false

	var final bool
	if len(block) < or.blockSize() {
		// Short block → necessarily the final block: a remainder of ≤ blockSize
		// (and a full block would have been read in full). A short block can
		// never be followed by more data in a well-formed stream.
		final = true
	} else {
		// Full block. Peek the next block to learn if this is the last.
		if err := or.fill(); err != nil {
			return err
		}
		final = !or.haveNxt
	}

	if len(block) < or.aead.Overhead() {
		return openError("framed segment too short for AEAD tag")
	}
	nonce := segmentNonce(or.prefix, or.index, final)
	pt, err := or.aead.Open(nil, nonce, block, or.aad)
	if err != nil {
		return openError("framed decryption failed — wrong key, tampered, reordered, or truncated stream")
	}
	or.pending = append(or.pending, pt...)
	or.index++
	if final {
		or.done = true
	}
	return nil
}

func (or *openReader) Read(p []byte) (int, error) {
	if or.err != nil {
		return 0, or.err
	}
	for len(or.pending) == 0 && !or.done {
		if err := or.decryptNext(); err != nil {
			or.err = err
			return 0, err
		}
	}
	if len(or.pending) == 0 && or.done {
		return 0, io.EOF
	}
	n := copy(p, or.pending)
	or.pending = or.pending[n:]
	return n, nil
}

// --- convenience buffer wrappers (thin, over the streaming API) ---

// SealFramed seals plaintext into a framed envelope, returning the whole blob in
// memory. It is a convenience over NewSealWriter for callers that already hold
// the full plaintext; for large data prefer NewSealWriter to avoid buffering the
// entire ciphertext.
func SealFramed(key, plaintext []byte, opts SealOptions) ([]byte, error) {
	var buf bytes.Buffer
	w, err := NewSealWriter(&buf, key, opts)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// sealFramedWithPrefix is the deterministic KAT seam: it seals with a
// caller-supplied salt and nonce prefix so framed wire vectors can be
// regenerated. The public SealFramed always uses a fresh random salt and prefix.
func sealFramedWithPrefix(key, plaintext []byte, opts SealOptions, salt, prefix []byte) ([]byte, error) {
	suite := opts.Suite
	if suite == 0 {
		suite = defaultSuite
	}
	aead, err := newFramedAEAD(suite, key, salt)
	if err != nil {
		return nil, sealError(err.Error())
	}
	var buf bytes.Buffer
	w, err := newSealWriterWithSaltPrefix(&buf, aead, suite, salt, prefix, opts)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// OpenFramed parses and decrypts a whole framed blob in memory, returning the
// plaintext and the parsed descriptor. It rejects single-shot / unknown-flag
// blobs. For large data prefer NewOpenReader.
func OpenFramed(key, blob, repoIdentity, objectPath []byte) ([]byte, Descriptor, error) {
	// Parse the descriptor up front so we can return it even though the streaming
	// reader does not expose it.
	desc, err := decodeDescriptor(blob)
	if err != nil {
		return nil, Descriptor{}, err
	}
	r, err := NewOpenReader(bytes.NewReader(blob), key, repoIdentity, objectPath)
	if err != nil {
		return nil, Descriptor{}, err
	}
	pt, err := io.ReadAll(r)
	if err != nil {
		return nil, Descriptor{}, err
	}
	return pt, desc, nil
}
