// Package casket — framed (streaming) at-rest envelope.
//
// The framed mode seals an arbitrarily large blob without holding the whole
// plaintext (or ciphertext) in memory. It uses the standard STREAM construction
// (Hoang–Reyhanitabar–Rogaway–Vizár, as deployed by age and Google Tink): the
// plaintext is split into fixed-size segments, each segment is AEAD-sealed under
// a per-segment nonce derived from a random prefix plus a 32-bit counter, and the
// final segment is marked with a distinct nonce flag byte. This binds segment
// order (the counter) and stream termination (the final flag) into the nonce, so
// reorder, truncation, duplication, and splice are all rejected by AEAD
// verification — no separately-authenticated length field is needed.
//
// Wire format (framed):
//
//	blob = DESCRIPTOR(20 bytes, flags bit0 set) || BODY
//	BODY = noncePrefix(nonceSize-5 bytes) || block_0 || block_1 || ... || block_last
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
// AAD: the *same* message-level AAD is authenticated for every segment:
//
//	AAD = descriptor(20B)
//	   || uint16be(len(repoIdentity)) || repoIdentity
//	   || uint16be(len(objectPath))   || objectPath
//
// (reuse buildAAD). Segment position is bound by the nonce counter and stream
// termination by the final flag, so the AAD need not vary per segment.
//
// Segmentation rules (identical between seal and open):
//
//   - Plaintext is split into framedSegSize-byte segments; the last is the
//     remainder. L==0 → exactly one 0-byte (final) segment. L>0 and L%S==0 →
//     L/S segments, the last a full S-byte segment marked final (no trailing
//     empty segment). Otherwise ceil(L/S) segments. Only the last is final.
//   - segmentCount must not exceed math.MaxUint32.
//
// Open derives boundaries from the body length: with blockSize = framedSegSize+16,
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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// framedSegSize is the fixed plaintext segment size (64 KiB). It is an unexported
// package var, not a const, so tests can shrink it to exercise multi-segment
// behaviour cheaply without changing the shipped wire format. Production code
// MUST NOT mutate it.
var framedSegSize = 65536

// framed nonce layout: ...prefix... || uint32be(counter) || finalFlag(1 byte).
const (
	framedCounterSize = 4 // uint32 big-endian segment index
	framedFlagSize    = 1 // final-segment flag
	framedSuffixSize  = framedCounterSize + framedFlagSize

	framedFinalFlag    byte = 0x01
	framedNonFinalFlag byte = 0x00
)

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
	prefix []byte // nonce prefix (nonceSize-5 bytes)
	aad    []byte // message-level AAD (constant across segments)

	buf     []byte // pending plaintext, < framedSegSize once a segment is flushed
	index   uint32 // next segment index to emit
	started bool   // header (descriptor + prefix) written
	closed  bool
	err     error // sticky error
}

// NewSealWriter returns an io.WriteCloser that seals everything written to it as
// a framed envelope written to w, using the STREAM construction. The descriptor
// (framed flag set) and random nonce prefix are written on the first flush. Each
// time the internal buffer fills to framedSegSize a non-final segment is sealed
// and written; Close seals the remaining buffer as the final segment (handling
// empty and exact-multiple inputs per the segmentation rules). Close is
// idempotent-safe in that a second call returns an error rather than corrupting
// output. Key length and AAD fields are validated up front.
func NewSealWriter(w io.Writer, key []byte, opts SealOptions) (io.WriteCloser, error) {
	suite := opts.Suite
	if suite == 0 {
		suite = defaultSuite
	}
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, sealError(err.Error())
	}
	if err := validateAADFields(opts.RepoIdentity, opts.ObjectPath); err != nil {
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
	return newSealWriterWithPrefix(w, aead, suite, prefix, opts)
}

// newSealWriterWithPrefix is the deterministic seam used by NewSealWriter and by
// KAT helpers: it takes a caller-supplied nonce prefix instead of a random one.
func newSealWriterWithPrefix(w io.Writer, aead cipher.AEAD, suite Suite, prefix []byte, opts SealOptions) (io.WriteCloser, error) {
	if err := validateAADFields(opts.RepoIdentity, opts.ObjectPath); err != nil {
		return nil, sealError(err.Error())
	}
	prefixLen, err := noncePrefixLen(aead)
	if err != nil {
		return nil, sealError(err.Error())
	}
	if len(prefix) != prefixLen {
		return nil, sealError(fmt.Sprintf("nonce prefix must be %d bytes for suite 0x%02x, got %d", prefixLen, byte(suite), len(prefix)))
	}
	desc := framedDescriptor(suite, opts)
	aad := buildAAD(desc.encode(), opts.RepoIdentity, opts.ObjectPath)
	return &sealWriter{
		w:      w,
		aead:   aead,
		prefix: append([]byte(nil), prefix...),
		aad:    aad,
		buf:    make([]byte, 0, framedSegSize),
	}, nil
}

// writeHeader emits descriptor + nonce prefix on first use. The descriptor bytes
// are exactly the first descriptorSize bytes of the AAD, so they are reused here
// to guarantee the on-wire header and the authenticated descriptor are identical.
func (sw *sealWriter) writeHeader() error {
	if sw.started {
		return nil
	}
	header := make([]byte, 0, descriptorSize+len(sw.prefix))
	header = append(header, sw.aad[:descriptorSize]...)
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
	if sw.index == math.MaxUint32 && !final {
		// Sealing this non-final segment would require a further index beyond
		// MaxUint32 for the next one; refuse before overflow.
		return sealError("segment count exceeds math.MaxUint32")
	}
	nonce := segmentNonce(sw.prefix, sw.index, final)
	block := sw.aead.Seal(nil, nonce, sw.buf, sw.aad)
	if _, err := sw.w.Write(block); err != nil {
		return sealError(fmt.Sprintf("writing framed segment %d: %v", sw.index, err))
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

	aead, err := newAEAD(desc.Suite, key)
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

	aad := buildAAD(descBytes, repoIdentity, objectPath)
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
// caller-supplied nonce prefix so framed wire vectors can be regenerated. The
// public SealFramed always uses a fresh random prefix.
func sealFramedWithPrefix(key, plaintext []byte, opts SealOptions, prefix []byte) ([]byte, error) {
	suite := opts.Suite
	if suite == 0 {
		suite = defaultSuite
	}
	aead, err := newAEAD(suite, key)
	if err != nil {
		return nil, sealError(err.Error())
	}
	var buf bytes.Buffer
	w, err := newSealWriterWithPrefix(&buf, aead, suite, prefix, opts)
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
