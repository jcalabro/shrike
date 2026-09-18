// Command gen produces the deterministic Jetstream v2 golden corpus that the
// Rust segment codec is tested against. It is a maintenance tool, not part of
// the Rust build: the outputs it writes under ../golden are committed, and the
// default Rust tests never require Go or a nearby Jetstream checkout.
//
// Two classes of fixture are produced:
//
//   - The columnar block/segment oracles (golden_block.bin, golden_seal.bin)
//     are copied verbatim from a pinned Jetstream checkout. They are emitted by
//     the reference `segment` package's own golden tests, so they are a genuine
//     independent implementation of the wire format. The event lists those
//     fixtures encode are recorded in manifest.json for cross-language asserts.
//
//   - The dictionary-zstd live frame (live_dict.bin + live_commit.dictzst) is
//     built here with klauspost's structured-dictionary builder — the same
//     builder Jetstream's own live_zstd_test.go uses — so the Rust decoders
//     (native zstd, wasm ruzstd) are exercised against a real RFC 8878 §5
//     dictionary frame produced by an independent encoder.
//
// Usage (offline, from a machine with the module cache populated):
//
//	JETSTREAM_REPO=/path/to/bluesky-social/jetstream \
//	  GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go run .
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	kpdict "github.com/klauspost/compress/dict"
	"github.com/klauspost/compress/zstd"
)

// dictID is the structured-dictionary ID stamped into live_dict.bin. It must be
// nonzero (id 0 is reserved) and is asserted by the Rust dictionary-parse test.
const dictID uint32 = 424242

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	outDir, err := filepath.Abs(filepath.Join("..", "golden"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	manifest := manifest{
		Description: "Jetstream v2 golden corpus for the Shrike Rust segment codec. " +
			"Regenerate with testdata/jetstream/gen. See that program's doc comment.",
		Klauspost: "github.com/klauspost/compress v1.19.2",
		Files:     map[string]string{},
	}

	// 1. Copy the block/segment oracles from the pinned Jetstream checkout.
	repo := os.Getenv("JETSTREAM_REPO")
	if repo == "" {
		return fmt.Errorf("set JETSTREAM_REPO to a bluesky-social/jetstream checkout")
	}
	commit, err := gitCommit(repo)
	if err != nil {
		return err
	}
	manifest.JetstreamCommit = commit

	for _, name := range []string{"golden_block.bin", "golden_seal.bin"} {
		src := filepath.Join(repo, "segment", "testdata", name)
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read %s: %w", src, err)
		}
		if err := writeFixture(outDir, name, data, &manifest); err != nil {
			return err
		}
	}

	// 2. Record the event lists those oracles encode (from the pinned reference
	// golden tests). These drive the Rust cross-language event-for-event asserts.
	manifest.GoldenBlockEvents = goldenBlockEvents()
	manifest.GoldenSealEvents = goldenSealEvents()

	// 3. Build a structured zstd dictionary and one dictionary-compressed
	// proposal-0015 commit frame.
	dict, err := buildDict(dictID)
	if err != nil {
		return err
	}
	if err := writeFixture(outDir, "live_dict.bin", dict, &manifest); err != nil {
		return err
	}
	manifest.LiveDictID = dictID

	plain := []byte(liveCommitFrameJSON(1, "did:plc:abcdefghijklmnopqrstuvwx",
		"app.bsky.feed.post", "3l3qo2vuowo2b"))
	if err := writeFixture(outDir, "live_commit.json", plain, &manifest); err != nil {
		return err
	}

	enc, err := zstd.NewWriter(nil, zstd.WithEncoderDict(dict), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return err
	}
	frame := enc.EncodeAll(plain, nil)
	if err := enc.Close(); err != nil {
		return err
	}
	if err := writeFixture(outDir, "live_commit.dictzst", frame, &manifest); err != nil {
		return err
	}

	// manifest last, so its own hash is never self-referential.
	buf, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	if err := os.WriteFile(filepath.Join(outDir, "manifest.json"), buf, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote golden corpus to %s (jetstream %s)\n", outDir, commit[:12])
	return nil
}

func writeFixture(dir, name string, data []byte, m *manifest) error {
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	sum := sha256.Sum256(data)
	m.Files[name] = hex.EncodeToString(sum[:])
	return nil
}

func gitCommit(repo string) (string, error) {
	cmd := exec.Command("git", "-C", repo, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse in %s: %w", repo, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// buildDict mirrors Jetstream's live_zstd_test.go buildKPDict: a small
// structured dictionary trained on synthetic commit frames, with a chosen ID
// stamped into the little-endian ID field of the RFC 8878 §5 header.
func buildDict(id uint32) ([]byte, error) {
	samples := make([][]byte, 0, 128)
	for i := range 128 {
		frame := liveCommitFrameJSON(uint64(i+1), "did:plc:traindata",
			"app.bsky.feed.post", strings.Repeat("r", i%7+1))
		samples = append(samples, []byte(frame))
	}
	dict, err := kpdict.BuildZstdDict(samples, kpdict.Options{
		MaxDictSize: 8 << 10,
		HashBytes:   6,
		ZstdDictID:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(dict) < 8 {
		return nil, fmt.Errorf("dictionary too short: %d bytes", len(dict))
	}
	binary.LittleEndian.PutUint32(dict[4:8], id)
	return dict, nil
}

// liveCommitFrameJSON reproduces Jetstream's client_test.go helper: a
// proposal-0015 #commit message envelope with a canonical six-fraction-digit
// timestamp.
func liveCommitFrameJSON(seq uint64, did, coll, rkey string) string {
	s := strconv.FormatUint(seq, 10)
	return `{"$type":"message","payload":{"$type":"network.bsky.jetstream.subscribeEvents#commit"` +
		`,"seq":` + s + `,"did":"` + did + `","time":"1970-01-01T00:00:00.000001Z"` +
		`,"rev":"r","operation":"create","collection":"` + coll +
		`","rkey":"` + rkey + `","cid":"bafytest","record":{"$type":"` + coll + `","text":"hi ` + rkey + `"}}}`
}

type manifest struct {
	Description       string            `json:"description"`
	JetstreamCommit   string            `json:"jetstream_commit"`
	Klauspost         string            `json:"klauspost"`
	LiveDictID        uint32            `json:"live_dict_id"`
	Files             map[string]string `json:"sha256"`
	GoldenBlockEvents []goldenEvent     `json:"golden_block_events"`
	GoldenSealEvents  []goldenEvent     `json:"golden_seal_events"`
}

// goldenEvent is the expected decode of one segment row, recorded so the Rust
// tests can assert field-for-field without a Go dependency at test time.
type goldenEvent struct {
	Seq         uint64 `json:"seq"`
	WitnessedAt int64  `json:"witnessed_at"`
	IndexedAt   int64  `json:"indexed_at"`
	Kind        uint8  `json:"kind"`
	DID         string `json:"did"`
	Collection  string `json:"collection,omitempty"`
	Rkey        string `json:"rkey,omitempty"`
	Rev         string `json:"rev,omitempty"`
	PayloadHex  string `json:"payload_hex,omitempty"`
}

// goldenBlockEvents mirrors segment/block_golden_test.go goldenEvents().
func goldenBlockEvents() []goldenEvent {
	return []goldenEvent{
		{Seq: 1, WitnessedAt: 1700000000_000000, IndexedAt: 0, Kind: 1,
			DID: "did:plc:abcdefghijklmnopqrstuvwx", Collection: "app.bsky.feed.post",
			Rkey: "3l3qo2vuowo2b", Rev: "3l3qo2vutsw2b", PayloadHex: "a16568656c6c6f05"},
		{Seq: 2, WitnessedAt: 1700000001_000000, IndexedAt: 1700000000_500000, Kind: 4,
			DID: "did:web:example.com"},
		{Seq: 3, WitnessedAt: 1700000002_000000, IndexedAt: 0, Kind: 3,
			DID: "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz", Collection: "app.bsky.feed.like",
			Rkey: "3l3qo2vuowo2c", Rev: "3l3qo2vutsw2c"},
	}
}

// goldenSealEvents mirrors the two-event list sealed in segment/seal_test.go.
func goldenSealEvents() []goldenEvent {
	return []goldenEvent{
		{Seq: 1, WitnessedAt: 100, IndexedAt: 0, Kind: 1, DID: "did:plc:a",
			Collection: "app.bsky.feed.post", Rkey: "k1", Rev: "v1", PayloadHex: "7031"},
		{Seq: 2, WitnessedAt: 200, IndexedAt: 250, Kind: 1, DID: "did:plc:b",
			Collection: "app.bsky.feed.like", Rkey: "k2", Rev: "v2", PayloadHex: "7032"},
	}
}
