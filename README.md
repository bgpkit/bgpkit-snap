# bgpkit-snap

A versioned, memory-mappable container for prefix tries, plus an append-only
journal for building one incrementally.

`bgpkit-snap` stores a map from IP prefixes to arbitrary values in a single
immutable file that can be memory-mapped and queried without parsing. The same
data built in any insertion order produces byte-identical files, so an object's
identity is a hash of its content. A journal turns a live, mutable tree into the
next snapshot without losing updates.

Status: **1.0-rc1**. The layout is frozen for release candidates; see
[Known limitations](#known-limitations) before depending on it.

## What it is for

- A sidecar index that answers "which prefix covers this address" from a file on
  disk or in object storage, without loading a database.
- A daily snapshot of routing or RPKI state that can be shipped as a single
  object, deduplicated by content id, and diffed against yesterday's.
- A live feed that is checkpointed to immutable objects while queries keep
  running against the current one.

It is not a database: there is no query language, no transactions across
objects, and no in-place update path. Changing a snapshot means building a new
one, which is what makes the file safe to share and cheap to verify.

## Quick start

```rust
use bgpkit_snap::{Snapshot, Writer};

// build
let mut w = Writer::<u32>::new();
w.insert("10.0.0.0/8".parse()?, 1);
w.insert("2001:db8::/32".parse()?, 2);
let bytes = w.finish("2026-11-13T00:00:00Z", "my-source")?;
std::fs::write("example.snap", &bytes)?;

// read
let snap: Snapshot<u32> = Snapshot::open("example.snap")?;
assert_eq!(snap.search("10.1.2.3/32".parse()?).map(|(p, _)| p.to_string()), Some("10.0.0.0/8".into()));
println!("{} prefixes, id {}", snap.len(), snap.content_id());
```

A reader identifies an object from its first 192 bytes, without touching the
body:

```rust
let header = bgpkit_snap::Header::parse(&std::fs::read("example.snap")?[..192])?;
println!("{} prefixes, type {}, stream {:?}", header.count_v4, header.type_id, header.base_seq);
```

The CLI does the same from a shell (install it with `cargo install bgpkit-snap --features cli`):

```sh
snap build --input prefixes.jsonl --out example.snap --created-at 2026-11-13T00:00:00Z --source my-source
snap info example.snap      # reads 192 bytes only
snap verify example.snap    # full integrity check
snap search example.snap 10.1.2.3/32
```

## The format

The normative contract is [`docs/format.md`](docs/format.md). Short version:

```text
header (192 B)   magic, version, tree_id, generation, content_id, type_id,
                 base_seq, sizes, counts, families, event window, crc32c
sections         META (canonical JSON), TRIE_V4, TRIE_V6, 16-byte aligned
footer           section table with per-section blake3, then body hash
```

- `content_id` hashes the data projection and every non-META section. Provenance
  is deliberately outside it: the same prefixes from two paths get one id, so
  object storage deduplicates them.
- The header is a projection of META and a reader rejects any disagreement, so a
  spliced header cannot describe another object.
- A stream object carries `tree_id`, `generation`, and `base_seq`; that triple,
  not the content id, identifies a live state.

## Journal

```text
segments   segment-<n>.log, 48-byte header with tree_id + generation,
           length+crc32c framed records, dense sequence numbers
checkpoint snapshot + checkpoint.json, verified against each other
state      state.json: the next sequence, written after the segment fsync
```

A torn tail ends its segment and is reported, never applied. A restart resumes
after the highest record on disk, so sequence numbers are never reissued, even
after a crash between an append and a checkpoint.

## Known limitations

One deliberate gap remains at 1.0-rc1, plus two items for 1.0 final:

1. A torn segment tail is reported and left in place, not truncated. Truncating
   it would require tolerating a sequence gap at that boundary, which would also
   hide a genuinely lost segment; leaving the bytes makes the tear visible and
   keeps the gap check strict.
2. Segment header `major`/`minor` and record `flags` are not checked yet.
3. Values inside a projection are validated for canonical form and for
   integer-or-ASCII leaves, but the check walks the parsed document rather than
   the bytes, so a producer with a different JSON writer must rely on the
   re-serialization check to catch it.

## Building

Rust 1.88 or newer. `cargo test --features cli` runs everything including the CLI tests. `cargo test` runs the suite, including a golden object that
fails if the archived layout of `prefix-trie` or `rkyv` ever drifts.

## License

MIT, see [LICENSE](LICENSE).
