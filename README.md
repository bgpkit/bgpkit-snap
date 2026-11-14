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
use bgpkit_snap::{Opts, SnapValue, Snapshot, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct RoaSet(Vec<u32>);

impl SnapValue for RoaSet {
    const TYPE_ID: &str = "example.roa-set:v1";
    fn canonicalize(&mut self) { self.0.sort_unstable(); }
}

// build, then write the bytes yourself
let mut w: Writer<RoaSet> = Writer::new();
w.insert("10.0.0.0/8".parse()?, RoaSet(vec![64512]));
let bytes = w.finish(&Opts {
    created_at: "2026-11-14T00:00:00Z",
    window: None,
    stream: None,
    extras: &[],
})?;
std::fs::write("example.snap", &bytes)?;

// read: one open verifies the whole object
let snap: Snapshot<RoaSet> = Snapshot::open("example.snap")?;
let (prefix, value) = snap.search("10.1.2.3".parse()?).ok_or("not covered")?;
println!("{prefix} -> {} origins, id {}", value.0.len(), snap.content_id());
```

`examples/quickstart.rs` is this code, compiled by `cargo build --examples`, so
the README cannot drift from the API.

A reader identifies an object from its first 192 bytes, without touching the
body:

```rust
let raw = std::fs::read("example.snap")?;
let header = bgpkit_snap::Header::parse(&raw[..192])?;
println!("{} sections, type {}", header.section_count, header.type_id_str());
```

The CLI does the same from a shell (install it with
`cargo install bgpkit-snap --features cli`):

```sh
snap build prefixes.jsonl --out example.snap --created-at 2026-11-14T00:00:00Z
snap info example.snap      # reads 192 bytes only
snap verify example.snap    # full integrity check
snap search example.snap 10.1.2.3
```

## The format

The normative contract is [`docs/v4-proposal.md`](docs/v4-proposal.md). Short
version:

```text
header (192 B)   magic, version, flags, tree_id, generation, base_seq,
                 type_id, file_len, section_count, table_len, window,
                 created_at, content_id, crc32c
table  (64 B per section)  id, kind, required, len; offsets are computed
sections         packed in ascending id order, 16-byte aligned
```

- `content_id` hashes `header[0..148]`, the table and every section. `created_at`,
  `content_id` and the crc sit after that range, so the hash input is contiguous.
- There is no metadata section and no footer: the header is the claim, and
  checked rkyv access is the proof.
- A section the reader does not know and that the writer marked required is
  refused, by id, unless the caller registers a `Validator` for it.

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
