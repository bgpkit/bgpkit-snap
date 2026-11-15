# bgpkit-snap

A versioned, single-file container for prefix tries, plus an append-only journal
for building one incrementally.

`bgpkit-snap` stores a map from IP prefixes to arbitrary values in a single
immutable file that is read once, validated once, and then queried in memory
without parsing. The same
data built in any insertion order produces byte-identical files, so an object's
identity is a hash of its content. A journal turns a live, mutable tree into the
next snapshot without losing updates.

Status: **1.0.0-rc.3**. The layout is frozen for release candidates; see
[Scope](#scope-and-what-this-is-not) and [Known limitations](#known-limitations)
before depending on it.

The normative byte contract is [`docs/format.md`](docs/format.md). The draft that
shipped with 1.0.0-rc.1 is kept as
[`docs/format-rc1.md`](docs/format-rc1.md) for reference only.

## Scope and what this is not

What this crate contributes, and what a reader can rely on:

- **An object is identifiable and verifiable from its first 192 bytes plus one
  hash.** Type, tree, coverage window, section count, file length and content id
  are in the header; the content id covers the header prefix, the section table
  and every section. This part is language-neutral: a Go, Python or JS tool can
  read and check it without this crate.
- **Recovery never answers with less than the writer committed.** The journal's
  commit record, strict sequence adjacency, checkpoint identity checks and torn
  tail rule are documented in [`docs/format.md`](docs/format.md) and covered by
  tests, including a 400-operation random sequence that must survive a restart.
- **Negative results, with measurements.** IPv4 mapped into an IPv6 trie costs
  twice the size and 3.8x the lookup time; per-section hashes were not worth
  their bytes; a metadata section duplicated what the header and rkyv validation
  already prove; a family tag is required because an IPv4 archive read as IPv6
  validates and returns wrong prefixes.

What it does not provide:

- **A portable trie encoding.** A family section is an `rkyv` archive of a
  `prefix_trie` map, pinned by version. Reading or writing one outside Rust means
  reimplementing that layout. The container rules are portable; the payload is
  not.
- **A query engine, a database, or cross-language bindings.** There is no query
  language, no transactions across objects, no in-place update path, and no
  partial reads.

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
    created_at: 1_794_614_400,   // unix seconds; Opts::now() for "now"
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
let mut head = [0u8; 192];
std::io::Read::read_exact(&mut std::fs::File::open("example.snap")?, &mut head)?;
let header = bgpkit_snap::Header::parse(&head)?;
println!("{} sections, type {}", header.section_count, header.type_id_str());
```

The CLI does the same from a shell (install it with
`cargo install bgpkit-snap --features cli`). It builds and searches `snap.u32:v1`
objects only, from a JSONL file of `{"prefix": "10.0.0.0/8", "value": 7}` lines:

```sh
snap build prefixes.jsonl --out example.snap --created-at 1794614400
snap info example.snap      # reads 192 bytes only
snap verify example.snap    # container, and bodies when the type is this binary's
snap search example.snap 10.1.2.3
```

## The format

The normative contract is [`docs/format.md`](docs/format.md). Short version:

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
- Bytes the document fixes to zero are checked, not assumed: padding, the type id
  tail, the reserved header block, a section entry's tail, a record's flags, the
  twelve bytes behind an IPv4 address, and a segment header's version, flags and
  reserved word.

## Journal

```text
segments   segment-<12-digit index>.log, 48-byte header with tree_id + generation,
           length + crc32c framed records, dense sequence numbers
state      state.json: next sequence, identity, and the checkpoint it belongs to
checkpoint snapshot-<seq>.snap, verified against the live tree before it is named
```

`sync` makes a record durable. `checkpoint` builds an ordinary object, verifies it
end to end, writes it, and only then records it in `state.json` and prunes the
segments it fully covers. A restart loads that checkpoint, replays the records
above it, and refuses to hand out a sequence number that was already committed.

A torn tail is the one tolerated failure: those bytes were never acknowledged, so
the next append cuts them away and reuses the number. Everything else (a hole, an
unreadable segment header, an unreadable or malformed `state.json`, a checkpoint
from another tree or generation) is an error rather than a smaller tree.

## Known limitations

1. **One consumer.** The crate is used by `wayback-rpki` for its ROA index. It
   has no other in-tree user yet, and no external user. The API is shaped by that
   one workload.
2. **Trie bodies are rkyv.** See above. A change in `rkyv` or `prefix-trie`'s
   archived layout is a format change; the golden object test exists to make that
   failure loud rather than silent.
3. **`content_id` excludes `created_at`.** Two objects with the same data and
   different creation times share an id. That is deliberate (identity is content),
   but it means the id does not name a byte sequence.
4. **No partial or ranged reads.** A reader validates the whole object at open,
   which is what makes later answers cheap; an object larger than the address
   space a reader accepts is rejected rather than partially served.

## Building

Rust 1.88 or newer. `cargo test --features cli` runs everything including the CLI tests. `cargo test` runs the suite, including a golden object that
fails if the archived layout of `prefix-trie` or `rkyv` ever drifts.

## License

MIT, see [LICENSE](LICENSE).
