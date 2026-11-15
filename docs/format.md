# snap format 1.0

Status: normative for 1.0.0-rc.2. This document is the byte contract for the
container and the journal. It replaces the draft that shipped with 1.0.0-rc.1,
which is kept as [`format-rc1.md`](format-rc1.md) for reference only.

Scope: an immutable, memory-mappable container for a prefix trie with arbitrary
values, an append-only journal for building one incrementally, and the rules a
reader must apply before it answers. What a section's bytes mean is named by the
value type; this document says where they are and how they are covered.

## 1. What the object is

```text
HEADER 192 B (fixed, one read identifies the object)
SECTION TABLE at 192, one 64 B entry per section
SECTIONS, packed in ascending id order, each starting on a 16-byte boundary
```

No META, no footer, no JSON, no projection, no body hash.

### Header, field by field

`created_at`, `content_id` and the crc sit after the hashed prefix, so the hash
input is one contiguous range `0..148` with no field-order puzzle.

| offset | size | field | why it cannot be deleted |
| --- | --- | --- | --- |
| 0 | 8 | magic `BGPKSNAP` | without it any byte stream parses |
| 8 | 2 | major | a future body read as v4 frames parses but means something else |
| 10 | 2 | flags | bit 0 has stream coordinates, bit 1 has a coverage window; the only place to add an optional feature without a major bump |
| 12 | 16 | tree_id | replay must refuse a snapshot of another tree |
| 28 | 16 | generation | without it a restore or fork reuses `(tree_id, seq)` |
| 44 | 8 | base_seq | replay would start from the wrong record |
| 52 | 32 | type_id | a trie read with the wrong value interpretation answers wrongly |
| 84 | 8 | file_len | distinguishes "ends here" from "trailing bytes appended" |
| 92 | 4 | section_count | bounds the table |
| 96 | 4 | section_table_len | `64 * section_count`, so a reader can range-read exactly the table and detect a mismatch |
| 100 | 16 | window `[i64; 2]`, unix seconds UTC | "is this value still valid" cannot be recovered from the data |
| 116 | 32 | reserved | zero; keeps the hashed prefix 148 bytes long |
| 148 | 8 | created_at, unix seconds UTC | operational ordering; deliberately outside the hash |
| 156 | 32 | content_id | dedup and "is this the object I asked for"; cannot hash itself |
| 188 | 4 | crc32c over bytes `0..188` | covers the header bytes the hash cannot: `content_id` and `created_at` |

Every integer in the header and the table is little-endian.

`HASH_END` = 148. Everything before it is a claim about the data and is hashed;
the three tail fields are bookkeeping. The header crc is computed over
`header[0..188]`, that is every byte before the crc field itself.

### Section table entry, 64 B

```text
 0  id u16          which section
 2  kind u32        'V4\0\0' / 'V6\0\0' / 'PAY\0' / anything a profile defines
 6  flags u16       bit 0 required: a reader that does not know this id must refuse
 8  len u64         section length; no offset, it is computed by packing
16  reserved [48]   zero
```

Offsets are computed: sections are packed in ascending id order, each starting at
the first 16-byte boundary at or after the previous end. Nothing to disagree
about, one less field to lie. The bytes skipped to reach that boundary are zero,
and a reader refuses an object where they are not, because two writers must agree
on what they emit even though the padding is outside the content id.

No per-section hashes. `content_id` covers every section, so a corrupt object is
caught at open; locating which section is damaged is not a requirement anyone has
demonstrated, and it costs 32 B per section plus a rule about which bytes they
cover.

### Identity

```text
content_id = blake3( "bgpkit-snap-v4\0"
                   || header[0..148]          (created_at excluded by placement)
                   || table bytes
                   || every section's bytes, ascending id )
```

The header prefix is a contiguous range, so there is no "which fields are
excluded" ambiguity: `created_at` lives after the prefix, `content_id` and the
crc live after it too.

## 2. Reference API

This section describes the Rust crate, not the bytes. Another implementation is
free to expose the same object differently; what it must not do is accept or emit
bytes that disagree with sections 1 and 3.

```rust
pub trait SnapValue: Archive + Clone + Serialize<HighSer> {
    const TYPE_ID: &str;
    fn canonicalize(&mut self) {}          // default: no-op
}

pub struct Opts<'a> {
    pub created_at: i64,        // unix seconds; Opts::now() for the current time
    pub stream: Option<StreamRef>,          // tree_id, generation, base_seq
    pub window: Option<(i64, i64)>,
    pub extras: &'a [ExtraSection],         // id, kind, required, bytes
}

pub struct ExtraSection<'a> { pub id: u16, pub kind: [u8;4], pub required: bool, pub bytes: &'a [u8] }

Writer::<T>::new()
Writer::insert(prefix, value)               // replaces an existing value
Writer::len()
Writer::finish(&Opts) -> Result<Vec<u8>>    // caller writes the file
Writer::finish_to(path, &Opts) -> Result<u64>

Snapshot::<T>::open(path)                   // takes any AsRef<Path>
Snapshot::<T>::open_with(path, &dyn Validator)
Snapshot::<T>::from_bytes(&[u8])            // and from_bytes_with
Writer::finish_to(path, &opts) -> u64        // or writes them, atomically

// longest-prefix lookups
Snapshot::search(ip: IpAddr) -> Option<(IpNet, &T::Archived)>
Snapshot::search_owned(ip: IpAddr) -> Option<(IpNet, T)>   // deserialized
Snapshot::get_exact(prefix) -> Option<&T::Archived>
Snapshot::get_exact_owned(prefix) -> Option<T>

// the prefix_trie read API, with IpNet keys and no family match in the caller
Snapshot::get_key_value(prefix) -> Option<(IpNet, &T::Archived)>
Snapshot::contains_key(prefix) -> bool
Snapshot::lpm(prefix) -> Option<(IpNet, &T::Archived)>           // most specific cover
Snapshot::lpm_prefix(prefix) -> Option<IpNet>
Snapshot::spm(prefix) -> Option<(IpNet, &T::Archived)>           // least specific cover
Snapshot::spm_prefix(prefix) -> Option<IpNet>
Snapshot::is_covered(prefix) -> bool
Snapshot::is_covered_in_aggregate(prefix) -> bool
Snapshot::iter() -> Iterator<(IpNet, &T::Archived)>              // v4 then v6
Snapshot::iter_from(prefix, inclusive) -> Iterator<...>
Snapshot::keys() -> Iterator<IpNet>
Snapshot::children(prefix) -> Vec<(IpNet, &T::Archived)>         // prefix plus subtree
Snapshot::cover(prefix) -> Vec<(IpNet, &T::Archived)>
Snapshot::section_bytes(id) -> Option<&[u8]>
Snapshot::header() -> &Header

pub trait Validator {
    // asked at open only about a required section the reader does not implement;
    // answering false refuses the object and names its id
    fn knows(&self, entry: &Entry) -> bool;
    // cross-section checks, run once at open before any value is handed out
    fn validate(&self, view: &SnapshotView<'_>) -> Result<(), Error>;
}
```

`WIDTH` is gone: it was an invariant callers could get wrong and nothing consumed
it. `replay`, sequence numbers, generations and the writer lock are not public
API; the journal owns them.

### What a family section holds

The container contract above is independent of what a section's bytes mean; the
`type_id` names the value type and, with it, the encoding of the family sections.
For the value types this crate defines, a family section is an
`rkyv 0.8` archive, with `little_endian`, `std`, `bytecheck` and `aligned`, of
`prefix_trie` 0.10's `PrefixMap<Ipv4Net, T>` or `PrefixMap<Ipv6Net, T>`, where `T`
is the profile's own archive type. The layout of that archive is rkyv's, not
this document's.

An implementation that cannot decode that layout must refuse the object and say
so; it must not guess, and it must not treat the section as empty. Reading the
header, the table, the identity and the journal framing needs none of this, so a
tool that only inspects objects is unaffected.

### Section ids

| id | kind | meaning |
| --- | --- | --- |
| 2 | `V4` | the IPv4 trie archive |
| 3 | `V6` | the IPv6 trie archive |
| 16 and up | caller | this profile's own sections |

A section whose kind is `V4` is at id 2 and a section whose kind is `V6` is at
id 3. A reader rejects any other pairing rather than ignoring the section,
because ignoring it turns a disagreement into an empty answer.

## 3. Journal

One owner: `Journal<T>` holds the live tree, the blob arena, the segment writer,
the writer lock and the directory, and it recovers on open.

```rust
Journal::<T>::open(dir, tree_id, Option<PayloadSection>) -> Result<Journal<T>>
journal.insert(prefix, &value)                  // updates the tree and the log
journal.insert_with_blob(prefix, &value, &blob) // also appends blob to the arena
journal.withdraw(prefix)
journal.sync()                                  // durable on return
journal.checkpoint(&opts) -> Result<PathBuf>     // verified before pruning, publishes current.snap
journal.adopt_checkpoint(file) -> Result<u64>    // repair when state.json was lost
journal.len()
```

### Journal bytes

A journal is a directory: `writer.lock`, `state.json`,
`segment-<12-digit index>.log` and `snapshot-<seq>.snap`. The
`type_id` is ASCII, NUL-terminated, zero-filled to 32 bytes; a reader refuses a
field without a terminator or with non-printable bytes. Reserved and padding
bytes are zero. Segment names are the
decimal index zero-padded to twelve digits, so lexicographic order is numeric
order; a reader that sorted `segment-1.log` and `segment-10.log` as strings would
replay them out of order and refuse the journal.

A segment starts with a 48-byte header, its integers in little endian:

| offset | size | field |
| --- | --- | --- |
| 0 | 8 | magic `BGPKLOG\0` |
| 8 | 2 | version, 4 |
| 10 | 2 | flags, 0 |
| 12 | 16 | tree id |
| 28 | 16 | generation |
| 44 | 4 | reserved, zero |

A record is framed `len u32 | crc32c u32 | payload`, every integer in little
endian. `len` counts the crc field and the payload. `crc32c` covers the payload
only. The payload is:

| offset | size | field |
| --- | --- | --- |
| 0 | 8 | sequence number |
| 8 | 8 | receive time, unix seconds |
| 16 | 8 | event time, unix seconds |
| 24 | 1 | kind: 1 insert, 2 withdraw |
| 25 | 1 | family: 4 or 6 |
| 26 | 1 | prefix length |
| 27 | 1 | flags, 0 |
| 28 | 16 | address in network order; IPv4 in bytes 0..4, bytes 4..16 zero |
| 44 | 4 | value length |
| 48 | value length | value, the profile's archive bytes |
| 48 + value length | 4 | blob length |
| 52 + value length | blob length | blob |

Replay stops at the first frame whose length runs past the file or whose crc
does not match: that is a torn tail, and the records after it are not trusted.
A record may be skipped only because a checkpoint already covers its sequence
number. Any other disagreement between the expected number and the number found
is an error: a hole in the middle of a journal is data loss, and a reader that
skipped it would answer from a smaller tree than the writer committed. A torn
frame at the end of a segment is the one case where the writer may keep going:
the bytes were never acknowledged, so the next append cuts them away and writes
the same sequence number again in the same segment, and nothing after the tear is
read. A
segment whose crc fails therefore cannot be followed by a later segment that
replays as if nothing were missing.

A `state.json` that exists but cannot be read is an error, never an absent
state: silently treating it as absent would reset `next_seq` and could overwrite
a live checkpoint. The checkpoint named by the state file must carry the same
tree id and generation as the journal it belongs to, or recovery refuses it.

`insert_with_blob` requires a payload section: a blob exists to back one, and
without it the bytes would be written to the segment and dropped by the next
checkpoint.

`state.json` is the commit record: `next_seq`, `tree_id`, `generation` and,
once a checkpoint exists, `checkpoint: {seq, file}`. It is written atomically
after an fsync of the segment or the snapshot, so a checkpoint can only be
named by a state file that survived.

Recovery order: load the named checkpoint, replay records above its sequence
number, refuse to hand out a number at or below `next_seq`, and prune a segment
only when every record in it is covered by a checkpoint.

Test vector, two records and a checkpoint:

```text
header  4247504b4c4f47000400000011111111111111111111111111111111
        2222222222222222222222222222222200000000
record  3c000000e8faa880 0100000000000000 0000000000000000 0000000000000000
        01 04 08 00 0a000000 000000000000000000000000 04000000 07000000
        00000000
record  4300000037180cdd 0200000000000000 0000000000000000 0000000000000000
        01 04 18 00 c0000200 000000000000000000000000 04000000 09000000
        07000000 7061796c6f6164
state   {"checkpoint":{"file":"snapshot-3.snap","seq":2},
        "generation":"22222222222222222222222222222222",
        "next_seq":3,"tree_id":"11111111111111111111111111111111"}
```

`examples/journal_vector.rs` regenerates these bytes; it passes the generation
explicitly (`Journal::open_with`), so the vector is the same on every run rather
than carrying whatever the journal minted.

## 4. Conformance

A conforming writer emits the bytes described above. A conforming reader refuses
anything else, and never returns a value it could not verify.

Two byte-pinned artifacts make drift detectable:

- **Golden object.** A tree with `10.0.0.0/8 → 1`, `10.1.0.0/16 → 2`,
  `192.0.2.0/24 → 3`, `2001:db8::/32 → 4`, `created_at` 2026-11-14T00:00:00Z and
  window `[1790000000, 1794355200]`, with the profile type
  `golden.v:v1`, is 612 bytes, blake3
  `d0ed63727b2d9212492b09f78bb652b9eba754b004815e0c792f1b238a9b9925`, content id
  `1a808769533d26aca6d24c918e21094e0842cfc7f14ebf270c71f58d1538224f`, and the
  same bytes for any insertion order.
- **Journal vector.** The two-record segment and state file printed in section 3,
  regenerated by `examples/journal_vector.rs` with an explicit generation.

The implementation's own test suite is listed under "Development" in the README;
those file names are not part of this contract.

## 5. Design notes: what the 1.0.0-rc.1 draft had, and why it is gone

This section is not normative. It records the reasoning so a future reader does
not reintroduce what was measured to be useless.

- META and the projection: redundant once the header is the claim and rkyv
  validation is the proof; it existed to cross-check itself.
- Footer: the file is immutable, so "append at the end" was never used, and a
  tail range read is worse on object storage than a read at offset 192.
- Per-section hashes: `content_id` covers every section.
- `WIDTH`, `type_id_len`, `minor`, `header_len`, `table_off`, per-entry offsets.
- Public `replay`, caller-supplied stream identity, `verify_checkpoint_binding`.

Kept despite advice to delete: `kind` in the table. Family confusion is a
measured failure (an IPv4 archive read as IPv6 validates and returns wrong
networks), and four bytes per section is the cheapest place to stop it.
