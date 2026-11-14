# bgpkit-snap v4: one container, no metadata section

Status: implementation underway. Supersedes v3 (which the panel held) and
1.0.0-rc.1 (published, no consumers). Owner decisions that shape everything here:

- adding a value type must not require a change to this crate
- the design must not feel over complicated; anything undemonstrated is deleted
- the format may break freely until something depends on it

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
| 100 | 16 | window `[i64; 2]` | "is this value still valid" cannot be recovered from the data |
| 116 | 32 | reserved | zero; keeps the hashed prefix 148 bytes long |
| 148 | 8 | created_at | operational ordering; deliberately outside the hash |
| 156 | 32 | content_id | dedup and "is this the object I asked for"; cannot hash itself |
| 188 | 4 | crc32c | covers the header bytes the hash cannot: `content_id` and `created_at` |

`HASH_END` = 148. Everything before it is a claim about the data and is hashed;
the three tail fields are bookkeeping.

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
about, one less field to lie.

No per-section hashes. `content_id` covers every section, so a corrupt object is
caught at open; locating which section is damaged is not a requirement anyone has
demonstrated, and it costs 32 B per section plus a rule about which bytes they
cover.

### Identity

```text
content_id = blake3( "bgpkit-snap-v4\0"
                   || header[0..152]          (created_at excluded by placement)
                   || table bytes
                   || every section's bytes, ascending id )
```

The header prefix is a contiguous range, so there is no "which fields are
excluded" ambiguity: `created_at` lives after the prefix, `content_id` and the
crc live after it too.

## 2. Library surface

```rust
pub trait SnapValue: Archive + Clone + Serialize<HighSer> {
    const TYPE_ID: &str;
    fn canonicalize(&mut self) {}          // default: no-op
}

pub struct Opts<'a> {
    pub created_at: &'a str,
    pub stream: Option<StreamRef>,          // tree_id, generation, base_seq
    pub window: Option<(i64, i64)>,
    pub extras: &'a [ExtraSection],         // id, kind, required, bytes
}

pub struct ExtraSection<'a> { pub id: u16, pub kind: [u8;4], pub required: bool, pub bytes: &'a [u8] }

Writer::<T>::new()
Writer::insert(prefix, value)               // replaces an existing value
Writer::len()
Writer::finish(&Opts) -> Result<Vec<u8>>    // caller writes the file

Snapshot::<T>::open(path)                   // refuses unknown required sections
Snapshot::<T>::open_with(path, &dyn Validator)
Snapshot::<T>::from_bytes(&[u8])            // and from_bytes_with
Snapshot::search(ip: IpAddr) -> Option<(IpNet, &T::Archived)>
Snapshot::children(prefix) -> iterator over the subtree
Snapshot::section_bytes(id) -> Option<&[u8]>
Snapshot::header() -> &Header

pub trait Validator {
    // runs once at open, after the table and identity check, before any value
    // is handed out; may reject the object
    fn validate(&self, snap: &SnapshotView<'_>) -> Result<(), Error>;
}
```

`WIDTH` is gone: it was an invariant callers could get wrong and nothing consumed
it. `replay`, sequence numbers, generations and the writer lock are not public
API; the journal owns them.

## 3. Journal

One owner: `Journal<T>` holds the live tree, the segment writer and the
directory.

```rust
Journal::<T>::open(dir, tree_id) -> Result<Journal<T>>   // recovers internally
journal.insert(prefix, value)
journal.withdraw(prefix)
journal.sync()                                            // durable on return
journal.checkpoint(&opts) -> Result<PathBuf>
journal.snapshot() -> &Snapshot<T>                        // current view
```

A record is `len | crc32c | seq | recv_ts | event_ts | kind | prefix fields |
value_len | value bytes | blob_len | blob bytes`.

The trailing blob is what makes handle values work: a `PathRef` points into a
payload section, and the newly interned payload bytes travel in the same record,
so replay rebuilds the section in record order and every offset reproduces
exactly. `blob_len = 0` means "reuse an offset that already exists".

Checkpoint writes a normal v4 object, verifies it end to end, and only then
prunes covered segments.

## 4. Acceptance

1. `tests/demo_a.rs`: a plain value type, build, write to disk, open, search a
   hit and a miss, read an archived field. Compiles and runs.
2. `tests/demo_b.rs`: a handle value plus a required payload section, a client
   validator, an out-of-range handle rejected at resolve, and a journal round
   trip whose replay reproduces the payload section byte for byte.
3. A downstream crate under `tests/downstream/` adds a value type and a section
   with no change to `src/`.
4. Golden objects: plain and with payload, byte-pinned.
5. Header-only peek answers type, id, counts of sections, sizes, stream and
   window in one 192-byte read.
6. `open` refuses an unknown required section and says which id; `open_with`
   accepts it once a validator is registered.
7. `cargo package` builds standalone, no internal names in docs.

## 5. Deleted from earlier drafts, with the reason

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
