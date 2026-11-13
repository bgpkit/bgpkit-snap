Source: /root/specs/bgpkit-snap/bgpkit-snap-format.md · generated 2026-11-12 · This document is the publishable format contract. It contains no BGPKIT-internal detail; the BGP value types and pipeline usage live in bgpkit-snap-design.md.

# snap format 1.0

An immutable, memory-mappable container for a prefix trie with arbitrary values, plus an append-only journal for building one incrementally.

## 1. Scope and non-goals

The container holds one prefix trie per address family, a canonical JSON metadata block, and integrity hashes. It is read by memory mapping and validating once, then querying in place. It is written in one pass and never modified.

Non-goals: SQL or a query planner, by-value search (find all keys with value X), partial or ranged reads, multi-writer concurrency, and any guarantee about the trie's internal byte layout beyond the version recorded in the metadata.

## 2. Object layout

This header supersedes the 64-byte `PREFIX` of draft 0.1. An object that only
satisfies the old prefix layout is not a v1 object and MUST be rejected.

One immutable file, conventionally named `<content_id>.snap`.

```text
HEADER (192 B, replaces the 64-byte prefix of draft 0.1; offsets are absolute)
   0..8    magic "BGPKSNAP"
   8..10   major u16 LE (1)
  10..12   minor u16 LE (0)
  12..14   header_len u16 LE (192)
  14..16   flags u16 LE   bit 0: HAS_STREAM, bit 1: HAS_EVENTS, rest zero
  16..32   tree_id [16]   all zero when HAS_STREAM is clear
  32..48   generation [16] random per journal incarnation, zero when clear
  48..80   content_id [32] raw bytes, authoritative copy is in META
  80..112  type_id [32]   ASCII; zero-padded only when type_id_len < 32
 112..120  base_seq u64 LE  last journal sequence the body reflects
 120..128  file_len u64 LE
 128..136  footer_off u64 LE
 136..144  meta_off u64 LE
 144..148  meta_len u32 LE
 148..152  section_count u32 LE
 152..156  count_v4 u32 LE
 156..160  count_v6 u32 LE
 160..168  first_event_ts i64 LE
 168..176  last_event_ts i64 LE
 176..184  created_at i64 LE   Unix seconds, never zero
 184..186  families u16 LE     bit 0 v4, bit 1 v6, no other bit
 186..188  type_id_len u16 LE  1..32
 188..192  header_crc32c u32 LE over bytes 0..188

SECTIONS, each starting at the first 16-byte boundary at or after the previous
end (zero padding between them), non-overlapping, the first at or after 192

FOOTER, ends the file
  0..4    section_count u32 LE
  4..8    footer_magic "SNPF"
  8..12   flags u32 LE   bit 0: body hash present (must be 1 in v1)
  12..16  reserved, zero
  entries, 64 bytes each, fields at fixed offsets
    +0  id    u16  1 META, 2 TRIE_V4, 3 TRIE_V6
    +2  kind  u16  same values as id
    +4  flags u16  bit 0: required by readers (0 for all v1 sections)
    +6  align u8   must be 16
    +7  pad   u8   must be 0
    +8  offset u64 LE  absolute, 16-byte aligned, >= 192
   +16  len    u64 LE
   +24  hash   [32]   blake3 of the section bytes
   +56  reserved [8]  zero
  body hash [32]      blake3 over the sections in file order
```

`footer_len` is not stored: it is `16 + 64 * section_count + 32`, and the footer
must end the file. The body hash is computed over the concatenation of section
bytes in the order the entries list them.

## 3. Sections

```text
1  META    canonical JSON (section 4), always present, always first
2  TRIE_V4 a zero-copy archive of a prefix map keyed by IPv4 prefixes
3  TRIE_V6 the same for IPv6
```

Rules: ids ascending and unique, META first, each section starts at the first 16-byte boundary at or after the previous section end (padding bytes are zero and belong to no section), the first starts at 192, and the last ends at or before `footer_off`, `meta_off`/`meta_len` in the header equal to the META entry, trie sections never compressed, at least one trie section present. A prefix-set is a trie whose value type is empty.

## 4. META

META is canonical JSON with three top-level keys:

```json
{
  "projection": { "...": "the hashed data projection, see section 6" },
  "content_id": "<64 hex chars>",
  "provenance": {
    "generator": "bgpkit-snap/<version>",
    "producer": "bgpkit-snap/<version>",
    "created_at": "<RFC 3339, matches header.created_at>",
    "sources": [{"uri": "<where the data came from>"}]
  }
}
```

`projection` carries: `canonical` (host bits zeroed, prefix form `network/len`),
`counts` (`v4`, `v6`, omitted when a family has no entries), `families` (array of
4 and 6), `kind` (`prefix-map`), `probe` (first and last key per family, so a
reader can prove the archive it decoded is the one META describes), `stream`
(`tree_id`, `generation`, `base_seq`, present only when `HAS_STREAM` is set),
`events` (`first_event_ts`, `last_event_ts`, present only when `HAS_EVENTS` is
set), `trie_layout`, and `value` (`type_id`, `width`).

`provenance` is never hashed. Two objects with the same `projection` and the same
trie sections have the same `content_id` no matter who built them, from which
path, or when: the id addresses data, not build history.

Every leaf inside `projection` is a non-negative integer or an ASCII string with
no characters below 0x20. Values may be nested objects and arrays, whose keys the
writer sorts by byte order and serialises with no whitespace. That contract is
what removes JSON escaping and float formatting from the hash input; a projection
field that needs a float, a non-ASCII string, or a control character is a major
version change. The golden test pins the exact bytes.

## 5. Values

A value type is the only extension point. A type declares a stable id, a canonical form, and a canonical order when the type is not already canonical:

```text
type_id        value              canonical form
snap.none:v1   ()                 prefix set, no value
snap.u32:v1    u32                plain scalar
snap.u64:v1    u64                plain scalar
<T>::vN        user types         declared by the type, with a canonicalizer
```

Export is not a format concern. The only primitive the format provides is ordered iteration over `(prefix, value)`; a consumer that wants JSON, CSV or Parquet writes it from that iterator with whatever library it already uses. Every non-scalar type must sort its inner collections before serializing. Archive byte identity holds only when the value is canonical; without that rule two logically equal data sets hash differently and content addressing stops working. A new type is a minor version change; changing an existing type's layout or meaning requires a new `:vN`.

## 6. Reader

A reader may stop after step 1 and answer identification questions from the
header alone, but it MUST report that answer as unverified, because only steps
4 through 6 prove the bytes match the claims.

In order:

1. Read 192 bytes. Check magic, `major`, `header_len = 192`, `header_crc32c`,
   `flags` bits, `families`, `type_id_len`, `created_at != 0`, and the stream and
   event window invariants (section 8). Any failure is a rejection.
2. If `file_len` is known (HTTP `Content-Length`), compare it before fetching the
   body.
3. Check `footer_off + 16 + 64 * section_count + 32 == file_len`, then read the
   footer: magic, flags bit 0, and `section_count` equal to the header's.
4. Require META first, ascending unique ids, `align = 16`, `pad = 0`,
   `offset % 16 == 0`, `offset + len <= footer_off`, no two entries overlapping,
   no section below 192, and the META entry equal to `meta_off`/`meta_len`.
5. Verify each section's `blake3`, then `body_blake3`, then recompute
   `content_id` from `projection` and the trie sections.
6. Check that every header field the projection also carries agrees with META:
   `content_id`, `type_id`, both counts, `families`, `created_at`, and the
   `stream` and `events` objects. A disagreement is a rejection: this is what
   makes a spliced header impossible to use.
7. Present section bytes with at least 16-byte alignment (a memory map or an
   aligned copy, never a plain byte vector), check `type_id`, then validate the
   archive.
8. Compare `counts` and every `probe` entry by exact lookup.

## 6a. content_id

`content_id = blake3( "snap-content-v1\0" || canonical_json(projection) ||
framed(section) for every non-META section in ascending id order )`, where
`framed(id, bytes)` is `id u16 LE || len u64 LE || bytes` and META is skipped.
Framing every non-META section is what keeps a section added by a later minor
version inside the object identity: two objects that differ in such a section
must have different ids. The header and the footer are not hashed, and neither is
anything under `provenance`.

Canonical JSON here means: keys sorted by byte order at every level, no
whitespace, integers only, strings ASCII with no escapes required (section 4),
UTF-8 otherwise. A conforming writer and reader must produce identical bytes for
the same `projection`; the test vector in `crates/bgpkit-snap/tests/golden.rs`
pins one.

## 7. Writer

Emit sections in id order with 16-byte padding; build META from the data actually written; reject a trie section at or above 2 GiB with an error that says to shard; buffer the sink, because a joint archive produces over a million small writes; never compress a zero-copy section. The prefix is patched last, so the writer needs a seekable sink: a file, or a buffered multipart upload where the prefix rides in the first buffered part.

## 8. Invariants, versioning, alignment, limits

Header invariants a reader MUST reject a violation of:

1. `families` is non-zero and has no bit outside bits 0 and 1.
2. A set family bit has a non-zero count; a clear bit has a zero count.
3. `type_id_len` is 1..32, the bytes below it are printable ASCII, and every
   byte above it is zero.
4. With `HAS_EVENTS` clear, both timestamps are zero; with it set, both are
   non-zero and `first_event_ts <= last_event_ts`.
5. With `HAS_STREAM` clear, `tree_id`, `generation` and `base_seq` are all zero;
   with it set, `tree_id` and `generation` are non-zero.
6. `created_at` is non-zero.
7. Flags and reserved bytes carry no bit outside their definition.

## 8a. Versioning, alignment, limits

- Major bumps when the prefix, footer, section ids or any archived layout changes meaning; minor for additive META keys, new section ids and new value types. Readers accept their major and any minor of that major; a minor bump never changes the layout of the header or the footer and never reuses reserved space for an incompatible meaning, and refuse a required section they do not know.
- Container integers are little-endian.
- The rkyv feature set is part of the format: `little_endian` and `aligned` on; `big_endian`, `unaligned` and all `pointer_width_*` off, explicitly, because Cargo feature unification can flip defaults. The crate pins these features in `Cargo.toml`; a consumer that enables an incompatible rkyv feature produces a compile error, not a silent layout change and fails a checked-in fixture if it drifts.
- One archive stays under 2 GiB because the archive uses 32-bit relative offsets; entries stay under 4.3 G. Larger datasets shard by top-level prefix into several objects.

## 9. Journal

The journal is how a mutable tree becomes a snapshot without losing updates. It is not an audit log and not the durable record.

```text
segment header (48 B): magic "BGPKLOG\0" | major u16 | minor u16 | tree_id [16] |
                      generation [16] | pad [4]
record: len u32 LE (bytes after this field, so a record is 4 + len)
        crc32c u32 LE (over the bytes after this field, never over itself)
        seq u64 LE (dense, monotonic)
        recv_ts i64 LE
        event_ts i64 LE (0 when absent)
        kind u8 (1 insert | 2 withdraw | 3 control)
        family u8 (4 or 6)
        prefix_len u8
        flags u8 (zero in v1)
        addr [16]  IPv4 in addr[0..4] with addr[4..16] zero; IPv6 in addr[0..16]
        value_len u32 LE
        value bytes (insert: the archived value in canonical form)
```

- One writer per tree, enforced by a lock.
- A record is applied only if `crc32c` matches and `4 + len` lands on the next record boundary. A torn tail is truncated on open and the byte count is reported.
- **Durability.** `insert` and `withdraw` append to a buffered segment; a record is durable once `sync()` returns. A feed that must ack a peer after durability calls `sync()` before acking its batch, which is the group-commit path; a per-record ack would pay one fsync per record. A checkpoint writes the snapshot, fsyncs the file and the directory, writes `checkpoint.json` (`{snapshot_file, base_seq, tree_id, generation}`) by temporary file plus rename, fsyncs the directory again, and only then deletes segments wholly below `base_seq + 1`.
- **Recovery.** Replay only records with `seq > base_seq` from segments whose
  `tree_id` and `generation` both match the snapshot's. `base_seq` is the highest
  sequence the snapshot reflects, so the first record written after a checkpoint
  has `seq == base_seq + 1` and is always replayed. A reader MUST refuse a
  segment whose generation differs from `checkpoint.json`: sequence numbers are
  only unique within one incarnation.
- **Retention.** Segments wholly at or below `base_seq` are deleted at the next checkpoint; a query older than the oldest retained segment returns a "history pruned" outcome rather than an answer derived from a later base.
- **Restore and fork.** A journal restored from a backup, or copied to start a divergent tree, MUST mint a new `generation`. Reusing the old one lets two different states claim the same `(tree_id, generation, base_seq)`, which is exactly the confusion the generation exists to prevent.
- **Checkpoint binding.** `checkpoint.json` names a snapshot; `tree_id`, `generation` and `base_seq` in it MUST equal the snapshot header's, and a reader MUST refuse the pair when they differ. A checkpoint from a later incarnation next to an older snapshot would otherwise replay from the wrong base.
- Control records carry a subtype and an opaque payload defined by the value type's owner. The format defines no session, gap or timestamp semantics.

Checkpoint triggers, whichever comes first: 60 s since the last checkpoint, 250,000 records, a 64 MiB segment roll, or a control record that marks a natural boundary. Skip when nothing changed. Keep the previous snapshot and its segments until the new one is written, fsynced and re-opened cleanly.

## 10. Merging

Two snapshots over the same key space merge losslessly only when the value is a join-semilattice: set union, bitmap union, or count addition. Both archives iterate in key order, so a merge is a streaming k-way fold. A scalar value is not mergeable in this sense: picking one side silently drops the other. Mutable or session state is never mergeable, because a merged tree no longer knows which source contributed an entry.
