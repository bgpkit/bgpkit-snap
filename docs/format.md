Source: /root/specs/bgpkit-snap/bgpkit-snap-format.md · generated 2026-11-12 · This document is the publishable format contract. It contains no BGPKIT-internal detail; the BGP value types and pipeline usage live in bgpkit-snap-design.md.

# snap format 1.0

An immutable, memory-mappable container for a prefix trie with arbitrary values, plus an append-only journal for building one incrementally.

## 1. Scope and non-goals

The container holds one prefix trie per address family, a canonical JSON metadata block, and integrity hashes. It is read by memory mapping and validating once, then querying in place. It is written in one pass and never modified.

Non-goals: SQL or a query planner, by-value search (find all keys with value X), partial or ranged reads, multi-writer concurrency, and any guarantee about the trie's internal byte layout beyond the version recorded in the metadata.

## 2. Object layout

One immutable file, conventionally named `<content_id>.snap`.

```text
PREFIX (64 B)
  0..8    magic "BGPKSNAP"
  8..10   major u16 LE (1)
  10..12  minor u16 LE (0)
  12..16  prefix_len u32 LE (64)
  16..24  file_len u64 LE
  24..32  footer_off u64 LE
  32..36  footer_len u32 LE
  36..64  reserved, zero

SECTIONS, each at a 16-byte aligned offset, contiguous, non-overlapping

FOOTER
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
    +8  offset u64
    +16 len    u64
    +24 blake3 [32] over the section bytes, no padding included
    +56 reserved [8] zero
  body_blake3 [32] over every section's bytes concatenated in file order,
  META included, no padding, no footer bytes
```

The magic is a compatibility marker, not a brand: a reader must reject an unknown major and name the highest major it supports.

## 3. Sections

```text
1  META    canonical JSON (section 4), always present, always first
2  TRIE_V4 a zero-copy archive of a prefix map keyed by IPv4 prefixes
3  TRIE_V6 the same for IPv6
```

Rules: ids ascending and unique, META first, sections contiguous from offset 64 to `footer_off`, trie sections never compressed, at least one trie section present. A prefix-set is a trie whose value type is empty.

## 4. META

Canonical JSON: UTF-8, sorted keys, integers and strings only, no floats, no insignificant whitespace. Unknown keys are ignored by readers.

```json
{
  "canonical": {"host_bits": "zeroed", "prefix_form": "network/len"},
  "content_id": "9f2c...",
  "counts": {"v4": 1042325, "v6": 246175},
  "families": [4, 6],
  "kind": "prefix-map",
  "probe": {"v4_first": "1.0.0.0/24", "v4_last": "223.255.255.0/24"},
  "provenance": {"created_at": "2026-11-12T22:14:09Z", "generator": "tool/0.9.4", "producer": "bgpkit-snap/0.1.0", "sources": [{"sha256": "ab12...", "uri": "https://example.org/input"}]},
  "trie_layout": {"crate": "prefix-trie", "key_bits": 32, "node_bits": 5, "rkyv": "0.8", "version": "0.10.2"},
  "value": {"note": "free text for humans, never parsed", "type_id": "snap.u32:v1", "width": 4}
}
```

- `kind` is `prefix-set` or `prefix-map`.
- `families` lists the families actually present; a query for an absent family is an error, not an empty result.
- `value.type_id` is the only link between bytes and meaning. A reader refuses a mismatch against the type it was asked for.
- `probe` holds the first and last entry per family, checked by exact lookup at open. It catches the one confusion the archive itself cannot: a trie read with the wrong key type validates and returns wrong prefixes.
- `content_id` is BLAKE3 over the domain string `snap-content-v1\0`, then the canonical META projection, then every non-META section in id order framed `id u16 LE || len u64 LE || bytes`. The projection is META with `content_id` and `created_at` removed and re-serialized canonically, so pinning the id authenticates every other metadata field.
- `created_at` is the only non-deterministic field, and it sits outside the projection, so equal data shares a `content_id`.
- The hashes detect corruption. Tamper-evidence comes from pinning the `content_id` outside the object; nothing here is a signature.
- Reserved bytes must be zero in major 1, and a reader rejects non-zero.

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

In order:

1. Read 64 bytes; check magic, `prefix_len`, major.
2. Check `file_len` against available bytes before fetching anything else.
3. Read the footer at `footer_off`; require `footer_off + footer_len == file_len`, check the magic, the flags bit, and `section_count`.
4. Require META first, ascending unique ids, `align = 16`, `pad = 0`, `offset % 16 == 0`, `offset + len <= footer_off`, and no two entries overlapping.
5. Verify each section's `blake3`, then `body_blake3`, then recompute `content_id`. All mandatory.
6. Present section bytes with at least 16-byte alignment (a memory map or an aligned copy, never a plain byte vector), check `value.type_id` against the requested type, then validate the archive.
7. Compare `counts` and every `probe` entry by exact lookup.

## 7. Writer

Emit sections in id order with 16-byte padding; build META from the data actually written; reject a trie section at or above 2 GiB with an error that says to shard; buffer the sink, because a joint archive produces over a million small writes; never compress a zero-copy section. The prefix is patched last, so the writer needs a seekable sink: a file, or a buffered multipart upload where the prefix rides in the first buffered part.

## 8. Versioning, alignment, limits

- Major bumps when the prefix, footer, section ids or any archived layout changes meaning; minor for additive META keys, new section ids and new value types. Readers accept their major and any minor, and refuse a required section they do not know.
- Container integers are little-endian.
- The rkyv feature set is part of the format: `little_endian` and `aligned` on; `big_endian`, `unaligned` and all `pointer_width_*` off, explicitly, because Cargo feature unification can flip defaults. The crate asserts the configuration at build time and fails a checked-in fixture if it drifts.
- One archive stays under 2 GiB because the archive uses 32-bit relative offsets; entries stay under 4.3 G. Larger datasets shard by top-level prefix into several objects.

## 9. Journal

The journal is how a mutable tree becomes a snapshot without losing updates. It is not an audit log and not the durable record.

```text
segment header (32 B): magic "BGPKLOG" | version u16 | pad u16 | tree_id [16] | pad [4]
record: len u32 LE (bytes after this field, so a record is 4 + len)
        crc32c u32 LE (over the bytes after this field, never over itself)
        seq u64 LE (dense, monotonic)
        recv_ts i64 LE
        event_ts i64 LE (0 when absent)
        kind u8 (1 insert | 2 withdraw | 3 control)
        family u8
        prefix_len u8
        flags u8 (zero in v1)
        addr [16]
        value_len u32 LE
        value bytes (insert: the archived value in canonical form)
```

- One writer per tree, enforced by a lock.
- A record is applied only if `crc32c` matches and `4 + len` lands on the next record boundary. A torn tail is truncated on open and the byte count is reported.
- **Durability.** A feed call returns after its segment is fsynced. A checkpoint writes the snapshot, fsyncs the file and the directory, writes `checkpoint.json` (`{snapshot_file, base_seq, tree_id}`) by temporary file plus rename, fsyncs the directory again, and only then deletes segments wholly below `base_seq + 1`.
- **Recovery.** Replay only records with `seq > base_seq` from segments whose `tree_id` matches the snapshot's.
- **Retention.** Segments below `base_seq` are deleted at the next checkpoint; a query older than the oldest retained segment returns a "history pruned" outcome rather than an answer derived from a later base.
- Control records carry a subtype and an opaque payload defined by the value type's owner. The format defines no session, gap or timestamp semantics.

Checkpoint triggers, whichever comes first: 60 s since the last checkpoint, 250,000 records, a 64 MiB segment roll, or a control record that marks a natural boundary. Skip when nothing changed. Keep the previous snapshot and its segments until the new one is written, fsynced and re-opened cleanly.

## 10. Merging

Two snapshots over the same key space merge losslessly only when the value is a join-semilattice: set union, bitmap union, or count addition. Both archives iterate in key order, so a merge is a streaming k-way fold. A scalar value is not mergeable in this sense: picking one side silently drops the other. Mutable or session state is never mergeable, because a merged tree no longer knows which source contributed an entry.
