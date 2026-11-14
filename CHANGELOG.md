# Changelog

## 1.0.0-rc.2

The container loses its metadata section, its footer and its JSON. The header is
now the only claim about the object, and checked rkyv access is the proof. This
release is the first one with a journal that survives restarts on its own terms,
and the first one reviewed against a written byte contract.

Format

- 192-byte header with the value type, file length, section count and table
  length, coverage window, stream coordinates and content id; a crc32c over
  `header[0..188]`. Everything up to byte 148 is hashed, so there is no
  field-exclusion rule.
- 64-byte section table without offsets: sections are packed in ascending id
  order, 16-byte aligned, padding zero and checked.
- Family sections are bound to their ids (2 and 3) in both directions: a section
  whose kind is V4 at any other id is refused instead of ignored.
- `content_id` covers the header prefix, the table and every section.
- Deleted: META, the projection, the footer, per-section hashes, `WIDTH`,
  `type_id_len`, `minor`, `header_len`, `table_off`, per-entry offsets.

Journal

- `Journal<T>` owns the tree, the blob arena, the writer lock and the segments.
- Records carry their value bytes, so replay rebuilds the value; a record with a
  blob carries the blob, so payload offsets reproduce exactly.
- `state.json` is the commit record: it names the checkpoint and the next
  sequence number, so recovery starts from the checkpoint, replays only records
  above it, and never hands out a number twice.
- A hole, an unreadable segment header, a malformed checkpoint, a foreign
  checkpoint, a checkpoint section the journal was not opened for, and an
  unreadable state file are all errors. A torn tail is not: the next append cuts
  it away and reuses the number.
- Checkpoint verifies the object it built against the live tree, is itself the
  validator for the section it wrote, and prunes only segments it fully covers.

Library and tooling

- `verify_bytes` checks the container without the value type, so the CLI can
  verify an object whose type belongs to another binary.
- `Writer::finish` refuses headers a reader would reject; a value that is missing
  or too wide is refused by `snap build` instead of becoming zero.
- `snap` CLI: build, info, verify, search; `info` still reads 192 bytes.

Review

The format document was rewritten as a byte contract (header, table, identity,
journal framing, section ids, payload dependency, test vector) and reviewed round
by round until the reviewer's verdict was SHIP. The nine rounds found reader
paths that could answer with less than the writer committed, state that moved
ahead of the log, and bytes the document fixed that the reader did not check.

## 1.0.0-rc.1


First release candidate. The layout is frozen; the items in the README's
"Known limitations" are tracked for 1.0 final.

- 192-byte peek header replacing the earlier 64-byte prefix: magic, version,
  tree id, journal generation, content id, type id, sequence, sizes, counts,
  families, event window, header CRC.
- Content id over the data projection and every non-META section; provenance is
  excluded, so equal data from different paths hashes equally.
- Journal with 48-byte segment headers, crc32c framed records, dense sequences,
  a writer lock, a generation per incarnation, checkpoint verification, and
  `state.json` for restart-safe sequence numbering.
- `snap` CLI: build, verify, search, info.
- Golden object test that fails on any archived-layout drift.
