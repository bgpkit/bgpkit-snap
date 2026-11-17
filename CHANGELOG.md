# Changelog

## 0.1.0

The first version under the pre-stable numbering. The crate moved from `1.0.0-rc.4` to
`0.1.0` on purpose: no service has leaned on this interface for long enough to freeze
it, and a 1.0 that has to break is worse than a 0.1 that is allowed to. The wire layout
is unchanged (v4) and is documented as the contract; the Rust API is not.

This is also the release that makes the surface small enough to describe without a
table of near-duplicates, and the one that makes the journal's durability claim true.

API

- `snap.owned()` answers every value-returning query with `T`; `search_owned` and
  `get_exact_owned` are gone, because a pair of owned methods covered two queries out
  of five and left the rest to the caller's own `rkyv` call.
- `TreeId` with `TreeId::from_name("...")` (the first 16 bytes of its BLAKE3 hash).
  `Journal::open`, `open_with` and `repair` take `impl Into<TreeId>`, so a plain
  `[u8; 16]` still works and no example has to invent sixteen bytes.
- `Journal::to_snapshot(&opts)` and `Journal::to_bytes(&opts)`: the object a
  checkpoint would write, opened or as bytes, without touching the disk. This is how
  a journal user reaches `children`, `cover` and `iter` without a second copy of the
  query surface on the journal.
- `Writer::insert_many` stops at the first refused prefix. `Writer` deliberately does
  not implement `Extend`, which cannot report that.
- `Snapshot::merge_last_wins` and `merge_with`: fold several objects into one, the
  daily-merge step. The merge drops stream coordinates because several streams are not
  one stream, and takes the union of the input windows when every input declares one.
- `ipnet` is re-exported. Unlike the archive re-export this one is complete, because no
  macro expands `::ipnet::` paths, so a caller cannot end up on a different `ipnet`
  version than the signatures use.
- five queries removed because they were compositions of the others: `lpm_prefix`,
  `spm_prefix`, `get_key_value`, `cover_keys`, `cover_values`.
- `Error::BadArchive(u16)` separates "this section's body is not an archive of your
  type" from `BadSectionKind`, which is about the four-byte kind tag. `Error` is
  `#[non_exhaustive]`, so a new refusal does not break a caller's match.
- `AddressCounts` / `Count { NoEntries, All, Exact(u128) }`: the old pair of options
  could not tell "no entries in this family" from "this family is covered end to end"
  (`::/0` covers 2^128 addresses, which does not fit in the count). `Count` prints
  (`all`, `0`, the number) and `Count::exact()` gives the number when there is one.
- `#[derive(SnapValue)]` from the new `bgpkit-snap-derive` crate (feature
  `derive`): `#[snap(type_id = "...")]` replaces the hand-written `impl`, and the
  id is checked where it is written rather than when an object is finished.
- `Journal::seq()` and `Journal::generation()`: the sequence the next record will
  carry and the stream incarnation, so a caller shipping records elsewhere can say
  how far the journal has got and which stream wrote it.
- a journal's value type is now pinned by its first record, not by its first sync: a
  directory whose records were never synced had no `state.json`, so a reader of
  another type could open it and decode those bytes as its own.
- `Snapshot::lpm` takes a prefix and `Snapshot::search` takes an address; both are
  documented as the same lookup, one with the host prefix built for you.
- `Journal::open(dir, tree)` and `open_with_payload(dir, tree, payload)` replace the
  positional `Option<PayloadSection>`; `checkpoint_with(&opts, &validator)` runs a
  profile's own check before the object is committed; `Snapshot::view()` is public so
  a validator can be run over an object a caller already holds.
- every write path takes the value by value (`Journal::insert(prefix, value)`), like
  `Writer::insert`, instead of borrowing one the journal copies anyway.

Journal

- rotation flushes and fsyncs the outgoing segment before dropping it, and keeps the
  segment if that fails. Previously `sync()` returned Ok while the records in a
  rotated segment had never reached stable storage.
- the torn-tail cut runs before rotation, so a recovery offset recorded against the
  old segment is not applied to the new one.
- `checkpoint` carries the journal's own sections only, because a checkpoint has to be
  an object the journal can reopen; recovery refuses a checkpoint written under a
  different payload configuration instead of opening it and losing the arena. Pruning
  is best effort and never fails a committed checkpoint.
- `children` returns stored keys: a query prefix with host bits answers for its
  network address instead of returning a key the object does not contain.
- the owned view reports a value whose `Deserialize` refuses as an error, not as an
  absent prefix (which made `len()` disagree with `iter().count()`).
- a zero generation is refused at open; it used to be accepted and then fail every
  checkpoint.
- a checkpoint that cannot be read reports the file system's error rather than
  "missing" for every `io::Error`, and rotation and `sync` keep errno on a failed
  flush.
- `state.json` records the value type and payload configuration, so reopening a
  directory with another type or another payload id is refused instead of
  reinterpreting the same bytes; `Error::ConfigMismatch` names that case.
- `repair` refuses a directory that still has a readable `state.json`, because
  rewriting `next_seq` there hides the sequence gap `open` reports.
- every checkpoint writes a new file name (`snapshot-<seq>-<n>.snap`), so a checkpoint
  with no new records cannot replace an object that is already committed.
- the padding walk in `verify_bytes` and `Snapshot::from_bytes` bounds-checks, so a
  crafted object is refused instead of panicking.
- a checkpoint decodes every value before it commits, because recovery decodes them on
  open; an object holding an undecodable value would be unopenable for good.
- recovery compares a payload section's `required` flag as well as its id and kind.
- `SnapshotView::sections` is `&[SectionRef]` with named fields instead of a tuple; the
  library returns `Error` where it used to `expect`.

Verification

- tests: reopen after a checkpoint with a sidecar, a required sidecar refused, host
  bits refused on the blob and withdraw paths, a journal crossing the 64 MiB segment
  boundary reopening with both records, `TreeId` stability and tree mismatch,
  `to_snapshot`/`to_bytes` without a file, and `insert_many` stopping.

## 1.0.0-rc.3

The first release where the API is what a developer guide can describe without
apologising for it, and the first with the write path's silent-loss cases closed.

API

- one name per query: `lpm`, `lpm_prefix`, `spm`, `spm_prefix`, `get_exact`,
  `get_exact_owned`. `search_prefix`, `get_lpm`, `get_spm` and `Snapshot::get` are
  gone; a reader wanting the stored entry can no longer silently get an ancestor.
- `Opts.created_at` is unix seconds and `Opts::now()` exists. `Opts::default()` is
  gone: a default would invent provenance.
- `Snapshot::open` takes any `AsRef<Path>`; `Writer::finish_to` writes atomically
  with a per-call temp name and fsyncs.
- `Writer::insert` returns a `Result` and refuses a prefix with host bits set in
  every build, not only in debug.
- `rkyv` is re-exported, but a value type still needs its own `rkyv` dependency:
  the derive generates paths the re-export cannot satisfy.

Journal

- `checkpoint` keeps the caller's `Opts.extras` instead of dropping them, always
  writes the payload section it was opened with (even when the arena is empty),
  publishes `current.snap` only after `state.json` names the object, and removes
  older snapshots instead of accumulating one per checkpoint.
- `Journal::repair(dir, tree_id, payload)` recovers a journal whose `state.json`
  was lost, taking the writer lock before it writes the state it is repairing.
  `adopt_checkpoint` is gone: two names for one repair confused two review rounds.
- `insert_with_blob(prefix, blob, |offset| value)` builds the handle from the
  offset in the same call that decides it; `insert_with_blob_at` adds timestamps.
- `Times { recv_ts, event_ts }`, `insert_at` and `withdraw_at` carry record time.
- segments rotate at 64 MiB instead of growing for the life of the writer.
- `Error::Locked`, `BadOpts`, `BadSectionId` and `BadPrefix` replace stringly-typed
  variants for the cases a caller must act on.

Verification

- `Validator::validate` now runs after both trie archives are byte-checked, which
  is what the documentation always claimed.
- CI builds with `--features cli` and builds `tests/downstream`, the out-of-crate
  consumer that proves a value type can be added without touching `src/`.

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
  or too wide is refused by `bgpkit-snap build` instead of becoming zero.
- `bgpkit-snap` CLI: `build`, `info`, `stats`, `verify`, `fold`. It is a container tool
  and answers no domain queries: `info` reads the header, `stats` reports the section
  table and the prefix count when the value type is one it decodes, `verify` checks the
  container (and the bodies for an integer type), `build` and `fold` produce objects.
  The two do not overlap: a header claim (content id, creation time, coverage window) is
  `info`'s, and what the body holds is `stats`'.
- every object carries both family sections, even when a family holds nothing (an empty
  archive is 32 bytes), so a client never has to ask which families a file happens to
  contain. A reader still accepts a missing family: objects written before this rule
  exist, and there an absent family is not an empty one.
- the writer records the entry counts in the object (section id 4, kind `CNT`, 32 bytes,
  optional for readers), so `stats` reports how many prefixes an object holds without
  knowing its value type. `verify` compares the recorded counts with the decoded ones
  when it can decode them, and an object whose halves disagree is refused.
  A query needs the value's meaning, which belongs to the program that declares the
  type, so `search` was removed rather than taught to refuse other people's objects.
  Every command takes `--json` and answers in one object.
- the CLI binary is `bgpkit-snap`, not `snap`: Ubuntu's package manager owns that name,
  so `cargo install` would have put a second `snap` on the path. Every command keeps its
  flags, and the error prefix changed with it.
- `bgpkit-snap fold <journal-dir> --out <file>`: read a journal and write the object its
  records describe, atomically. Writing a journal is the application's job; the CLI's
  job is the readable artifact, so there is one read-only command instead of a shell API
  for `insert`/`sync`/`checkpoint`.
- `u8`, `u16` and `u128` are value types as well (`snap.u8:v1`, `snap.u16:v1`,
  `snap.u128:v1`), so an integer-valued table needs no type of its own and the CLI can
  build, verify, search and fold all of them.
- `docs/usage.md`: the whole crate and CLI in one place, including the JSON fields and
  exit codes a caller programs against.
- `examples/wayback.rs`: a downstream tool over a real `.snap` object, with its own value
  type (`bgpkit.roa-set:v1`), answering "which ROA covers this netblock" and "which one
  was valid on this day" against the 219 MB wayback dump. It is the pattern for every
  project whose values are not integers.

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
- `snap` CLI: build, verify, search, info (renamed to `bgpkit-snap` in 0.1.0).
- Golden object test that fails on any archived-layout drift.
