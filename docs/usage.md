# Using bgpkit-snap

Everything this crate does, for a person reading it once and for a program calling it.
Two data shapes, one library, one binary; the format itself is in
[format.md](format.md) and the API walk-through is in
[bgpkit-snap-developer-guide.md](bgpkit-snap-developer-guide.md).

- **A snapshot**: one file holding a prefix → value table. Build it once from whatever
  you have (a RIB, a CSV, a crawl), then answer `search`, `lpm`, `spm`, `get_exact`,
  `children`, `cover` and `iter` against it in microseconds. Opening it reads the
  header and trusts the body layout, so a 900k-prefix table opens in tens of
  milliseconds, not by replaying an MRT file.
- **A journal**: a directory that takes an append-only stream of the same prefix → value
  pairs, survives a crash, and can be checkpointed into a snapshot whenever you like.
  Readers open `current.snap` and never touch the writer.

Both are plain files. No daemon, no index build step, no database.

## Install

Library, without the derive:

```toml
[dependencies]
bgpkit-snap = "0.1"
```

With `#[derive(SnapValue)]` (brings `syn` and `quote` into your build):

```toml
bgpkit-snap = { version = "0.1", features = ["derive"] }
```

The CLI (binary `bgpkit-snap`: `snap` is Ubuntu's):

```sh
cargo install --git https://github.com/bgpkit/bgpkit-snap --features cli
bgpkit-snap --help
```

## Your value type

The trie stores any `rkyv` type. A value has to declare one stable id, because the id
goes into the file header and a reader refuses an object written under another id.

`#[snap_value]` takes the type and does the rest, so a caller needs no `rkyv` in its
manifest at all. It is on `main` and ships in 0.2.0; this crate at 0.1.0 has only the
derive form below:

```rust
use bgpkit_snap::snap_value;

#[snap_value("demo.peer-count:v1")]
#[derive(Clone, Debug)]
struct PeerCount(u32);
```

That expands to `rkyv`'s three derives, the `rkyv` crate path, and the `SnapValue` impl.
`canonicalize = some_fn` adds the ordering hook, for a value whose byte order is not
already fixed:

```rust
#[snap_value("demo.roa-set:v1", canonicalize = sort_entries)]
#[derive(Clone)]
struct RoaSet(Vec<u32>);

fn sort_entries(v: &mut RoaSet) { v.0.sort_unstable(); }
```
A crate that already depends on `rkyv` can spell the same thing out and keep its own
`rkyv` version; the derive writes only the id:

```rust
#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, bgpkit_snap::SnapValue)]
#[snap(type_id = "demo.peer-count:v1")]
struct PeerCount(u32);
```

Doing it by hand is the third way, and the shortest: implement `SnapValue` yourself and
the id is all you add.

`snap_value` refuses a type that already derives `rkyv`'s traits, because that would be
two archive impls, and it names both ways out. A type that forgets `rkyv` entirely
(calling the derive without the rkyv derives) does not compile: the error names the
missing `Serialize<Strategy<...>>` bound at the type and `cannot be stored in a
snapshot` where it is used. Nothing about a value type involves `serde`: the stored
bytes are rkyv's, and `serde` in this crate is only for the journal's `state.json` and
the CLI's JSON.

The id is at most 31 bytes of printable ASCII, no space, quote or backslash, and never
empty. A value that cannot fit is refused when the object is written, not when it is
read. `u32` (`snap.u32:v1`) and `u64` (`snap.u64:v1`) are implemented by the crate, so a
simple counter needs no type of its own.

## Snapshots

Build, write, read back:

```rust
use bgpkit_snap::{Opts, Snapshot, Writer};

let mut w: Writer<PeerCount> = Writer::new();
w.insert("10.0.0.0/8".parse()?, PeerCount(3))?;
w.insert_many(vec![("192.0.2.0/24".parse()?, PeerCount(1))])?;
let entries = w.len();                       // `finish_to` consumes the writer
w.finish_to("peers.snap", &Opts::now())?;    // written beside, then renamed

let snap: Snapshot<PeerCount> = Snapshot::open("peers.snap")?;
```

Queries. `search` takes an address, everything else takes a prefix:

| you want | call | returns |
| --- | --- | --- |
| value for an address, most specific match | `search(addr)` | `Option<(IpNet, T)>` on the owned view |
| same, for a prefix | `lpm(prefix)` | same |
| the least specific entry covering this prefix | `spm(prefix)` | same |
| the entry stored exactly here | `get_exact(prefix)` | `Option<T>` |
| every entry under a prefix | `children(prefix)` | `Vec<(IpNet, T)>` |
| every entry covering a prefix, least specific first | `cover(prefix)` | `Vec<(IpNet, T)>` |
| every entry | `iter()` | `Vec<(IpNet, T)>` |
| how much of the space is covered | `address_counts()` | `AddressCounts { v4, v6 }` |
| every entry from a prefix upward | `iter_from(prefix, inclusive)` | `Vec<(IpNet, T)>` |
| just the values | `values()` | `Vec<T>` |

`Snapshot` answers with archived values (`&T::Archived`); `snap.owned()` answers with
`T`. Both are views over the same bytes, so `owned()` costs nothing until a value is
decoded. Use the archived form in a loop and the owned form when you want to keep or
print a value.

`address_counts()` returns `Count::{NoEntries, All, Exact(u128)}`; `Display` prints
`0`, `all` or the number, and `Count::exact()` gives the number when there is one. A
whole RIB usually reports `All` for both families, because some peer announces `0.0.0.0/0`
and `::/0`.

Merge several objects into one, later inputs winning on the same key:

```rust
let bytes = Snapshot::merge_last_wins(&[&a, &b], &Opts::now())?;
```

A merge refuses an input that carries a profile section of its own, and claims a
`window` only when every input has one and the spans join (two disjoint spans claim
nothing, because one window is a validity claim over its whole range).

## A second trie in the same object

One object holds one value type, because a reader has to know what a value is before it
touches the body. A profile that needs a second table with other values (prefix to path
attributes, prefix to a first-seen time) puts it in a section of its own:

```rust
use bgpkit_snap::profile::TrieSection;
use bgpkit_snap::ExtraSection;

let mut side = TrieSection::<FirstSeen>::new();
side.insert("10.0.0.0/8".parse()?, FirstSeen(1_763_164_800))?;
let body = side.to_bytes()?;

let extras = [ExtraSection { id: 16, kind: *b"SEEN", required: false, bytes: &body }];
let bytes = w.finish(&Opts { created_at: 1_763_164_800, stream: None, window: None, extras: &extras })?;

// later, on the reading side
let seen = snap.section_trie::<FirstSeen>(16)?.expect("the section exists");
let (prefix, first) = seen.lpm("10.1.2.3/32".parse()?)?;
```

The same queries as the main trie are there: `len`, `get_exact`, `lpm`, `iter`. The body
records the value type id, so reading a section as the wrong type is `ConfigMismatch`
instead of a reinterpretation of its bytes.

## Verification

Three layers, cheapest first. Each answers a different question, and the SDK exposes
all three so a service can verify as part of its own startup instead of shelling out.

```rust
use bgpkit_snap::{recorded_counts, Snapshot, verify_bytes};

let raw = std::fs::read("table.snap")?;

// layer 1: no value type. Header, CRC, layout, section table, content id.
let header = verify_bytes(&raw)?;
println!("{}: {} sections, {} bytes", header.type_id_str(), header.section_count, header.file_len);

// layer 2: with your type. Adds the type check and rkyv bytecheck of both tries.
let snap: Snapshot<Origin> = Snapshot::from_bytes(&raw)?;

// layer 3: decode every value and compare with the count the writer recorded.
if let Some(counted) = recorded_counts(&raw)? {
    assert_eq!(counted.entries, snap.len() as u64);
}
```

What the content id covers: BLAKE3 over `"bgpkit-snap-v4\0"`, header bytes `0..148`
(flags, tree id, generation, base sequence, type id, layout fields, coverage window), the
section table, and every section body. It does **not** cover `created_at`, the content id
field itself, the header CRC, or the alignment padding between sections.

What each layer refuses:

- container: wrong magic or version, a header field out of range, a header CRC mismatch,
  a file shorter than its layout claims, section ids out of order, a kind that disagrees
  with its id, non-zero padding, a length that runs past the end, extra bytes after the
  last section, and any byte changed in a hashed region (`Error::ContentId`).
- typed: everything above, plus a different `TYPE_ID` (`Error::TypeMismatch`), a required
  section this reader does not implement (`UnknownRequiredSection`), and a trie body that
  is not a valid archive of `T` (`BadArchive`).
- content: a body that decodes to a different number of entries than the object records.

What verification does not prove: that the data is true, who produced it (the format has
no signature), or its provenance (`created_at` and `window` are outside the content id, so
a re-dated copy keeps the same id). For a value type other than the integers this crate
implements, `bgpkit-snap verify` stops at the container layer and says so; the typed layer
runs in the program that declares the type.

A journal verifies itself as it opens: each record carries a CRC32C and a dense sequence
number, so a hole or a torn frame is an error rather than a shorter tree, and a checkpoint
is verified against the live tree before `state.json` names it.

## Journals

A journal is a log of changes over **one object**. It is never a tree of its own: it
starts from a base object, records what changed, and folds base plus log into the next
object when you checkpoint. The directory holds `state.json`, segments, checkpoints,
`writer.lock`, and `current.snap` (a link to the newest checkpoint).

```rust
use bgpkit_snap::journal::Journal;

// `table.snap` is the object this log keeps current
let mut j: Journal<PeerCount> = Journal::attach("table.snap", "table.journal")?;
j.insert("10.0.0.0/8".parse()?, PeerCount(3))?;   // buffered
j.sync()?;                                        // durable from here
println!("{} entries, next sequence {}", j.len(), j.seq());
let next = j.checkpoint(&Opts::now())?;           // base + log, verified first
```

Three ways in, one meaning each:

- `Journal::attach(base, dir)` adopts an existing object. The base is recorded by content
  id; until the first checkpoint the journal cannot be opened without it, and a base
  that was replaced is `Error::BaseLost` rather than silently adopted.
- `Journal::open(dir)` reopens a journal that exists.
- `Journal::start(dir, tree_id)` is the empty-base case, for a stream that has no object
  yet. Calling it on a directory that already holds a journal resumes it, so a service
  can call it on every start; a different tree id is refused.

- `insert` returns the sequence number the record got; `seq()` is the next one.
- `sync` is the durability point. A record that was never synced may be lost after a
  crash, and nothing else may: a torn tail is cut back on the next append, and a record
  the state file committed to must be on disk or the open fails with a sequence gap.
- `checkpoint` writes an ordinary snapshot, verifies it against the live tree, commits
  it into `state.json`, and only then prunes the segments it covers. Recovery time is
  the checkpoint interval, not the journal's age.
- `current.snap` is the reader's entry point. It is published after the state names the
  object, so a reader never opens a half-written or uncommitted file.
- `generation()` identifies the stream incarnation; `TreeId` identifies the tree. A
  second writer on one directory gets `Error::Locked` rather than a corrupted log.

Payload sections (values that point into a blob arena) are supported:
`Journal::options(dir).attach(base).payload(section).open()` (or `.start(tree)` for an
empty base), and the section has to match the base or the directory exactly or the open
is refused. `insert_with_blob` and `blobs()` are on the
journal, `section_bytes` and `payload_arena` on the snapshot.

If `state.json` is lost, `Journal::repair(dir, tree, payload)` rebuilds it from the
newest checkpoint, proves the result opens, and leaves the directory untouched if it
cannot. A state file that is present but unreadable is also repair's case; a healthy one
is not, because rewriting it would hide a gap.

## A loaded snapshot and an incoming feed

This is the shape most services end up in: one object is being served, and changes keep
arriving. The two sides are separate handles on the same lineage.

```rust
use bgpkit_snap::journal::Journal;
use bgpkit_snap::{Opts, Snapshot};

// read side: one validated open, then queries that never touch the disk
let mut current: Snapshot<Origin> = Snapshot::open("table.snap")?;

// write side: one journal over that same object
let mut log: Journal<Origin> = Journal::attach("table.snap", "table.journal")?;

// the feed arrives
log.insert("192.0.2.0/24".parse()?, Origin(64512))?;
log.withdraw("10.0.0.0/8".parse()?)?;
log.sync()?;                                   // durable from here

// the loaded object has not changed: readers keep the answers they had
assert!(current.owned().lpm("192.0.2.1/32".parse()?)?.is_none());

// the writer sees base plus log through the same queries
let seen = log.lpm("192.0.2.1/32".parse()?);

// a consistent object that includes the pending changes, without publishing anything
let with_pending: Snapshot<Origin> = log.to_snapshot(&Opts::now())?;

// publish: a new object inside the journal directory, named by state.json
let next = log.checkpoint(&Opts::now())?;
current = Snapshot::open(&next)?;              // the reader moves by reopening
```

Rules this buys, and the costs that come with them:

- **A snapshot is immutable.** The object a process opened keeps answering from the bytes
  it opened, whatever the writer does in the meantime. That is why several processes can
  read one file with no lock and no coordination.
- **The journal is the writer's view.** `log.lpm(..)`, `log.get_exact(..)` and
  `log.to_snapshot(&opts)` answer from base plus the records so far. A service that must
  answer with the newest data either queries the journal or swaps to a new snapshot.
- **Only a checkpoint moves the reader.** `checkpoint` writes a complete object, verifies
  it against the live tree, records it in `state.json`, and republishes `current.snap`.
  Readers pick it up by reopening; nothing updates in place, and an object already open
  stays valid.
- **Costs.** The writer holds the tree in memory, so a process that serves a snapshot and
  writes its journal pays for both: the object's bytes plus the writer's map. Reopening is
  cheap (a validated pass, tens of milliseconds for a RIB-sized table), so swapping on
  every checkpoint is reasonable; swapping per record is not.
- **One writer per directory.** The second writer gets `Error::Locked`. Readers never take
  the lock.

Two patterns fit this:

- **long-lived journal**: keep appending and checkpointing in place, and treat
  `<dir>/current.snap` as the service's read path.
- **publish and roll**: checkpoint, copy the new object to wherever objects live, then
  attach a fresh journal to it. The old journal directory can be dropped once no reader
  needs it, and the base of the new one is the object you just published.

`examples/live.rs` in the crate is this whole flow, runnable.

## CLI

The binary is `bgpkit-snap` (not `snap`: Ubuntu owns that name). It is a **container**
tool: it inspects, verifies, builds and folds objects, and it deliberately does not answer
domain queries, because a query depends on what the value means and only the program that
declares the type knows that.

```
bgpkit-snap build <in.jsonl> --out <file> [--value u8|u16|u32|u64|u128] [--created-at T] [--window A,B]
bgpkit-snap info <file>
bgpkit-snap stats <file>
bgpkit-snap verify <file>
bgpkit-snap fold <journal-dir> --out <file> [--tree NAME] [--value-type u8|u16|u32|u64|u128]
```

`build` and `fold` produce objects; `info`, `stats` and `verify` read them.

- `info` reads the 192-byte header and nothing else: type id, content id, length,
  sections, creation time, coverage window, stream coordinates.
- `stats` reports the contents instead: the section table (id, kind, required, bytes),
  their total, and the number of entries and per-family counts, which the writer records
  in the object itself so they are available whatever the value type is.
- `verify` checks the container (header, layout, table, content id); for an integer value
  type it also checks every body.
- `fold` turns a journal directory into one object, atomically and read-only. Writing a
  journal is the application's job, so there is no `insert` here. A live writer makes it
  fail with `another writer holds this journal`: fold the `current.snap` it publishes, or
  fold after it stops.

Everything works on an object whose value type belongs to another program. `info` and
`verify` never need the type; `stats` reports the section table and says the count is not
available rather than guessing it.

```sh
bgpkit-snap stats /data/regions.snap
# file          /data/regions.snap
# type_id       example.region-set:v1
# sections      3
#   id   2  kind 56340000                     52 bytes
#   id   3  kind 56360000                    132 bytes
#   id   4  kind 434e5400                     32 bytes
# section_bytes 216
# entries       1042 (v4 918, v6 124)
```

The count comes from section 4, which the writer fills in: it is the one number a
reader can report without knowing the value type, because a trie's node layout depends
on the value type while four little-endian integers do not. An object written before
that section existed reports `entries not recorded`.

`stats` answers "what is in it"; `info` answers "what does its header claim". The
coverage window, creation time and content id are header claims, so they live in `info`
only. `section_bytes` plus the 192-byte header, the 64-byte table rows and the padding
equals `file_len`, which is the one cross-check the two commands give you together.

Answering "which ROA covers 8.8.8.8" is the wayback program's job, because it owns the
value type. `examples/wayback.rs` is that program in 120 lines; every project with its own
value type writes the same thing.

### JSON

Every command takes `--json` and prints exactly one JSON object:

| command | fields |
| --- | --- |
| `build --json` | `out`, `entries`, `bytes` |
| `info --json` | `type_id`, `content_id`, `file_len`, `file_len_on_disk`, `consistent`, `sections`, `created_at`, `created_at_unix`, `window`, `stream` |
| `stats --json` | `file`, `type_id`, `sections` (`id`, `kind`, `required`, `bytes`), `section_bytes`, `entries`, `v4_entries`, `v6_entries` (null only for an object that predates the counts section) |
| `verify --json` | `ok`, `type_id`, `sections`, `bodies_checked`, `entries` |
| `fold --json` | `journal`, `out`, `entries`, `seq`, `type_id`, `bytes` |

Exit codes: `0` success, `1` anything else, with the reason on stderr prefixed
`bgpkit-snap: `. A caller checks the exit code and reads stdout as an object.

### For agents

One JSON object per invocation, stable field names, exit code `0`/`1`, no prompts:

```sh
# is this file what it claims, and is it intact?
bgpkit-snap --json verify big.snap | jq -e '.ok'

# what is in it, and how big is each part?
bgpkit-snap --json stats big.snap | jq '{type_id, entries, sections: [.sections[] | {id, kind, bytes}]}'

# a journal your program writes, folded into one object for everyone else
bgpkit-snap --json fold ./tbl --out tbl.snap | jq '.entries, .seq, .bytes'
```

## What it does not do

- One value type per object. Both tries hold the same `T`: the header records a single
  type id, and `Snapshot<T>` is one type parameter. A profile that needs a second
  structure with another value type puts it in its own section (id 16 and up), opens
  those bytes itself, and the crate will not query it for you.
- Every object carries both family sections, even when a family holds nothing, so the
  shape of a file does not depend on its contents. A reader still tolerates a missing
  family, because objects written before that rule exist.
- A writer holds the whole tree in memory. A build larger than RAM is out of scope.
- One writer per directory (enforced by a lock). Readers are unlimited and need no lock.
- The CLI reads and writes objects whose value type is an integer (`snap.u8:v1` through
  `snap.u128:v1`). A journal or object over a caller's own type is a library call, and
  the CLI says which type it found instead of guessing.
- No compaction beyond checkpoints, no replication, no S3 backend: a journal is a
  directory, and moving it is `mv` or a sync job you write.
