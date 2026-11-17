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

The CLI:

```sh
cargo install --git https://github.com/bgpkit/bgpkit-snap --features cli
snap --help
```

## Your value type

The trie stores any `rkyv` type. A value has to declare one stable id, because the id
goes into the file header and a reader refuses an object written under another id.

```rust
use bgpkit_snap::SnapValue;

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, SnapValue)]
#[snap(type_id = "demo.peer-count:v1")]
struct PeerCount(u32);
```

Without the derive, the same thing by hand:

```rust
impl SnapValue for PeerCount {
    const TYPE_ID: &'static str = "demo.peer-count:v1";
}
```

`SnapValue` supplies only that id. A type that forgets rkyv's three derives does not
compile: the error names the missing `Serialize<Strategy<...>>` bound at the type, and
`cannot be stored in a snapshot` where it is used. Nothing about a value type involves
`serde`: the stored bytes are rkyv's, and `serde` in this crate is only for the
journal's `state.json` and the CLI's JSON.

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

## Journals

A journal is a directory: `state.json`, segments, checkpoints, `writer.lock`, and
`current.snap` (a link to the newest checkpoint).

```rust
use bgpkit_snap::journal::Journal;
use bgpkit_snap::TreeId;

let tree = TreeId::from_name("peers");          // the same name is the same journal
let mut j: Journal<PeerCount> = Journal::open("peers.journal", tree)?;
j.insert("10.0.0.0/8".parse()?, PeerCount(3))?;  // buffered
j.sync()?;                                       // durable from here
let path = j.checkpoint(&Opts::now())?;           // snapshot + prune, verified first
println!("{} entries, next sequence {}", j.len(), j.seq());
```

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
`Journal::options(dir, tree).payload(section).open()`, and the section has to match the
directory exactly or the open is refused. `insert_with_blob` and `blobs()` are on the
journal, `section_bytes` and `payload_arena` on the snapshot.

If `state.json` is lost, `Journal::repair(dir, tree, payload)` rebuilds it from the
newest checkpoint, proves the result opens, and leaves the directory untouched if it
cannot. A state file that is present but unreadable is also repair's case; a healthy one
is not, because rewriting it would hide a gap.

## CLI

```
snap build <in.jsonl> --out <file> [--value u8|u16|u32|u64|u128] [--created-at T] [--window A,B]
snap info <file>
snap verify <file>
snap search <file> <address-or-prefix>
snap fold <journal-dir> --out <file> [--tree NAME] [--value-type u8|u16|u32|u64|u128]
```

`build` reads one JSON object per line, `{"prefix": "10.0.0.0/8", "value": 7}`. A value
that is missing, not an unsigned integer, or too wide for the chosen type is an error
with the line number; it never becomes zero.

`info` reads the 192-byte header and nothing else. `verify` checks the container and,
for an integer value type, every body. `search` takes an address or a prefix and prints
the longest match.

`fold` is the one journal operation the CLI has, and it is read-only: it opens the
journal, builds the object its records describe, and writes it atomically to `--out`.
Writing a journal is the application's job, so there is no `insert` here; what a caller
needs afterwards is one file it can ship and query.

```sh
# a program appended to ./tbl; turn it into something everyone can read
snap --json fold ./tbl --out tbl.snap
snap --json search tbl.snap 8.8.8.8
```

A journal is single-writer, so `fold` fails with `another writer holds this journal`
while the application has it open. Either fold the `current.snap` it publishes (the last
checkpoint), or fold after the writer stops.

Every command takes `--json` and prints exactly one JSON object, whatever the outcome:

| command | fields |
| --- | --- |
| `build --json` | `out`, `entries`, `bytes` |
| `info --json` | `type_id`, `content_id`, `file_len`, `file_len_on_disk`, `consistent`, `sections`, `created_at`, `created_at_unix`, `window`, `stream` |
| `verify --json` | `ok`, `type_id`, `sections`, `bodies_checked`, `entries` |
| `search --json` | `query`, `type_id`, `match` (`{prefix, value}` or `null`) |
| `fold --json` | `journal`, `out`, `entries`, `seq`, `type_id`, `bytes` |

Exit codes: `0` success, `1` anything else, with the reason on stderr prefixed `snap: `.
So a caller checks the exit code and, on `--json`, reads stdout as an object.

An object written by another program for its own value type can be `info`'d and
`verify`'d, and `search` says which type it holds and what to do about it. Decoding that
value needs the program that declares the type, because the bytes only mean something to
the `rkyv` layout that wrote them.

### For agents

The CLI is meant to be driven by a program: one JSON object per invocation, stable
field names, exit code `0`/`1`, and no interactive prompts. Some recipes:

```sh
# does this file hold what I think, and is it intact?
snap --json verify big.snap | jq -e '.ok and .bodies_checked'

# which prefix covers this address, and what is its value?
snap --json search big.snap 8.8.8.8 | jq -r '.match.prefix, .match.value'

# a journal your program writes, folded into one object for everyone else
snap --json fold ./tbl --out tbl.snap | jq '.entries, .seq, .bytes'
```

## What it does not do

- A writer holds the whole tree in memory. A build larger than RAM is out of scope.
- One writer per directory (enforced by a lock). Readers are unlimited and need no lock.
- The CLI reads and writes objects whose value type is an integer (`snap.u8:v1` through
  `snap.u128:v1`). A journal or object over a caller's own type is a library call, and
  the CLI says which type it found instead of guessing.
- No compaction beyond checkpoints, no replication, no S3 backend: a journal is a
  directory, and moving it is `mv` or a sync job you write.
