# bgpkit-snap: developer guide

Status: 0.1.0, pre-stable. The API will change between minor versions: this is a
format and a library that real services have not yet leaned on, so the interface
follows what those services need rather than a freeze date. Do not install
`1.0.0-rc.3` from crates.io and expect this page to work: it predates the owned view,
`TreeId`, `to_snapshot`, merge and the journal durability fixes.

```toml
bgpkit-snap = { git = "https://github.com/bgpkit/bgpkit-snap", branch = "main" }
rkyv = { version = "0.8", features = ["bytecheck"] }   # you derive on it
```

Both extra lines are real: a value type derives `rkyv::Archive`, and the derive
generates paths to the `rkyv` crate itself, so re-exporting it from this crate does
not remove the dependency. `ipnet` is re-exported as `bgpkit_snap::ipnet`, so a lookup that returns a prefix
cannot land on a different `ipnet` version than the one in the signature.

The examples on this page are doctests of the crate (`cargo test --doc` runs them), so
they compile and run against the version they describe.

Audience: someone adding this crate to their own project.
The byte contract lives in [`docs/format.md`](https://github.com/bgpkit/bgpkit-snap/blob/main/docs/format.md);
this page is how to use it.

## What you get, in one paragraph

A map from IP prefixes to your own values, stored in one immutable file that a
service opens once and then queries by longest-prefix match. The same content
always produces the same bytes, so the file has a content id you can record next
to it. An append-only journal lets you build that file incrementally from a live
feed without losing updates; a checkpoint turns the journal into the next file.
There is no server, no query language, and no in-place edit.

## Adding it

Rust 1.88 or newer. What a value type needs depends on how far you go: a plain
`Snapshot` reader wants `Clone + Archive + Serialize` where `Archived: CheckBytes`
(that is `Archive`, `Serialize` and `Deserialize` in the derive list the examples
use); a `Journal` also needs `Archived: Deserialize`, so keep `Deserialize` in the
list even if you only read.

## A value type

A value type is any type that can be archived by `rkyv`, plus a type id and an
optional canonicalisation hook.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PeerCount(u32);

impl bgpkit_snap::SnapValue for PeerCount {
    const TYPE_ID: &str = "example.peer-count:v1";

    // this is the trait's default: a no-op. Correct when the value has one
    // representation (a scalar, a set kept sorted by construction). For anything
    // with more than one, implement it: the content id covers the canonical bytes,
    // so a Vec written as [2,1] and as [1,2] otherwise hashes differently.
    fn canonicalize(&mut self) {}
}
# Ok(())
# }
```

Printing a lookup result needs `Debug` on the *archived* type, which rkyv does not
derive for you: add `#[rkyv(derive(Debug))]` to the value type, or return an owned
value with `snap.owned().lpm(..)`.

With the default hook, `PeerCount(3)` always produces the same bytes, but
`PeerSet(vec![1,2])` and `PeerSet(vec![2,1])` produce different content ids. If
that matters, sort in the hook.

`TYPE_ID` is checked when a reader opens the object: opening a `PeerCount` object
as `u64` fails instead of returning nonsense. It is at most 31 bytes of printable
ASCII with no space, quote or backslash, and it cannot be empty; keep it stable and
versioned, because it is the only thing that names the meaning of the bytes.

## Write and read

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use bgpkit_snap::{Opts, Writer};
# // hidden setup: the value type every example below uses
# use bgpkit_snap::SnapValue;
# #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
# struct PeerCount(u32);
# impl SnapValue for PeerCount {
#     const TYPE_ID: &str = "example.peer-count:v1";
# }

let mut w: Writer<PeerCount> = Writer::new();
w.insert("10.0.0.0/8".parse()?, PeerCount(3))?;      // Err if the prefix has host bits
w.insert("2001:db8::/32".parse()?, PeerCount(7))?;

// either collect the bytes yourself...
let bytes = w.finish(&Opts {
    created_at: 1_794_614_400,  // unix seconds UTC; Opts::now() for "now"
    window: None,               // optional claim: (first_ts, last_ts)
    stream: None,               // set when the object came out of a journal
    extras: &[],                // sections your profile owns, see below
})?;

// ...or let the crate write it atomically
let mut w: Writer<PeerCount> = Writer::new();
w.insert("10.0.0.0/8".parse()?, PeerCount(3))?;
# let peers_path = std::env::temp_dir().join(format!("guide-peers-{}.snap", std::process::id()));
w.finish_to(&peers_path, &Opts::now())?;
# Ok(())
# }
```

Loading many entries at once is `w.insert_many(iter)`, which stops at the first
prefix it refuses rather than skipping it: a writer that silently drops what it cannot
store is worse than one that stops.

`Opts` has no `Default` on purpose: a default would have to invent a creation
time, and `created_at` is provenance, so an invented one is a false claim in a
valid header.

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use bgpkit_snap::Snapshot;
# use bgpkit_snap::SnapValue;
# #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
# struct PeerCount(u32);
# impl SnapValue for PeerCount { const TYPE_ID: &str = "example.peer-count:v1"; }

# let peers_path = std::env::temp_dir().join(format!("guide-peers-open-{}.snap", std::process::id()));
# let _ = &peers_path;
let snap: Snapshot<PeerCount> = Snapshot::open(&peers_path)?;   // any AsRef<Path>
assert_eq!(snap.len(), 1);
# Ok(())
# }
```

If your bytes are already in memory (object storage, an HTTP body), `from_bytes` and
`from_bytes_with` take them directly; `verify_bytes` checks the container without
the value type, which is what a tool that only inspects objects wants.

`open` validates the container and both trie sections: header, layout, section
table, content id, and the archive of the IPv4 and IPv6 sections. A section your
profile added is *not* interpreted at open, because the crate does not know its
shape; that is what `Validator::validate` is for, below. Anything that disagrees
returns an error instead of a partly-trusted mapping. The cost is paid once;
lookups afterwards are in-memory.

## Which query to call

Names are one operation each: `lpm` is the longest covering prefix, `spm` the
least specific covering prefix, `get_exact` only the stored entry.

| you want | call | returns |
| --- | --- | --- |
| value for an address, most specific match | `search(addr)` | `Option<(IpNet, &T::Archived)>` |
| same, for a prefix | `lpm(prefix)` | `Option<(IpNet, &T::Archived)>` |
| value stored exactly at this prefix | `get_exact(prefix)` | `Option<&T::Archived>` |
| the least specific prefix covering this one | `spm(prefix)` | `Option<(IpNet, &T::Archived)>` |
| whether anything covers this prefix | `is_covered(prefix)` | `bool` |
| whether the whole range is tiled by entries | `is_covered_in_aggregate(prefix)` | `bool` |
| this prefix when stored, plus everything under it | `children(prefix)` | `Vec<(IpNet, &T::Archived)>` |
| every prefix covering this one | `cover(prefix)` | `Vec<(IpNet, &T::Archived)>` |
| the whole object | `iter()` / `keys()` / `values()` | iterators |

The prefix-based calls take `IpNet` and handle both address families, so a caller
does not branch on the family; `search` takes an `IpAddr` instead.
`get_exact` and `values()` return the value alone; everything
else that returns a value also returns the prefix it came from, which is what you
want when an ancestor answers.

Two more that do not fit a table row: `iter_from(prefix, inclusive)` for a trie-ordered
range inside that prefix's family, and `contains_key(prefix)` when a bool is all you need.

### When you want the value, not a view of it

Every call above hands back `&T::Archived`, which is the point of the format but
forces your code to name the archived type. `snap.owned()` answers the same
questions with `T`:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# use bgpkit_snap::{SnapValue, Snapshot};
# #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
# struct PeerCount(u32);
# impl SnapValue for PeerCount { const TYPE_ID: &str = "example.peer-count:v1"; }
# let snap: Snapshot<PeerCount> = {
#     let mut w = bgpkit_snap::Writer::<PeerCount>::new();
#     w.insert("10.0.0.0/8".parse()?, PeerCount(1))?;
#     Snapshot::from_bytes(&w.finish(&bgpkit_snap::Opts::now())?)?
# };
let owned = snap.owned();
let hit: Option<(bgpkit_snap::ipnet::IpNet, PeerCount)> = owned.lpm("10.1.2.0/24".parse()?)?;
let under: Vec<(bgpkit_snap::ipnet::IpNet, PeerCount)> = owned.children("10.0.0.0/8".parse()?)?;
let all: Vec<(bgpkit_snap::ipnet::IpNet, PeerCount)> = owned.iter()?;
// a value the type cannot decode is an Err here, not a missing prefix
# Ok(())
# }
```

Every owned query returns `Result`: a value that is present but cannot be
deserialized must not read as absent, which is what made `len()` disagree with
`iter().count()` in an earlier draft. `owned.iter()` materialises the whole object;
the archived view streams if you need that.

## Merging a day

The per-source objects become one day's object:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# use bgpkit_snap::{Opts, Snapshot};
# use bgpkit_snap::SnapValue;
# #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
# struct PeerCount(u32);
# impl SnapValue for PeerCount { const TYPE_ID: &str = "example.peer-count:v1"; }

let a: Snapshot<PeerCount> = Snapshot::open("rrc00.snap")?;
let b: Snapshot<PeerCount> = Snapshot::open("route-views2.snap")?;

// later inputs win where they overlap
let bytes = Snapshot::merge_last_wins(&[&a, &b], &Opts::now())?;

// or decide the overlap yourself; `None` drops the prefix
let bytes = Snapshot::merge_with(&[&a, &b], &Opts::now(), |_, earlier, later| Some(PeerCount(earlier.0.max(later.0))))?;
std::fs::write("day.snap", &bytes)?;
# Ok(())
# }
```

The result does not depend on input order for disjoint inputs, because it is built by
the same writer as any other object. A merge drops the stream coordinates: several
streams are not one stream. `opts.window` left as `None` becomes the union of the
inputs' windows when every input declares one, and stays absent otherwise, so a merge
never invents a coverage claim.

## Your own sections

A profile can attach extra bytes next to the tries, for example an arena that
handle values point into.

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use bgpkit_snap::{ExtraSection, KIND_PAYLOAD, Opts, Writer};
# use bgpkit_snap::SnapValue;
# #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
# struct PeerCount(u32);
# impl SnapValue for PeerCount { const TYPE_ID: &str = "example.peer-count:v1"; }

let mut w: Writer<PeerCount> = Writer::new();
w.insert("10.0.0.0/8".parse()?, PeerCount(3))?;
let arena: Vec<u8> = vec![1, 2, 3, 4];
let bytes = w.finish(&Opts {
    created_at: 1_794_614_400,
    extras: &[ExtraSection { id: 16, kind: KIND_PAYLOAD, required: true, bytes: &arena }],
    ..Opts::now()
})?;
# let peers_path = std::env::temp_dir().join(format!("guide-sections-{}.snap", std::process::id()));
std::fs::write(&peers_path, &bytes)?;
# Ok(())
# }
```

Section ids 2 and 3 are the tries; 16 and up are yours. A section marked
`required` makes a reader that does not implement it refuse the object by id,
which is what you want: a reader silently skipping your section would answer from
less than the writer stored.

A reader that does implement it registers a `Validator`. Both hooks matter: `knows`
says which ids you handle, and is asked **only about required sections** (an optional
one is not a reason to refuse the object); `validate` runs after both trie archives
are byte-checked, and is where a check on your section belongs, including the kind of
an optional one. `SnapshotView::entry(id)` gives you that table row.

Be clear about `validate`'s reach: it is handed the header, the section table and
the raw bytes, **not** the typed tree, so it can check the shape of your section
(for example that the arena is long enough to hold the handles you are about to
resolve) but it cannot walk values looking for bad offsets. A handle's range is
checked when you resolve it, which is the only place that knows the value type:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use bgpkit_snap::{Entry, Snapshot, SnapshotView, Validator};
# use bgpkit_snap::SnapValue;
# #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
# struct PeerCount(u32);
# impl SnapValue for PeerCount { const TYPE_ID: &str = "example.peer-count:v1"; }

struct MySections;

impl Validator for MySections {
    fn knows(&self, entry: &Entry) -> bool {
        entry.id == 16
    }

    // the crate does not interpret your section; this hook sees its bytes, not
    // the values that point into it
    fn validate(&self, view: &SnapshotView<'_>) -> Result<(), bgpkit_snap::Error> {
        let bytes = view.section_bytes(16).unwrap_or_default();
        // an empty arena is legal: a journal with no blobs writes the section
        // anyway, and a reader that demanded four bytes here could not open it
        if !bytes.len().is_multiple_of(4) {
            return Err(bgpkit_snap::Error::BadSectionTable("arena is not whole handles"));
        }
        Ok(())
    }
}

# let peers_path = std::env::temp_dir().join(format!("guide-validator-{}.snap", std::process::id()));
# let snap: bgpkit_snap::Snapshot<PeerCount> = bgpkit_snap::Snapshot::from_bytes_with(
#     &{
#         let mut w = bgpkit_snap::Writer::<PeerCount>::new();
#         w.insert("10.0.0.0/8".parse()?, PeerCount(1))?;
#         let arena = [1u8, 2, 3, 4];
#         w.finish(&bgpkit_snap::Opts {
#             created_at: 1_794_614_400,
#             window: None,
#             stream: None,
#             extras: &[bgpkit_snap::ExtraSection {
#                 id: 16,
#                 kind: bgpkit_snap::KIND_PAYLOAD,
#                 required: true,
#                 bytes: &arena,
#             }],
#         })?
#     },
#     &MySections,
# )?;
let arena = snap.section_bytes(16);
# Ok(())
# }
```

## Journal: building the object from a feed

Use a journal when the tree changes over time and you cannot afford to rebuild
the whole file for every change.

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use bgpkit_snap::journal::Journal;
use bgpkit_snap::{Opts, TreeId};
# use bgpkit_snap::SnapValue;
# #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
# struct PeerCount(u32);
# impl SnapValue for PeerCount { const TYPE_ID: &str = "example.peer-count:v1"; }


// the id names this tree: the same name reopens the same journal, and a typo
// gives a different journal instead of adopting this one
# let feed_dir = std::env::temp_dir().join(format!("guide-feed-{}", std::process::id()));
# std::fs::remove_dir_all(&feed_dir).ok();
let mut journal: Journal<PeerCount> =
    Journal::open(&feed_dir, TreeId::from_name("peer-counts"))?;
journal.insert("10.0.0.0/8".parse()?, PeerCount(3))?;
journal.sync()?;                                        // durable on return

let object = journal.checkpoint(&Opts::now())?;          // verified, then named
// <journal dir>/current.snap now points at `object`
# Ok(())
# }
```

Rules the implementation enforces, because they are the difference between a
smaller tree and a correct one:

- One writer per journal directory. A second `open` fails.
- `sync` is what makes a record durable *without* a checkpoint: a record that no
  checkpoint covers is gone if you crash before `sync`. A checkpoint fsyncs the
  object and the state that names it, so records it covers are durable too.
- `checkpoint` builds an ordinary object, verifies it end to end, names it in
  `state.json`, publishes `current.snap` in the journal directory as a link to it,
  and only then prunes segments it fully covers. A service opens
  `<dir>/current.snap` with the same value type and, if the journal was opened with
  a payload section, the same `Validator`; a plain `open` refuses an object whose
  required section it does not know.
- On open, the journal recovers from that checkpoint plus the records above it.
  A hole in the sequence, a segment with an unreadable header, an unreadable or
  malformed `state.json`, and a checkpoint from another tree are errors.
- A torn tail is the one tolerated failure. A bad frame ends the scan of that
  segment; the records after it are not read and the journal continues in a new
  segment. A failed write *inside* the writing process is different: the next
  append cuts those bytes away and reuses the number, because they were never
  acknowledged.
- If `state.json` is lost but a checkpoint survives, `Journal::repair(dir, tree_id,
  payload)` is the way back: it takes the newest object, adopts its tree and
  generation, writes the state file and hands you the journal `open` would have
  returned. Records above that checkpoint are replayed; segments already pruned
  and not covered by it are gone, and the call does not pretend otherwise. Plain
  `open` refuses that directory on purpose, because it cannot tell which object is
  current.
- A checkpoint carries the journal's own sections only: the tries and, when the
journal was opened with one, its payload. Your own sections belong to a general
object written with `Writer::finish`, because a checkpoint has to be an object the
journal itself can reopen. The payload section is written even when the arena is
empty, so a validator that requires it can always open the object. Opening the
directory without that payload is refused: the arena the handles point into would
otherwise be dropped.
- `checkpoint_with(&opts, &validator)` runs your validator over the finished object
  before it is committed, for a profile whose own section has rules the container
  cannot check.

A journal answers the same two lookup shapes as a snapshot, under the same names:
`get_exact(prefix)` and `lpm(prefix)`, plus `for_each(f)` to walk every prefix it
holds. `children`, `cover` and the iterators belong to the immutable object. When you need them without
touching the disk:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# use bgpkit_snap::journal::Journal;
# use bgpkit_snap::{Opts, TreeId};
# use bgpkit_snap::SnapValue;
# #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
# struct PeerCount(u32);
# impl SnapValue for PeerCount { const TYPE_ID: &str = "example.peer-count:v1"; }
# let d = std::env::temp_dir().join(format!("guide-to-snapshot-{}", std::process::id()));
# std::fs::remove_dir_all(&d).ok();
# let mut journal: Journal<PeerCount> = Journal::open(&d, TreeId::from_name("guide-to-snapshot"))?;
let snap = journal.to_snapshot(&Opts::now())?;   // every Snapshot query, no file
let under = snap.children("10.0.0.0/8".parse()?);
# Ok(())
# }
```

`to_snapshot` builds the object the journal would checkpoint and opens it, which is
why it works where a plain `Snapshot::from_bytes` would refuse: the journal knows the
payload section it wrote. `journal.to_bytes(&opts)` gives the same object as bytes,
for a caller that wants to ship it somewhere else.

The journal holds the tree in memory. It is a writer's structure, not a store
  for a tree larger than your RAM.

`insert_with_blob` exists for handle values. The value has to be encoded before the
record is appended, so the offset cannot be discovered afterwards; the call takes a
closure that receives it:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use bgpkit_snap::journal::{Journal, PayloadSection};
use bgpkit_snap::{SnapValue, TreeId};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PathRef { off: u64, len: u64 }     // u64: an arena may pass 4 GiB
impl SnapValue for PathRef { const TYPE_ID: &str = "example.path-ref:v1"; }

# let journal_path = std::env::temp_dir().join(format!("guide-aspaths-{}.journal", std::process::id()));
# std::fs::remove_dir_all(&journal_path).ok();
let mut journal: Journal<PathRef> = Journal::open_with_payload(
    &journal_path,
    TreeId::from_name("aspaths"),
    PayloadSection::payload(16),
)?;
let arena_bytes: &[u8] = b"aspathbytes!";   // 12 bytes: this toy profile pads to 4
let inserted = journal.insert_with_blob("10.0.0.0/8".parse()?, arena_bytes, |off| PathRef {
    off,
    len: arena_bytes.len() as u64,
})?;
assert_eq!(inserted.offset, 0);   // the first blob in an empty arena
# Ok(())
# }
```

It returns `BlobInserted { seq, offset }`. Replay rebuilds the payload section in
record order, so every offset reproduces. It requires the journal to have been
opened with a payload section.

Removal is `withdraw(prefix)` or `withdraw_at(prefix, Times)`; either appends the
record before the tree changes, so a failed append leaves the tree holding what the
previous record promised. Both, like every insert path, refuse a prefix with host
bits set.

`insert_at` and `insert_with_blob_at` take a `Times { recv_ts, event_ts }`: unix
seconds, both optional, both written into the record. The plain `insert` leaves
them zero, which is right for a feed with no clock and wrong for one that has
one, because a record is the only place that time is kept.

## Pitfalls worth knowing before you ship

- **Prefixes must be canonical.** Every write path refuses `addr() != network()` with
  `Error::BadPrefix`, in release builds too, rather than storing the value under the
  network address. Reads that take a prefix (`get_exact`, `contains_key`, `lpm`,
  `children`, `cover`) read it as its network address.
- **`lpm` is a longest-prefix match, not an exact one.** For an exact check use `get_exact`,
  or you will compare a value from an ancestor prefix and believe it is the
  child's.
- **Keep the value small and fixed-size.** A value that carries a `Vec` or a `String`
  makes the archive build an out-of-line buffer per prefix. Measured on a real update
  stream (1.4 million BGP4MP records, 46 peers, 96,000 distinct prefixes): a
  `Vec`-valued cell came to 934 bytes per prefix at the announcement multiplicity of
  that stream, about 25 bytes per announcement, and an 8-byte handle into a payload
  section kept the value at 8 bytes. That same stream also shows why a dictionary
  matters: 3.3 million announcements carried only 38,903 distinct AS paths.
- **`canonicalize` decides the content id.** Two producers of the same logical
  data that sort or dedupe differently produce different objects. Do the sorting
  in the hook, not in your caller.
- **`rkyv` is part of the interface.** Archived access means your crate depends on
  it, and the re-export does not change that: the derive writes `rkyv::` paths.
  The `*_owned` variants exist so a read path with no interest in archives still
  does not have to name the types.
- **Timestamps are unix seconds UTC everywhere**, and a journal record's address
  is in network order with the IPv4 bytes left-aligned.
- **A value that changes every second makes a poor identity.** The content id is
  over content, not over time: `created_at` is deliberately outside it, so two
  objects with the same data share an id.
- **Do not merge two snapshots of mutable state.** Merging is only defined for
  values that form a join-semilattice. A RIB is session state: rebuild it through
  the journal instead.

## Cost, measured

Host: a 16-thread x86-64 dev box, Rust 1.88 release build, page cache warm, one
thread, values in memory. Treat these as orders of magnitude, not as your numbers.

From the ROA index used by wayback (1,172,951 prefixes, values of a few hundred
bytes): 219,462,112 bytes on disk, open 365 ms, 100k longest-prefix lookups in
2.1 ms. From a per-peer RIB index (1,200,000 prefixes, `u64` values):
11,034,048 bytes, write 102 ms, open 8 ms, 1000 lookups under 1 ms. A journal run
at the same scale wrote 1.17M records in 1.3 s, recovered in 0.5-0.75 s, and
checkpointed in 2.4-2.6 s.

## What it is not

No query language, no transactions across objects, no in-place update, no
byte-range reads (a trie-ordered range walk via `iter_from` and a subtree via
`children` do exist), no cross-language reader today: the container rules (header, section table,
identity, journal framing) are language-neutral, but a trie section is a `rkyv`
archive of a `prefix_trie` map, so reading one outside Rust means reimplementing
that layout.
