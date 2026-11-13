Source: /root/specs/bgpkit-snap/bgpkit-snap-design.md · generated 2026-11-12 · Project design and BGP usage. The publishable container contract is a separate document, bgpkit-snap-format.md; this one is allowed to name BGPKIT concepts.

# bgpkit snap: project design

Status: design complete, implementation not started. Crate `bgpkit-snap`, types `bgpkit_snap::{Tree, Snapshot, Journal}`, extension `.snap`.

## 1. What it is

A versioned container for prefix tries, plus the library that reads, writes, feeds and queries them. The format contract lives in the companion document; this one covers why the project exists, how BGPKIT's own uses map onto it, and what is planned.

Three reasons it exists:

- **The indexes are scattered.** Five implementations today: `prefix-trie`, `ipnet-trie` behind `bgpkit-commons::rpki::RpkiTrie`, per-peer `IpnetTrie` in focl, `BTreeMap`/`HashMap` in lg, a columnar snapshot in vistrack, plus hash tables and spill files in condenser, and four incompatible persistence formats (wayback's `.rkyv` with a version in the root struct, vistrack's `VISTRK01`, focl's dumps, condenser's spill files).
- **Every app rebuilds the same machinery.** Longest-prefix match, canonical ordering, a file layout, a loader, a cache.
- **Nothing we publish is self-describing or content-addressed.** No artifact says which family, value type or source it holds, and two builds of equal data share no identity, so a bucket cannot dedupe and a reader cannot say which version answered a query.

## 2. What the BGP work needs

Four value shapes cover every consumer. Measured on a real RIB snapshot (section 6), IPv4, 1,042,325 网段:

```text
shape                         archive total   per 网段   owned memory
prefix set                      3,331,008 B     3.20 B       4.02 B
prefix -> u32 (origin)          7,500,308 B     7.20 B      12.07 B
prefix -> u64 (mask, bitset)   11,669,608 B    11.20 B      20.12 B
prefix -> u128 (visibility)    20,008,208 B    19.20 B      36.22 B
```

IPv6 costs more per 网段 at RIB density, because most 网段 sit at /33 to /48 where a five-level node holds one or two entries: 14.95 B per 网段 for a u32 map, of which 10.95 B is nodes. Size every estimate per family.

Coverage of today's call sites, verified by reading each consumer: insert, remove, exact get, longest-prefix match, shortest-prefix match, subtree view and ordered iteration are all used and all available, because the tree is `prefix-trie` underneath.

## 3. Two modes

The value API is where the modes divide, and it is the only rule that can silently corrupt a live tree if broken:

- **Batch** (wayback, commons, prism): build, optionally mutate through `get_mut`, never journal, produce a `Snapshot`, discard the tree. wayback's read-modify-write of `Vec<RoaRecord>` lives here, which is why a fat mutable value never has to be journalled.
- **Live** (focl, a feed): only `apply(record)`; no `&mut V` escape, because a mutation the journal cannot see is a silent divergence. Readers take a shared lock while the writer applies records.

## 4. BGP value types

Registered in the BGP layer, not in the core format:

```text
type_id                value             canonical form
bgpkit.origin:v1       u32               single origin
bgpkit.origin2:v1      u64               primary origin high 32, secondary low 32, 0 for none
bgpkit.roa-set:v1      Vec<RoaRecord>    sorted by (max_len, origin, dates), dates merged
```

`bgpkit.origin2:v1` exists because a 网段 can have two origins in one day: measured on 2026-11-11, 2.14 percent of withdrawal 网段 had more than one origin in the RIB. A u32 value would silently fold the minority origin into the majority, which is exactly the kind of error that shows up later as a phantom AS outage.

## 5. Daily origin trie

The clearest second consumer, and the reason the daily pattern matters: a withdrawal carries no origin and no path, so attributing it to an ASN means looking the 网段 up in the RIB of that day.

One snapshot per day, value `bgpkit.origin2:v1`, built from condenser's `bgp.origin` (about 1.7 M 网段) rather than from raw MRT. Cost: 19 MB per day, about 6.9 GB per year.

The attribution rule, with three outcomes that must stay distinguishable:

```text
exact hit        origin from that day's RIB      rib_exact      observed
covering hit     origin from a covering 网段     rib_covering   inferred, record the covering length
no hit           asn = 0, keep the 网段          orphan         0.66 percent of withdrawals on 2026-11-11
```

Treating a covering hit as exact manufactures false ASN outages, because a more-specific announced by a different AS gets attributed to the upstream origin. `rib_covering` stays a label that a query may use or ignore, never mixed into disconnection statistics.

The lookup is sized by **distinct 网段, not rows**: 1,443,983 distinct withdrawal 网段 on 2026-11-11, so 60 to 80 ms single-threaded, and the join back onto the rows is a hash lookup. Dedupe first, load the day's snapshot once, keep it in memory.

## 6. Measurements

Fixture: RIS peer 193.0.0.56 (AS3333), `bview` 2026-05-11 00:00 UTC, IPv4 1,042,325 and IPv6 246,175 网段. 16 threads, release build, `prefix-trie` 0.10.1, `rkyv` 0.8.18. Ranges are min and max over four warm runs; the cold first run is listed separately.

```text
metric                         warm (4 runs)      cold (run 1)
build u32, 1M 网段               68.3-69.2 ms       87.5 ms
serialize u32                  28.2-32.7 ms       35.8 ms
validate checked, 7.5 MB      0.69-0.82 ms       0.92 ms  (9.2-10.8 GB/s warm)
longest-prefix match u32       25.5-29.7 M ops/s  18.4 M ops/s
iterate all entries            29.1-30.6 ms/M     40.8 ms/M
joint build, 1.29 M 网段         90.7-96.2 ms       113.6 ms
```

Bulk lookups are a throughput problem, and threads beat ordering: 1,000,000 probes run at 17.6 M ops/s single-threaded random, 74.0 M with 16 threads, 42.2 M single-threaded sorted, and 222.3 M with both. Ordering is worth more in parallel because random input makes every thread contend for the same cache lines. A comparison sort costs more than it saves; a counting sort by the top 16 bits does not, and input that is already prefix-ordered is free. `lookup_batch` chunks across threads and only bucketises when the input is not ordered; the implementation belongs in `prefix-trie`, which owns the node layout. For a BGP-sized job (1 to 2 M distinct 网段) none of this matters.

Two rejected alternatives, measured rather than argued:

- **Map IPv4 into IPv6 to get one tree per collector.** Native v4 is 7.20 B per 网段 and 24.6 M lookups/s; the same 网段 at `::ffff:0:0/96` are 16.15 B and 6.4 M/s. Mapping turns an IPv4 tree into a sparse IPv6 one, and the one-handle interface is already available.
- **Sort queries before looking up.** A comparison sort costs 60 ms per million against the 25 ms it saves.

## 7. Many trees

A tree is one view, not one process and not one prefix space. Owned memory at 14.65 B per 网段 for a u32 value and 1.29 M 网段 per tree:

```text
one merged tree, u128 collector mask   ~34 MB total, one journal, one checkpoint
one tree per collector, peer mask      ~34 MB each, 65 collectors is ~2.2 GB
one tree per peer                      ~19 MB each, 65 peers is ~1.2 GB, 1,000 is ~19 GB
```

The default for live feeding is one tree per collector with a peer bitmap in the value: `session_down` for one peer clears that peer's bit and decrements a count, and the 网段 leaves the tree only when the count reaches zero, so a single peer reset does not delete 网段 the collector still sees.

Merging: at build time, fold each collector into the value in one pass; retrospectively, merge snapshots with a streaming k-way fold over key-ordered iterators (84 M entries for 65 trees, about 2.5 s). Merging needs a mergeable value, so the daily trie stores the origin pair rather than a scalar. Session state is never mergeable. The rule: **merge snapshots per day, never merge live trees.**

## 8. Long-term storage

The container is a serving artifact. The durable side is whatever each product already owns: wayback keeps PostgreSQL plus the JSONL transport, recomputable from the RPKI repositories; spectrum and condenser keep ClickHouse for live facts and Parquet in binnacle for the long copy. A snap is never the archival record of anything, and the compatibility promise is correspondingly narrow: major 1 readers read major 1 objects while the crate is maintained, and golden fixtures turn upstream layout drift into a build failure.

## 9. Plan

```text
phase 0  spec, crate skeleton, golden fixtures, table regeneration   0.5 day
phase 1  tree engine, snapshot reader/writer, error taxonomy         2.0 days
phase 2  wayback adapter as the acceptance test (serving only)       1.0 day
phase 3  journal, replay, time travel, capacity measurement          2.0 days
phase 4  adapters: focl, lg, monocle index, condenser                1 day each
```

Phase 1 and 2 are the gate. If the only consumer after phase 3 is the emulator, run it in-process and skip any service work.

### Development harness with wayback

wayback is the proving ground because it already has the two things a format needs: a builder that produces a trie from a known source, and a query surface with a stable contract. The order below keeps production untouched until the differential test passes.

```text
commit 1  snap: golden fixture plus a reader that opens it          RED until commit 2
commit 2  snap: writer that reproduces the fixture byte for byte    GREEN
commit 3  wayback: `snap export` builds a .snap from the builder    artifact, no behaviour change
commit 4  wayback: `snap diff` replays queries against .rkyv and .snap and reports mismatches
```

The fixture is generated by a checked-in script from a few hundred ROA records, so it is small enough to review and its hash is asserted by a test. The differential harness lives in wayback, never in the core crate, and it takes its query corpus from three places: the API access log, generated adversarial cases (supernets, more-specifics, misses, /0, maximum-length edges, dates before the first ROA, v6), and every prefix in the archive itself.

The gate is four checks, in order:

1. Byte identity: the same ROA set built in two insertion orders yields one `content_id`.
2. Semantic identity: `search` and `validate` agree on every query in the corpus, including the order of multi-ROA prefixes.
3. Cost: open time, lookup throughput and resident memory measured against the current `.rkyv`, on the same host.
4. Shadow serve: both backends behind the existing `serve`, same query stream on two ports, responses diffed for 24 hours.

Cutover is a separate decision: publish `roas_trie.snap` alongside `roas_trie.rkyv`, keep the old file readable for one release, and only then stop writing it. The PG ingest and `export-spans` paths are not touched by any of this.

Acceptance tests: golden bytes for three archives; wrong-family read rejected by probe; misalignment and plain-byte-buffer rejected; six distinct integrity failures; one `content_id` across five insertion orders, two ROA ingest orders and two equivalent date-range splits; round trip including empty and single-entry families; replay across a kill between apply and checkpoint; single-writer refusal; gap and session-down semantics; memory accounting within 5 percent of resident growth; open of an 11 MB joint snapshot under 15 ms including the hash path; 10 M lookups/s single-threaded random.

## 10. Decisions

1. Archival stance: two layers, trie rebuildable and the product store durable.
2. Value binding: generic `T` plus a type registry, not a closed enum.
3. Home: new repo `bgpkit/bgpkit-snap`, one crate plus a thin CLI.
4. First consumer: the wayback adapter ships with v1.
5. Object key: dated prefix plus `content_id`.
6. Duplicate RPKI trie in commons: replace after phase 1, behind an unchanged public API.

## 12. Exports

The only export primitive is the ordered iterator: `snapshot.iter()` and `snapshot.iter_subtree(prefix)` yield `(prefix, &ArchivedValue)` in key order. Consumers write their own sink with whatever library they already use, which keeps the core free of serde, arrow and Parquet.

Iteration is the cheap half, 29 to 31 ms per million entries, so a 1.29 M snapshot streams in about 40 ms and the cost is always the sink. Because iteration is in key order, a consumer that writes Parquet gets a prefix-sorted column for free, which is the layout DuckDB and ClickHouse compress best.

Two rules survive: any export goes through the same canonical order, or the exported row order stops matching `content_id`; and when a snap has a Parquet sibling, META's `data_ref` records its hash so the fast artifact and the analysis copy are provably the same data.

## 13. Public surface versus BGPKIT internals

The contribution over `prefix-trie` is the container, the identity rules, the value registry and the journal; the algorithms are not ours. That is worth publishing, and it exists as a gap: `prefix-trie`, `ipnet-trie`, `iptrie`, `poptrie`, `routemap` and `ip_network_table` are all in-memory, `zerotrie` serialises string tries without values, and `matchy` ships an MMDB-compatible IP trie file without content identity or a journal.

So the split is explicit:

- **Publishable** (the format document plus the core crate): object layout, META, the value trait, reader, writer, versioning, journal and merge rule. No collector names, no pipeline descriptions, no bucket layout, no R2 conventions.
- **BGPKIT-side** (this document): the BGP value types, session and coverage semantics, the daily origin trie, the attribution rules, the adapter list.
- **Never in either**: host names, credentials, internal paths, the exact key layout used in our own bucket.

Do not publish before the wayback adapter proves the format; the first public release should follow a working internal consumer, not precede one.
