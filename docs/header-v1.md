# bgpkit-snap header, version 1 (draft for review)

Status: draft, pre-publication. Nothing has been published under this format, so
this document is free to break.

This document specifies the fixed-size header that begins every snap object. It
follows the layout conventions of BGP RFCs (RFC 4271, RFC 6396): a bit-aligned
diagram, a field table with offsets and widths, a normative validation list, and
a version rule. Unlike MRT, multi-byte fields are little endian, because the body
is a little-endian rkyv archive and a byte-swapped header would be a second
convention with no benefit.

The key words MUST, MUST NOT, SHOULD, and MAY are used as in RFC 2119.

## 1. Motivation

A snap object can be hundreds of megabytes. A reader that only wants to answer
"what is this, how many 网段, which tree, which state, do I already have it"
must not transfer the body. Today that answer lives in META (near the start of
the body) and in the footer (at the end), so it costs at least two range reads
and one of them touches the archive.

The header makes identification a single read of a fixed 192 bytes, and makes
the writer state its identity claims before the body is read at all.

## 2. Header layout

Offsets are in bytes from the start of the object. Widths are in bytes.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Magic ("BGPKSNAP")                      +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Major               |            Minor              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         HeaderLength          |             Flags             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                            TreeId                             +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            BaseSeq                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          BodyLength                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     SectionTableOffset                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         SectionCount                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            CountV4                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            CountV6                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Families            |          TypeIdLength         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          MetaOffset                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          MetaLength                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         FirstEventTs                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          LastEventTs                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           CreatedAt                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                          Reserved                             +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                          ContentId                            +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                            TypeId                             +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Reserved                             |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         HeaderCrc32c                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## 3. Fields

| Offset | Width | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | Magic | `BGPKSNAP`, exactly. |
| 8 | 2 | Major | Format major version. 1 for this document. |
| 10 | 2 | Minor | Format minor version. 0 for this document. |
| 12 | 2 | HeaderLength | 192 for this document. |
| 14 | 2 | Flags | Bit 0 `HAS_STREAM`, bit 1 `HAS_EVENTS`. All other bits zero. |
| 16 | 16 | TreeId | Identity of the tree this object materializes. All zero when the object is not tied to a stream. |
| 32 | 8 | BaseSeq | Journal sequence the body reflects. Zero when `HAS_STREAM` is clear. |
| 40 | 8 | BodyLength | Bytes from the end of the header to the start of the footer. |
| 48 | 4 | SectionTableOffset | Offset of the first section table entry, relative to the start of the body. |
| 52 | 4 | SectionCount | Number of section table entries. |
| 56 | 4 | CountV4 | Entries in the IPv4 section, 0 when absent. |
| 60 | 4 | CountV6 | Entries in the IPv6 section, 0 when absent. |
| 64 | 2 | Families | Bit 0 IPv4 present, bit 1 IPv6 present. No other bit may be set. |
| 66 | 2 | TypeIdLength | Length of the TypeId string, 1 to 32, excluding the NUL padding. |
| 68 | 4 | MetaOffset | Offset of the META section, relative to the start of the body. |
| 72 | 4 | MetaLength | Length of the META section. |
| 76 | 8 | FirstEventTs | Earliest event timestamp covered, Unix seconds. Zero when `HAS_EVENTS` is clear. |
| 84 | 8 | LastEventTs | Latest event timestamp covered, Unix seconds. Zero when `HAS_EVENTS` is clear. |
| 92 | 8 | CreatedAt | Unix seconds at which the object was written. Never zero. |
| 100 | 12 | Reserved | Zero. |
| 112 | 32 | ContentId | The object's content id, 32 raw bytes. Never all zero. |
| 144 | 32 | TypeId | Value type identifier, ASCII, NUL padded. |
| 176 | 12 | Reserved | Zero. |
| 188 | 4 | HeaderCrc32c | CRC-32C over bytes 0 through 187. |

`ContentId` appears in both the header and META. The META copy is authoritative:
`header.ContentId` is a projection and the reader MUST reject a mismatch. The id
itself is defined by the format document: a hash over the canonical META
projection and the non-META sections, excluding provenance that does not change
the data.

## 4. Validation

A reader MUST reject an object when any of the following holds:

1. `Magic` is not `BGPKSNAP`.
2. `Major` is not 1, or `Minor` exceeds the highest minor the reader supports.
3. `HeaderLength` is not the length this reader was built for.
4. `HeaderCrc32c` does not match bytes 0 through 187.
5. `Families` has a bit set outside bits 0 and 1.
6. `Families` is zero, or a set bit has a matching count of zero, or a clear bit
   has a non-zero count.
7. `TypeIdLength` is zero or greater than 32, or the TypeId field has no NUL at
   or after `TypeIdLength`.
8. `BodyLength` does not equal the object length minus the header and footer.
9. `MetaOffset + MetaLength` exceeds `BodyLength`, or the META section does not
   fit the section table.
10. `CreatedAt` is zero.
11. `HAS_STREAM` is clear and `TreeId` or `BaseSeq` is non-zero.
12. The header projection differs from the META projection in `TreeId`,
    `BaseSeq`, `CountV4`, `CountV6`, `Families`, `TypeId`, `FirstEventTs`,
    `LastEventTs`, or `ContentId`.

Rules 3, 4, and 12 are the ones that keep the header from drifting away from the
body: the header is generated from the same projection function that META uses,
and any disagreement is an error, not a compatibility question.

A reader that only peeks the header and never opens the body MAY skip rules 8,
9, and 12, and MUST report its answer as unverified when it does.

## 5. Version rule

`Major` changes when the layout of any field before `TypeId` changes, when a
reserved bit becomes defined in a way that changes parsing, or when the header
length changes. `Minor` changes when a new optional field is added inside
reserved space or a new flag gains meaning that a reader may ignore.

A reader MUST ignore reserved bits it does not know and MUST NOT write an object
whose reserved bits are non-zero.

## 6. Relationship to the journal

The journal segment header carries the same `TreeId` in the same width, and its
sequence numbers are the `BaseSeq` this header refers to. A snapshot with
`HAS_STREAM` set is a materialization of the journal state at `BaseSeq`; a
snapshot with it clear is a standalone object with no replay relationship.

## 7. Open questions for the reviewers

1. Is 192 bytes the right fixed size, or should the type id move into the body so
   the header can stay 128 bytes with only a hash of the type id?
2. Should `ContentId` be in the header at all, given that the writer must compute
   it before emitting the header?
3. `CreatedAt` is a wall clock in a content-addressed object. Does that make the
   field misleading, and should it instead be the max event timestamp?
4. Is per-object `TypeId` redundancy worth a byte limit at all, or should the
   header carry a registered 2-byte value-type code?
5. Does `BaseSeq` alone identify a stream state, or does a reader also need the
   journal generation (`tree_epoch`) to avoid comparing states across restarts?
