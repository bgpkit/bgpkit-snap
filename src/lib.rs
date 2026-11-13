//! `bgpkit-snap` PoC: a versioned prefix-trie container.
//!
//! One immutable object = a 64-byte prefix, sections (META, TRIE_V4, TRIE_V6)
//! and a footer with per-section hashes. The normative contract is
//! `/root/specs/bgpkit-snap/bgpkit-snap-format.md`; this file is the working
//! PoC of it, not the shipped crate.

use std::fmt;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::rkyv::ArchivedPrefixMap;

use prefix_trie::PrefixMap;
use rkyv::rancor::Error as RkyvError;
use rkyv::util::AlignedVec;

pub mod journal;

pub mod header;

pub use header::{Header, HeaderInputs, StreamRef, HEADER_LEN, MAGIC, MAJOR, MINOR};

pub const FOOTER_MAGIC: &[u8; 4] = b"SNPF";
pub const ENTRY_LEN: usize = 64;
pub const ALIGN: usize = 16;
const CONTENT_DOMAIN: &[u8] = b"snap-content-v1\0";

pub const ID_META: u16 = 1;
pub const ID_V4: u16 = 2;
pub const ID_V6: u16 = 3;

// ---------------------------------------------------------------- errors

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    BadMagic,
    UnsupportedMajor(u16),
    Truncated {
        need: usize,
        have: usize,
    },
    BadFooter,
    BadSectionTable(&'static str),
    SectionMisaligned(u16),
    SectionOverlap(u16),
    SectionHash(u16),
    BodyHash,
    ContentId,
    BadMeta(String),
    TypeMismatch {
        expected: &'static str,
        found: String,
    },
    CountMismatch {
        family: u8,
        meta: u64,
        actual: u64,
    },
    ProbeMismatch {
        family: u8,
        which: &'static str,
    },
    MissingMeta,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::BadMagic => write!(f, "not a snap object (magic mismatch)"),
            Error::UnsupportedMajor(v) => write!(
                f,
                "unsupported major version {v}, highest supported is {MAJOR}"
            ),
            Error::Truncated { need, have } => {
                write!(f, "truncated: need {need} bytes, have {have}")
            }
            Error::BadFooter => write!(f, "footer magic mismatch"),
            Error::BadSectionTable(why) => write!(f, "bad section table: {why}"),
            Error::SectionMisaligned(id) => write!(f, "section {id} is not 16-byte aligned"),
            Error::SectionOverlap(id) => write!(f, "section {id} overlaps another section"),
            Error::SectionHash(id) => write!(f, "section {id} blake3 mismatch"),
            Error::BodyHash => write!(f, "body blake3 mismatch"),
            Error::ContentId => write!(f, "content_id mismatch"),
            Error::BadMeta(e) => write!(f, "bad META: {e}"),
            Error::TypeMismatch { expected, found } => {
                write!(
                    f,
                    "value type mismatch: expected {expected}, object declares {found}"
                )
            }
            Error::CountMismatch {
                family,
                meta,
                actual,
            } => {
                write!(
                    f,
                    "count mismatch for family {family}: meta {meta}, archive {actual}"
                )
            }
            Error::ProbeMismatch { family, which } => {
                write!(f, "probe mismatch for family {family} ({which})")
            }
            Error::MissingMeta => write!(f, "META section is missing"),
        }
    }
}

impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

// ---------------------------------------------------------------- values

/// The exact serializer `rkyv::to_bytes` builds, so the value bound can name it.
pub type HighSer<'a> =
    rkyv::api::high::HighSerializer<AlignedVec, rkyv::ser::allocator::ArenaHandle<'a>, RkyvError>;

/// A value type that can live in a snap object.
pub trait SnapValue: rkyv::Archive + Clone + for<'a> rkyv::Serialize<HighSer<'a>> {
    /// Stable identifier, e.g. `snap.u32:v1`.
    const TYPE_ID: &'static str;
    /// Declared width in bytes, advisory, checked against `size_of`.
    const WIDTH: u32;
    /// Put the value in canonical form before it is written.
    fn canonicalize(&mut self) {}
}

/// Value types that can be written to and read back from a journal.
///
/// A blanket impl covers every value type whose derives give the archived form
/// validation and deserialization, so no value type implements this by hand.
pub trait Codec: SnapValue + Sized {
    /// The archived bytes stored in a record.
    fn encode(value: &Self) -> Result<Vec<u8>, Error>;
    /// Rebuild an owned value from record bytes.
    fn decode(bytes: &[u8]) -> Result<Self, Error>;
    /// Copy an archived value (from a snapshot) into owned form.
    fn materialize(archived: &Self::Archived) -> Result<Self, Error>;
}

impl<T> Codec for T
where
    T: SnapValue,
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<RkyvError>>,
{
    fn encode(value: &Self) -> Result<Vec<u8>, Error> {
        rkyv::to_bytes::<RkyvError>(value)
            .map(|bytes| bytes.to_vec())
            .map_err(|_| Error::BodyHash)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        rkyv::from_bytes::<T, RkyvError>(bytes).map_err(|_| Error::BodyHash)
    }

    fn materialize(archived: &T::Archived) -> Result<Self, Error> {
        rkyv::deserialize::<T, RkyvError>(archived).map_err(|_| Error::BodyHash)
    }
}

impl SnapValue for u32 {
    const TYPE_ID: &'static str = "snap.u32:v1";
    const WIDTH: u32 = 4;
}

impl SnapValue for u64 {
    const TYPE_ID: &'static str = "snap.u64:v1";
    const WIDTH: u32 = 8;
}

// ---------------------------------------------------------------- metadata

fn jstr(s: &str) -> serde_json::Value {
    serde_json::Value::String(s.to_string())
}

/// Build the META projection (everything except `content_id` and
/// `provenance.created_at`). `serde_json::Map` is BTreeMap-backed by default,
/// so keys serialize sorted, which is the canonical form the contract wants.
/// The hashed projection: data only, never provenance. Every value is an
/// integer or an ASCII string, so canonical serialization cannot vary between
/// implementations.
fn data_projection<T: SnapValue>(
    v4: &PrefixMap<Ipv4Net, T>,
    v6: &PrefixMap<Ipv6Net, T>,
    inputs: &HeaderInputs,
) -> serde_json::Value {
    use serde_json::{json, Map, Value};

    let mut families = Vec::new();
    let mut counts = Map::new();
    let mut probe = Map::new();
    if !v4.is_empty() {
        families.push(Value::from(4));
        counts.insert("v4".into(), Value::from(v4.len() as u64));
        let first = v4
            .iter()
            .next()
            .map(|(p, _)| p.to_string())
            .unwrap_or_default();
        let last = v4
            .iter()
            .last()
            .map(|(p, _)| p.to_string())
            .unwrap_or_default();
        probe.insert("v4_first".into(), jstr(&first));
        probe.insert("v4_last".into(), jstr(&last));
    }
    if !v6.is_empty() {
        families.push(Value::from(6));
        counts.insert("v6".into(), Value::from(v6.len() as u64));
        let first = v6
            .iter()
            .next()
            .map(|(p, _)| p.to_string())
            .unwrap_or_default();
        let last = v6
            .iter()
            .last()
            .map(|(p, _)| p.to_string())
            .unwrap_or_default();
        probe.insert("v6_first".into(), jstr(&first));
        probe.insert("v6_last".into(), jstr(&last));
    }

    let mut meta = Map::new();
    meta.insert(
        "canonical".into(),
        json!({"host_bits": "zeroed", "prefix_form": "network/len"}),
    );
    meta.insert("counts".into(), Value::Object(counts));
    meta.insert("families".into(), Value::Array(families));
    meta.insert("kind".into(), jstr("prefix-map"));
    meta.insert("probe".into(), Value::Object(probe));
    if let Some(stream) = inputs.stream {
        meta.insert(
            "stream".into(),
            json!({
                "base_seq": stream.base_seq,
                "generation": hex16(&stream.generation),
                "tree_id": hex16(&stream.tree_id),
            }),
        );
    }
    if inputs.first_event_ts != 0 || inputs.last_event_ts != 0 {
        meta.insert(
            "events".into(),
            json!({"first_event_ts": inputs.first_event_ts, "last_event_ts": inputs.last_event_ts}),
        );
    }
    meta.insert(
        "trie_layout".into(),
        json!({
            "crate": "prefix-trie",
            "key_bits": {"v4": 32, "v6": 128},
            "node_bits": 5,
            "rkyv": "0.8",
            "version": "0.10"
        }),
    );
    meta.insert(
        "value".into(),
        json!({"note": "PoC", "type_id": T::TYPE_ID, "width": T::WIDTH}),
    );
    Value::Object(meta)
}

fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn framed_hasher() -> blake3::Hasher {
    blake3::Hasher::new()
}

fn update_framed(h: &mut blake3::Hasher, id: u16, bytes: &[u8]) {
    h.update(&id.to_le_bytes());
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

// ---------------------------------------------------------------- writer

pub struct Writer<T: SnapValue> {
    v4: PrefixMap<Ipv4Net, T>,
    v6: PrefixMap<Ipv6Net, T>,
}

impl<T: SnapValue> Default for Writer<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: SnapValue> Writer<T> {
    pub fn new() -> Self {
        Writer {
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
        }
    }

    pub fn insert(&mut self, prefix: IpNet, mut value: T) {
        value.canonicalize();
        match prefix {
            IpNet::V4(p) => {
                self.v4.insert(p, value);
            }
            IpNet::V6(p) => {
                self.v6.insert(p, value);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serialize into the container. `created_at` must be RFC 3339.
    pub fn finish(self, created_at: &str, source: &str) -> Result<Vec<u8>, Error> {
        self.finish_with(created_at, source, HeaderInputs::default())
    }

    /// Serialize, declaring the stream state and event window the body reflects.
    pub fn finish_with(
        self,
        created_at: &str,
        source: &str,
        inputs: HeaderInputs,
    ) -> Result<Vec<u8>, Error> {
        let created_unix = chrono::DateTime::parse_from_rfc3339(created_at)
            .map_err(|e| Error::BadMeta(format!("created_at is not RFC 3339: {e}")))?
            .timestamp();

        let v4_bytes = rkyv::to_bytes::<RkyvError>(&self.v4).map_err(|_| Error::BodyHash)?;
        // one archive is limited to 2 GiB by the 32-bit relative offsets; larger
        // sets shard, and a writer must say so rather than emit an invalid object
        if v4_bytes.len() as u64 >= 2 * 1024 * 1024 * 1024 {
            return Err(Error::BadMeta(
                "TRIE_V4 exceeds the 2 GiB archive limit".into(),
            ));
        }
        let v6_bytes = rkyv::to_bytes::<RkyvError>(&self.v6).map_err(|_| Error::BodyHash)?;
        if v6_bytes.len() as u64 >= 2 * 1024 * 1024 * 1024 {
            return Err(Error::BadMeta(
                "TRIE_V6 exceeds the 2 GiB archive limit".into(),
            ));
        }
        let mut trie_sections: Vec<(u16, &[u8])> = Vec::new();
        if !self.v4.is_empty() {
            trie_sections.push((ID_V4, &v4_bytes));
        }
        if !self.v6.is_empty() {
            trie_sections.push((ID_V6, &v6_bytes));
        }

        // content_id covers the data projection and the trie sections. Provenance
        // is outside it on purpose: the id addresses data, not build history.
        let proj = data_projection(&self.v4, &self.v6, &inputs);
        let proj_bytes = serde_json::to_vec(&proj).map_err(|e| Error::BadMeta(e.to_string()))?;
        let mut id_hasher = framed_hasher();
        id_hasher.update(CONTENT_DOMAIN);
        id_hasher.update(&proj_bytes);
        for (id, bytes) in &trie_sections {
            update_framed(&mut id_hasher, *id, bytes);
        }
        let content_hash = id_hasher.finalize();
        let content_id_hex = content_hash.to_hex().to_string();

        // META nests the hashed projection verbatim, so a reader can rehash the
        // exact bytes the writer hashed without reconstructing anything.
        let meta = serde_json::json!({
            "projection": proj,
            "content_id": content_id_hex,
            "provenance": {
                "generator": "bgpkit-snap/0.0.1",
                "producer": "bgpkit-snap/0.0.1",
                "created_at": created_at,
                "sources": [{"uri": source}],
            },
        });
        let meta_bytes = serde_json::to_vec(&meta).map_err(|e| Error::BadMeta(e.to_string()))?;

        let mut offsets: Vec<(u16, u64, u64, [u8; 32])> = Vec::new();
        let mut body: Vec<u8> = Vec::new();
        let push_section = |body: &mut Vec<u8>,
                            offsets: &mut Vec<(u16, u64, u64, [u8; 32])>,
                            id: u16,
                            bytes: &[u8]| {
            while !(HEADER_LEN + body.len()).is_multiple_of(ALIGN) {
                body.push(0);
            }
            let off = (HEADER_LEN + body.len()) as u64;
            body.extend_from_slice(bytes);
            offsets.push((id, off, bytes.len() as u64, *blake3::hash(bytes).as_bytes()));
        };
        push_section(&mut body, &mut offsets, ID_META, &meta_bytes);
        for (id, bytes) in trie_sections {
            push_section(&mut body, &mut offsets, id, bytes);
        }

        let body_hash = {
            let mut h = blake3::Hasher::new();
            for (_, off, len, _) in &offsets {
                let start = (*off as usize) - HEADER_LEN;
                h.update(&body[start..start + *len as usize]);
            }
            h.finalize()
        };

        let mut footer = Vec::new();
        footer.extend_from_slice(&(offsets.len() as u32).to_le_bytes());
        footer.extend_from_slice(FOOTER_MAGIC);
        footer.extend_from_slice(&1u32.to_le_bytes());
        footer.extend_from_slice(&0u32.to_le_bytes());
        for (id, off, len, hash) in &offsets {
            footer.extend_from_slice(&id.to_le_bytes());
            footer.extend_from_slice(&id.to_le_bytes());
            footer.extend_from_slice(&0u16.to_le_bytes());
            footer.push(ALIGN as u8);
            footer.push(0);
            footer.extend_from_slice(&off.to_le_bytes());
            footer.extend_from_slice(&len.to_le_bytes());
            footer.extend_from_slice(hash);
            footer.extend_from_slice(&[0u8; 8]);
        }
        footer.extend_from_slice(body_hash.as_bytes());

        let footer_off = (HEADER_LEN + body.len()) as u64;
        let file_len = footer_off + footer.len() as u64;
        let meta_entry = offsets
            .iter()
            .find(|(id, _, _, _)| *id == ID_META)
            .expect("META is always written first");

        let (flags, tree_id, generation, base_seq) = match inputs.stream {
            Some(s) => (header::FLAG_HAS_STREAM, s.tree_id, s.generation, s.base_seq),
            None => (0u16, [0u8; 16], [0u8; 16], 0u64),
        };
        let flags = if inputs.first_event_ts != 0 || inputs.last_event_ts != 0 {
            flags | header::FLAG_HAS_EVENTS
        } else {
            flags
        };
        let mut families = 0u16;
        if !self.v4.is_empty() {
            families |= header::FAMILY_V4;
        }
        if !self.v6.is_empty() {
            families |= header::FAMILY_V6;
        }
        let header = Header {
            flags,
            tree_id,
            generation,
            content_id: *content_hash.as_bytes(),
            type_id: T::TYPE_ID.to_string(),
            base_seq,
            file_len,
            footer_off,
            meta_off: meta_entry.1,
            meta_len: meta_entry.2 as u32,
            section_count: offsets.len() as u32,
            count_v4: self.v4.len() as u32,
            count_v6: self.v6.len() as u32,
            first_event_ts: inputs.first_event_ts,
            last_event_ts: inputs.last_event_ts,
            created_at: created_unix,
            families,
        };

        let mut out = header.encode().to_vec();
        out.extend_from_slice(&body);
        out.extend_from_slice(&footer);
        // the writer refuses to emit an object its own reader would reject
        Header::parse(&out)?;
        debug_assert_eq!(out.len() as u64, file_len);
        Ok(out)
    }
}

// ---------------------------------------------------------------- reader

pub struct Snapshot<T: Codec> {
    bytes: AlignedVec,
    meta: serde_json::Value,
    sections: Vec<(u16, usize, usize)>,
    content_id: String,
    _t: std::marker::PhantomData<T>,
}

impl<T: Codec> fmt::Debug for Snapshot<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("content_id", &self.content_id)
            .field("entries", &self.len())
            .field("entries", &self.len())
            .finish()
    }
}

impl<T: Codec> Snapshot<T> {
    /// Opening is the only place that needs the validating bound: it proves the
    /// archives are sound, after which the unchecked views below are safe.
    pub fn open(path: &str) -> Result<Self, Error>
    where
        T::Archived:
            for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>,
    {
        Self::from_bytes(&std::fs::read(path)?)
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error>
    where
        T::Archived:
            for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>,
    {
        let header = Header::parse(raw)?;
        header.check_layout(raw.len())?;
        if header.type_id != T::TYPE_ID {
            return Err(Error::TypeMismatch {
                expected: T::TYPE_ID,
                found: header.type_id.clone(),
            });
        }
        let footer_off = header.footer_off as usize;

        // every section byte is read from an aligned copy: rkyv validation
        // depends on the alignment of the slice it is handed, so validating the
        // caller's bytes would accept or reject one object depending on where
        // the caller's buffer sits
        let mut aligned = AlignedVec::with_capacity(raw.len());
        aligned.extend_from_slice(raw);

        let footer = &aligned[footer_off..];
        let count = u32::from_le_bytes(footer[0..4].try_into().unwrap()) as usize;
        if &footer[4..8] != FOOTER_MAGIC {
            return Err(Error::BadFooter);
        }
        let flags = u32::from_le_bytes(footer[8..12].try_into().unwrap());
        if flags & 1 == 0 {
            return Err(Error::BadSectionTable("body hash flag is not set"));
        }
        if count != header.section_count as usize {
            return Err(Error::BadSectionTable(
                "footer count disagrees with the header",
            ));
        }

        let mut sections: Vec<(u16, usize, usize)> = Vec::new();
        let mut prev_id = 0u16;
        let mut prev_end = HEADER_LEN;
        for i in 0..count {
            let e = &footer[16 + i * ENTRY_LEN..16 + (i + 1) * ENTRY_LEN];
            let id = u16::from_le_bytes([e[0], e[1]]);
            let align = e[6] as usize;
            let off = u64::from_le_bytes(e[8..16].try_into().unwrap()) as usize;
            let len = u64::from_le_bytes(e[16..24].try_into().unwrap()) as usize;
            let hash = &e[24..56];
            if id <= prev_id && i > 0 {
                return Err(Error::BadSectionTable("section ids are not ascending"));
            }
            if align != ALIGN || !off.is_multiple_of(ALIGN) {
                return Err(Error::SectionMisaligned(id));
            }
            let Some(end) = off.checked_add(len) else {
                return Err(Error::SectionOverlap(id));
            };
            if off < prev_end || end > footer_off {
                return Err(Error::SectionOverlap(id));
            }
            if &blake3::hash(&aligned[off..off + len]).as_bytes()[..] != hash {
                return Err(Error::SectionHash(id));
            }
            sections.push((id, off, len));
            prev_id = id;
            prev_end = end;
        }
        if sections.first().map(|s| s.0) != Some(ID_META) {
            return Err(Error::MissingMeta);
        }
        // a family section may only exist when the header declares that family,
        // otherwise a reader would answer from data the object says it has not got
        for (id, family_bit, count) in [
            (ID_V4, header::FAMILY_V4, header.count_v4),
            (ID_V6, header::FAMILY_V6, header.count_v6),
        ] {
            let present = sections.iter().any(|s| s.0 == id);
            let declared = header.families & family_bit != 0;
            if present != declared || (present && count == 0) {
                return Err(Error::BadSectionTable(
                    "section disagrees with the declared families",
                ));
            }
        }
        if sections[0].1 as u64 != header.meta_off || sections[0].2 as u64 != header.meta_len as u64
        {
            return Err(Error::BadSectionTable(
                "META entry disagrees with the header",
            ));
        }

        // body hash over sections in file order
        {
            let mut h = blake3::Hasher::new();
            for (_, off, len) in &sections {
                h.update(&aligned[*off..*off + *len]);
            }
            let expect = &footer[16 + count * ENTRY_LEN..16 + count * ENTRY_LEN + 32];
            if h.finalize().as_bytes() != expect {
                return Err(Error::BodyHash);
            }
        }

        // an untrusted object can carry a hash-consistent but structurally
        // invalid archive, so every trie section is checked before any
        // unchecked access below is allowed to run
        for (id, off, len) in &sections {
            match *id {
                ID_V4 => {
                    rkyv::access::<ArchivedPrefixMap<Ipv4Net, T>, RkyvError>(
                        &aligned[*off..*off + *len],
                    )
                    .map_err(|_| Error::BadSectionTable("TRIE_V4 archive is invalid"))?;
                }
                ID_V6 => {
                    rkyv::access::<ArchivedPrefixMap<Ipv6Net, T>, RkyvError>(
                        &aligned[*off..*off + *len],
                    )
                    .map_err(|_| Error::BadSectionTable("TRIE_V6 archive is invalid"))?;
                }
                _ => {}
            }
        }

        let (_, meta_off, meta_len) = *sections
            .iter()
            .find(|s| s.0 == ID_META)
            .ok_or(Error::MissingMeta)?;
        let meta_bytes = &aligned[meta_off..meta_off + meta_len];
        let meta: serde_json::Value =
            serde_json::from_slice(meta_bytes).map_err(|e| Error::BadMeta(e.to_string()))?;
        // canonical form is part of the contract: anything that does not
        // re-serialize to the exact bytes received is out of spec
        if serde_json::to_vec(&meta).map_err(|e| Error::BadMeta(e.to_string()))? != meta_bytes {
            return Err(Error::BadMeta("META is not in canonical form".into()));
        }
        let declared = meta
            .pointer("/projection/value/type_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if declared != T::TYPE_ID {
            return Err(Error::TypeMismatch {
                expected: T::TYPE_ID,
                found: declared,
            });
        }
        let content_id = meta
            .pointer("/content_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let snap = Snapshot {
            bytes: aligned,
            meta,
            sections,
            content_id,
            _t: std::marker::PhantomData,
        };
        snap.verify_content_id()?;
        snap.verify_counts_and_probes()?;
        snap.verify_header_agreement(&header)?;
        Ok(snap)
    }

    fn section(&self, id: u16) -> Option<&[u8]> {
        self.sections
            .iter()
            .find(|s| s.0 == id)
            .map(|(_, off, len)| &self.bytes[*off..*off + *len])
    }

    /// SAFETY: every section was hash-checked and the archive was validated
    /// with `rkyv::access` at open; the bytes are immutable for the lifetime of
    /// `self`, so re-reading them unchecked cannot observe a bad archive.
    pub fn v4(&self) -> Option<&ArchivedPrefixMap<Ipv4Net, T>> {
        self.section(ID_V4)
            .map(|s| unsafe { rkyv::access_unchecked::<ArchivedPrefixMap<Ipv4Net, T>>(s) })
    }

    pub fn v6(&self) -> Option<&ArchivedPrefixMap<Ipv6Net, T>> {
        self.section(ID_V6)
            .map(|s| unsafe { rkyv::access_unchecked::<ArchivedPrefixMap<Ipv6Net, T>>(s) })
    }

    pub fn meta(&self) -> &serde_json::Value {
        &self.meta
    }

    pub fn content_id(&self) -> &str {
        &self.content_id
    }

    pub fn len(&self) -> usize {
        self.v4().map(|m| m.len()).unwrap_or(0) + self.v6().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Longest-prefix match across families.
    pub fn search(&self, prefix: IpNet) -> Option<(IpNet, &T::Archived)> {
        match prefix {
            IpNet::V4(p) => {
                let a = self.v4()?.get_lpm(&p)?;
                Some((IpNet::V4(a.0), a.1))
            }
            IpNet::V6(p) => {
                let a = self.v6()?.get_lpm(&p)?;
                Some((IpNet::V6(a.0), a.1))
            }
        }
    }

    fn verify_content_id(&self) -> Result<(), Error> {
        let proj = self
            .meta
            .get("projection")
            .ok_or_else(|| Error::BadMeta("META has no projection".into()))?;
        let proj_bytes = serde_json::to_vec(proj).map_err(|e| Error::BadMeta(e.to_string()))?;
        let mut h = framed_hasher();
        h.update(CONTENT_DOMAIN);
        h.update(&proj_bytes);
        for (id, off, len) in &self.sections {
            if *id != ID_META {
                update_framed(&mut h, *id, &self.bytes[*off..*off + *len]);
            }
        }
        let got = h.finalize().to_hex().to_string();
        if got != self.content_id {
            return Err(Error::ContentId);
        }
        Ok(())
    }

    /// Rule 13: every field the header projects must equal the META copy, or a
    /// spliced header could describe an object that is not there.
    fn verify_header_agreement(&self, header: &Header) -> Result<(), Error> {
        let bad = |what: &str| Error::BadMeta(format!("header disagrees with META on {what}"));
        if self.meta.pointer("/content_id").and_then(|v| v.as_str())
            != Some(header.content_id_hex().as_str())
        {
            return Err(bad("content_id"));
        }
        let p = |path: &str| self.meta.pointer(path);
        if p("/projection/value/type_id").and_then(|v| v.as_str()) != Some(header.type_id.as_str())
        {
            return Err(bad("type_id"));
        }
        for (path, want) in [
            ("/projection/counts/v4", header.count_v4 as u64),
            ("/projection/counts/v6", header.count_v6 as u64),
        ] {
            let got = p(path).and_then(|v| v.as_u64()).unwrap_or(0);
            if got != want {
                return Err(bad(path));
            }
        }
        let families: u64 = p("/projection/families")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64())
                    .fold(0u64, |acc, f| match f {
                        4 => acc | header::FAMILY_V4 as u64,
                        6 => acc | header::FAMILY_V6 as u64,
                        _ => acc,
                    })
            })
            .unwrap_or(u64::MAX);
        if families != header.families as u64 {
            return Err(bad("families"));
        }
        let created = self
            .meta
            .pointer("/provenance/created_at")
            .and_then(|v| v.as_str());
        let created_unix = created
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp());
        if created_unix != Some(header.created_at) {
            return Err(bad("created_at"));
        }
        match header.flags & header::FLAG_HAS_EVENTS {
            0 => {
                if p("/projection/events").is_some() {
                    return Err(bad("events"));
                }
            }
            _ => {
                if p("/projection/events/first_event_ts").and_then(|v| v.as_i64())
                    != Some(header.first_event_ts)
                {
                    return Err(bad("first_event_ts"));
                }
                if p("/projection/events/last_event_ts").and_then(|v| v.as_i64())
                    != Some(header.last_event_ts)
                {
                    return Err(bad("last_event_ts"));
                }
            }
        }
        match header.flags & header::FLAG_HAS_STREAM {
            0 => {
                if p("/projection/stream").is_some() {
                    return Err(bad("stream"));
                }
            }
            _ => {
                if p("/projection/stream/tree_id").and_then(|v| v.as_str())
                    != Some(hex16(&header.tree_id).as_str())
                {
                    return Err(bad("tree_id"));
                }
                if p("/projection/stream/generation").and_then(|v| v.as_str())
                    != Some(hex16(&header.generation).as_str())
                {
                    return Err(bad("generation"));
                }
                if p("/projection/stream/base_seq").and_then(|v| v.as_u64())
                    != Some(header.base_seq)
                {
                    return Err(bad("base_seq"));
                }
            }
        }
        Ok(())
    }

    fn verify_counts_and_probes(&self) -> Result<(), Error> {
        for (family, n) in [
            (4u8, self.v4().map(|m| m.len()).unwrap_or(0) as u64),
            (6u8, self.v6().map(|m| m.len()).unwrap_or(0) as u64),
        ] {
            let key = format!("v{family}");
            if let Some(v) = self.meta.pointer(&format!("/projection/counts/{key}")) {
                let meta_n = v.as_u64().unwrap_or(0);
                if meta_n != n {
                    return Err(Error::CountMismatch {
                        family,
                        meta: meta_n,
                        actual: n,
                    });
                }
            }
        }
        for (family, key, probe) in [
            (4u8, "v4_first", "first"),
            (4u8, "v4_last", "last"),
            (6u8, "v6_first", "first"),
            (6u8, "v6_last", "last"),
        ] {
            // an absent family carries no probe; a declared one must carry both
            if (family == 4 && self.v4().is_none()) || (family == 6 && self.v6().is_none()) {
                continue;
            }
            let want = self
                .meta
                .pointer(&format!("/projection/probe/{key}"))
                .and_then(|v| v.as_str())
                .ok_or(Error::ProbeMismatch {
                    family,
                    which: probe,
                })?;
            let Ok(p) = want.parse::<IpNet>() else {
                return Err(Error::ProbeMismatch {
                    family,
                    which: probe,
                });
            };
            let found = match (family, key, p) {
                (4, "v4_first", IpNet::V4(p)) => {
                    self.v4().and_then(|m| m.iter().next().map(|(k, _)| k)) == Some(p)
                }
                (4, "v4_last", IpNet::V4(p)) => {
                    self.v4().and_then(|m| m.iter().last().map(|(k, _)| k)) == Some(p)
                }
                (6, "v6_first", IpNet::V6(p)) => {
                    self.v6().and_then(|m| m.iter().next().map(|(k, _)| k)) == Some(p)
                }
                (6, "v6_last", IpNet::V6(p)) => {
                    self.v6().and_then(|m| m.iter().last().map(|(k, _)| k)) == Some(p)
                }
                _ => false,
            };
            if !found {
                return Err(Error::ProbeMismatch {
                    family,
                    which: probe,
                });
            }
        }
        Ok(())
    }
}
