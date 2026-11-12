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

pub const MAGIC: &[u8; 8] = b"BGPKSNAP";
pub const FOOTER_MAGIC: &[u8; 4] = b"SNPF";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const PREFIX_LEN: usize = 64;
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
fn projection<T: SnapValue>(
    v4: &PrefixMap<Ipv4Net, T>,
    v6: &PrefixMap<Ipv6Net, T>,
    source: &str,
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
    meta.insert(
        "provenance".into(),
        json!({
            "generator": "bgpkit-snap/0.0.1",
            "producer": "bgpkit-snap/0.0.1",
            "sources": [{"uri": source}],
        }),
    );
    meta.insert(
        "trie_layout".into(),
        json!({"crate": "prefix-trie", "key_bits": 32, "node_bits": 5, "rkyv": "0.8", "version": "0.10"}),
    );
    meta.insert(
        "value".into(),
        json!({"note": "PoC", "type_id": T::TYPE_ID, "width": T::WIDTH}),
    );
    Value::Object(meta)
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
        let v4_bytes = rkyv::to_bytes::<RkyvError>(&self.v4).map_err(|_| Error::BodyHash)?;
        let v6_bytes = rkyv::to_bytes::<RkyvError>(&self.v6).map_err(|_| Error::BodyHash)?;

        // only families that carry entries get a section, and content_id covers
        // exactly the sections that are written
        let mut trie_sections: Vec<(u16, &[u8])> = Vec::new();
        if !self.v4.is_empty() {
            trie_sections.push((ID_V4, &v4_bytes));
        }
        if !self.v6.is_empty() {
            trie_sections.push((ID_V6, &v6_bytes));
        }

        // content_id covers the canonical META projection plus the non-META
        // sections, so it is not circular and is producer independent.
        let mut proj = projection(&self.v4, &self.v6, source);
        let proj_bytes = serde_json::to_vec(&proj).map_err(|e| Error::BadMeta(e.to_string()))?;
        let mut id_hasher = framed_hasher();
        id_hasher.update(CONTENT_DOMAIN);
        id_hasher.update(&proj_bytes);
        for (id, bytes) in &trie_sections {
            update_framed(&mut id_hasher, *id, bytes);
        }
        let content_id = id_hasher.finalize().to_hex().to_string();

        // full META: projection + content_id + provenance.created_at
        {
            let obj = proj.as_object_mut().ok_or(Error::MissingMeta)?;
            obj.insert("content_id".into(), jstr(&content_id));
            if let Some(prov) = obj.get_mut("provenance").and_then(|p| p.as_object_mut()) {
                prov.insert("created_at".into(), jstr(created_at));
            }
        }
        let meta_bytes = serde_json::to_vec(&proj).map_err(|e| Error::BadMeta(e.to_string()))?;

        // layout: only families that actually carry entries get a section
        let mut trie_sections: Vec<(u16, &[u8])> = Vec::new();
        if !self.v4.is_empty() {
            trie_sections.push((ID_V4, &v4_bytes));
        }
        if !self.v6.is_empty() {
            trie_sections.push((ID_V6, &v6_bytes));
        }
        let mut offsets: Vec<(u16, u64, u64, [u8; 32])> = Vec::new();
        let mut body: Vec<u8> = Vec::new(); // sections after the 64-byte prefix

        let push_section = |body: &mut Vec<u8>,
                            offsets: &mut Vec<(u16, u64, u64, [u8; 32])>,
                            id: u16,
                            bytes: &[u8]| {
            while !(PREFIX_LEN + body.len()).is_multiple_of(ALIGN) {
                body.push(0);
            }
            let off = (PREFIX_LEN + body.len()) as u64;
            body.extend_from_slice(bytes);
            offsets.push((id, off, bytes.len() as u64, *blake3::hash(bytes).as_bytes()));
        };

        push_section(&mut body, &mut offsets, ID_META, &meta_bytes);
        for (id, bytes) in trie_sections {
            push_section(&mut body, &mut offsets, id, bytes);
        }

        // body hash covers every section in file order, META included
        let body_hash = {
            let mut h = blake3::Hasher::new();
            for (id, off, len, _) in &offsets {
                let _ = id;
                let start = (*off as usize) - PREFIX_LEN;
                h.update(&body[start..start + *len as usize]);
            }
            h.finalize()
        };

        // footer
        let mut footer = Vec::new();
        footer.extend_from_slice(&(offsets.len() as u32).to_le_bytes());
        footer.extend_from_slice(FOOTER_MAGIC);
        footer.extend_from_slice(&1u32.to_le_bytes()); // flags: body hash present
        footer.extend_from_slice(&0u32.to_le_bytes()); // reserved
        for (id, off, len, hash) in &offsets {
            footer.extend_from_slice(&id.to_le_bytes());
            footer.extend_from_slice(&id.to_le_bytes()); // kind
            footer.extend_from_slice(&0u16.to_le_bytes()); // flags
            footer.push(ALIGN as u8);
            footer.push(0);
            footer.extend_from_slice(&off.to_le_bytes());
            footer.extend_from_slice(&len.to_le_bytes());
            footer.extend_from_slice(hash);
            footer.extend_from_slice(&[0u8; 8]);
        }
        footer.extend_from_slice(body_hash.as_bytes());

        let footer_off = (PREFIX_LEN + body.len()) as u64;
        let footer_len = footer.len() as u64;
        let file_len = footer_off + footer_len;

        let mut out = vec![0u8; PREFIX_LEN];
        out[0..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&MAJOR.to_le_bytes());
        out[10..12].copy_from_slice(&MINOR.to_le_bytes());
        out[12..16].copy_from_slice(&(PREFIX_LEN as u32).to_le_bytes());
        out[16..24].copy_from_slice(&file_len.to_le_bytes());
        out[24..32].copy_from_slice(&footer_off.to_le_bytes());
        out[32..36].copy_from_slice(&(footer_len as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&footer);
        debug_assert_eq!(out.len() as u64, file_len);
        Ok(out)
    }
}

// ---------------------------------------------------------------- reader

pub struct Snapshot<T: SnapValue> {
    bytes: AlignedVec,
    meta: serde_json::Value,
    sections: Vec<(u16, usize, usize)>,
    content_id: String,
    _t: std::marker::PhantomData<T>,
}

impl<T: SnapValue> fmt::Debug for Snapshot<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("content_id", &self.content_id)
            .field("sections", &self.sections.len())
            .field("entries", &self.len())
            .finish()
    }
}

impl<T: SnapValue> Snapshot<T> {
    pub fn open(path: &str) -> Result<Self, Error> {
        Self::from_bytes(&std::fs::read(path)?)
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < PREFIX_LEN {
            return Err(Error::Truncated {
                need: PREFIX_LEN,
                have: raw.len(),
            });
        }
        if &raw[0..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        let major = u16::from_le_bytes([raw[8], raw[9]]);
        if major != MAJOR {
            return Err(Error::UnsupportedMajor(major));
        }
        let prefix_len = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]) as usize;
        let file_len = u64::from_le_bytes(raw[16..24].try_into().unwrap());
        let footer_off = u64::from_le_bytes(raw[24..32].try_into().unwrap()) as usize;
        let footer_len = u32::from_le_bytes(raw[32..36].try_into().unwrap()) as usize;
        if prefix_len != PREFIX_LEN {
            return Err(Error::BadSectionTable("prefix_len is not 64"));
        }
        if file_len as usize != raw.len() {
            return Err(Error::Truncated {
                need: file_len as usize,
                have: raw.len(),
            });
        }
        if footer_off + footer_len != raw.len() {
            return Err(Error::BadSectionTable("footer does not end the file"));
        }

        let footer = &raw[footer_off..];
        let count = u32::from_le_bytes(footer[0..4].try_into().unwrap()) as usize;
        if &footer[4..8] != FOOTER_MAGIC {
            return Err(Error::BadFooter);
        }
        let flags = u32::from_le_bytes(footer[8..12].try_into().unwrap());
        if flags & 1 == 0 {
            return Err(Error::BadSectionTable("body hash flag is not set"));
        }

        let mut sections: Vec<(u16, usize, usize)> = Vec::new();
        let mut prev_id = 0u16;
        let mut prev_end = PREFIX_LEN;
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
            if off < prev_end || off + len > footer_off {
                return Err(Error::SectionOverlap(id));
            }
            if &blake3::hash(&raw[off..off + len]).as_bytes()[..] != hash {
                return Err(Error::SectionHash(id));
            }
            sections.push((id, off, len));
            prev_id = id;
            prev_end = off + len;
        }
        if sections.first().map(|s| s.0) != Some(ID_META) {
            return Err(Error::MissingMeta);
        }

        // body hash over sections in file order
        {
            let mut h = blake3::Hasher::new();
            for (_, off, len) in &sections {
                h.update(&raw[*off..*off + *len]);
            }
            let expect = &footer[16 + count * ENTRY_LEN..16 + count * ENTRY_LEN + 32];
            if h.finalize().as_bytes() != expect {
                return Err(Error::BodyHash);
            }
        }

        // copy into an aligned buffer; a plain Vec is not a legal input
        let mut aligned = AlignedVec::with_capacity(raw.len());
        aligned.extend_from_slice(raw);

        let (_, meta_off, meta_len) = *sections
            .iter()
            .find(|s| s.0 == ID_META)
            .ok_or(Error::MissingMeta)?;
        let meta: serde_json::Value =
            serde_json::from_slice(&aligned[meta_off..meta_off + meta_len])
                .map_err(|e| Error::BadMeta(e.to_string()))?;
        let declared = meta
            .pointer("/value/type_id")
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
        let mut proj = self.meta.clone();
        if let Some(obj) = proj.as_object_mut() {
            obj.remove("content_id");
            if let Some(prov) = obj.get_mut("provenance").and_then(|p| p.as_object_mut()) {
                prov.remove("created_at");
            }
        }
        let proj_bytes = serde_json::to_vec(&proj).map_err(|e| Error::BadMeta(e.to_string()))?;
        let mut h = framed_hasher();
        h.update(CONTENT_DOMAIN);
        h.update(&proj_bytes);
        for id in [ID_V4, ID_V6] {
            if let Some(s) = self.section(id) {
                update_framed(&mut h, id, s);
            }
        }
        let got = h.finalize().to_hex().to_string();
        if got != self.content_id {
            return Err(Error::ContentId);
        }
        Ok(())
    }

    fn verify_counts_and_probes(&self) -> Result<(), Error> {
        for (family, n) in [
            (4u8, self.v4().map(|m| m.len()).unwrap_or(0) as u64),
            (6u8, self.v6().map(|m| m.len()).unwrap_or(0) as u64),
        ] {
            let key = format!("v{family}");
            if let Some(v) = self.meta.pointer(&format!("/counts/{key}")) {
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
            let Some(want) = self
                .meta
                .pointer(&format!("/probe/{key}"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Ok(p) = want.parse::<IpNet>() else {
                return Err(Error::ProbeMismatch {
                    family,
                    which: probe,
                });
            };
            let found = match (family, p) {
                (4, IpNet::V4(p)) => self.v4().and_then(|m| m.get(&p)).is_some(),
                (6, IpNet::V6(p)) => self.v6().and_then(|m| m.get(&p)).is_some(),
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
