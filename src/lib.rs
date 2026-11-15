//! bgpkit-snap v4: an immutable container for prefix tries.
//!
//! The container owns framing, identity and integrity. It knows nothing about
//! what a trie holds beyond the value type's `TYPE_ID`, and nothing about what a
//! client section means. See `docs/format.md`.

use std::fmt;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::rkyv::ArchivedPrefixMap;
use prefix_trie::{AsView, PrefixMap, TrieView};
use rkyv::rancor::Error as RkyvError;

/// The archive library this crate builds value types on, re-exported so a
/// caller can name the same version in a signature.
///
/// It does not remove the dependency: `#[derive(rkyv::Archive)]` expands to paths
/// rooted at `rkyv`, so a crate that derives needs `rkyv` in its own manifest even
/// though this re-export exists.
pub use rkyv;
use rkyv::util::AlignedVec;
use std::io::Write;

pub mod header;
pub mod journal;

pub use header::{
    Entry, Header, StreamRef, ENTRY_LEN, FLAG_STREAM, FLAG_WINDOW, HEADER_LEN, ID_V4, ID_V6,
    KIND_PAYLOAD, KIND_V4, KIND_V6,
};

/// The serializer `rkyv::to_bytes` builds, so the value bound can name it.
pub type HighSer<'a> =
    rkyv::api::high::HighSerializer<AlignedVec, rkyv::ser::allocator::ArenaHandle<'a>, RkyvError>;

// ---------------------------------------------------------------- errors

/// Every way this crate refuses.
///
/// `#[non_exhaustive]`: a new refusal is a change to the crate, not to the caller's
/// match, so a caller needs a catch-all arm.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Io(std::io::Error),
    BadMagic,
    BadVersion(u16),
    BadHeader(&'static str),
    BadHeaderCrc,
    Truncated {
        need: usize,
        have: usize,
    },
    BadSectionTable(&'static str),
    SectionOrder,
    UnknownRequiredSection(u16),
    BadSectionKind(u16),
    TypeMismatch {
        expected: String,
        found: String,
    },
    ContentId,
    /// Another writer holds this journal's lock. Retry later; this is not damage.
    Locked,
    /// A caller-supplied option is not something a writer can emit.
    BadOpts(&'static str),
    /// A section id the caller supplied is not usable here.
    BadSectionId(u16),
    /// A prefix the caller supplied has host bits set.
    BadPrefix(String),
    /// A section's body is not a valid archive of the type this reader asked for.
    BadArchive(u16),
    BadValue,
    // journal
    BadRecord(&'static str),
    SequenceGap {
        expected: u64,
        found: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::BadMagic => write!(f, "not a snap object"),
            Error::BadVersion(v) => write!(f, "unsupported format version {v}"),
            Error::BadHeader(why) => write!(f, "bad header: {why}"),
            Error::BadHeaderCrc => write!(f, "header crc mismatch"),
            Error::Truncated { need, have } => write!(f, "truncated: need {need}, have {have}"),
            Error::BadSectionTable(why) => write!(f, "bad section table: {why}"),
            Error::SectionOrder => write!(f, "sections are not in ascending id order"),
            Error::UnknownRequiredSection(id) => write!(
                f,
                "section {id} is required but this reader does not know it; \
                 open the object with a validator that implements it"
            ),
            Error::BadSectionKind(id) => write!(f, "section {id} has an unexpected kind tag"),
            Error::TypeMismatch { expected, found } => {
                write!(
                    f,
                    "value type mismatch: expected {expected}, found {found:?}"
                )
            }
            Error::ContentId => write!(f, "content id mismatch"),
            Error::Locked => write!(f, "another writer holds this journal"),
            Error::BadOpts(what) => write!(f, "bad writer option: {what}"),
            Error::BadSectionId(id) => write!(f, "section id {id} cannot be used here"),
            Error::BadPrefix(p) => write!(f, "prefix {p} has host bits set"),
            Error::BadArchive(id) => {
                write!(f, "section {id} is not an archive of this value type")
            }
            Error::BadValue => write!(f, "value could not be decoded"),
            Error::BadRecord(why) => write!(f, "bad journal record: {why}"),
            Error::SequenceGap { expected, found } => {
                write!(
                    f,
                    "journal sequence gap: expected {expected}, found {found}"
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

// ---------------------------------------------------------------- coverage

/// How much of an address space a tree's entries cover.
///
/// A tuple of options could not tell "this family has no entries" from "this family
/// is covered end to end" (an IPv6 tree holding `::/0` covers 2^128 addresses, which
/// does not fit in the count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    /// The tree holds no entry for this family.
    NoEntries,
    /// The whole address space is claimed.
    All,
    /// That many distinct addresses are covered; overlapping entries count once.
    Exact(u128),
}

/// The answer to `Snapshot::address_counts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressCounts {
    pub v4: Count,
    pub v6: Count,
}

// ---------------------------------------------------------------- values

/// A value type that can live in a trie.
pub trait SnapValue: rkyv::Archive + Clone + for<'a> rkyv::Serialize<HighSer<'a>> {
    /// Stable identifier, e.g. `snap.u32:v1`.
    ///
    /// At most 31 bytes of printable ASCII, no space, quote or backslash, and not
    /// empty: it is stored verbatim in the header and compared on every open, so a
    /// value that cannot round-trip through those bytes is rejected at `finish`.
    const TYPE_ID: &'static str;

    /// Bring the value into canonical form before it is written. The default is
    /// a no-op; override it when the value has an order that does not come from
    /// its own fields.
    fn canonicalize(&mut self) {}
}

impl SnapValue for u32 {
    const TYPE_ID: &str = "snap.u32:v1";
}

impl SnapValue for u64 {
    const TYPE_ID: &str = "snap.u64:v1";
}

/// Decode a value from archived bytes, used by the journal.
pub trait Codec: SnapValue + Sized {
    fn encode(value: &Self) -> Result<Vec<u8>, Error>;
    fn decode(bytes: &[u8]) -> Result<Self, Error>;
}

impl<T> Codec for T
where
    T: SnapValue,
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<RkyvError>>,
{
    fn encode(value: &Self) -> Result<Vec<u8>, Error> {
        rkyv::to_bytes::<RkyvError>(value)
            .map(|b| b.to_vec())
            .map_err(|_| Error::BadValue)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        rkyv::from_bytes::<T, RkyvError>(bytes).map_err(|_| Error::BadValue)
    }
}

// ---------------------------------------------------------------- writer

/// One section the caller supplies next to the tries: an arena, a sidecar, any
/// bytes the profile owns. `id` is 16 or higher, `kind` is a four-byte tag, and
/// `required` makes a reader that does not implement the id refuse the object.
/// The identity of the tree a journal writes.
///
///
/// A journal refuses a checkpoint that belongs to another tree, so the id is what
/// stops two feeds from writing into one directory. `from_name` exists because
/// hand-writing sixteen bytes is the kind of detail a caller gets wrong silently.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TreeId([u8; 16]);

impl TreeId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// A stable id for a human name: the first 16 bytes of its BLAKE3 hash.
    ///
    /// The same name always gives the same id, so a service that starts with
    /// `TreeId::from_name("wayback-roas")` reopens its own journal and a typo in
    /// the name gives a different journal instead of silently adopting this one.
    pub fn from_name(name: &str) -> Self {
        let mut out = [0u8; 16];
        out.copy_from_slice(&blake3::hash(name.as_bytes()).as_bytes()[..16]);
        Self(out)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for TreeId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for TreeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// One section the caller supplies next to the tries: an arena, a sidecar, any
/// bytes the profile owns. `id` is 16 or higher, `kind` is a four-byte tag, and
/// `required` makes a reader that does not implement the id refuse the object.
#[derive(Clone, Copy)]
pub struct ExtraSection<'a> {
    pub id: u16,
    pub kind: [u8; 4],
    pub required: bool,
    pub bytes: &'a [u8],
}

/// Everything a writer declares about the object.
pub struct Opts<'a> {
    /// unix seconds UTC, written into the header. `created_at` is deliberately
    /// outside the content id, so this is provenance rather than identity.
    pub created_at: i64,
    /// Set by a journal, which owns the stream coordinates; ignored if a caller sets
    /// it, because the journal's own `tree_id`, `generation` and `base_seq` are the
    /// ones the checkpoint is written under.
    pub stream: Option<StreamRef>,
    pub window: Option<(i64, i64)>,
    pub extras: &'a [ExtraSection<'a>],
}

impl Opts<'_> {
    /// The options most writers want: the current time, no window, no extras.
    ///
    /// There is no `Default`: a default would have to invent a creation time, and
    /// an invented one is a valid header with false provenance.
    pub fn now() -> Self {
        Self {
            created_at: chrono::Utc::now().timestamp(),
            stream: None,
            window: None,
            extras: &[],
        }
    }
}

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
        Self {
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
        }
    }

    /// Store `value` under `prefix`, replacing any value already there.
    ///
    /// The prefix must be canonical (`addr() == network()`); a prefix with host
    /// bits set is refused with `Error::BadPrefix` in every build, because silently
    /// storing it under its network address would make the key you asked for and
    /// the key you get back differ.
    pub fn insert(&mut self, prefix: IpNet, mut value: T) -> Result<(), Error> {
        if prefix.addr() != prefix.network() {
            // storing it under its network address would make the key you asked
            // for and the key you get back differ, and two inputs would collide
            return Err(Error::BadPrefix(prefix.to_string()));
        }
        value.canonicalize();
        match prefix {
            IpNet::V4(p) => {
                self.v4.insert(p, value);
            }
            IpNet::V6(p) => {
                self.v6.insert(p, value);
            }
        }
        Ok(())
    }

    /// Insert many entries, stopping at the first prefix that is refused.
    ///
    /// `Writer` deliberately does not implement `Extend`: a set that silently
    /// drops the entries it could not store is worse than a loop that stops.
    pub fn insert_many(
        &mut self,
        entries: impl IntoIterator<Item = (IpNet, T)>,
    ) -> Result<(), Error> {
        for (prefix, value) in entries {
            self.insert(prefix, value)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Build the object. The caller writes the returned bytes wherever it likes.
    pub fn finish(self, opts: &Opts<'_>) -> Result<Vec<u8>, Error> {
        let created_at = opts.created_at;

        let v4_bytes = rkyv::to_bytes::<RkyvError>(&self.v4).map_err(|_| Error::BadValue)?;
        let v6_bytes = rkyv::to_bytes::<RkyvError>(&self.v6).map_err(|_| Error::BadValue)?;

        // sections in ascending id order, each starting on a 16-byte boundary
        let mut sections: Vec<(Entry, &[u8])> = Vec::new();
        if !self.v4.is_empty() {
            sections.push((
                Entry {
                    id: ID_V4,
                    kind: KIND_V4,
                    required: false,
                    len: v4_bytes.len() as u64,
                },
                &v4_bytes,
            ));
        }
        if !self.v6.is_empty() {
            sections.push((
                Entry {
                    id: ID_V6,
                    kind: KIND_V6,
                    required: false,
                    len: v6_bytes.len() as u64,
                },
                &v6_bytes,
            ));
        }
        let mut extras: Vec<&ExtraSection<'_>> = opts.extras.iter().collect();
        extras.sort_by_key(|e| e.id);
        for extra in extras {
            if extra.id < header::FIRST_PROFILE_ID {
                return Err(Error::BadHeader("extra section id is below 16"));
            }
            // the family kinds live at ids 2 and 3 and nowhere else, so an extra
            // claiming one would build an object the reader refuses
            if extra.kind == KIND_V4 || extra.kind == KIND_V6 {
                return Err(Error::BadHeader("extra section uses a family kind"));
            }
            if sections.iter().any(|(e, _)| e.id == extra.id) {
                return Err(Error::BadHeader("duplicate section id"));
            }
            sections.push((
                Entry {
                    id: extra.id,
                    kind: extra.kind,
                    required: extra.required,
                    len: extra.bytes.len() as u64,
                },
                extra.bytes,
            ));
        }
        sections.sort_by_key(|(e, _)| e.id);

        let table_len = sections.len() * ENTRY_LEN;
        let mut body: Vec<u8> = Vec::new();
        let mut table: Vec<u8> = Vec::with_capacity(table_len);
        for (entry, bytes) in &sections {
            while !(HEADER_LEN + table_len + body.len()).is_multiple_of(16) {
                body.push(0);
            }
            table.extend_from_slice(&entry.encode());
            body.extend_from_slice(bytes);
        }
        let file_len = (HEADER_LEN + table_len + body.len()) as u64;

        let mut type_id = [0u8; 32];
        let id_bytes = T::TYPE_ID.as_bytes();
        if id_bytes.is_empty() {
            return Err(Error::BadHeader("type id is empty"));
        }
        if id_bytes.len() > 31 {
            return Err(Error::BadHeader("type id is longer than 31 bytes"));
        }
        type_id[..id_bytes.len()].copy_from_slice(id_bytes);

        let (flags, tree_id, generation, base_seq) = match opts.stream {
            Some(s) => (FLAG_STREAM, s.tree_id, s.generation, s.base_seq),
            None => (0, [0u8; 16], [0u8; 16], 0),
        };
        let (flags, window) = match opts.window {
            Some((from, to)) => (flags | FLAG_WINDOW, [from, to]),
            None => (flags, [0, 0]),
        };

        let mut head = Header {
            flags,
            tree_id,
            generation,
            base_seq,
            type_id,
            file_len,
            section_count: sections.len() as u32,
            section_table_len: table_len as u32,
            window,
            created_at,
            content_id: [0u8; 32],
        };
        // the hash covers header[0..HASH_END]; content_id cannot hash itself, so
        // it is filled in after the first encode
        let mut prefix = head.encode();
        let mut h = blake3::Hasher::new();
        h.update(b"bgpkit-snap-v4\0");
        h.update(&prefix[..header::HASH_END]);
        h.update(&table);
        for (_, bytes) in &sections {
            h.update(bytes);
        }
        head.content_id = *h.finalize().as_bytes();

        let mut out = Vec::with_capacity(file_len as usize);
        prefix = head.encode();
        // a writer must not produce an object its own reader rejects: the
        // semantic rules live in Header::parse, so run them on the bytes here
        Header::parse(&prefix)?;
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&table);
        out.extend_from_slice(&body);
        debug_assert_eq!(out.len() as u64, file_len);
        Ok(out)
    }

    /// Build the object and write it to `path` in one call, returning the number
    /// of bytes written. The file is written beside the target and renamed, so a
    /// reader never sees a half-written object.
    pub fn finish_to(
        self,
        path: impl AsRef<std::path::Path>,
        opts: &Opts<'_>,
    ) -> Result<u64, Error> {
        let bytes = self.finish(opts)?;
        let path = path.as_ref();
        // one temp name per call: two writers to one path must not share a temp
        static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = path.with_extension(format!("snap.{}.{n}.tmp", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
        }
        Ok(bytes.len() as u64)
    }
}

// ---------------------------------------------------------------- owned view

/// The same queries `Snapshot` answers, returning values you own.
///
/// `snap.lpm(..)` hands back `&T::Archived`, which is the point of the format but
/// forces every caller to name the archived type. `snap.owned()` answers the same
/// questions with `T`. Both views exist for every value-returning query, which is
/// what a pair of `*_owned` methods got wrong: they covered two queries out of five.
pub struct Owned<'a, T: SnapValue> {
    snap: &'a Snapshot<T>,
}

impl<T: SnapValue> Snapshot<T> {
    /// Every value-returning query, with the value deserialized.
    pub fn owned(&self) -> Owned<'_, T> {
        Owned { snap: self }
    }
}

impl<T: SnapValue> Owned<'_, T>
where
    T::Archived: rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<RkyvError>>,
{
    /// A value whose `Deserialize` refuses is an error, not an absence: returning
    /// `None` would make `len()` disagree with `iter().count()` and hide a broken
    /// value type behind a lookup miss.
    fn decode(value: &T::Archived) -> Result<T, Error> {
        rkyv::deserialize::<T, RkyvError>(value).map_err(|_| Error::BadValue)
    }

    pub fn len(&self) -> usize {
        self.snap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snap.is_empty()
    }

    /// The entry stored exactly at `prefix`.
    pub fn get_exact(&self, prefix: IpNet) -> Result<Option<T>, Error> {
        match self.snap.get_exact(prefix) {
            Some(value) => Ok(Some(Self::decode(value)?)),
            None => Ok(None),
        }
    }

    /// The most specific stored entry covering `addr`.
    pub fn search(&self, addr: std::net::IpAddr) -> Result<Option<(IpNet, T)>, Error> {
        match self.snap.search(addr) {
            Some((prefix, value)) => Ok(Some((prefix, Self::decode(value)?))),
            None => Ok(None),
        }
    }

    /// The most specific stored entry covering `prefix`.
    pub fn lpm(&self, prefix: IpNet) -> Result<Option<(IpNet, T)>, Error> {
        match self.snap.lpm(prefix) {
            Some((prefix, value)) => Ok(Some((prefix, Self::decode(value)?))),
            None => Ok(None),
        }
    }

    /// The least specific stored entry covering `prefix`.
    pub fn spm(&self, prefix: IpNet) -> Result<Option<(IpNet, T)>, Error> {
        match self.snap.spm(prefix) {
            Some((prefix, value)) => Ok(Some((prefix, Self::decode(value)?))),
            None => Ok(None),
        }
    }

    /// Every stored entry covering `prefix`, in trie order (least specific first).
    pub fn cover(&self, prefix: IpNet) -> Result<Vec<(IpNet, T)>, Error> {
        self.snap
            .cover(prefix)
            .into_iter()
            .map(|(p, v)| Ok((p, Self::decode(v)?)))
            .collect()
    }

    /// `prefix` itself when stored, plus every stored entry under it.
    pub fn children(&self, prefix: IpNet) -> Result<Vec<(IpNet, T)>, Error> {
        self.snap
            .children(prefix)
            .into_iter()
            .map(|(p, v)| Ok((p, Self::decode(v)?)))
            .collect()
    }

    /// The whole object, IPv4 then IPv6.
    pub fn iter(&self) -> Result<Vec<(IpNet, T)>, Error> {
        self.snap
            .iter()
            .map(|(p, v)| Ok((p, Self::decode(v)?)))
            .collect()
    }

    /// The values alone, IPv4 then IPv6.
    pub fn values(&self) -> Result<Vec<T>, Error> {
        self.snap.values().map(|v| Self::decode(v)).collect()
    }

    /// Entries at or after `prefix` in trie order, within `prefix`'s family.
    pub fn iter_from(&self, prefix: IpNet, inclusive: bool) -> Result<Vec<(IpNet, T)>, Error> {
        self.snap
            .iter_from(prefix, inclusive)
            .map(|(p, v)| Ok((p, Self::decode(v)?)))
            .collect()
    }
}

// ---------------------------------------------------------------- reader

/// What a validator may inspect when an object is opened.
pub struct SnapshotView<'a> {
    /// The parsed header: type, identity, stream coordinates, coverage window.
    pub header: &'a Header,
    /// One tuple per section: `(entry, offset, len)`, where `offset` is a byte
    /// offset into the whole object and `len` is the section's length.
    pub sections: &'a [(Entry, usize, usize)],
    bytes: &'a [u8],
    table: &'a [u8],
}

impl SnapshotView<'_> {
    /// The raw bytes of section `id`, exactly as written.
    pub fn section_bytes(&self, id: u16) -> Option<&[u8]> {
        self.sections
            .iter()
            .find(|(e, _, _)| e.id == id)
            .map(|(_, off, len)| &self.bytes[*off..*off + *len])
    }

    /// The table entry for section `id`: its id, kind, required flag and length.
    /// `knows` only runs for required sections, so a profile that also wants to
    /// check the kind of an optional one does it here.
    pub fn entry(&self, id: u16) -> Option<&Entry> {
        self.sections
            .iter()
            .find(|(e, _, _)| e.id == id)
            .map(|(e, _, _)| e)
    }

    /// Raw table bytes, for a reader that only wants to enumerate sections.
    pub fn table(&self) -> &[u8] {
        self.table
    }
}

/// Container-level verification that needs no value type: header, layout,
/// section table, trailing bytes and the content id. What it cannot check is
/// that a section body is a valid archive of its declared type; a reader with
/// the type does that on open.
pub fn verify_bytes(raw: &[u8]) -> Result<Header, Error> {
    let header = Header::parse(raw)?;
    header.check_layout(raw.len())?;

    let table_start = HEADER_LEN;
    let table_end = table_start + header.section_table_len as usize;
    let table = &raw[table_start..table_end];

    let mut cursor = table_end;
    let mut prev_id = 0u16;
    for i in 0..header.section_count as usize {
        let entry = Entry::parse(&table[i * ENTRY_LEN..(i + 1) * ENTRY_LEN])?;
        if entry.id <= prev_id && i > 0 {
            return Err(Error::SectionOrder);
        }
        match entry.id {
            ID_V4 if entry.kind != KIND_V4 => return Err(Error::BadSectionKind(entry.id)),
            ID_V6 if entry.kind != KIND_V6 => return Err(Error::BadSectionKind(entry.id)),
            _ => {}
        }
        match entry.kind {
            KIND_V4 if entry.id != ID_V4 => return Err(Error::BadSectionKind(entry.id)),
            KIND_V6 if entry.id != ID_V6 => return Err(Error::BadSectionKind(entry.id)),
            _ => {}
        }
        while !cursor.is_multiple_of(16) {
            if raw[cursor] != 0 {
                return Err(Error::BadSectionTable("padding is not zero"));
            }
            cursor += 1;
        }
        let Some(end) = cursor.checked_add(entry.len as usize) else {
            return Err(Error::BadSectionTable("section length overflows"));
        };
        if end > raw.len() {
            return Err(Error::Truncated {
                need: end,
                have: raw.len(),
            });
        }
        cursor = end;
        prev_id = entry.id;
    }
    if cursor != raw.len() {
        return Err(Error::BadSectionTable("sections do not end the file"));
    }

    let mut h = blake3::Hasher::new();
    h.update(b"bgpkit-snap-v4\0");
    h.update(&raw[..header::HASH_END]);
    h.update(table);
    let mut cursor = table_end;
    for i in 0..header.section_count as usize {
        let entry = Entry::parse(&table[i * ENTRY_LEN..(i + 1) * ENTRY_LEN])?;
        while !cursor.is_multiple_of(16) {
            cursor += 1;
        }
        h.update(&raw[cursor..cursor + entry.len as usize]);
        cursor += entry.len as usize;
    }
    if h.finalize().as_bytes() != &header.content_id {
        return Err(Error::ContentId);
    }
    Ok(header)
}

/// Profile-side validation, run once at open before any value is handed out.
pub trait Validator {
    /// Does this validator implement the section behind `entry`? A required
    /// section that nobody knows is refused with its id.
    fn knows(&self, _entry: &Entry) -> bool {
        false
    }

    /// Cross-section checks (for example handle ranges) run here.
    fn validate(&self, _view: &SnapshotView<'_>) -> Result<(), Error> {
        Ok(())
    }
}

struct NoValidator;
impl Validator for NoValidator {}

pub struct Snapshot<T: SnapValue> {
    bytes: AlignedVec,
    header: Header,
    sections: Vec<(Entry, usize, usize)>,
    table_range: (usize, usize),
    _t: std::marker::PhantomData<T>,
}

impl<T: SnapValue> fmt::Debug for Snapshot<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("content_id", &self.header.content_id_hex())
            .field("sections", &self.sections.len())
            .finish()
    }
}

impl<T: SnapValue> Snapshot<T> {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, Error>
    where
        T::Archived:
            for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>,
    {
        Self::from_bytes(&std::fs::read(path.as_ref())?)
    }

    pub fn open_with(
        path: impl AsRef<std::path::Path>,
        validator: &dyn Validator,
    ) -> Result<Self, Error>
    where
        T::Archived:
            for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>,
    {
        Self::from_bytes_with(&std::fs::read(path.as_ref())?, validator)
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error>
    where
        T::Archived:
            for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>,
    {
        Self::from_bytes_with(raw, &NoValidator)
    }

    pub fn from_bytes_with(raw: &[u8], validator: &dyn Validator) -> Result<Self, Error>
    where
        T::Archived:
            for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>,
    {
        let header = Header::parse(raw)?;
        header.check_layout(raw.len())?;

        let mut aligned = AlignedVec::with_capacity(raw.len());
        aligned.extend_from_slice(raw);

        let table_start = HEADER_LEN;
        let table_end = table_start + header.section_table_len as usize;
        let table = &aligned[table_start..table_end];

        let mut sections: Vec<(Entry, usize, usize)> = Vec::new();
        let mut cursor = table_end;
        let mut prev_id = 0u16;
        for i in 0..header.section_count as usize {
            let entry = Entry::parse(&table[i * ENTRY_LEN..(i + 1) * ENTRY_LEN])?;
            if entry.id <= prev_id && i > 0 {
                return Err(Error::SectionOrder);
            }
            // every section starts at the next 16-byte boundary at or after the
            // previous end, so the offset is computed and never stored
            while !cursor.is_multiple_of(16) {
                if raw[cursor] != 0 {
                    return Err(Error::BadSectionTable("padding is not zero"));
                }
                cursor += 1;
            }
            let len = entry.len as usize;
            let Some(end) = cursor.checked_add(len) else {
                return Err(Error::BadSectionTable("section length overflows"));
            };
            if end > raw.len() {
                return Err(Error::Truncated {
                    need: end,
                    have: raw.len(),
                });
            }
            sections.push((entry, cursor, len));
            prev_id = entry.id;
            cursor = end;
        }
        if cursor != raw.len() {
            return Err(Error::BadSectionTable("sections do not end the file"));
        }

        // the family sections must be the kind they claim, which is the guard
        // against reading an IPv4 archive as IPv6
        for (entry, _, _) in &sections {
            match entry.id {
                ID_V4 if entry.kind != KIND_V4 => return Err(Error::BadSectionKind(entry.id)),
                ID_V6 if entry.kind != KIND_V6 => return Err(Error::BadSectionKind(entry.id)),
                _ => {}
            }
            // and the reverse: a family kind lives at its normative id, so an
            // object cannot dodge a reader by putting it somewhere else
            match entry.kind {
                KIND_V4 if entry.id != ID_V4 => return Err(Error::BadSectionKind(entry.id)),
                KIND_V6 if entry.id != ID_V6 => return Err(Error::BadSectionKind(entry.id)),
                _ => {}
            }
        }

        // identity: header prefix, table, every section
        let mut h = blake3::Hasher::new();
        h.update(b"bgpkit-snap-v4\0");
        h.update(&aligned[..header::HASH_END]);
        h.update(table);
        for (_, off, len) in &sections {
            h.update(&aligned[*off..*off + *len]);
        }
        if *h.finalize().as_bytes() != header.content_id {
            return Err(Error::ContentId);
        }

        let declared = header.type_id_str();
        if declared != T::TYPE_ID {
            return Err(Error::TypeMismatch {
                expected: T::TYPE_ID.to_string(),
                found: declared,
            });
        }

        let snap = Snapshot {
            bytes: aligned,
            header,
            sections,
            table_range: (table_start, table_end),
            _t: std::marker::PhantomData,
        };

        let view = snap.view();
        for (entry, _, _) in &snap.sections {
            let known = matches!(entry.id, ID_V4 | ID_V6);
            if entry.required && !known && !validator.knows(entry) {
                return Err(Error::UnknownRequiredSection(entry.id));
            }
        }
        snap.validate_archives()?;
        validator.validate(&view)?;
        Ok(snap)
    }

    /// The table bytes, for a reader that wants to list sections without
    /// touching the body.
    pub fn table_bytes(&self) -> &[u8] {
        &self.bytes[self.table_range.0..self.table_range.1]
    }

    pub fn entries(&self) -> Vec<Entry> {
        self.sections.iter().map(|(e, _, _)| *e).collect()
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn content_id(&self) -> String {
        self.header.content_id_hex()
    }

    pub fn section_bytes(&self, id: u16) -> Option<&[u8]> {
        self.sections
            .iter()
            .find(|(e, _, _)| e.id == id)
            .map(|(_, off, len)| &self.bytes[*off..*off + *len])
    }

    /// What a `Validator` is handed: the header, the section table and the raw
    /// bytes, after the container and both trie archives have been checked.
    pub fn view(&self) -> SnapshotView<'_> {
        SnapshotView {
            header: &self.header,
            sections: &self.sections,
            bytes: &self.bytes,
            table: &self.bytes[self.table_range.0..self.table_range.1],
        }
    }

    fn validate_archives(&self) -> Result<(), Error>
    where
        T::Archived:
            for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>,
    {
        for (entry, off, len) in &self.sections {
            let slice = &self.bytes[*off..*off + *len];
            match entry.id {
                ID_V4 => {
                    rkyv::access::<ArchivedPrefixMap<Ipv4Net, T>, RkyvError>(slice)
                        .map_err(|_| Error::BadArchive(ID_V4))?;
                }
                ID_V6 => {
                    rkyv::access::<ArchivedPrefixMap<Ipv6Net, T>, RkyvError>(slice)
                        .map_err(|_| Error::BadArchive(ID_V6))?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The IPv4 trie, if the object has one.
    pub fn v4(&self) -> Option<&ArchivedPrefixMap<Ipv4Net, T>> {
        self.section_bytes(ID_V4)
            .map(|s| unsafe { rkyv::access_unchecked::<ArchivedPrefixMap<Ipv4Net, T>>(s) })
    }

    /// The IPv6 trie, if the object has one.
    pub fn v6(&self) -> Option<&ArchivedPrefixMap<Ipv6Net, T>> {
        self.section_bytes(ID_V6)
            .map(|s| unsafe { rkyv::access_unchecked::<ArchivedPrefixMap<Ipv6Net, T>>(s) })
    }

    pub fn len(&self) -> usize {
        self.v4().map(|m| m.len()).unwrap_or(0) + self.v6().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Longest-prefix match for a single address.
    pub fn search(&self, addr: std::net::IpAddr) -> Option<(IpNet, &T::Archived)> {
        match addr {
            std::net::IpAddr::V4(a) => {
                let p = Ipv4Net::new(a, 32).ok()?;
                let map = self.v4()?;
                let (lpm, value) = map.get_lpm(&p)?;
                Some((IpNet::V4(lpm), value))
            }
            std::net::IpAddr::V6(a) => {
                let p = Ipv6Net::new(a, 128).ok()?;
                let map = self.v6()?;
                let (lpm, value) = map.get_lpm(&p)?;
                Some((IpNet::V6(lpm), value))
            }
        }
    }

    /// Longest prefix that covers `prefix`, and its value.
    pub fn lpm(&self, prefix: IpNet) -> Option<(IpNet, &T::Archived)> {
        match prefix {
            IpNet::V4(p) => {
                let map = self.v4()?;
                let (lpm, value) = map.get_lpm(&p)?;
                Some((IpNet::V4(lpm), value))
            }
            IpNet::V6(p) => {
                let map = self.v6()?;
                let (lpm, value) = map.get_lpm(&p)?;
                Some((IpNet::V6(lpm), value))
            }
        }
    }

    // ---- the read side of prefix_trie, with IpNet keys ----
    //
    // A snapshot holds two tries, one per family. These forward the map's own
    // read API so a caller does not have to match on the family and hold two
    // code paths for every query.

    /// The value stored exactly at `prefix`, with no ancestor fallback.
    pub fn get_exact(&self, prefix: IpNet) -> Option<&T::Archived> {
        match prefix {
            IpNet::V4(p) => self.v4().and_then(|m| m.get(&p)),
            IpNet::V6(p) => self.v6().and_then(|m| m.get(&p)),
        }
    }

    pub fn contains_key(&self, prefix: IpNet) -> bool {
        match prefix {
            IpNet::V4(p) => self.v4().is_some_and(|m| m.contains_key(&p)),
            IpNet::V6(p) => self.v6().is_some_and(|m| m.contains_key(&p)),
        }
    }

    pub fn spm(&self, prefix: IpNet) -> Option<(IpNet, &T::Archived)> {
        match prefix {
            IpNet::V4(p) => self
                .v4()
                .and_then(|m| m.get_spm(&p))
                .map(|(k, v)| (IpNet::V4(k), v)),
            IpNet::V6(p) => self
                .v6()
                .and_then(|m| m.get_spm(&p))
                .map(|(k, v)| (IpNet::V6(k), v)),
        }
    }

    pub fn is_covered(&self, prefix: IpNet) -> bool {
        match prefix {
            IpNet::V4(p) => self.v4().is_some_and(|m| m.is_covered(&p)),
            IpNet::V6(p) => self.v6().is_some_and(|m| m.is_covered(&p)),
        }
    }

    /// Whether `prefix` is covered by an aggregate entry, that is a stored
    /// prefix carrying its whole subtree.
    pub fn is_covered_in_aggregate(&self, prefix: IpNet) -> bool {
        match prefix {
            IpNet::V4(p) => self.v4().is_some_and(|m| m.is_covered_in_aggregate(&p)),
            IpNet::V6(p) => self.v6().is_some_and(|m| m.is_covered_in_aggregate(&p)),
        }
    }

    /// Every entry, IPv4 first then IPv6, in trie order.
    pub fn iter(&self) -> Box<dyn Iterator<Item = (IpNet, &T::Archived)> + '_> {
        let v4 = self
            .v4()
            .into_iter()
            .flat_map(|m| m.iter())
            .map(|(p, v)| (IpNet::V4(p), v));
        let v6 = self
            .v6()
            .into_iter()
            .flat_map(|m| m.iter())
            .map(|(p, v)| (IpNet::V6(p), v));
        Box::new(v4.chain(v6))
    }

    /// Every key, IPv4 first then IPv6.
    pub fn keys(&self) -> Box<dyn Iterator<Item = IpNet> + '_> {
        Box::new(self.iter().map(|(p, _)| p))
    }

    /// Every entry at or after `prefix` in trie order, within `prefix`'s family;
    /// an IPv4 start does not continue into the IPv6 trie. Use `iter()` for both.
    pub fn iter_from(
        &self,
        prefix: IpNet,
        inclusive: bool,
    ) -> Box<dyn Iterator<Item = (IpNet, &T::Archived)> + '_> {
        match prefix {
            IpNet::V4(p) => {
                let it = self
                    .v4()
                    .into_iter()
                    .flat_map(move |m| m.iter_from(&p, inclusive))
                    .map(|(k, v)| (IpNet::V4(k), v));
                Box::new(it)
            }
            IpNet::V6(p) => {
                let it = self
                    .v6()
                    .into_iter()
                    .flat_map(move |m| m.iter_from(&p, inclusive))
                    .map(|(k, v)| (IpNet::V6(k), v));
                Box::new(it)
            }
        }
    }

    /// Every value, IPv4 first then IPv6.
    pub fn values(&self) -> Box<dyn Iterator<Item = &T::Archived> + '_> {
        let v4 = self.v4().into_iter().flat_map(|m| m.values());
        let v6 = self.v6().into_iter().flat_map(|m| m.values());
        Box::new(v4.chain(v6))
    }

    pub fn address_counts(&self) -> AddressCounts {
        let count = |m: Option<Option<u128>>| match m {
            None => Count::NoEntries,
            Some(None) => Count::All,
            Some(Some(n)) => Count::Exact(n),
        };
        AddressCounts {
            v4: count(self.v4().map(|m| m.address_count().map(u128::from))),
            v6: count(self.v6().map(|m| m.address_count())),
        }
    }

    /// The prefixes that cover `prefix`, each with its value.
    pub fn cover(&self, prefix: IpNet) -> Vec<(IpNet, &T::Archived)> {
        match prefix {
            IpNet::V4(p) => self
                .v4()
                .map(|m| m.cover(&p).map(|(k, v)| (IpNet::V4(k), v)).collect())
                .unwrap_or_default(),
            IpNet::V6(p) => self
                .v6()
                .map(|m| m.cover(&p).map(|(k, v)| (IpNet::V6(k), v)).collect())
                .unwrap_or_default(),
        }
    }

    /// The prefix itself when it is stored, plus everything under it, in trie
    /// order. A query for a block that is not stored returns only what is under
    /// it, never a sibling.
    ///
    /// The query prefix is read as its network address, and every key returned is a
    /// key the object contains: a query for `10.1.2.3/16` answers for `10.1.0.0/16`
    /// and returns that key, never the caller's spelling of it.
    pub fn children(&self, prefix: IpNet) -> Vec<(IpNet, &T::Archived)> {
        let mut out: Vec<(IpNet, &T::Archived)> = Vec::new();
        match prefix {
            IpNet::V4(p) => {
                let p = p.trunc();
                let Some(map) = self.v4() else { return out };
                if let Some((k, v)) = map.get_key_value(&p) {
                    out.push((IpNet::V4(k), v));
                }
                if let Some(view) = map.view_at(&p) {
                    for (k, v) in view.iter() {
                        if k != p {
                            out.push((IpNet::V4(k), v));
                        }
                    }
                }
            }
            IpNet::V6(p) => {
                let p = p.trunc();
                let Some(map) = self.v6() else { return out };
                if let Some((k, v)) = map.get_key_value(&p) {
                    out.push((IpNet::V6(k), v));
                }
                if let Some(view) = map.view_at(&p) {
                    for (k, v) in view.iter() {
                        if k != p {
                            out.push((IpNet::V6(k), v));
                        }
                    }
                }
            }
        }
        out
    }
}
