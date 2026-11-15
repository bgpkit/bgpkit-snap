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
/// caller can write `bgpkit_snap::rkyv::Archive` instead of adding a second
/// dependency that must match this one exactly.
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

#[derive(Debug)]
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

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

// ---------------------------------------------------------------- values

/// A value type that can live in a trie.
pub trait SnapValue: rkyv::Archive + Clone + for<'a> rkyv::Serialize<HighSer<'a>> {
    /// Stable identifier, e.g. `snap.u32:v1`.
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

/// One section the caller supplies, e.g. a payload arena.
/// One section the caller supplies next to the tries: an arena, a sidecar, any
/// bytes the profile owns. `id` is 16 or higher, `kind` is a four-byte tag, and
/// `required` makes a reader that does not implement the id refuse the object.
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

    /// Insert a value, replacing any value already stored for that prefix.
    /// Store `value` under `prefix`, replacing any value already there.
    ///
    /// The prefix must be canonical (`addr() == network()`); a prefix with host
    /// bits set is a caller error and trips a debug assertion, because silently
    /// storing it under its network address would make the key you asked for and
    /// the key you get back differ.
    pub fn insert(&mut self, prefix: IpNet, mut value: T) {
        debug_assert!(
            prefix.addr() == prefix.network(),
            "prefix {prefix} has host bits set; it would be stored as {}/{}",
            prefix.network(),
            prefix.prefix_len()
        );
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
        // one temp name per writer, or two writers to one path fight over it
        let tmp = path.with_extension(format!("snap.{}.tmp", std::process::id()));
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
        validator.validate(&view)?;
        snap.validate_archives()?;
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

    fn view(&self) -> SnapshotView<'_> {
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
                        .map_err(|_| Error::BadSectionKind(ID_V4))?;
                }
                ID_V6 => {
                    rkyv::access::<ArchivedPrefixMap<Ipv6Net, T>, RkyvError>(slice)
                        .map_err(|_| Error::BadSectionKind(ID_V6))?;
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

    /// The stored prefix and its value, when `prefix` is stored as given.
    pub fn get_key_value(&self, prefix: IpNet) -> Option<(IpNet, &T::Archived)> {
        match prefix {
            IpNet::V4(p) => self
                .v4()
                .and_then(|m| m.get_key_value(&p))
                .map(|(k, v)| (IpNet::V4(k), v)),
            IpNet::V6(p) => self
                .v6()
                .and_then(|m| m.get_key_value(&p))
                .map(|(k, v)| (IpNet::V6(k), v)),
        }
    }

    /// Whether `prefix` is stored as given.
    pub fn contains_key(&self, prefix: IpNet) -> bool {
        match prefix {
            IpNet::V4(p) => self.v4().is_some_and(|m| m.contains_key(&p)),
            IpNet::V6(p) => self.v6().is_some_and(|m| m.contains_key(&p)),
        }
    }

    /// The key of the longest prefix that covers `prefix`.
    pub fn lpm_prefix(&self, prefix: IpNet) -> Option<IpNet> {
        self.lpm(prefix).map(|(p, _)| p)
    }

    /// Least specific prefix that covers `prefix`, and its value. This is
    /// prefix_trie's `get_spm`: the shortest stored prefix containing the query.
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

    /// The key of the shortest prefix that sits under `prefix`.
    pub fn spm_prefix(&self, prefix: IpNet) -> Option<IpNet> {
        self.spm(prefix).map(|(p, _)| p)
    }

    /// Whether some stored prefix covers `prefix`.
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

    /// The value stored exactly at `prefix`, deserialized.
    ///
    /// A caller that only reads a scalar should not have to depend on the
    /// archive library to get it out.
    pub fn get_exact_owned(&self, prefix: IpNet) -> Option<T>
    where
        T::Archived: rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<RkyvError>>,
    {
        let value = self.get_exact(prefix)?;
        rkyv::deserialize::<T, RkyvError>(value).ok()
    }

    /// Longest-prefix match for an address, with the value deserialized.
    pub fn search_owned(&self, addr: std::net::IpAddr) -> Option<(IpNet, T)>
    where
        T::Archived: rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<RkyvError>>,
    {
        let (prefix, value) = self.search(addr)?;
        let value = rkyv::deserialize::<T, RkyvError>(value).ok()?;
        Some((prefix, value))
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

    /// Every entry at or after `prefix` in trie order, for a caller that wants to
    /// walk a range instead of the whole object.
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

    /// The keys of the prefixes that cover `prefix`.
    pub fn cover_keys(&self, prefix: IpNet) -> Vec<IpNet> {
        match prefix {
            IpNet::V4(p) => self
                .v4()
                .map(|m| m.cover_keys(&p).map(IpNet::V4).collect())
                .unwrap_or_default(),
            IpNet::V6(p) => self
                .v6()
                .map(|m| m.cover_keys(&p).map(IpNet::V6).collect())
                .unwrap_or_default(),
        }
    }

    /// The values of the prefixes that cover `prefix`.
    pub fn cover_values(&self, prefix: IpNet) -> Vec<&T::Archived> {
        self.cover(prefix).into_iter().map(|(_, v)| v).collect()
    }

    /// How many addresses each family's entries cover, when the trie tracks it.
    pub fn address_counts(&self) -> (Option<u128>, Option<u128>) {
        let v4 = self.v4().and_then(|m| m.address_count()).map(u128::from);
        let v6 = self.v6().and_then(|m| m.address_count());
        (v4, v6)
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
    pub fn children(&self, prefix: IpNet) -> Vec<(IpNet, &T::Archived)> {
        let mut out: Vec<(IpNet, &T::Archived)> = Vec::new();
        match prefix {
            IpNet::V4(p) => {
                let Some(map) = self.v4() else { return out };
                if let Some(v) = map.get(&p) {
                    out.push((IpNet::V4(p), v));
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
                let Some(map) = self.v6() else { return out };
                if let Some(v) = map.get(&p) {
                    out.push((IpNet::V6(p), v));
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
