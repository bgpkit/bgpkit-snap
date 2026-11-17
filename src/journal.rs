//! The journal: one owner of the live tree, the blob arena and the segments.
//!
//! A record is
//! `len | crc32c | seq | recv_ts | event_ts | kind | family | plen | flags |
//!  addr[16] | value_len | value | blob_len | blob`.
//!
//! The trailing blob is what makes handle values work: a value may point into a
//! payload section, and the bytes it points at travel in the same record, so a
//! replay rebuilds the section in record order and every offset reproduces.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use prefix_trie::PrefixMap;

use crate::header::KIND_PAYLOAD;
use crate::{Codec, Error, ExtraSection, Opts, Snapshot, Writer};
use rkyv::rancor::Error as RkyvError;

const MAGIC: &[u8; 8] = b"BGPKLOG\0";
const SEGMENT_HEADER_LEN: usize = 48;
const SEGMENT_VERSION: u16 = 4;
const RECORD_FIXED_LEN: usize = 56;

/// Record kind: a value was inserted or replaced.
pub const KIND_INSERT: u8 = 1;
/// Record kind: a value was removed.
pub const KIND_WITHDRAW: u8 = 2;

/// When a record happened. Both fields are unix seconds; leave them zero when the
/// feed has no clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Times {
    /// When the collector received the event.
    pub recv_ts: i64,
    /// When the event itself happened, if the feed says so.
    pub event_ts: i64,
}

/// What `insert_with_blob` did: the record's sequence number and the arena offset
/// its blob landed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobInserted {
    /// The sequence number this record was written with.
    pub seq: u64,
    /// Byte offset the blob landed at in the journal's arena.
    pub offset: u64,
}

#[derive(Debug, Clone, Copy)]
/// Where a journal's blob arena lands in the snapshots it checkpoints: the
/// section id (16 or higher), its kind tag, and whether a reader must know it.
pub struct PayloadSection {
    /// Section id the arena is written as; 16 or higher.
    pub id: u16,
    /// Four-byte kind tag of that section.
    pub kind: [u8; 4],
    /// Whether a reader that does not implement the section must refuse the object.
    pub required: bool,
}

impl PayloadSection {
    /// A required payload section at `id`, with the standard `PAY` kind.
    pub fn payload(id: u16) -> Self {
        Self {
            id,
            kind: KIND_PAYLOAD,
            required: true,
        }
    }
}

/// A journal constructor with the uncommon knobs as methods.
///
/// `Journal::open` and `Journal::open_with_payload` cover the two cases a service
/// meets; this covers a caller that mints its own generation, which is normally a
/// fixture rather than a deployment.
pub struct JournalOptions<T: Codec> {
    dir: std::path::PathBuf,
    base: BaseSource,
    payload: Option<PayloadSection>,
    generation: Option<[u8; 16]>,
    _t: std::marker::PhantomData<T>,
}

impl<T: Codec> JournalOptions<T>
where
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    /// Values point into a blob arena, carried by this section.
    pub fn payload(mut self, section: PayloadSection) -> Self {
        self.payload = Some(section);
        self
    }

    /// Reuse a known incarnation id instead of minting one.
    ///
    /// Only a directory that has none yet accepts it: a journal that already holds a
    /// generation is opened with that one, and asking for a different one is an
    /// error rather than a silent no-op.
    pub fn generation(mut self, generation: [u8; 16]) -> Self {
        self.generation = Some(generation);
        self
    }

    /// Start the journal from `base` instead of reopening an existing directory.
    pub fn attach(mut self, base: impl AsRef<Path>) -> Self {
        self.base = BaseSource::Attach(base.as_ref().to_path_buf());
        self
    }

    /// Start the journal from an empty object with this tree id, or resume it.
    pub fn start(mut self, tree_id: impl Into<crate::TreeId>) -> Self {
        self.base = BaseSource::Start(tree_id.into());
        self
    }

    /// Open with these options.
    pub fn open(self) -> Result<Journal<T>, Error> {
        Journal::<T>::open_inner(self.dir, self.base, self.payload, self.generation)
    }
}

/// How a journal starts: reopening a directory, adopting an object as its base, or
/// minting an empty base for a stream that has none yet.
pub(crate) enum BaseSource {
    Reopen,
    Attach(PathBuf),
    Start(crate::TreeId),
}

/// What a fresh journal takes from its base: the tree id, the generation it writes
/// under, and the base record `(content id hex, path)`.
pub(crate) struct StartIdentity {
    pub tree_id: [u8; 16],
    pub generation: [u8; 16],
    pub base: Option<(String, String)>,
}

struct Segment {
    file: BufWriter<File>,
    bytes: u64,
}

/// An append-only log plus the tree it describes, and the only writer of both.
///
/// One journal owns one directory: the tree, the arena, the segment writer and the
/// writer lock all live here, so a caller cannot append without the tree following
/// and cannot open a second writer by accident.
pub struct Journal<T: Codec> {
    /// Advisory lock, held until the journal is dropped: one writer per tree.
    _lock: File,
    dir: PathBuf,
    tree_id: [u8; 16],
    generation: [u8; 16],
    stream: crate::StreamRef,
    seg: Option<Segment>,
    seg_path: Option<PathBuf>,
    seg_index: u64,
    /// Offset to cut back to before the next append, set when a write failed.
    seg_dirty_from: Option<u64>,
    /// The committed checkpoint: `(base_seq, file)`. Held in memory so a `sync`
    /// after a lost `state.json` cannot silently drop it.
    checkpoint: Option<(u64, String)>,
    /// The object this journal was attached to, `(content id hex, path)`.
    base: Option<(String, String)>,
    /// How many checkpoints this process has written, so two of them at the same
    /// sequence number do not share a file name.
    checkpoints: u64,
    seq: u64,
    base_seq: u64,
    /// Whether `state.json` has been written for this directory in this session. The
    /// first record writes it, so the value type is pinned from the first byte: without
    /// it a reader of another type could decode these records as its own.
    state_written: bool,
    v4: PrefixMap<ipnet::Ipv4Net, T>,
    v6: PrefixMap<ipnet::Ipv6Net, T>,
    blob: Vec<u8>,
    payload: Option<PayloadSection>,
}

impl<T: Codec> Journal<T>
where
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    /// Reopen the journal in `dir`.
    ///
    /// A journal is a log of changes to one object, never a tree of its own: it is
    /// created by `attach` (or `create` for an empty start) and reopened by this
    /// call, which recovers the tree from the last checkpoint plus the segments, and
    /// from the base object when no checkpoint has been written yet.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_inner(dir, BaseSource::Reopen, None, None)
    }

    /// Start a journal whose base is `base`, the object the log will keep current.
    ///
    /// The base is read once and recorded by content id; until the first checkpoint
    /// the journal cannot be opened without it, and a base that was replaced is
    /// refused instead of silently adopted. After the first checkpoint the tree comes
    /// from that checkpoint and the base is provenance.
    pub fn attach(base: impl AsRef<Path>, dir: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_inner(
            dir,
            BaseSource::Attach(base.as_ref().to_path_buf()),
            None,
            None,
        )
    }

    /// Start a journal whose base is an empty object with this tree id, for a stream
    /// that has no snapshot yet.
    ///
    /// A directory that already holds a journal is resumed instead, and the tree id has
    /// to be the one that journal records: a service can call this on every start
    /// without first asking whether the directory is new.
    pub fn start(dir: impl AsRef<Path>, tree_id: impl Into<crate::TreeId>) -> Result<Self, Error> {
        Self::open_inner(dir, BaseSource::Start(tree_id.into()), None, None)
    }

    /// A journal whose values point into a blob arena. The section has to be the one
    /// the base or the checkpoint carries, or open refuses it.
    pub fn open_with_payload(
        dir: impl AsRef<Path>,
        payload: PayloadSection,
    ) -> Result<Self, Error> {
        Self::open_inner(dir, BaseSource::Reopen, Some(payload), None)
    }

    /// The knobs a constructor should not take positionally: the payload section, a
    /// caller-minted generation, and how the journal starts.
    pub fn options(dir: impl AsRef<Path>) -> JournalOptions<T> {
        JournalOptions {
            dir: dir.as_ref().to_path_buf(),
            base: BaseSource::Reopen,
            payload: None,
            generation: None,
            _t: std::marker::PhantomData,
        }
    }

    pub(crate) fn open_inner(
        dir: impl AsRef<Path>,
        base: BaseSource,
        payload: Option<PayloadSection>,
        generation: Option<[u8; 16]>,
    ) -> Result<Self, Error> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let lock = Self::take_writer_lock(&dir)?;
        Self::open_locked(dir, base, payload, generation, lock)
    }

    /// The writer lock for this directory, or `Locked` when another journal has it.
    fn take_writer_lock(dir: &Path) -> Result<File, Error> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("writer.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| Error::Locked)?;
        Ok(lock)
    }

    /// Open with a writer lock the caller already holds. `repair` uses this so the
    /// lock covers its state write and the check that the state can be adopted:
    /// releasing it in between lets another writer commit a state file that this
    /// call would then delete.
    fn open_locked(
        dir: impl AsRef<Path>,
        base: BaseSource,
        payload: Option<PayloadSection>,
        generation: Option<[u8; 16]>,
        lock: File,
    ) -> Result<Self, Error> {
        let dir = dir.as_ref().to_path_buf();
        // a journal is a log for one object, so the two ways to start are explicit and
        // a directory that already holds a journal is only ever reopened
        let start = match (&base, read_state(&dir)?) {
            (BaseSource::Reopen, None) => return Err(Error::BadOpts(
                "this directory holds no journal yet: start one with Journal::attach(base, dir) \
                     or Journal::create(dir, tree_id)",
            )),
            (BaseSource::Reopen, Some(state)) => Some(state),
            (_, None) => None,
            (BaseSource::Start(tree_id), Some(state)) => {
                // resuming is only resuming when it is the same tree; anything else is a
                // caller pointing a stream at another stream's directory
                if *tree_id.as_bytes() != state.tree_id {
                    return Err(Error::ConfigMismatch(format!(
                        "this journal belongs to tree {}, not {}",
                        crate::header::hex16(&state.tree_id),
                        crate::header::hex16(tree_id.as_bytes())
                    )));
                }
                Some(state)
            }
            (BaseSource::Attach(_), Some(_)) => {
                return Err(Error::BadOpts(
                    "this directory already holds a journal: reopen it with Journal::open instead \
                     of attaching another base",
                ))
            }
        };
        // reject here what a checkpoint would reject later, after data was written
        if generation.unwrap_or([1u8; 16]) == [0u8; 16] {
            return Err(Error::BadOpts(
                "a journal generation of all zeros means \"mint one\"; pass None to mint it",
            ));
        }
        if let Some(p) = payload {
            if p.id < crate::header::FIRST_PROFILE_ID {
                return Err(Error::BadSectionId(p.id));
            }
            if p.kind == crate::header::KIND_V4 || p.kind == crate::header::KIND_V6 {
                return Err(Error::BadRecord("payload section uses a family kind"));
            }
        }

        // the directory records what wrote it; a reopen with another value type or
        // another payload would reinterpret the same bytes without a word
        let (tree_id, generation, base_record, fresh) = match &start {
            Some(state) => {
                if let Some(type_id) = state.type_id.as_deref() {
                    if type_id != T::TYPE_ID {
                        return Err(Error::ConfigMismatch(format!(
                            "this journal was written as {type_id}, not {}",
                            T::TYPE_ID
                        )));
                    }
                }
                let configured = payload.map(|p| (p.id, p.kind, p.required));
                if let Some(written) = state.payload {
                    if Some(written) != configured {
                        return Err(Error::ConfigMismatch(format!(
                            "this journal was written with payload section {} (kind {}, required \
                             {}); open it with that configuration",
                            written.0,
                            String::from_utf8_lossy(&written.1),
                            written.2
                        )));
                    }
                }
                if let Some(wanted) = generation {
                    if wanted != state.generation {
                        return Err(Error::ConfigMismatch(format!(
                            "this journal was minted as generation {}, not {}",
                            crate::header::hex16(&state.generation),
                            crate::header::hex16(&wanted)
                        )));
                    }
                }
                (state.tree_id, state.generation, state.base.clone(), false)
            }
            None => {
                let identity = Self::start_from(&dir, base, generation)?;
                (identity.tree_id, identity.generation, identity.base, true)
            }
        };
        // a new segment, never the existing ones: reopening must not truncate
        let index = segment_paths(&dir)?
            .iter()
            .filter_map(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_prefix("segment-"))
                    .and_then(|n| n.strip_suffix(".log"))
                    .and_then(|n| n.parse::<u64>().ok())
            })
            .max()
            .map_or(1, |m| m + 1);
        let mut journal = Journal {
            _lock: lock,
            dir: dir.clone(),
            tree_id,
            generation,
            stream: crate::StreamRef {
                tree_id,
                generation,
                base_seq: 0,
            },
            seg: None,
            seg_path: None,
            seg_index: index,
            seg_dirty_from: None,
            checkpoint: None,
            base: base_record.clone(),
            checkpoints: 0,
            seq: 1,
            base_seq: 0,
            state_written: !fresh,
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
            blob: Vec::new(),
            payload,
        };
        // a fresh directory records itself before it accepts a record, so a crash
        // before the first sync still leaves a journal that names its base
        let state = match start {
            Some(state) => Some(state),
            None => {
                if !snapshot_paths(&journal.dir)?.is_empty() {
                    // the checkpoints exist but nothing says which one is current, and
                    // the segments they replaced may already be gone
                    return Err(Error::BadRecord(
                        "checkpoints exist but state.json is missing",
                    ));
                }
                let state = State {
                    next_seq: 1,
                    generation,
                    tree_id,
                    checkpoint: None,
                    base: journal.base.clone(),
                    type_id: Some(T::TYPE_ID.to_string()),
                    payload: journal.payload.map(|p| (p.id, p.kind, p.required)),
                };
                write_state(&journal.dir, &state)?;
                journal.state_written = true;
                Some(state)
            }
        };
        let keep = journal.recover(state)?;
        // the snapshot name carries a per-sequence ordinal; seeding it from disk keeps
        // the first checkpoint after a restart from reusing a committed name
        journal.checkpoints = highest_checkpoint_ordinal(&journal.dir, journal.seq);
        // the stable name is published before anything is reclaimed: a publication
        // that fails must not leave it pointing at an object this open deleted
        match keep.as_ref() {
            Some(name) => journal.publish_current(name)?,
            None => {
                let _ = std::fs::remove_file(journal.dir.join("current.snap"));
            }
        }
        // a snapshot written just before a crash is not named by the state file,
        // so it is an orphan: recovery already came from the segments
        for path in snapshot_paths(&journal.dir)? {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            if Some(&name) != keep.as_ref() {
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(journal)
    }

    /// The identity a fresh journal takes from its base, and the base record it stores:
    /// `(tree id, generation, (content id hex, path))`.
    ///
    /// The tree id comes from the object the log extends, not from a name the caller
    /// types: a plain snapshot has none, so the id is derived from its content id, and a
    /// checkpoint keeps the id of the stream it belongs to.
    fn start_from(
        dir: &Path,
        base: BaseSource,
        generation: Option<[u8; 16]>,
    ) -> Result<StartIdentity, Error> {
        match base {
            BaseSource::Reopen => unreachable!("a reopen never starts a directory"),
            BaseSource::Start(tree_id) => {
                let tree_id = *tree_id.as_bytes();
                if tree_id == [0u8; 16] {
                    return Err(Error::BadOpts("tree id is all zero"));
                }
                let generation = generation.unwrap_or_else(random_generation);
                let opts = crate::Opts {
                    created_at: chrono::Utc::now().timestamp(),
                    stream: Some(crate::StreamRef {
                        tree_id,
                        generation,
                        base_seq: 0,
                    }),
                    window: None,
                    extras: &[],
                };
                let path = dir.join("base.snap");
                crate::Writer::<T>::new().finish_to(&path, &opts)?;
                let raw = std::fs::read(&path)?;
                let content_id = crate::header::hex32(&crate::Header::parse(&raw)?.content_id);
                // absolute: the record outlives this call, and a relative path would be
                // read against whatever directory the next process runs in
                let path = std::fs::canonicalize(&path)?;
                Ok(StartIdentity {
                    tree_id,
                    generation,
                    base: Some((content_id, path.to_string_lossy().into_owned())),
                })
            }
            BaseSource::Attach(path) => {
                // reading the base once here is also the check that it is a whole object
                // of this value type, so a wrong file is named at attach time
                let snap = Snapshot::<T>::open(&path)?;
                if snap.header().type_id_str() != T::TYPE_ID {
                    return Err(Error::ConfigMismatch(format!(
                        "the base object holds {}, not {}",
                        snap.header().type_id_str(),
                        T::TYPE_ID
                    )));
                }
                let content_id = crate::header::hex32(&snap.header().content_id);
                let tree_id = match snap.header().stream() {
                    Some(s) => s.tree_id,
                    None => *crate::TreeId::from_name(&content_id).as_bytes(),
                };
                Ok(StartIdentity {
                    tree_id,
                    generation: generation.unwrap_or_else(random_generation),
                    base: Some((
                        content_id,
                        std::fs::canonicalize(&path)?.to_string_lossy().into_owned(),
                    )),
                })
            }
        }
    }

    /// Create this session's segment. Called on the first append, so a journal
    /// that is opened and closed without writes leaves no empty file.
    /// A segment is rotated once it passes this size, so a long-running journal
    /// does not carry every record since start in one file.
    const SEGMENT_MAX_BYTES: u64 = 64 * 1024 * 1024;

    /// Close the current segment and start the next one.
    ///
    /// `sync` only reaches the open segment, so a rotated one that was never
    /// flushed would be reported durable while its last records sat in a buffer
    /// that `drop` discards on failure. Flush and fsync here, and on failure keep
    /// the segment so the next append can cut back to the last acknowledged byte.
    fn rotate_segment(&mut self) -> Result<(), Error> {
        let Some(mut seg) = self.seg.take() else {
            return Ok(());
        };
        // keep the file system's error: on a full disk or a dying device, errno is
        // the only thing that says which
        let durability = seg
            .file
            .flush()
            .and_then(|()| seg.file.get_ref().sync_all());
        if let Err(e) = durability {
            self.seg_dirty_from = Some(seg.bytes);
            self.seg = Some(seg);
            return Err(Error::Io(e));
        }
        self.seg_path = None;
        self.seg_index += 1;
        self.open_segment()
    }

    /// What this journal writes, recorded in `state.json` so another configuration
    /// cannot adopt the directory.
    fn config(&self) -> (String, Option<(u16, [u8; 4], bool)>) {
        (
            T::TYPE_ID.to_string(),
            self.payload.map(|p| (p.id, p.kind, p.required)),
        )
    }

    fn open_segment(&mut self) -> Result<(), Error> {
        let path = self.dir.join(format!("segment-{:012}.log", self.seg_index));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.seg = Some(Segment {
            file: BufWriter::new(file),
            bytes: 0,
        });
        self.seg_path = Some(path);
        self.write_segment_header()
    }

    /// Remove the bytes a failed write left behind. Only the writing side calls
    /// this, and only for bytes it wrote itself in this session: recovery never
    /// truncates, because there a short segment may mean a lost one.
    fn discard_torn_write(&mut self) -> Result<(), Error> {
        // the offset is the only record of where the acknowledged bytes end. It is
        // cleared after the cut-back succeeds, never before: a retry on a full disk
        // fails here too, and the next append must still cut from the same offset
        let Some(offset) = self.seg_dirty_from else {
            return Ok(());
        };
        if let Some(seg) = self.seg.as_mut() {
            seg.file.flush()?;
            seg.file.get_ref().set_len(offset)?;
            seg.file.get_ref().sync_all()?;
            seg.bytes = offset;
        }
        self.seg_dirty_from = None;
        Ok(())
    }

    /// Point `<dir>/current.snap` at `name`, atomically.
    fn publish_current(&self, name: &str) -> Result<(), Error> {
        let link = self.dir.join("current.snap");
        let tmp = self.dir.join(".current.snap.tmp");
        let _ = std::fs::remove_file(&tmp);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(name, &tmp)?;
            std::fs::rename(&tmp, &link)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::copy(self.dir.join(name), &tmp)?;
            std::fs::rename(&tmp, &link)?;
        }
        Ok(())
    }

    fn write_segment_header(&mut self) -> Result<(), Error> {
        let Some(seg) = self.seg.as_mut() else {
            return Ok(());
        };
        let mut header = Vec::with_capacity(SEGMENT_HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&SEGMENT_VERSION.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&self.tree_id);
        header.extend_from_slice(&self.generation);
        header.extend_from_slice(&[0u8; 4]);
        seg.file.write_all(&header)?;
        seg.bytes = SEGMENT_HEADER_LEN as u64;
        Ok(())
    }

    /// Recover the tree: the committed checkpoint first, then the records after
    /// it. A checkpoint that has been written and fsynced is the state, so a
    /// lost or truncated segment after it costs only the records on top.
    fn recover(&mut self, state: Option<State>) -> Result<Option<String>, Error> {
        // nothing has been checkpointed yet: the tree is the base object the journal was
        // attached to, and it has to still be the object that was attached
        if let Some((content_id, path)) = state
            .as_ref()
            .filter(|s| s.checkpoint.is_none())
            .and_then(|s| s.base.clone())
        {
            let raw = match std::fs::read(&path) {
                Ok(raw) => raw,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error::BaseLost(format!(
                        "the object this journal was attached to is gone: {path}"
                    )))
                }
                Err(e) => return Err(Error::Io(e)),
            };
            let snap: Snapshot<T> = Snapshot::from_bytes(&raw).map_err(|e| match e {
                // a base that no longer verifies was replaced under the journal
                Error::ContentId => Error::BaseLost(format!(
                    "the object at {path} is not the one this journal was attached to"
                )),
                other => other,
            })?;
            if snap.header().type_id_str() != T::TYPE_ID {
                return Err(Error::ConfigMismatch(format!(
                    "the base object holds {}, not {}",
                    snap.header().type_id_str(),
                    T::TYPE_ID
                )));
            }
            if crate::header::hex32(&snap.header().content_id) != content_id {
                return Err(Error::BaseLost(format!(
                    "the object at {path} is not the one this journal was attached to"
                )));
            }
            // a plain object makes no tree claim, and the id was derived from its content
            // id at attach time; only a checkpoint can disagree about which stream it is
            if let Some(s) = snap.header().stream() {
                if s.tree_id != self.tree_id {
                    return Err(Error::BadRecord(
                        "the base object belongs to another tree than this journal",
                    ));
                }
            }
            for (p, v) in snap.v4().map(|m| m.iter()).into_iter().flatten() {
                let value = rkyv::deserialize::<T, RkyvError>(v)
                    .map_err(|_| Error::BadRecord("base value does not decode"))?;
                self.v4.insert(p, value);
            }
            for (p, v) in snap.v6().map(|m| m.iter()).into_iter().flatten() {
                let value = rkyv::deserialize::<T, RkyvError>(v)
                    .map_err(|_| Error::BadRecord("base value does not decode"))?;
                self.v6.insert(p, value);
            }
        }

        if let Some((base, file)) = state.as_ref().and_then(|s| s.checkpoint.clone()) {
            let path = self.dir.join(&file);
            let raw = std::fs::read(&path).map_err(|e| match e.kind() {
                // a missing checkpoint is a state problem the caller can repair
                std::io::ErrorKind::NotFound => {
                    Error::BadRecord("checkpoint named by state.json is missing")
                }
                // permission, a directory in its place, a broken mount: report what
                // the file system said rather than guessing at its meaning
                _ => Error::Io(e),
            })?;
            struct KnownPayload(Option<u16>);
            impl crate::Validator for KnownPayload {
                fn knows(&self, entry: &crate::Entry) -> bool {
                    Some(entry.id) == self.0
                }
            }
            let snap: Snapshot<T> =
                match Snapshot::from_bytes_with(&raw, &KnownPayload(self.payload.map(|p| p.id))) {
                    Ok(snap) => snap,
                    // a checkpoint opened under another payload configuration is the
                    // mistake that costs the arena, so name it in the journal's terms
                    Err(Error::UnknownRequiredSection(id)) => {
                        return Err(Error::ConfigMismatch(format!(
                            "checkpoint carries payload section {id}, which this journal was \
                             not opened with; reopen it with that PayloadSection"
                        )));
                    }
                    Err(e) => return Err(e),
                };
            match snap.header().stream() {
                Some(s) if s.tree_id == self.tree_id && s.generation == self.generation => {}
                _ => {
                    return Err(Error::BadRecord(
                        "checkpoint belongs to another tree or generation",
                    ))
                }
            }
            for (p, v) in snap.v4().map(|m| m.iter()).into_iter().flatten() {
                let value = rkyv::deserialize::<T, RkyvError>(v)
                    .map_err(|_| Error::BadRecord("checkpoint value does not decode"))?;
                self.v4.insert(p, value);
            }
            for (p, v) in snap.v6().map(|m| m.iter()).into_iter().flatten() {
                let value = rkyv::deserialize::<T, RkyvError>(v)
                    .map_err(|_| Error::BadRecord("checkpoint value does not decode"))?;
                self.v6.insert(p, value);
            }
            match snap.header().stream() {
                Some(s) if s.base_seq == base => {}
                _ => return Err(Error::BadRecord("checkpoint base_seq disagrees with state")),
            }
            // The checkpoint must have exactly the sections this journal writes:
            // the tries plus the payload it was opened with. Anything else means the
            // directory was written under a different configuration, and opening it
            // anyway would drop the arena that the handles point into.
            for entry in snap.entries() {
                if entry.id == crate::header::ID_V4
                    || entry.id == crate::header::ID_V6
                    || entry.id == crate::header::ID_STATS
                {
                    // the family tries are the journal's own, and the counts section is
                    // one this crate writes: neither says anything about the payload
                    continue;
                }
                let is_payload = self.payload.is_some_and(|p| {
                    p.id == entry.id && p.kind == entry.kind && p.required == entry.required
                });
                if !is_payload {
                    return Err(Error::BadRecord(
                        "checkpoint carries a section this journal was not opened with; \
                         reopen it with that payload section, or the data it holds is lost",
                    ));
                }
            }
            if let Some(payload) = self.payload {
                if snap.section_bytes(payload.id).is_none() {
                    return Err(Error::BadRecord(
                        "checkpoint has no payload section, but this journal was opened \
                         with one; the arena the handles point into would be lost",
                    ));
                }
            }
            if let Some(payload) = self.payload {
                if let Some(bytes) = snap.section_bytes(payload.id) {
                    self.blob = bytes.to_vec();
                }
            }
            self.base_seq = base;
            self.seq = base
                .checked_add(1)
                .ok_or(Error::BadRecord("checkpoint sequence is not representable"))?;
            self.checkpoint = Some((base, file.clone()));
        }

        let mut paths = segment_paths(&self.dir)?;
        paths.sort();
        let mut expected: Option<u64> = self.base_seq.checked_add(1);
        for path in paths {
            let mut raw = Vec::new();
            File::open(&path)?.read_to_end(&mut raw)?;
            if raw.is_empty() {
                // a segment created but never written holds nothing
                continue;
            }
            if raw.len() < SEGMENT_HEADER_LEN || &raw[..8] != MAGIC {
                return Err(Error::BadRecord(
                    "segment header is unreadable: the journal is damaged",
                ));
            }
            // the header's fixed fields: version, flags and the reserved word
            if u16::from_le_bytes([raw[8], raw[9]]) != SEGMENT_VERSION
                || u16::from_le_bytes([raw[10], raw[11]]) != 0
                || raw[44..48].iter().any(|b| *b != 0)
            {
                return Err(Error::BadRecord(
                    "segment header has fields this reader does not accept",
                ));
            }
            if raw[12..28] != self.tree_id || raw[28..44] != self.generation {
                return Err(Error::BadRecord("segment belongs to another journal"));
            }
            let mut off = SEGMENT_HEADER_LEN;
            while off + 8 <= raw.len() {
                let len = u32::from_le_bytes(four(&raw[off..off + 4])?) as usize;
                if len < RECORD_FIXED_LEN || off + 4 + len > raw.len() {
                    break;
                }
                let crc = u32::from_le_bytes(four(&raw[off + 4..off + 8])?);
                let payload = &raw[off + 8..off + 4 + len];
                if crc32c::crc32c(payload) != crc {
                    break;
                }
                off += 4 + len;
                let record = parse_record(payload)?;
                if record.seq <= self.base_seq {
                    // covered by the checkpoint this journal recovered from
                    continue;
                }
                if let Some(want) = expected {
                    if record.seq != want {
                        // a hole is data loss: a torn tail ends the scan instead
                        // of leaving a gap in the middle
                        return Err(Error::SequenceGap {
                            expected: want,
                            found: record.seq,
                        });
                    }
                }
                expected = Some(
                    record
                        .seq
                        .checked_add(1)
                        .ok_or(Error::BadRecord("record sequence is not representable"))?,
                );
                self.apply(&record)?;
                self.seq =
                    expected.ok_or(Error::BadRecord("record sequence is not representable"))?;
            }
        }
        if self.payload.is_none() && !self.blob.is_empty() {
            return Err(Error::BadRecord(
                "journal holds blobs but was opened without a payload section",
            ));
        }
        if let Some(committed) = state.as_ref().map(|s| s.next_seq) {
            // a record the state file committed to must be on disk; only the
            // last unacknowledged one may be missing after a tear
            let last = self.seq.saturating_sub(1);
            if committed > self.base_seq.saturating_add(1) && last < committed - 1 {
                return Err(Error::SequenceGap {
                    expected: last + 1,
                    found: committed,
                });
            }
            self.seq = self.seq.max(committed);
        }
        self.stream.base_seq = self.base_seq;
        Ok(state.and_then(|s| s.checkpoint).map(|(_, file)| file))
    }

    fn apply(&mut self, record: &Record) -> Result<(), Error> {
        match record.kind {
            KIND_INSERT => {
                let value = T::decode(&record.value)?;
                match record.prefix {
                    IpNet::V4(p) => {
                        self.v4.insert(p, value);
                    }
                    IpNet::V6(p) => {
                        self.v6.insert(p, value);
                    }
                }
            }
            KIND_WITHDRAW => match record.prefix {
                IpNet::V4(p) => {
                    self.v4.remove(&p);
                }
                IpNet::V6(p) => {
                    self.v6.remove(&p);
                }
            },
            other => {
                return Err(Error::BadRecord(if other == 0 {
                    "no kind"
                } else {
                    "unknown kind"
                }))
            }
        }
        if !record.blob.is_empty() {
            self.blob.extend_from_slice(&record.blob);
        }
        Ok(())
    }

    /// Append a value, replacing whatever the prefix held, and return its sequence
    /// number. Durable only once `sync` returns.
    pub fn insert(&mut self, prefix: IpNet, value: T) -> Result<u64, Error> {
        self.insert_at(prefix, value, Times::default())
    }

    /// Insert a value and record when it was received and when the event it
    /// describes happened, both unix seconds. `Times::default()` leaves both zero,
    /// which is what a caller who does not track time wants.
    pub fn insert_at(&mut self, prefix: IpNet, value: T, times: Times) -> Result<u64, Error> {
        if prefix.addr() != prefix.network() {
            return Err(Error::BadPrefix(prefix.to_string()));
        }
        let mut value = value;
        value.canonicalize();
        let bytes = T::encode(&value)?;
        let seq = self.append(KIND_INSERT, prefix, &bytes, &[], times)?;
        self.apply_value(prefix, value);
        Ok(seq)
    }

    /// Append `blob` to the arena and insert a value built from where it landed.
    ///
    /// `build` receives the offset the blob will occupy, so the handle is written
    /// in the same call that decides it. There is no way to do that after the
    /// fact: the value is encoded before the record is appended.
    pub fn insert_with_blob(
        &mut self,
        prefix: IpNet,
        blob: &[u8],
        build: impl FnOnce(u64) -> T,
    ) -> Result<BlobInserted, Error> {
        self.insert_with_blob_at(prefix, blob, build, Times::default())
    }

    /// The same, with timestamps.
    pub fn insert_with_blob_at(
        &mut self,
        prefix: IpNet,
        blob: &[u8],
        build: impl FnOnce(u64) -> T,
        times: Times,
    ) -> Result<BlobInserted, Error> {
        if self.payload.is_none() {
            return Err(Error::BadOpts(
                "insert_with_blob needs a payload section to carry the blob",
            ));
        }
        if prefix.addr() != prefix.network() {
            return Err(Error::BadPrefix(prefix.to_string()));
        }
        let offset = self.blob.len() as u64;
        let mut value = build(offset);
        value.canonicalize();
        let bytes = T::encode(&value)?;
        let seq = self.append(KIND_INSERT, prefix, &bytes, blob, times)?;
        // only now: a failed append must not leave the arena ahead of the log,
        // or the offsets recorded earlier would point past what replay rebuilds
        self.blob.extend_from_slice(blob);
        self.apply_value(prefix, value);
        Ok(BlobInserted { seq, offset })
    }

    fn apply_value(&mut self, prefix: IpNet, value: T) {
        match prefix {
            IpNet::V4(p) => {
                self.v4.insert(p, value);
            }
            IpNet::V6(p) => {
                self.v6.insert(p, value);
            }
        }
    }

    /// Remove `prefix` from the tree and record the removal.
    ///
    /// The record is appended before the tree changes, so a failed append leaves
    /// the tree holding what the previous record promised.
    pub fn withdraw(&mut self, prefix: IpNet) -> Result<u64, Error> {
        self.withdraw_at(prefix, Times::default())
    }

    /// The same, with the times the feed knows.
    pub fn withdraw_at(&mut self, prefix: IpNet, times: Times) -> Result<u64, Error> {
        if prefix.addr() != prefix.network() {
            return Err(Error::BadPrefix(prefix.to_string()));
        }
        // log first: if the append fails, the tree must still hold what the
        // previous record promised, or a later checkpoint would drop it
        let seq = self.append(KIND_WITHDRAW, prefix, &[], &[], times)?;
        match prefix {
            IpNet::V4(p) => {
                self.v4.remove(&p);
            }
            IpNet::V6(p) => {
                self.v6.remove(&p);
            }
        }
        Ok(seq)
    }

    fn append(
        &mut self,
        kind: u8,
        prefix: IpNet,
        value: &[u8],
        blob: &[u8],
        times: Times,
    ) -> Result<u64, Error> {
        let seq = self.seq;
        // the record about to be written has to be acknowledgeable: refuse before the
        // bytes exist rather than after, where a failed increment would leave a record
        // nobody was told about
        let next_seq = seq
            .checked_add(1)
            .ok_or(Error::BadRecord("sequence space is exhausted"))?;
        let (family, plen, addr) = prefix_fields(prefix);
        let mut payload = Vec::with_capacity(RECORD_FIXED_LEN + value.len() + blob.len());
        payload.extend_from_slice(&seq.to_le_bytes());
        payload.extend_from_slice(&times.recv_ts.to_le_bytes());
        payload.extend_from_slice(&times.event_ts.to_le_bytes());
        payload.push(kind);
        payload.push(family);
        payload.push(plen);
        payload.push(0);
        payload.extend_from_slice(&addr);
        payload.extend_from_slice(&(value.len() as u32).to_le_bytes());
        payload.extend_from_slice(value);
        payload.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        payload.extend_from_slice(blob);

        if self.seg.is_none() {
            self.open_segment()?;
        }
        // the recovery offset belongs to the segment it was recorded on, so a torn
        // tail is cut before any rotation moves the bookkeeping to a new file
        self.discard_torn_write()?;
        if self
            .seg
            .as_ref()
            .is_some_and(|s| s.bytes >= Self::SEGMENT_MAX_BYTES)
        {
            self.rotate_segment()?;
        }
        let start = self
            .seg
            .as_ref()
            .ok_or(Error::BadRecord("no open segment after opening one"))?
            .bytes;
        let len = (payload.len() + 4) as u32;
        let crc = crc32c::crc32c(&payload);
        let seg = self
            .seg
            .as_mut()
            .ok_or(Error::BadRecord("no open segment after opening one"))?;
        let mut write = || -> std::io::Result<()> {
            seg.file.write_all(&len.to_le_bytes())?;
            seg.file.write_all(&crc.to_le_bytes())?;
            seg.file.write_all(&payload)
        };
        if let Err(e) = write() {
            // the bytes on disk are a torn frame; the next append cuts them away
            self.seg_dirty_from = Some(start);
            return Err(Error::Io(e));
        }
        seg.bytes += 8 + payload.len() as u64;
        self.seq = next_seq;
        if !self.state_written {
            // the identity of the directory has to exist before a second session can
            // read this record: a reader of another value type would decode it as its own
            self.persist_state()?;
        }
        Ok(seq)
    }

    /// Recover a journal directory whose `state.json` was lost but whose snapshots
    /// survive.
    ///
    /// `open` refuses that state on purpose, because it cannot tell which object
    /// is current; this picks the newest checkpoint, adopts its own tree and
    /// generation, writes the state file, and returns the journal `open` would
    /// have returned. Records above that checkpoint are replayed; anything pruned
    /// and not covered by it is gone.
    pub fn repair(
        dir: impl AsRef<Path>,
        tree_id: impl Into<crate::TreeId>,
        payload: Option<PayloadSection>,
    ) -> Result<Self, Error> {
        let tree_id = *tree_id.into().as_bytes();
        let dir = dir.as_ref().to_path_buf();
        // take the writer lock first: writing state before it would overwrite a
        // live writer's commit record on the way to reporting Locked
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("writer.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| Error::Locked)?;

        // a healthy state file means opening is the only correct move: repair would
        // rewrite next_seq and hide the gap that open reports. A state file that is
        // there but does not parse is the case repair exists for, and leaving it in
        // place made both entries refuse the directory.
        if matches!(read_state(&dir), Ok(Some(_))) {
            return Err(Error::BadOpts(
                "state.json exists; open the journal instead of repairing it",
            ));
        }

        let mut candidates: Vec<(u64, String)> = snapshot_paths(&dir)?
            .into_iter()
            .filter_map(|p| {
                let name = p.file_name()?.to_str()?.to_string();
                // `snapshot-<seq>-<n>.snap`; the seq is what state.json names, the
                // second number only keeps two checkpoints at one seq apart
                let seq = name
                    .strip_prefix("snapshot-")?
                    .strip_suffix(".snap")?
                    .split('-')
                    .next()?
                    .parse()
                    .ok()?;
                Some((seq, name))
            })
            .collect();
        candidates.sort();
        let Some((_, file)) = candidates.last() else {
            return Err(Error::BadOpts("there is no checkpoint to repair from"));
        };
        let raw = std::fs::read(dir.join(file)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                Error::BadRecord("the newest checkpoint named on disk is gone")
            }
            _ => Error::Io(e),
        })?;

        struct KnownPayload(Option<u16>);
        impl crate::Validator for KnownPayload {
            fn knows(&self, entry: &crate::Entry) -> bool {
                Some(entry.id) == self.0
            }
        }
        let (generation, base) = {
            let header = crate::Header::parse(&raw)?;
            match header.stream() {
                Some(s) if s.tree_id == tree_id => (s.generation, s.base_seq),
                _ => return Err(Error::BadRecord("the checkpoint belongs to another tree")),
            }
        };
        let snapshot = Snapshot::<T>::from_bytes_with(&raw, &KnownPayload(payload.map(|p| p.id)))?;

        // the state written below must describe the object that exists, not the
        // configuration the caller happened to pass. Comparing every non-family
        // section also covers the caller who passes no payload at all: the checkpoint
        // can still carry one, and a state that omits it makes every later open and
        // repair refuse the directory.
        let wanted = payload.map(|p| (p.id, p.kind, p.required));
        for entry in snapshot.entries() {
            if entry.id == crate::header::ID_V4
                || entry.id == crate::header::ID_V6
                || entry.id == crate::header::ID_STATS
            {
                continue;
            }
            let matches = wanted.is_some_and(|(id, kind, required)| {
                entry.id == id && entry.kind == kind && entry.required == required
            });
            if !matches {
                return Err(Error::ConfigMismatch(format!(
                    "the checkpoint carries section {} as kind {} required {}, not the \
                     configuration this repair was called with",
                    entry.id,
                    crate::header::hex4(&entry.kind),
                    entry.required
                )));
            }
        }
        if let Some((id, _, _)) = wanted {
            if snapshot.section_bytes(id).is_none() {
                return Err(Error::ConfigMismatch(format!(
                    "the checkpoint has no section {id}, so repairing with that payload \
                     would describe a journal that does not exist"
                )));
            }
        }

        write_state(
            &dir,
            &State {
                next_seq: base
                    .checked_add(1)
                    .ok_or(Error::BadRecord("checkpoint sequence is not representable"))?,
                base: None,
                generation,
                tree_id,
                checkpoint: Some((base, file.clone())),
                type_id: Some(T::TYPE_ID.to_string()),
                payload: wanted,
            },
        )?;
        // prove the state describes a journal that opens before leaving it behind, and
        // do it under the lock this call already holds: releasing the lock first lets
        // another writer commit a state file that the cleanup below would then delete
        let adopted = lock
            .try_clone()
            .map_err(Error::Io)
            .and_then(|held| Self::open_locked(&dir, BaseSource::Reopen, payload, None, held));
        match adopted {
            Ok(journal) => {
                drop(lock);
                Ok(journal)
            }
            Err(e) => {
                // we still hold the lock, so this state file is the one this call wrote
                let _ = std::fs::remove_file(dir.join("state.json"));
                drop(lock);
                Err(e)
            }
        }
    }

    /// A record is durable once this returns.
    pub fn sync(&mut self) -> Result<(), Error> {
        if let Some(seg) = self.seg.as_mut() {
            // a failed flush or fsync leaves bytes whose completeness is unknown;
            // the next append must cut back to the last acknowledged offset
            let start = seg.bytes;
            let durability = seg
                .file
                .flush()
                .and_then(|()| seg.file.get_ref().sync_all());
            if let Err(e) = durability {
                self.seg_dirty_from = Some(start);
                return Err(Error::Io(e));
            }
        }
        self.persist_state()
    }

    /// Write `state.json`, which is what tells a reader what wrote this directory.
    fn persist_state(&mut self) -> Result<(), Error> {
        let (type_id, payload) = self.config();
        let state = State {
            next_seq: self.seq,
            generation: self.generation,
            tree_id: self.tree_id,
            checkpoint: self.checkpoint.clone(),
            base: self.base.clone(),
            type_id: Some(type_id),
            payload,
        };
        write_state(&self.dir, &state)?;
        self.state_written = true;
        Ok(())
    }

    /// The object this journal would checkpoint, as bytes, without writing or
    /// pruning anything.
    ///
    /// The object carries the journal's payload section, so a plain
    /// `Snapshot::from_bytes` refuses it; use `to_snapshot` for queries, or
    /// `Snapshot::from_bytes_with` with a validator that knows that section.
    pub fn to_bytes(&self, opts: &Opts<'_>) -> Result<Vec<u8>, Error> {
        Self::build_object(
            &self.v4,
            &self.v6,
            self.payload,
            &self.blob,
            self.tree_id,
            self.generation,
            self.seq.saturating_sub(1),
            opts,
        )
    }

    /// The object as a `Snapshot`, without writing or pruning anything.
    ///
    /// The journal can open its own object because it knows the payload section it
    /// wrote; a plain `Snapshot::from_bytes` cannot, since that section is required.
    /// This is how a caller reaches `children`, `cover` and `iter`, which the
    /// journal does not answer itself.
    pub fn to_snapshot(&self, opts: &Opts<'_>) -> Result<Snapshot<T>, Error> {
        struct KnownPayload(Option<u16>);
        impl crate::Validator for KnownPayload {
            fn knows(&self, entry: &crate::Entry) -> bool {
                Some(entry.id) == self.0
            }
        }
        let bytes = self.to_bytes(opts)?;
        Snapshot::from_bytes_with(&bytes, &KnownPayload(self.payload.map(|p| p.id)))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_object(
        v4: &PrefixMap<ipnet::Ipv4Net, T>,
        v6: &PrefixMap<ipnet::Ipv6Net, T>,
        payload: Option<PayloadSection>,
        blob: &[u8],
        tree_id: [u8; 16],
        generation: [u8; 16],
        base_seq: u64,
        opts: &Opts<'_>,
    ) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::<T>::new();
        // the journal's own keys are canonical, so these cannot fail; a failure
        // here would mean the in-memory tree holds a prefix it could not have
        for (p, v) in v4.iter() {
            writer
                .insert(IpNet::V4(p), v.clone())
                .map_err(|_| Error::BadPrefix(p.to_string()))?;
        }
        for (p, v) in v6.iter() {
            writer
                .insert(IpNet::V6(p), v.clone())
                .map_err(|_| Error::BadPrefix(p.to_string()))?;
        }
        // the caller's sections travel with the object; the journal adds the arena
        // it owns. Dropping them silently would produce a checkpoint that is not
        // what the caller asked for.
        if !opts.extras.is_empty() {
            return Err(Error::BadOpts(
                "a checkpoint carries the journal's own sections only: write a general \
                 object with Writer::finish when you need your own",
            ));
        }
        let mut extras: Vec<ExtraSection<'_>> = opts.extras.to_vec();
        if let Some(payload) = payload {
            if extras.iter().any(|e| e.id == payload.id) {
                return Err(Error::BadSectionId(payload.id));
            }
            extras.push(ExtraSection {
                id: payload.id,
                kind: payload.kind,
                required: payload.required,
                bytes: blob,
            });
        }
        let stream = crate::StreamRef {
            tree_id,
            generation,
            base_seq,
        };
        let opts = Opts {
            created_at: opts.created_at,
            stream: Some(stream),
            window: opts.window,
            extras: &extras,
        };
        let bytes = writer.finish(&opts)?;

        Ok(bytes)
    }

    /// Write a snapshot of the live tree, verify it, commit it, publish it and prune
    /// what it covers.
    ///
    /// The commit point is `state.json`: before it is written, a failure leaves the
    /// previous checkpoint current and the call can simply be retried. Publishing
    /// `current.snap` and pruning after the commit are best effort, because a reader
    /// that opens `current.snap` after a crash gets the previous object and the
    /// journal itself is already correct; a failed prune costs disk, not data.
    ///
    /// A checkpoint carries the journal's own sections only. Use `Writer::finish`
    /// when the object needs a profile section, and `checkpoint_with` when the
    /// profile has a validator that must pass before the object is committed.
    pub fn checkpoint(&mut self, opts: &Opts<'_>) -> Result<PathBuf, Error> {
        struct NoSections;
        impl crate::Validator for NoSections {}
        self.checkpoint_with(opts, &NoSections)
    }

    /// A checkpoint that also runs `validator` over the object before committing it.
    ///
    /// `checkpoint` only proves the container and the tries; a profile that adds a
    /// section of its own is the only thing that can check it.
    pub fn checkpoint_with(
        &mut self,
        opts: &Opts<'_>,
        validator: &dyn crate::Validator,
    ) -> Result<PathBuf, Error> {
        let bytes = self.to_bytes(opts)?;

        // verify before pruning: a bad object must not take the history with it.
        // The journal knows which section it just wrote, so it is its own
        // validator for that id and nothing else.
        struct KnownPayload(Option<u16>);
        impl crate::Validator for KnownPayload {
            fn knows(&self, entry: &crate::Entry) -> bool {
                Some(entry.id) == self.0
            }
        }
        let snap: Snapshot<T> =
            Snapshot::from_bytes_with(&bytes, &KnownPayload(self.payload.map(|p| p.id)))?;
        // the container and the tries are the journal's business; the profile's own
        // sections are the caller's, and only its validator can check them
        validator.validate(&snap.view())?;
        if snap.len() != self.len() {
            return Err(Error::BadRecord("checkpoint does not hold the live tree"));
        }
        // recovery decodes every value, so a value that cannot be decoded here would
        // be a checkpoint nobody can open: fail before the commit, not after it
        for (_, value) in snap.v4().map(|m| m.iter()).into_iter().flatten() {
            rkyv::deserialize::<T, RkyvError>(value).map_err(|_| Error::BadValue)?;
        }
        for (_, value) in snap.v6().map(|m| m.iter()).into_iter().flatten() {
            rkyv::deserialize::<T, RkyvError>(value).map_err(|_| Error::BadValue)?;
        }
        self.checkpoints += 1;
        let name = format!("snapshot-{}-{}.snap", self.seq, self.checkpoints);
        let path = self.dir.join(&name);
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let written = (|| -> Result<(), Error> {
            let mut f = File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = written {
            // a failed write must not leave a hidden file behind: the orphan sweep
            // only knows `snapshot-` names, so nothing would ever reclaim this one
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            // the write succeeded, so the temp file is a complete object: it still must
            // not survive a rename that could not put it in place
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Io(e));
        }
        File::open(&self.dir)?.sync_all()?;

        // commit the checkpoint first: from here on, recovery starts from this
        // object. The stable link is published after the state names it, so a crash
        // in between cannot leave current.snap pointing at an unnamed snapshot,
        // which the next open would delete.
        let covered = self.seq.saturating_sub(1);
        write_state(
            &self.dir,
            &State {
                next_seq: self.seq,
                generation: self.generation,
                tree_id: self.tree_id,
                checkpoint: Some((covered, name.clone())),
                base: self.base.clone(),
                type_id: Some(T::TYPE_ID.to_string()),
                payload: self.payload.map(|p| (p.id, p.kind, p.required)),
            },
        )?;
        self.checkpoint = Some((covered, name.clone()));
        // published after the commit, so a failure here leaves a correct journal and
        // a stale link; the next checkpoint republishes
        let _ = self.publish_current(&name);

        // An older snapshot is dead weight once a newer one is committed. This is
        // reclamation, not correctness, so it never fails a checkpoint that is
        // already committed; the next one tries again. The object `current.snap`
        // still names is kept, because a failed publication above would otherwise
        // leave the documented stable path dangling.
        let linked = std::fs::read_link(self.dir.join("current.snap"))
            .ok()
            .and_then(|target| target.file_name().map(|n| n.to_string_lossy().into_owned()));
        if let Ok(old_snapshots) = snapshot_paths(&self.dir) {
            for old in old_snapshots {
                let old_name = old
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if old_name != name && Some(&old_name) != linked.as_ref() {
                    let _ = std::fs::remove_file(&old);
                }
            }
        }

        self.base_seq = covered;
        self.stream.base_seq = covered;

        // only now may a fully covered segment go, and only while the open segment is
        // left alone. Reclamation cannot fail a checkpoint that is already committed.
        if let Ok(segments) = segment_paths(&self.dir) {
            for segment in segments {
                if Some(&segment) == self.seg_path.as_ref() {
                    continue;
                }
                if let Ok(Some(max)) = segment_max_seq(&segment) {
                    if max <= covered {
                        let _ = std::fs::remove_file(&segment);
                    }
                }
            }
        }
        Ok(path)
    }

    /// How many bytes the arena holds. `insert_with_blob` reports the offset a
    /// blob landed at, so this is only needed to inspect the arena as a whole.
    pub fn blob_len(&self) -> usize {
        self.blob.len()
    }

    /// The value the journal currently holds for `prefix`, with no ancestor
    /// fallback. A writer needs this to compute the next value from the previous
    /// one instead of rebuilding the whole tree for every update.
    pub fn get_exact(&self, prefix: ipnet::IpNet) -> Option<&T> {
        match prefix {
            ipnet::IpNet::V4(p) => self.v4.get(&p),
            ipnet::IpNet::V6(p) => self.v6.get(&p),
        }
    }

    /// The longest stored prefix that covers `prefix`, with its value.
    pub fn lpm(&self, prefix: ipnet::IpNet) -> Option<(ipnet::IpNet, &T)> {
        match prefix {
            ipnet::IpNet::V4(p) => self.v4.get_lpm(&p).map(|(k, v)| (ipnet::IpNet::V4(k), v)),
            ipnet::IpNet::V6(p) => self.v6.get_lpm(&p).map(|(k, v)| (ipnet::IpNet::V6(k), v)),
        }
    }

    /// Every prefix in the journal, in trie order. A caller that has to compare
    /// two trees walks this instead of guessing the key space.
    pub fn for_each(&self, mut f: impl FnMut(ipnet::IpNet, &T)) {
        for (p, v) in self.v4.iter() {
            f(ipnet::IpNet::V4(p), v);
        }
        for (p, v) in self.v6.iter() {
            f(ipnet::IpNet::V6(p), v);
        }
    }

    /// How many prefixes the journal holds right now.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Whether the journal holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The sequence number the next record will carry.
    ///
    /// A caller that ships records somewhere else uses this to say how far the
    /// journal has got; it survives a reopen, so the number is the journal's, not the
    /// process's.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The base object this journal was attached to, `(content id hex, path)`.
    pub fn base(&self) -> Option<&(String, String)> {
        self.base.as_ref()
    }

    /// The newest committed checkpoint, `(base seq, file name)`.
    pub fn last_checkpoint(&self) -> Option<&(u64, String)> {
        self.checkpoint.as_ref()
    }

    /// The stream incarnation this journal writes under.
    ///
    /// It is minted on first use and reused from then on, so a reader can tell a
    /// continued stream from a new one that happens to share the tree.
    pub fn generation(&self) -> [u8; 16] {
        self.generation
    }
}

struct Record {
    seq: u64,
    kind: u8,
    prefix: IpNet,
    value: Vec<u8>,
    blob: Vec<u8>,
}

fn parse_record(payload: &[u8]) -> Result<Record, Error> {
    if payload.len() < 48 {
        return Err(Error::BadRecord("record is short"));
    }
    let seq = u64::from_le_bytes(
        payload
            .get(0..8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .ok_or(Error::BadRecord(
                "record is shorter than its sequence number",
            ))?,
    );
    let kind = payload[24];
    let family = payload[25];
    let plen = payload[26];
    if payload[27] != 0 {
        return Err(Error::BadRecord("record flags are not zero"));
    }
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&payload[28..44]);
    if family == 4 && addr[4..].iter().any(|b| *b != 0) {
        return Err(Error::BadRecord(
            "an IPv4 record carries bytes behind its address",
        ));
    }
    let value_len = u32::from_le_bytes(four(&payload[44..48])?) as usize;
    if payload.len() < 48 + value_len + 4 {
        return Err(Error::BadRecord("record value is short"));
    }
    let value = payload[48..48 + value_len].to_vec();
    let blob_len = u32::from_le_bytes(four(&payload[48 + value_len..52 + value_len])?) as usize;
    if payload.len() < 52 + value_len + blob_len {
        return Err(Error::BadRecord("record blob is short"));
    }
    let blob = payload[52 + value_len..52 + value_len + blob_len].to_vec();
    let prefix = prefix_from_fields(family, plen, &addr)
        .ok_or(Error::BadRecord("record prefix is unusable"))?;
    Ok(Record {
        seq,
        kind,
        prefix,
        value,
        blob,
    })
}

/// Four bytes, or an error. Every caller has already checked the length; this turns
/// an impossible one into a refusal instead of a panic.
fn four(bytes: &[u8]) -> Result<[u8; 4], Error> {
    <[u8; 4]>::try_from(bytes).map_err(|_| Error::BadRecord("record field is short"))
}

fn prefix_fields(prefix: IpNet) -> (u8, u8, [u8; 16]) {
    let mut addr = [0u8; 16];
    match prefix {
        IpNet::V4(p) => {
            addr[..4].copy_from_slice(&p.addr().octets());
            (4, p.prefix_len(), addr)
        }
        IpNet::V6(p) => {
            addr.copy_from_slice(&p.addr().octets());
            (6, p.prefix_len(), addr)
        }
    }
}

fn prefix_from_fields(family: u8, len: u8, addr: &[u8; 16]) -> Option<IpNet> {
    match family {
        4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&addr[..4]);
            ipnet::Ipv4Net::new(octets.into(), len).ok().map(IpNet::V4)
        }
        6 => ipnet::Ipv6Net::new((*addr).into(), len).ok().map(IpNet::V6),
        _ => None,
    }
}

/// The durable commit record: what the journal promises survives a crash, plus what
/// the directory was written as, so a reopen with another value type or payload is
/// refused instead of silently reinterpreted.
/// The value type a journal directory records, for a tool that has to choose a `T`
/// before it can open one. `None` when the directory holds no journal yet.
pub fn recorded_type_id(dir: impl AsRef<Path>) -> Result<Option<String>, Error> {
    Ok(read_state(dir.as_ref())?.and_then(|s| s.type_id))
}

struct State {
    next_seq: u64,
    generation: [u8; 16],
    tree_id: [u8; 16],
    /// `(base_seq, file name)` of the newest verified checkpoint.
    checkpoint: Option<(u64, String)>,
    /// `(content id hex, path)` of the object this journal was attached to. Read only
    /// until the first checkpoint: from then on the tree comes from that checkpoint and
    /// the base is provenance.
    base: Option<(String, String)>,
    type_id: Option<String>,
    payload: Option<(u16, [u8; 4], bool)>,
}

fn read_state(dir: &Path) -> Result<Option<State>, Error> {
    let path = dir.join("state.json");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::BadRecord("state.json cannot be read")),
    };
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::BadRecord("state.json is not json"))?;
    let next_seq = v["next_seq"]
        .as_u64()
        .ok_or(Error::BadRecord("state.json has no next_seq"))?;
    let mut generation = [0u8; 16];
    let mut tree_id = [0u8; 16];
    crate::header::hex_to_bytes(
        v["generation"].as_str().unwrap_or_default(),
        &mut generation,
    )?;
    crate::header::hex_to_bytes(v["tree_id"].as_str().unwrap_or_default(), &mut tree_id)?;
    // a checkpoint that is present but unreadable is corruption: treating it as
    // absent would let recovery delete the snapshot it can no longer name
    let checkpoint = match v.get("checkpoint") {
        None => None,
        Some(serde_json::Value::Object(c)) => {
            match (
                c.get("seq").and_then(|s| s.as_u64()),
                c.get("file").and_then(|f| f.as_str()),
            ) {
                (Some(seq), Some(file)) => Some((seq, file.to_string())),
                _ => return Err(Error::BadRecord("state.json checkpoint is malformed")),
            }
        }
        Some(_) => return Err(Error::BadRecord("state.json checkpoint is malformed")),
    };
    let type_id = v["type_id"].as_str().map(str::to_string);
    let payload = match v.get("payload") {
        None => None,
        Some(serde_json::Value::Object(p)) => {
            let id = p.get("id").and_then(|x| x.as_u64()).map(|x| x as u16);
            let required = p.get("required").and_then(|x| x.as_bool());
            let kind = p
                .get("kind")
                .and_then(|x| x.as_str())
                .and_then(crate::header::hex4_to_bytes);
            match (id, kind, required) {
                (Some(id), Some(kind), Some(required)) => Some((id, kind, required)),
                _ => return Err(Error::BadRecord("state.json payload is malformed")),
            }
        }
        Some(_) => return Err(Error::BadRecord("state.json payload is malformed")),
    };
    let base = match &v["base"] {
        serde_json::Value::Null => None,
        serde_json::Value::Object(o) => match (o.get("content_id"), o.get("path")) {
            (Some(serde_json::Value::String(c)), Some(serde_json::Value::String(p))) => {
                Some((c.clone(), p.clone()))
            }
            _ => return Err(Error::BadRecord("state.json base is malformed")),
        },
        _ => return Err(Error::BadRecord("state.json base is malformed")),
    };
    Ok(Some(State {
        next_seq,
        generation,
        tree_id,
        checkpoint,
        base,
        type_id,
        payload,
    }))
}

fn write_state(dir: &Path, state: &State) -> Result<(), Error> {
    let mut v = serde_json::json!({
        "next_seq": state.next_seq,
        "generation": crate::header::hex16(&state.generation),
        "tree_id": crate::header::hex16(&state.tree_id),
    });
    if let Some((seq, file)) = &state.checkpoint {
        v["checkpoint"] = serde_json::json!({ "seq": seq, "file": file });
    }
    if let Some(type_id) = &state.type_id {
        v["type_id"] = serde_json::json!(type_id);
    }
    if let Some((content_id, path)) = &state.base {
        v["base"] = serde_json::json!({ "content_id": content_id, "path": path });
    }
    if let Some((id, kind, required)) = &state.payload {
        v["payload"] = serde_json::json!({
            "id": id,
            // hex: four arbitrary bytes do not survive a JSON string round trip
            "kind": crate::header::hex4(kind),
            "required": required,
        });
    }
    let tmp = dir.join(".state.json.tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(
            serde_json::to_vec(&v)
                .map_err(|_| Error::BadRecord("state"))?
                .as_slice(),
        )?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join("state.json"))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// The highest sequence number in a segment, or `None` when it holds no intact
/// record. Used to decide whether a checkpoint fully covers it.
fn segment_max_seq(path: &Path) -> Result<Option<u64>, Error> {
    let raw = std::fs::read(path)?;
    if raw.len() < SEGMENT_HEADER_LEN || &raw[..8] != MAGIC {
        return Ok(None);
    }
    let mut off = SEGMENT_HEADER_LEN;
    let mut max: Option<u64> = None;
    while off + 8 <= raw.len() {
        let len = u32::from_le_bytes(four(&raw[off..off + 4])?) as usize;
        if len < RECORD_FIXED_LEN || off + 4 + len > raw.len() {
            break;
        }
        let crc = u32::from_le_bytes(four(&raw[off + 4..off + 8])?);
        let payload = &raw[off + 8..off + 4 + len];
        if crc32c::crc32c(payload) != crc {
            break;
        }
        if let Ok(record) = parse_record(payload) {
            max = Some(max.map_or(record.seq, |m: u64| m.max(record.seq)));
        }
        off += 4 + len;
    }
    Ok(max)
}

/// The highest ordinal already on disk for `seq`, so a fresh process does not reuse a
/// checkpoint name that `state.json` still points at.
fn highest_checkpoint_ordinal(dir: &Path, seq: u64) -> u64 {
    let prefix = format!("snapshot-{seq}-");
    snapshot_paths(dir)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?.to_string();
            let rest = name.strip_prefix(&prefix)?.strip_suffix(".snap")?;
            rest.parse::<u64>().ok()
        })
        .max()
        .unwrap_or(0)
}

fn snapshot_paths(dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("snapshot-") && n.ends_with(".snap"))
        {
            out.push(path);
        }
    }
    Ok(out)
}

fn segment_paths(dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("segment-") && n.ends_with(".log"))
        {
            out.push(path);
        }
    }
    Ok(out)
}

fn random_generation() -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut out).is_ok() {
            return out;
        }
    }
    let h = blake3::hash(&std::process::id().to_le_bytes());
    out.copy_from_slice(&h.as_bytes()[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct V(u32);

    impl crate::SnapValue for V {
        const TYPE_ID: &str = "test.v:v1";
    }

    /// A cut-back whose truncate fails must keep the offset: the next append cuts
    /// from it, and forgetting it wrote a record behind a partial frame that no open
    /// can replay (ENOSPC, retry while full, free space, sync Ok, then SequenceGap).
    #[test]
    fn a_failed_cut_back_keeps_the_offset_for_the_next_attempt() {
        let dir = std::env::temp_dir().join(format!("snap-cutback-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let tree_id = [72u8; 16];
        let mut j: Journal<V> = Journal::start(&dir, tree_id).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();

        // a half-written frame lands past the acknowledged bytes
        let (seg_path, acknowledged) = {
            let seg = j.seg.as_mut().expect("an open segment");
            seg.file.flush().unwrap();
            let path = j.seg_path.clone().unwrap();
            (path, seg.bytes)
        };
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&seg_path)
                .unwrap();
            f.write_all(&[0xAB; 24]).unwrap();
        }

        // an offset no file can have makes the truncate fail, which stands in for a
        // full disk or a failing device at the same step
        j.seg_dirty_from = Some(u64::MAX);
        assert!(
            j.discard_torn_write().is_err(),
            "the cut-back must report the failure"
        );
        assert_eq!(
            j.seg_dirty_from,
            Some(u64::MAX),
            "a failed cut-back must keep the offset for the next attempt"
        );

        // and the next attempt with a real offset still does the job
        j.seg_dirty_from = Some(acknowledged);
        j.discard_torn_write().expect("the cut-back must succeed");
        assert_eq!(j.seg_dirty_from, None);
        let len = std::fs::metadata(&seg_path).unwrap().len();
        assert_eq!(len, acknowledged, "the torn bytes must be gone");
        drop(j);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The bytes the spec fixes inside a record: the flags byte must be zero and
    /// an IPv4 address must not carry anything behind its four octets.
    #[test]
    fn a_record_with_reserved_bytes_set_is_refused() {
        let payload_base = SEGMENT_HEADER_LEN + 8; // after the frame's len and crc
        let flags_at = payload_base + 27;
        let addr_tail_at = payload_base + 32;
        for (name, offset, value) in [("flags", flags_at, 1u8), ("addr tail", addr_tail_at, 1)] {
            let dir =
                std::env::temp_dir().join(format!("snap-rec-{offset}-{}", std::process::id()));
            std::fs::remove_dir_all(&dir).ok();
            let tree_id = [71u8; 16];
            {
                let mut j: Journal<V> = Journal::options(&dir)
                    .start(tree_id)
                    .payload(PayloadSection::payload(16))
                    .open()
                    .unwrap();
                j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
                j.sync().unwrap();
            }
            let segment = std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok().map(|e| e.path()))
                .find(|p| p.to_string_lossy().contains("segment-"))
                .unwrap();
            let mut raw = std::fs::read(&segment).unwrap();
            raw[offset] = value;
            // keep the frame crc valid, so only the field rule can reject it
            let len = u32::from_le_bytes(
                raw[SEGMENT_HEADER_LEN..SEGMENT_HEADER_LEN + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let payload_end = SEGMENT_HEADER_LEN + 4 + len;
            let crc = crc32c::crc32c(&raw[payload_base..payload_end]);
            raw[SEGMENT_HEADER_LEN + 4..payload_base].copy_from_slice(&crc.to_le_bytes());
            std::fs::write(&segment, &raw).unwrap();

            let reopened = Journal::<V>::open_with_payload(&dir, PayloadSection::payload(16));
            match reopened {
                Ok(j) => panic!(
                    "a record with {name} set must be refused, got len {}",
                    j.len()
                ),
                Err(e) => {
                    let text = format!("{e}");
                    assert!(
                        text.contains("flags") || text.contains("address"),
                        "{name}: unexpected error {text}"
                    );
                }
            }
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// A failed write leaves a torn frame on disk. The next append must cut it
    /// away, or replay stops at the tear and refuses the good record behind it.
    #[test]
    fn a_torn_write_is_cut_before_the_next_append() {
        let dir = std::env::temp_dir().join(format!("snap-torn-write-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let mut j: Journal<V> = Journal::options(&dir)
            .start([1u8; 16])
            .payload(PayloadSection::payload(16))
            .open()
            .unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.sync().unwrap();

        // what a half-finished write looks like: the length and crc of a frame
        // whose payload never arrived
        let seg_path = j.seg_path.clone().unwrap();
        let written = j.seg.as_ref().unwrap().bytes;
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&seg_path)
                .unwrap();
            f.write_all(&64u32.to_le_bytes()).unwrap();
            f.write_all(&0u32.to_le_bytes()).unwrap();
            f.write_all(&[0u8; 20]).unwrap();
        }
        j.seg_dirty_from = Some(written);

        j.insert("192.0.2.0/24".parse().unwrap(), V(2)).unwrap();
        j.sync().unwrap();
        drop(j);

        let j: Journal<V> = Journal::open_with_payload(&dir, PayloadSection::payload(16))
            .expect("the torn bytes must not survive into a reopen");
        assert_eq!(j.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}
