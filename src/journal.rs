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
const RECORD_FIXED_LEN: usize = 56;

pub const KIND_INSERT: u8 = 1;
pub const KIND_WITHDRAW: u8 = 2;

/// Where the journal's blob arena lands in a snapshot.
#[derive(Debug, Clone, Copy)]
pub struct PayloadSection {
    pub id: u16,
    pub kind: [u8; 4],
    pub required: bool,
}

impl PayloadSection {
    pub fn payload(id: u16) -> Self {
        Self {
            id,
            kind: KIND_PAYLOAD,
            required: true,
        }
    }
}

struct Segment {
    file: BufWriter<File>,
    bytes: u64,
}

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
    seq: u64,
    base_seq: u64,
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
    /// Open a journal, recovering the tree from the last checkpoint plus the
    /// segments. The generation is reused when a journal already exists.
    pub fn open(
        dir: impl AsRef<Path>,
        tree_id: [u8; 16],
        payload: Option<PayloadSection>,
    ) -> Result<Self, Error> {
        Self::open_with(dir, tree_id, payload, None)
    }

    /// `generation` names the stream incarnation. A caller passes `Some` only to
    /// reproduce a fixture or to restore a known journal; otherwise it is minted
    /// on first use and reused from then on.
    pub fn open_with(
        dir: impl AsRef<Path>,
        tree_id: [u8; 16],
        payload: Option<PayloadSection>,
        generation: Option<[u8; 16]>,
    ) -> Result<Self, Error> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;

        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("writer.lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .map_err(|_| Error::BadRecord("another writer holds this journal"))?;

        let state = read_state(&dir)?;
        let generation = state
            .as_ref()
            .map(|s| s.generation)
            .or(existing_generation(&dir)?)
            .or(generation)
            .unwrap_or_else(random_generation);
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
            seq: 1,
            base_seq: 0,
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
            blob: Vec::new(),
            payload,
        };
        if state.is_none() && !snapshot_paths(&journal.dir)?.is_empty() {
            // the checkpoints exist but nothing says which one is current, and
            // the segments they replaced may already be gone
            return Err(Error::BadRecord(
                "checkpoints exist but state.json is missing",
            ));
        }
        let keep = journal.recover(state)?;
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

    /// Create this session's segment. Called on the first append, so a journal
    /// that is opened and closed without writes leaves no empty file.
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

    fn write_segment_header(&mut self) -> Result<(), Error> {
        let Some(seg) = self.seg.as_mut() else {
            return Ok(());
        };
        let mut header = Vec::with_capacity(SEGMENT_HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&4u16.to_le_bytes());
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
        if let Some((base, file)) = state.as_ref().and_then(|s| s.checkpoint.clone()) {
            let path = self.dir.join(&file);
            let raw = std::fs::read(&path)
                .map_err(|_| Error::BadRecord("checkpoint named by state.json is missing"))?;
            struct KnownPayload(Option<u16>);
            impl crate::Validator for KnownPayload {
                fn knows(&self, entry: &crate::Entry) -> bool {
                    Some(entry.id) == self.0
                }
            }
            let snap: Snapshot<T> =
                Snapshot::from_bytes_with(&raw, &KnownPayload(self.payload.map(|p| p.id)))?;
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
            // a section this journal was not opened for would be dropped, and a
            // payload section is the blob arena, so its absence is data loss
            for entry in snap.entries() {
                if entry.id == crate::header::ID_V4 || entry.id == crate::header::ID_V6 {
                    continue;
                }
                match self.payload {
                    Some(payload) if payload.id == entry.id => {}
                    _ => {
                        return Err(Error::BadRecord(
                            "checkpoint has a section this journal was not configured for",
                        ))
                    }
                }
            }
            if let Some(payload) = self.payload {
                if let Some(bytes) = snap.section_bytes(payload.id) {
                    self.blob = bytes.to_vec();
                }
            }
            self.base_seq = base;
            self.seq = base + 1;
        }

        let mut paths = segment_paths(&self.dir)?;
        paths.sort();
        let mut expected: Option<u64> = Some(self.base_seq + 1);
        for path in paths {
            let mut raw = Vec::new();
            File::open(&path)?.read_to_end(&mut raw)?;
            if raw.len() < SEGMENT_HEADER_LEN || &raw[..8] != MAGIC {
                continue;
            }
            if raw[12..28] != self.tree_id || raw[28..44] != self.generation {
                return Err(Error::BadRecord("segment belongs to another journal"));
            }
            let mut off = SEGMENT_HEADER_LEN;
            while off + 8 <= raw.len() {
                let len = u32::from_le_bytes(raw[off..off + 4].try_into().expect("4")) as usize;
                if len < RECORD_FIXED_LEN || off + 4 + len > raw.len() {
                    break;
                }
                let crc = u32::from_le_bytes(raw[off + 4..off + 8].try_into().expect("4"));
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
                expected = Some(record.seq + 1);
                self.apply(&record)?;
                self.seq = record.seq + 1;
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
            if committed > self.base_seq + 1 && last < committed - 1 {
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

    pub fn insert(&mut self, prefix: IpNet, value: &T) -> Result<u64, Error> {
        let mut value = value.clone();
        value.canonicalize();
        let bytes = T::encode(&value)?;
        let seq = self.append(KIND_INSERT, prefix, &bytes, &[])?;
        self.apply_value(prefix, value);
        Ok(seq)
    }

    pub fn insert_with_blob(
        &mut self,
        prefix: IpNet,
        value: &T,
        blob: &[u8],
    ) -> Result<u64, Error> {
        if self.payload.is_none() {
            return Err(Error::BadRecord(
                "insert_with_blob needs a payload section to carry the blob",
            ));
        }
        let mut value = value.clone();
        value.canonicalize();
        let bytes = T::encode(&value)?;
        self.blob.extend_from_slice(blob);
        let seq = self.append(KIND_INSERT, prefix, &bytes, blob)?;
        self.apply_value(prefix, value);
        Ok(seq)
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

    pub fn withdraw(&mut self, prefix: IpNet) -> Result<u64, Error> {
        // log first: if the append fails, the tree must still hold what the
        // previous record promised, or a later checkpoint would drop it
        let seq = self.append(KIND_WITHDRAW, prefix, &[], &[])?;
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

    fn append(&mut self, kind: u8, prefix: IpNet, value: &[u8], blob: &[u8]) -> Result<u64, Error> {
        let seq = self.seq;
        let (family, plen, addr) = prefix_fields(prefix);
        let mut payload = Vec::with_capacity(RECORD_FIXED_LEN + value.len() + blob.len());
        payload.extend_from_slice(&seq.to_le_bytes());
        payload.extend_from_slice(&0i64.to_le_bytes()); // recv_ts
        payload.extend_from_slice(&0i64.to_le_bytes()); // event_ts
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
        let len = (payload.len() + 4) as u32;
        let crc = crc32c::crc32c(&payload);
        let seg = self.seg.as_mut().expect("segment just opened");
        seg.file.write_all(&len.to_le_bytes())?;
        seg.file.write_all(&crc.to_le_bytes())?;
        seg.file.write_all(&payload)?;
        seg.bytes += 4 + payload.len() as u64;
        self.seq += 1;
        Ok(seq)
    }

    /// A record is durable once this returns.
    pub fn sync(&mut self) -> Result<(), Error> {
        if let Some(seg) = self.seg.as_mut() {
            seg.file.flush()?;
            seg.file.get_ref().sync_all()?;
        }
        let state = State {
            next_seq: self.seq,
            generation: self.generation,
            tree_id: self.tree_id,
            checkpoint: read_state(&self.dir)?.and_then(|s| s.checkpoint),
        };
        write_state(&self.dir, &state)?;
        Ok(())
    }

    /// Write and verify a snapshot of the current state, then drop covered
    /// segments. The object is verified end to end before anything is deleted.
    pub fn checkpoint(&mut self, opts: &Opts<'_>) -> Result<PathBuf, Error> {
        let mut writer = Writer::<T>::new();
        for (p, v) in self.v4.iter() {
            writer.insert(IpNet::V4(p), v.clone());
        }
        for (p, v) in self.v6.iter() {
            writer.insert(IpNet::V6(p), v.clone());
        }
        let mut extras: Vec<ExtraSection<'_>> = Vec::new();
        if let (Some(payload), true) = (self.payload, !self.blob.is_empty()) {
            extras.push(ExtraSection {
                id: payload.id,
                kind: payload.kind,
                required: payload.required,
                bytes: &self.blob,
            });
        }
        let stream = crate::StreamRef {
            tree_id: self.tree_id,
            generation: self.generation,
            base_seq: self.seq.saturating_sub(1),
        };
        let opts = Opts {
            created_at: opts.created_at,
            stream: Some(stream),
            window: opts.window,
            extras: &extras,
        };
        let bytes = writer.finish(&opts)?;

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
        if snap.len() != self.len() {
            return Err(Error::BadRecord("checkpoint does not hold the live tree"));
        }
        let name = format!("snapshot-{}.snap", self.seq);
        let path = self.dir.join(&name);
        let tmp = self.dir.join(format!(".{name}.tmp"));
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        File::open(&self.dir)?.sync_all()?;

        // commit the checkpoint: from here on, recovery starts from this object
        let covered = self.seq.saturating_sub(1);
        write_state(
            &self.dir,
            &State {
                next_seq: self.seq,
                generation: self.generation,
                tree_id: self.tree_id,
                checkpoint: Some((covered, name.clone())),
            },
        )?;
        self.base_seq = covered;
        self.stream.base_seq = covered;

        // only now may a fully covered segment go; the open segment never does
        for segment in segment_paths(&self.dir)? {
            if Some(&segment) == self.seg_path.as_ref() {
                continue;
            }
            if let Some(max) = segment_max_seq(&segment)? {
                if max <= covered {
                    std::fs::remove_file(&segment)?;
                }
            }
        }
        Ok(path)
    }

    pub fn blob_len(&self) -> usize {
        self.blob.len()
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    let seq = u64::from_le_bytes(payload[0..8].try_into().expect("8"));
    let kind = payload[24];
    let family = payload[25];
    let plen = payload[26];
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&payload[28..44]);
    let value_len = u32::from_le_bytes(payload[44..48].try_into().expect("4")) as usize;
    if payload.len() < 48 + value_len + 4 {
        return Err(Error::BadRecord("record value is short"));
    }
    let value = payload[48..48 + value_len].to_vec();
    let blob_len = u32::from_le_bytes(
        payload[48 + value_len..52 + value_len]
            .try_into()
            .expect("4"),
    ) as usize;
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

/// The durable commit record: what the journal promises survives a crash.
struct State {
    next_seq: u64,
    generation: [u8; 16],
    tree_id: [u8; 16],
    /// `(base_seq, file name)` of the newest verified checkpoint.
    checkpoint: Option<(u64, String)>,
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
    let checkpoint = v["checkpoint"].as_object().and_then(|c| {
        Some((
            c.get("seq")?.as_u64()?,
            c.get("file")?.as_str()?.to_string(),
        ))
    });
    Ok(Some(State {
        next_seq,
        generation,
        tree_id,
        checkpoint,
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
        let len = u32::from_le_bytes(raw[off..off + 4].try_into().expect("4")) as usize;
        if len < RECORD_FIXED_LEN || off + 4 + len > raw.len() {
            break;
        }
        let crc = u32::from_le_bytes(raw[off + 4..off + 8].try_into().expect("4"));
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

fn existing_generation(dir: &Path) -> Result<Option<[u8; 16]>, Error> {
    let mut paths = segment_paths(dir)?;
    paths.sort();
    for path in paths {
        let raw = std::fs::read(&path)?;
        if raw.len() >= SEGMENT_HEADER_LEN && &raw[..8] == MAGIC {
            let mut generation = [0u8; 16];
            generation.copy_from_slice(&raw[28..44]);
            return Ok(Some(generation));
        }
    }
    Ok(None)
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
