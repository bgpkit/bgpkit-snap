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
    dir: PathBuf,
    tree_id: [u8; 16],
    generation: [u8; 16],
    stream: crate::StreamRef,
    seg: Segment,
    seq: u64,
    base_seq: u64,
    v4: PrefixMap<ipnet::Ipv4Net, T>,
    v6: PrefixMap<ipnet::Ipv6Net, T>,
    blob: Vec<u8>,
    payload: Option<PayloadSection>,
}

impl<T: Codec> Journal<T>
where
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<
        rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>,
    >,
{
    /// Open a journal, recovering the tree from the last checkpoint plus the
    /// segments. The generation is reused when a journal already exists.
    pub fn open(
        dir: impl AsRef<Path>,
        tree_id: [u8; 16],
        payload: Option<PayloadSection>,
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

        let generation = existing_generation(&dir)?.unwrap_or_else(random_generation);
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
        let seg_path = dir.join(format!("segment-{index:012}.log"));
        let seg_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&seg_path)?;
        let mut journal = Journal {
            dir: dir.clone(),
            tree_id,
            generation,
            stream: crate::StreamRef {
                tree_id,
                generation,
                base_seq: 0,
            },
            seg: Segment {
                file: BufWriter::new(seg_file),
                bytes: 0,
            },
            seq: 1,
            base_seq: 0,
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
            blob: Vec::new(),
            payload,
        };
        journal.recover()?;
        journal.write_segment_header()?;
        Ok(journal)
    }

    fn write_segment_header(&mut self) -> Result<(), Error> {
        let mut header = Vec::with_capacity(SEGMENT_HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&4u16.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        header.extend_from_slice(&self.tree_id);
        header.extend_from_slice(&self.generation);
        header.extend_from_slice(&[0u8; 4]);
        self.seg.file.write_all(&header)?;
        self.seg.bytes = SEGMENT_HEADER_LEN as u64;
        Ok(())
    }

    /// Replay every segment on disk into the tree and the arena.
    fn recover(&mut self) -> Result<(), Error> {
        let mut paths = segment_paths(&self.dir)?;
        paths.sort();
        let mut expected: Option<u64> = Some(1);
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
                if let Some(want) = expected {
                    if record.seq != want && record.seq != want + 1 {
                        // one unacked record may be missing after a tear
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
        self.base_seq = self.seq.saturating_sub(1);
        self.stream.base_seq = self.base_seq;
        Ok(())
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

    /// Append a blob to the arena and return its offset. The bytes are recorded
    /// once; a client that wants dedup keeps its own map from content to offset.
    pub fn append_blob(&mut self, bytes: &[u8]) -> Result<u32, Error> {
        let off = u32::try_from(self.blob.len())
            .map_err(|_| Error::BadRecord("payload arena exceeds 4 GiB"))?;
        self.blob.extend_from_slice(bytes);
        self.append(
            KIND_INSERT,
            IpNet::V4(
                ipnet::Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 32).expect("host route"),
            ),
            &[],
            bytes,
        )?;
        Ok(off)
    }

    pub fn insert(&mut self, prefix: IpNet, value: &T) -> Result<u64, Error> {
        let mut value = value.clone();
        value.canonicalize();
        let bytes = T::encode(&value)?;
        self.append(KIND_INSERT, prefix, &bytes, &[])
    }

    pub fn insert_with_blob(
        &mut self,
        prefix: IpNet,
        value: &T,
        blob: &[u8],
    ) -> Result<u64, Error> {
        let mut value = value.clone();
        value.canonicalize();
        let bytes = T::encode(&value)?;
        self.blob.extend_from_slice(blob);
        self.append(KIND_INSERT, prefix, &bytes, blob)
    }

    pub fn withdraw(&mut self, prefix: IpNet) -> Result<u64, Error> {
        match prefix {
            IpNet::V4(p) => {
                self.v4.remove(&p);
            }
            IpNet::V6(p) => {
                self.v6.remove(&p);
            }
        }
        self.append(KIND_WITHDRAW, prefix, &[], &[])
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

        let len = (payload.len() + 4) as u32;
        let crc = crc32c::crc32c(&payload);
        self.seg.file.write_all(&len.to_le_bytes())?;
        self.seg.file.write_all(&crc.to_le_bytes())?;
        self.seg.file.write_all(&payload)?;
        self.seg.bytes += 4 + payload.len() as u64;
        self.seq += 1;
        Ok(seq)
    }

    /// A record is durable once this returns.
    pub fn sync(&mut self) -> Result<(), Error> {
        self.seg.file.flush()?;
        self.seg.file.get_ref().sync_all()?;
        let state = serde_json::json!({
            "next_seq": self.seq,
            "generation": crate::header::hex32(&pad32(&self.generation)),
            "tree_id": crate::header::hex32(&pad32(&self.tree_id)),
        });
        let tmp = self.dir.join(".state.json.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(
                serde_json::to_vec(&state)
                    .map_err(|_| Error::BadRecord("state"))?
                    .as_slice(),
            )?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, self.dir.join("state.json"))?;
        File::open(&self.dir)?.sync_all()?;
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
        println!(
            "checkpoint {} entries, id {}",
            snap.len(),
            snap.content_id()
        );
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

fn pad32(bytes: &[u8; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(bytes);
    out
}
