//! The append-only journal and the mutable tree that feeds it.
//!
//! A journal turns a mutable tree into a snapshot without losing updates. It is
//! not an audit log: segments below the checkpoint's `base_seq` are deleted.
//!
//! Record layout (little endian), see the format document section 9:
//! `len u32 | crc32c u32 | seq u64 | recv_ts i64 | event_ts i64 | kind u8 |
//! family u8 | prefix_len u8 | flags u8 | addr [16] | value_len u32 | value`.
//! `len` counts the bytes after itself, so a record is `4 + len` bytes, and the
//! CRC covers the bytes after the CRC field, never itself.

use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use prefix_trie::{AsView, PrefixMap, TrieView};

use crate::{Error, RkyvError, Snapshot, Writer, ID_V4, ID_V6, MAJOR, MINOR};

/// Segment magic. Deliberately different from the snapshot magic so a mixed-up
/// file is rejected rather than parsed.
pub const JOURNAL_MAGIC: &[u8; 8] = b"BGPKLOG\0";
/// Segment header: magic 8 + version 2 + minor 2 + tree_id 16 + generation 16 +
/// pad 4. The generation makes sequence numbers unique across journal
/// incarnations, so a stale snapshot cannot be replayed against a new journal.
pub const SEGMENT_HEADER_LEN: usize = 48;
/// Fixed record bytes after the length field, with an empty value.
pub const RECORD_FIXED_LEN: usize = 52;

pub const KIND_INSERT: u8 = 1;
pub const KIND_WITHDRAW: u8 = 2;
pub const KIND_CONTROL: u8 = 3;

pub use crate::Codec;

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

/// One decoded record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub recv_ts: i64,
    pub event_ts: i64,
    pub kind: u8,
    pub prefix: IpNet,
    pub value: Vec<u8>,
}

/// The append side. One writer per tree.
pub struct Journal {
    dir: PathBuf,
    /// Advisory lock, held until this journal is dropped: one writer per tree.
    _lock: File,
    tree_id: [u8; 16],
    generation: [u8; 16],
    seg_path: PathBuf,
    seg: BufWriter<File>,
    seg_bytes: u64,
    seq: u64,
    records: u64,
}

impl Journal {
    /// Open (or create) a journal directory and start a new segment.
    pub fn open(dir: impl AsRef<Path>, tree_id: [u8; 16]) -> Result<Self, Error> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        // one writer per tree: an advisory lock held for the process lifetime
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("writer.lock"))?;
        lock.try_lock_exclusive()
            .map_err(|_| Error::BadMeta("another writer holds this journal".into()))?;
        std::fs::write(dir.join("writer.pid"), std::process::id().to_string())?;
        // reuse the generation of the segment already on disk, otherwise mint a
        // new one for this incarnation
        let generation = Self::existing_generation(&dir)?.unwrap_or_else(random_generation);
        let start = Self::next_seq(&dir)?;
        let seg_path = dir.join(format!("segment-{start:012}.log"));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&seg_path)?;
        let mut header = Vec::with_capacity(SEGMENT_HEADER_LEN);
        header.extend_from_slice(JOURNAL_MAGIC);
        header.extend_from_slice(&MAJOR.to_le_bytes());
        header.extend_from_slice(&MINOR.to_le_bytes());
        header.extend_from_slice(&tree_id);
        header.extend_from_slice(&generation);
        header.extend_from_slice(&[0u8; 4]);
        file.write_all(&header)?;
        file.sync_all()?;
        Ok(Self {
            dir,
            _lock: lock,
            tree_id,
            generation,
            seg_path,
            seg: BufWriter::new(file),
            seg_bytes: SEGMENT_HEADER_LEN as u64,
            seq: start,
            records: 0,
        })
    }

    /// Highest sequence already on disk plus one. Scanning the records rather
    /// than trusting the segment name is what keeps a restarted incarnation from
    /// reissuing sequence numbers.
    fn next_seq(dir: &Path) -> Result<u64, Error> {
        let mut segments: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("segment-") && n.ends_with(".log"))
            })
            .collect();
        segments.sort();
        let mut max = 0u64;
        for path in segments {
            let raw = std::fs::read(&path)?;
            if raw.len() < SEGMENT_HEADER_LEN {
                continue;
            }
            let mut off = SEGMENT_HEADER_LEN;
            while off + 8 <= raw.len() {
                let len =
                    u32::from_le_bytes(raw[off..off + 4].try_into().expect("4 bytes")) as usize;
                if off + 4 + len > raw.len() {
                    break;
                }
                let payload = &raw[off + 8..off + 4 + len];
                if payload.len() < 8 {
                    break;
                }
                let seq = u64::from_le_bytes(payload[0..8].try_into().expect("8 bytes"));
                max = max.max(seq);
                off += 4 + len;
            }
        }
        Ok(max + 1)
    }

    pub fn generation(&self) -> [u8; 16] {
        self.generation
    }

    /// The generation recorded in the first segment on disk, if any.
    fn existing_generation(dir: &Path) -> Result<Option<[u8; 16]>, Error> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Ok(None);
        };
        let mut names: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("segment-") && n.ends_with(".log"))
            })
            .collect();
        names.sort();
        for path in names {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if bytes.len() >= SEGMENT_HEADER_LEN && &bytes[..8] == JOURNAL_MAGIC {
                let mut generation = [0u8; 16];
                generation.copy_from_slice(&bytes[28..44]);
                return Ok(Some(generation));
            }
        }
        Ok(None)
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    pub fn segment_bytes(&self) -> u64 {
        self.seg_bytes
    }

    /// Append one record. Returns the assigned sequence number.
    fn append(
        &mut self,
        kind: u8,
        prefix: IpNet,
        value: &[u8],
        recv_ts: i64,
        event_ts: i64,
    ) -> Result<u64, Error> {
        let seq = self.seq;
        let (family, prefix_len, addr) = prefix_fields(prefix);
        let mut payload = Vec::with_capacity(RECORD_FIXED_LEN + value.len());
        payload.extend_from_slice(&seq.to_le_bytes());
        payload.extend_from_slice(&recv_ts.to_le_bytes());
        payload.extend_from_slice(&event_ts.to_le_bytes());
        payload.push(kind);
        payload.push(family);
        payload.push(prefix_len);
        payload.push(0);
        payload.extend_from_slice(&addr);
        payload.extend_from_slice(&(value.len() as u32).to_le_bytes());
        payload.extend_from_slice(value);

        let len = (payload.len() + 4) as u32;
        let crc = crc32c::crc32c(&payload);
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(&crc.to_le_bytes());
        framed.extend_from_slice(&payload);
        self.seg.write_all(&framed)?;
        self.seg_bytes += framed.len() as u64;
        self.seq += 1;
        self.records += 1;
        Ok(seq)
    }

    /// Append an insert. The value is stored in its archived form.
    pub fn insert<V: Codec>(
        &mut self,
        prefix: IpNet,
        value: &V,
        event_ts: i64,
    ) -> Result<u64, Error> {
        let bytes = V::encode(value)?;
        self.append(KIND_INSERT, prefix, &bytes, now_ts(), event_ts)
    }

    /// Append a withdraw. Withdrawals carry no value.
    pub fn withdraw(&mut self, prefix: IpNet, event_ts: i64) -> Result<u64, Error> {
        self.append(KIND_WITHDRAW, prefix, &[], now_ts(), event_ts)
    }

    /// A record is durable once this returns.
    pub fn sync(&mut self) -> Result<(), Error> {
        self.seg.flush()?;
        self.seg.get_ref().sync_all()?;
        Ok(())
    }

    /// Write the tree as a snapshot, then drop the segments the snapshot covers.
    ///
    /// The previous snapshot and its segments survive until the new snapshot is
    /// on disk, so a crash mid-checkpoint replays cleanly against the old base.
    pub fn checkpoint(
        &mut self,
        tree: &Tree<impl Codec>,
        dir: impl AsRef<Path>,
        created_at: &str,
        source: &str,
    ) -> Result<String, Error> {
        let bytes = tree.to_writer().finish_with(
            created_at,
            source,
            crate::HeaderInputs {
                stream: Some(crate::StreamRef {
                    tree_id: self.tree_id,
                    generation: self.generation,
                    base_seq: self.seq.saturating_sub(1),
                }),
                first_event_ts: 0,
                last_event_ts: 0,
            },
        )?;
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let name = format!("snapshot-{}.snap", self.seq);
        let final_path = dir.join(&name);
        let tmp_path = dir.join(format!(".{name}.tmp"));
        {
            let mut f = File::create(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, &final_path)?;
        File::open(dir)?.sync_all()?;

        let checkpoint = serde_json::json!({
            "snapshot_file": name,
            // the snapshot reflects records up to and including self.seq - 1;
            // replay applies `seq > base_seq`, so storing self.seq would drop the
            // first record appended after this checkpoint.
            "base_seq": self.seq.saturating_sub(1),
            "tree_id": hex(&self.tree_id),
            "generation": hex(&self.generation),
        });
        let cp_path = dir.join("checkpoint.json");
        let cp_tmp = dir.join(".checkpoint.json.tmp");
        {
            let mut f = File::create(&cp_tmp)?;
            f.write_all(
                &serde_json::to_vec_pretty(&checkpoint)
                    .map_err(|e| Error::BadMeta(e.to_string()))?,
            )?;
            f.sync_all()?;
        }
        std::fs::rename(&cp_tmp, &cp_path)?;
        File::open(dir)?.sync_all()?;

        self.prune_segments()?;
        Ok(name)
    }

    /// Delete segments whose records are all covered by the checkpoint.
    fn prune_segments(&mut self) -> Result<(), Error> {
        let covered = self.seq.saturating_sub(1);
        for entry in std::fs::read_dir(&self.dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with("segment-") || !name.ends_with(".log") {
                continue;
            }
            // keep the segment currently being appended to
            if path == self.seg_path {
                continue;
            }
            let Some(last) = last_record_seq(&path)? else {
                continue;
            };
            if last <= covered {
                std::fs::remove_file(&path)?;
            }
        }
        Ok(())
    }
}

/// A mutable tree. Values are owned; a snapshot is a point-in-time projection.
pub struct Tree<V> {
    v4: PrefixMap<ipnet::Ipv4Net, V>,
    v6: PrefixMap<ipnet::Ipv6Net, V>,
}

impl<V: Codec> Default for Tree<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Codec> Tree<V> {
    pub fn new() -> Self {
        Self {
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
        }
    }

    /// Load every entry of a snapshot into owned memory. This is the cost of
    /// mutating a snapshot: there is no in-place edit path.
    pub fn open(snapshot: &Snapshot<V>) -> Result<Self, Error>
    where
        V::Archived:
            for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, RkyvError>>,
    {
        let mut tree = Self::new();
        if let Some(map) = snapshot.v4() {
            for (p, v) in map.view().iter() {
                tree.v4.insert(p, V::materialize(v)?);
            }
        }
        if let Some(map) = snapshot.v6() {
            for (p, v) in map.view().iter() {
                tree.v6.insert(p, V::materialize(v)?);
            }
        }
        Ok(tree)
    }

    pub fn insert(&mut self, prefix: IpNet, value: V) -> Option<V> {
        match prefix {
            IpNet::V4(p) => self.v4.insert(p, value),
            IpNet::V6(p) => self.v6.insert(p, value),
        }
    }

    pub fn withdraw(&mut self, prefix: IpNet) -> Option<V> {
        match prefix {
            IpNet::V4(p) => self.v4.remove(&p),
            IpNet::V6(p) => self.v6.remove(&p),
        }
    }

    pub fn get(&self, prefix: IpNet) -> Option<(IpNet, &V)> {
        match prefix {
            IpNet::V4(p) => self.v4.get_spm(&p).map(|(k, v)| (IpNet::V4(k), v)),
            IpNet::V6(p) => self.v6.get_spm(&p).map(|(k, v)| (IpNet::V6(k), v)),
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Visit every entry in prefix order, each family separately.
    pub fn for_each(&self, mut f: impl FnMut(IpNet, &V)) {
        for (p, v) in self.v4.view().iter() {
            f(IpNet::V4(p), v);
        }
        for (p, v) in self.v6.view().iter() {
            f(IpNet::V6(p), v);
        }
    }

    pub fn to_writer(&self) -> Writer<V> {
        let mut w = Writer::new();
        for (p, v) in self.v4.view().iter() {
            w.insert(IpNet::V4(p), v.clone());
        }
        for (p, v) in self.v6.view().iter() {
            w.insert(IpNet::V6(p), v.clone());
        }
        w
    }
}

/// What a replay did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayStats {
    pub applied: u64,
    pub skipped: u64,
    pub torn_bytes: u64,
}

/// The checkpoint a journal directory refers to.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub snapshot_file: String,
    pub base_seq: u64,
    pub generation: [u8; 16],
    pub tree_id: [u8; 16],
}

/// Read `checkpoint.json`, if the directory has one.
pub fn read_checkpoint(dir: impl AsRef<Path>) -> Result<Option<Checkpoint>, Error> {
    let path = dir.as_ref().join("checkpoint.json");
    let Ok(raw) = std::fs::read(&path) else {
        return Ok(None);
    };
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| Error::BadMeta(e.to_string()))?;
    let snapshot_file = v["snapshot_file"]
        .as_str()
        .ok_or_else(|| Error::BadMeta("checkpoint.json: snapshot_file".into()))?
        .to_string();
    let base_seq = v["base_seq"]
        .as_u64()
        .ok_or_else(|| Error::BadMeta("checkpoint.json: base_seq".into()))?;
    let tree_id = v["tree_id"]
        .as_str()
        .and_then(parse_hex16)
        .ok_or_else(|| Error::BadMeta("checkpoint.json: tree_id".into()))?;
    let generation = v["generation"]
        .as_str()
        .and_then(parse_hex16)
        .ok_or_else(|| Error::BadMeta("checkpoint.json: generation".into()))?;
    Ok(Some(Checkpoint {
        snapshot_file,
        base_seq,
        generation,
        tree_id,
    }))
}

/// Check that `checkpoint.json` describes the snapshot it names.
///
/// Reads only the snapshot's 192-byte header, so it needs no value type: the
/// tree id, generation and base sequence must match the checkpoint exactly, or
/// replay would start from the wrong base.
pub fn verify_checkpoint_binding(dir: impl AsRef<Path>) -> Result<Checkpoint, Error> {
    let dir = dir.as_ref();
    let cp = read_checkpoint(dir)?.ok_or_else(|| Error::BadMeta("no checkpoint.json".into()))?;
    let path = dir.join(&cp.snapshot_file);
    let mut raw = [0u8; crate::header::HEADER_LEN];
    {
        let mut f = File::open(&path)?;
        f.read_exact(&mut raw)?;
    }
    let header = crate::Header::parse(&raw)?;
    if header.tree_id != cp.tree_id
        || header.generation != cp.generation
        || header.base_seq != cp.base_seq
    {
        return Err(Error::BadMeta(
            "checkpoint.json does not describe the snapshot it names".into(),
        ));
    }
    Ok(cp)
}

/// Replay every record with `seq > base_seq` into `tree`.
///
/// A torn tail (short final record, bad length, or CRC mismatch) stops the scan
/// without failing: the valid prefix is applied and the byte count is reported.
pub fn replay<V: Codec>(
    tree: &mut Tree<V>,
    dir: impl AsRef<Path>,
    base_seq: u64,
    tree_id: [u8; 16],
    generation: [u8; 16],
) -> Result<ReplayStats, Error> {
    let dir = dir.as_ref();
    let mut segments: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("segment-") && n.ends_with(".log"))
        {
            segments.push(path);
        }
    }
    segments.sort();

    let mut stats = ReplayStats {
        applied: 0,
        skipped: 0,
        torn_bytes: 0,
    };
    let mut next_expected: Option<u64> = None;
    for path in segments {
        let mut raw = Vec::new();
        File::open(&path)?.read_to_end(&mut raw)?;
        if raw.len() < SEGMENT_HEADER_LEN || &raw[..8] != JOURNAL_MAGIC {
            return Err(Error::BadMagic);
        }
        if raw[12..28] != tree_id {
            return Err(Error::TypeMismatch {
                expected: "journal tree_id",
                found: hex(&raw[12..28]),
            });
        }
        if raw[28..44] != generation {
            return Err(Error::TypeMismatch {
                expected: "journal generation",
                found: hex(&raw[28..44]),
            });
        }
        let mut off = SEGMENT_HEADER_LEN;
        while off + 4 <= raw.len() {
            let len = u32::from_le_bytes(raw[off..off + 4].try_into().expect("4 bytes")) as usize;
            if off + 4 + len > raw.len() {
                stats.torn_bytes += (raw.len() - off) as u64;
                break;
            }
            let crc = u32::from_le_bytes(raw[off + 4..off + 8].try_into().expect("4 bytes"));
            let payload = &raw[off + 8..off + 4 + len];
            if crc32c::crc32c(payload) != crc {
                stats.torn_bytes += (raw.len() - off) as u64;
                break;
            }
            let record = parse_payload(payload)?;
            if let Some(expected) = next_expected {
                if record.seq != expected {
                    return Err(Error::BadMeta(format!(
                        "journal sequence gap: expected {expected}, found {}",
                        record.seq
                    )));
                }
            }
            next_expected = Some(record.seq + 1);
            if record.seq <= base_seq {
                stats.skipped += 1;
            } else {
                match record.kind {
                    KIND_INSERT => {
                        tree.insert(record.prefix, V::decode(&record.value)?);
                    }
                    KIND_WITHDRAW => {
                        tree.withdraw(record.prefix);
                    }
                    KIND_CONTROL => {}
                    _ => {}
                }
                stats.applied += 1;
            }
            off += 4 + len;
        }
        if off < raw.len() && stats.torn_bytes == 0 {
            stats.torn_bytes += (raw.len() - off) as u64;
        }
    }
    Ok(stats)
}

fn parse_payload(payload: &[u8]) -> Result<Record, Error> {
    if payload.len() < 48 {
        return Err(Error::Truncated {
            need: 48,
            have: payload.len(),
        });
    }
    let seq = u64::from_le_bytes(payload[0..8].try_into().expect("8 bytes"));
    let recv_ts = i64::from_le_bytes(payload[8..16].try_into().expect("8 bytes"));
    let event_ts = i64::from_le_bytes(payload[16..24].try_into().expect("8 bytes"));
    let kind = payload[24];
    let family = payload[25];
    let prefix_len = payload[26];
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&payload[28..44]);
    let value_len = u32::from_le_bytes(payload[44..48].try_into().expect("4 bytes")) as usize;
    if payload.len() < 48 + value_len {
        return Err(Error::Truncated {
            need: 48 + value_len,
            have: payload.len(),
        });
    }
    let prefix = prefix_from_fields(family, prefix_len, &addr).ok_or(Error::BadSectionTable(
        "journal record has an unusable prefix",
    ))?;
    Ok(Record {
        seq,
        recv_ts,
        event_ts,
        kind,
        prefix,
        value: payload[48..48 + value_len].to_vec(),
    })
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Highest valid record sequence in a segment.
fn last_record_seq(path: &Path) -> Result<Option<u64>, Error> {
    let raw = std::fs::read(path)?;
    if raw.len() < SEGMENT_HEADER_LEN {
        return Ok(None);
    }
    let mut off = SEGMENT_HEADER_LEN;
    let mut last = None;
    while off + 8 <= raw.len() {
        let len = u32::from_le_bytes(raw[off..off + 4].try_into().expect("4 bytes")) as usize;
        if off + 4 + len > raw.len() {
            break;
        }
        let payload = &raw[off + 8..off + 4 + len];
        if payload.len() < 8 {
            break;
        }
        last = Some(u64::from_le_bytes(
            payload[0..8].try_into().expect("8 bytes"),
        ));
        off += 4 + len;
    }
    Ok(last)
}

/// 16 bytes from the OS RNG. A deterministic hash is not an incarnation id:
/// two journals opened in the same second would share coordinates.
fn random_generation() -> [u8; 16] {
    let mut generation = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut generation).is_ok() {
            return generation;
        }
    }
    let mut h = blake3::Hasher::new();
    h.update(b"snap-journal-generation\0");
    h.update(&now_ts().to_le_bytes());
    h.update(&std::process::id().to_le_bytes());
    h.update(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
            .to_le_bytes(),
    );
    generation.copy_from_slice(&h.finalize().as_bytes()[..16]);
    generation
}

fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Section ids are re-exported so callers can assert a journal round trip did
/// not change which families the snapshot carries.
pub const FAMILY_IDS: [u16; 2] = [ID_V4, ID_V6];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_fields_round_trip() {
        for p in ["1.2.3.0/24", "2001:db8::/32"] {
            let prefix: IpNet = p.parse().expect("valid prefix");
            let (family, len, addr) = prefix_fields(prefix);
            assert_eq!(prefix_from_fields(family, len, &addr), Some(prefix));
        }
    }

    #[test]
    fn value_encoding_round_trip() {
        let bytes = u32::encode(&42u32).expect("encode");
        let back: u32 = u32::decode(&bytes).expect("decode");
        assert_eq!(back, 42);
    }
}
