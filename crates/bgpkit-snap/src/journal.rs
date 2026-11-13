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

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use prefix_trie::{AsView, PrefixMap, TrieView};

use crate::{Error, RkyvError, SnapValue, Snapshot, Writer, ID_V4, ID_V6, MAJOR, MINOR};

/// Segment magic. Deliberately different from the snapshot magic so a mixed-up
/// file is rejected rather than parsed.
pub const JOURNAL_MAGIC: &[u8; 8] = b"BGPKLOG\0";
/// Segment header: magic 8 + version 2 + pad 2 + tree_id 16 + pad 4.
pub const SEGMENT_HEADER_LEN: usize = 32;
/// Fixed record bytes after the length field, with an empty value.
pub const RECORD_FIXED_LEN: usize = 52;

pub const KIND_INSERT: u8 = 1;
pub const KIND_WITHDRAW: u8 = 2;
pub const KIND_CONTROL: u8 = 3;

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
    tree_id: [u8; 16],
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
        let start = Self::last_seq(&dir)?.map_or(1, |s| s + 1);
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
        header.extend_from_slice(&[0u8; 4]);
        file.write_all(&header)?;
        file.sync_all()?;
        Ok(Self {
            tree_id,
            seg_path,
            seg: BufWriter::new(file),
            seg_bytes: SEGMENT_HEADER_LEN as u64,
            seq: start,
            records: 0,
        })
    }

    fn last_seq(dir: &Path) -> Result<Option<u64>, Error> {
        let mut last = None;
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(rest) = name.strip_prefix("segment-") {
                if let Some(digits) = rest.strip_suffix(".log") {
                    if let Ok(seq) = digits.parse::<u64>() {
                        last = last.max(Some(seq));
                    }
                }
            }
        }
        Ok(last)
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
        let bytes = tree.to_writer().finish(created_at, source)?;
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
            "base_seq": self.seq,
            "tree_id": hex(&self.tree_id),
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

        self.prune_segments(dir)?;
        Ok(name)
    }

    /// Delete segments whose records are all covered by the checkpoint.
    fn prune_segments(&mut self, dir: &Path) -> Result<(), Error> {
        for entry in std::fs::read_dir(dir)? {
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
            let first = name
                .trim_start_matches("segment-")
                .trim_end_matches(".log")
                .parse::<u64>()
                .ok();
            if let Some(first) = first {
                if first <= self.seq {
                    std::fs::remove_file(&path)?;
                }
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
    pub fn open(snapshot: &Snapshot<V>) -> Result<Self, Error> {
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
    Ok(Some(Checkpoint {
        snapshot_file,
        base_seq,
    }))
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
