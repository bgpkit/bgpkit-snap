//! The fixed 192-byte object header, version 1.
//!
//! A reader identifies an object from these bytes alone: a single range read of
//! 192 bytes answers what the object is, how many 网段 it holds, which stream
//! state it reflects, and whether the reader already has it.
//!
//! All multi-byte fields are little endian, matching the rkyv body. The header
//! is a fixed projection of META: `Snapshot::from_bytes` parses it, then checks
//! every projected field against META and rejects a mismatch, so the two can
//! never drift apart silently.
//!
//! Layout (offsets in bytes):
//!
//! ```text
//!  0  magic "BGPKSNAP"          16  tree_id[16]        32  generation[16]
//! 48  content_id[32]            80  type_id[32]       112  base_seq u64
//! 120  file_len u64            128  footer_off u64    136  meta_off u64
//! 144  meta_len u32            148  section_count u32 152  count_v4 u32
//! 156  count_v6 u32            160  first_event_ts i64 168  last_event_ts i64
//! 176  created_at i64          184  families u16      186  type_id_len u16
//! 188  header_crc32c u32
//! ```

/// Fixed header length. A change here is a major-version change.
pub const HEADER_LEN: usize = 192;
/// The header CRC covers bytes `0..HEADER_CRC_COVER`.
const HEADER_CRC_COVER: usize = 188;

pub const MAGIC: &[u8; 8] = b"BGPKSNAP";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;

/// Bit 0: the object materializes a journal state. Bit 1: the object declares
/// an event window.
pub const FLAG_HAS_STREAM: u16 = 1 << 0;
pub const FLAG_HAS_EVENTS: u16 = 1 << 1;
const FLAG_KNOWN: u16 = FLAG_HAS_STREAM | FLAG_HAS_EVENTS;

pub const FAMILY_V4: u16 = 1 << 0;
pub const FAMILY_V6: u16 = 1 << 1;

/// Journal coordinates a snapshot materializes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StreamRef {
    /// Identity of the tree. Non-zero whenever the stream is set.
    pub tree_id: [u8; 16],
    /// Random per journal incarnation, so sequence numbers cannot be reused
    /// across restarts under the same tree id.
    pub generation: [u8; 16],
    /// Highest journal sequence the body reflects.
    pub base_seq: u64,
}

impl StreamRef {
    pub fn is_zero(&self) -> bool {
        self.tree_id == [0u8; 16] && self.generation == [0u8; 16] && self.base_seq == 0
    }
}

/// Everything a writer can declare about the object beyond its entries.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeaderInputs {
    pub stream: Option<StreamRef>,
    pub first_event_ts: i64,
    pub last_event_ts: i64,
}

/// A parsed header. Constructed by the writer, validated by the reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub flags: u16,
    pub tree_id: [u8; 16],
    pub generation: [u8; 16],
    pub content_id: [u8; 32],
    pub type_id: String,
    pub base_seq: u64,
    pub file_len: u64,
    pub footer_off: u64,
    pub meta_off: u64,
    pub meta_len: u32,
    pub section_count: u32,
    pub count_v4: u32,
    pub count_v6: u32,
    pub first_event_ts: i64,
    pub last_event_ts: i64,
    pub created_at: i64,
    pub families: u16,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(MAGIC);
        b[8..10].copy_from_slice(&MAJOR.to_le_bytes());
        b[10..12].copy_from_slice(&MINOR.to_le_bytes());
        b[12..14].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        b[14..16].copy_from_slice(&self.flags.to_le_bytes());
        b[16..32].copy_from_slice(&self.tree_id);
        b[32..48].copy_from_slice(&self.generation);
        b[48..80].copy_from_slice(&self.content_id);
        let type_bytes = self.type_id.as_bytes();
        b[80..80 + type_bytes.len()].copy_from_slice(type_bytes);
        b[112..120].copy_from_slice(&self.base_seq.to_le_bytes());
        b[120..128].copy_from_slice(&self.file_len.to_le_bytes());
        b[128..136].copy_from_slice(&self.footer_off.to_le_bytes());
        b[136..144].copy_from_slice(&self.meta_off.to_le_bytes());
        b[144..148].copy_from_slice(&self.meta_len.to_le_bytes());
        b[148..152].copy_from_slice(&self.section_count.to_le_bytes());
        b[152..156].copy_from_slice(&self.count_v4.to_le_bytes());
        b[156..160].copy_from_slice(&self.count_v6.to_le_bytes());
        b[160..168].copy_from_slice(&self.first_event_ts.to_le_bytes());
        b[168..176].copy_from_slice(&self.last_event_ts.to_le_bytes());
        b[176..184].copy_from_slice(&self.created_at.to_le_bytes());
        b[184..186].copy_from_slice(&self.families.to_le_bytes());
        b[186..188].copy_from_slice(&(type_bytes.len() as u16).to_le_bytes());
        let crc = crc32c::crc32c(&b[..HEADER_CRC_COVER]);
        b[188..192].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Parse and validate the header. Every rule that can be checked from these
    /// 192 bytes is checked here; META agreement is checked by the reader.
    pub fn parse(raw: &[u8]) -> Result<Self, crate::Error> {
        use crate::Error;
        if raw.len() < HEADER_LEN {
            return Err(Error::Truncated {
                need: HEADER_LEN,
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
        let header_len = u16::from_le_bytes([raw[12], raw[13]]) as usize;
        if header_len != HEADER_LEN {
            return Err(Error::BadSectionTable("header length is not 192"));
        }
        let crc = u32::from_le_bytes(raw[188..192].try_into().expect("4 bytes"));
        if crc32c::crc32c(&raw[..HEADER_CRC_COVER]) != crc {
            return Err(Error::BodyHash);
        }
        let flags = u16::from_le_bytes([raw[14], raw[15]]);
        if flags & !FLAG_KNOWN != 0 {
            return Err(Error::BadMeta("unknown header flag".into()));
        }
        let mut tree_id = [0u8; 16];
        tree_id.copy_from_slice(&raw[16..32]);
        let mut generation = [0u8; 16];
        generation.copy_from_slice(&raw[32..48]);
        let mut content_id = [0u8; 32];
        content_id.copy_from_slice(&raw[48..80]);
        let type_id_len = u16::from_le_bytes([raw[186], raw[187]]) as usize;
        if type_id_len == 0 || type_id_len > 32 {
            return Err(Error::BadMeta("type id length out of range".into()));
        }
        let type_bytes = &raw[80..80 + 32];
        if type_bytes[..type_id_len]
            .iter()
            .any(|b| *b == 0 || !b.is_ascii_graphic())
        {
            return Err(Error::BadMeta("type id is not printable ASCII".into()));
        }
        if type_bytes[type_id_len..].iter().any(|b| *b != 0) {
            return Err(Error::BadMeta("type id padding is not zero".into()));
        }
        let type_id = String::from_utf8_lossy(&type_bytes[..type_id_len]).into_owned();
        let families = u16::from_le_bytes([raw[184], raw[185]]);
        if families == 0 || families & !(FAMILY_V4 | FAMILY_V6) != 0 {
            return Err(Error::BadMeta("families bitmap is invalid".into()));
        }
        let count_v4 = u32::from_le_bytes(raw[152..156].try_into().expect("4 bytes"));
        let count_v6 = u32::from_le_bytes(raw[156..160].try_into().expect("4 bytes"));
        if (families & FAMILY_V4 != 0) != (count_v4 > 0)
            || (families & FAMILY_V6 != 0) != (count_v6 > 0)
        {
            return Err(Error::BadMeta(
                "counts disagree with the families bitmap".into(),
            ));
        }
        let first_event_ts = i64::from_le_bytes(raw[160..168].try_into().expect("8 bytes"));
        let last_event_ts = i64::from_le_bytes(raw[168..176].try_into().expect("8 bytes"));
        let has_events = flags & FLAG_HAS_EVENTS != 0;
        if has_events {
            if first_event_ts == 0 || last_event_ts == 0 || first_event_ts > last_event_ts {
                return Err(Error::BadMeta("event window is invalid".into()));
            }
        } else if first_event_ts != 0 || last_event_ts != 0 {
            return Err(Error::BadMeta(
                "event window is set without the flag".into(),
            ));
        }
        let base_seq = u64::from_le_bytes(raw[112..120].try_into().expect("8 bytes"));
        let has_stream = flags & FLAG_HAS_STREAM != 0;
        if has_stream {
            if tree_id == [0u8; 16] || generation == [0u8; 16] {
                return Err(Error::BadMeta(
                    "stream flags without stream identity".into(),
                ));
            }
        } else if tree_id != [0u8; 16] || generation != [0u8; 16] || base_seq != 0 {
            return Err(Error::BadMeta(
                "stream identity without the stream flag".into(),
            ));
        }
        let created_at = i64::from_le_bytes(raw[176..184].try_into().expect("8 bytes"));
        if created_at == 0 {
            return Err(Error::BadMeta("created_at is zero".into()));
        }
        if content_id == [0u8; 32] {
            return Err(Error::BadMeta("content id is zero".into()));
        }
        let header = Header {
            flags,
            tree_id,
            generation,
            content_id,
            type_id,
            base_seq,
            file_len: u64::from_le_bytes(raw[120..128].try_into().expect("8 bytes")),
            footer_off: u64::from_le_bytes(raw[128..136].try_into().expect("8 bytes")),
            meta_off: u64::from_le_bytes(raw[136..144].try_into().expect("8 bytes")),
            meta_len: u32::from_le_bytes(raw[144..148].try_into().expect("4 bytes")),
            section_count: u32::from_le_bytes(raw[148..152].try_into().expect("4 bytes")),
            count_v4,
            count_v6,
            first_event_ts,
            last_event_ts,
            created_at,
            families,
        };
        Ok(header)
    }

    /// Rules that need the real file length: the footer must end the file and
    /// META must sit inside the body. A peeking reader skips this and reports
    /// its answer as unverified.
    pub fn check_layout(&self, actual_len: usize) -> Result<(), crate::Error> {
        use crate::Error;
        const ENTRY_LEN: u64 = 64;
        const FOOTER_PREFIX_LEN: u64 = 16;
        const FOOTER_HASH_LEN: u64 = 32;
        let footer_len =
            FOOTER_PREFIX_LEN + ENTRY_LEN * self.section_count as u64 + FOOTER_HASH_LEN;
        if self.file_len as usize != actual_len {
            return Err(Error::Truncated {
                need: self.file_len as usize,
                have: actual_len,
            });
        }
        if self.footer_off + footer_len != self.file_len {
            return Err(Error::BadSectionTable("footer does not end the file"));
        }
        if self.footer_off < HEADER_LEN as u64 {
            return Err(Error::BadSectionTable("footer overlaps the header"));
        }
        if self.meta_off < HEADER_LEN as u64
            || self.meta_off + self.meta_len as u64 > self.footer_off
        {
            return Err(Error::BadSectionTable("META is outside the body"));
        }
        Ok(())
    }

    pub fn content_id_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.content_id {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// CRC-32C of the header, exposed so tests and the CLI can assert a peek read.
pub fn header_crc(raw: &[u8]) -> Option<u32> {
    if raw.len() < HEADER_LEN {
        return None;
    }
    Some(u32::from_le_bytes(raw[188..192].try_into().ok()?))
}
