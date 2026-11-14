//! The 192-byte v4 header and the section table.
//!
//! Layout (all little endian):
//!
//! ```text
//!  0  magic "BGPKSNAP"       12  tree_id [16]       28  generation [16]
//! 44  base_seq u64           52  type_id [32]       84  file_len u64
//! 92  section_count u32      96  table_len u32     100  window [2 x i64]
//!116  reserved [32]         148  created_at i64    156  content_id [32]
//!188  crc32c u32
//! ```
//!
//! Bytes `0..148` are hashed; `created_at`, `content_id` and the crc follow, so
//! the hash input is one contiguous range with no exclusion puzzle.

use crate::Error;

pub const MAGIC: &[u8; 8] = b"BGPKSNAP";
pub const HEADER_LEN: usize = 192;
pub const HASH_END: usize = 148;
pub const VERSION: u16 = 4;

/// One section table entry: 64 bytes.
pub const ENTRY_LEN: usize = 64;

pub const FLAG_STREAM: u16 = 1 << 0;
pub const FLAG_WINDOW: u16 = 1 << 1;
const FLAG_KNOWN: u16 = FLAG_STREAM | FLAG_WINDOW;

pub const KIND_V4: [u8; 4] = *b"V4\0\0";
pub const KIND_V6: [u8; 4] = *b"V6\0\0";
pub const KIND_PAYLOAD: [u8; 4] = *b"PAY\0";

pub const ID_V4: u16 = 2;
pub const ID_V6: u16 = 3;
/// Profile sections use ids 16 and above.
pub const FIRST_PROFILE_ID: u16 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StreamRef {
    pub tree_id: [u8; 16],
    pub generation: [u8; 16],
    pub base_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub flags: u16,
    pub tree_id: [u8; 16],
    pub generation: [u8; 16],
    pub base_seq: u64,
    pub type_id: [u8; 32],
    pub file_len: u64,
    pub section_count: u32,
    pub section_table_len: u32,
    pub window: [i64; 2],
    pub created_at: i64,
    pub content_id: [u8; 32],
}

impl Header {
    pub fn type_id_str(&self) -> String {
        let end = self
            .type_id
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.type_id.len());
        String::from_utf8_lossy(&self.type_id[..end]).into_owned()
    }

    pub fn content_id_hex(&self) -> String {
        hex32(&self.content_id)
    }

    pub fn stream(&self) -> Option<StreamRef> {
        (self.flags & FLAG_STREAM != 0).then_some(StreamRef {
            tree_id: self.tree_id,
            generation: self.generation,
            base_seq: self.base_seq,
        })
    }

    pub fn window(&self) -> Option<(i64, i64)> {
        (self.flags & FLAG_WINDOW != 0).then_some((self.window[0], self.window[1]))
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(MAGIC);
        b[8..10].copy_from_slice(&VERSION.to_le_bytes());
        b[10..12].copy_from_slice(&self.flags.to_le_bytes());
        b[12..28].copy_from_slice(&self.tree_id);
        b[28..44].copy_from_slice(&self.generation);
        b[44..52].copy_from_slice(&self.base_seq.to_le_bytes());
        b[52..84].copy_from_slice(&self.type_id);
        b[84..92].copy_from_slice(&self.file_len.to_le_bytes());
        b[92..96].copy_from_slice(&self.section_count.to_le_bytes());
        b[96..100].copy_from_slice(&self.section_table_len.to_le_bytes());
        b[100..108].copy_from_slice(&self.window[0].to_le_bytes());
        b[108..116].copy_from_slice(&self.window[1].to_le_bytes());
        b[148..156].copy_from_slice(&self.created_at.to_le_bytes());
        b[156..188].copy_from_slice(&self.content_id);
        let crc = crc32c::crc32c(&b[..188]);
        b[188..192].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Parse and check everything that can be judged from the header alone.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < HEADER_LEN {
            return Err(Error::Truncated {
                need: HEADER_LEN,
                have: raw.len(),
            });
        }
        if &raw[0..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        let version = u16::from_le_bytes([raw[8], raw[9]]);
        if version != VERSION {
            return Err(Error::BadVersion(version));
        }
        let crc = u32::from_le_bytes(raw[188..192].try_into().expect("4 bytes"));
        if crc32c::crc32c(&raw[..188]) != crc {
            return Err(Error::BadHeaderCrc);
        }
        let flags = u16::from_le_bytes([raw[10], raw[11]]);
        if flags & !FLAG_KNOWN != 0 {
            return Err(Error::BadHeader("undefined flag bit"));
        }
        let mut type_id = [0u8; 32];
        type_id.copy_from_slice(&raw[52..84]);
        if !type_id.contains(&0) {
            return Err(Error::BadHeader("type id is not terminated"));
        }
        let end = type_id
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(type_id.len());
        if type_id[..end]
            .iter()
            .any(|b| !b.is_ascii_graphic() || *b == b'"' || *b == b'\\')
        {
            return Err(Error::BadHeader("type id is not plain ASCII"));
        }
        if type_id[end..].iter().any(|b| *b != 0) {
            return Err(Error::BadHeader(
                "type id is not zero filled after its terminator",
            ));
        }
        if raw[116..148].iter().any(|b| *b != 0) {
            return Err(Error::BadHeader("reserved header bytes are not zero"));
        }
        let mut content_id = [0u8; 32];
        content_id.copy_from_slice(&raw[156..188]);
        if content_id == [0u8; 32] {
            return Err(Error::BadHeader("content id is zero"));
        }
        let mut tree_id = [0u8; 16];
        tree_id.copy_from_slice(&raw[12..28]);
        let mut generation = [0u8; 16];
        generation.copy_from_slice(&raw[28..44]);
        let base_seq = u64::from_le_bytes(raw[44..52].try_into().expect("8 bytes"));
        match flags & FLAG_STREAM {
            0 => {
                if tree_id != [0u8; 16] || generation != [0u8; 16] || base_seq != 0 {
                    return Err(Error::BadHeader("stream identity without the flag"));
                }
            }
            _ => {
                if tree_id == [0u8; 16] || generation == [0u8; 16] {
                    return Err(Error::BadHeader("stream flag without identity"));
                }
            }
        }
        let window = [
            i64::from_le_bytes(raw[100..108].try_into().expect("8 bytes")),
            i64::from_le_bytes(raw[108..116].try_into().expect("8 bytes")),
        ];
        match flags & FLAG_WINDOW {
            0 => {
                if window != [0, 0] {
                    return Err(Error::BadHeader("window without the flag"));
                }
            }
            _ => {
                if window[0] == 0 || window[1] == 0 || window[0] > window[1] {
                    return Err(Error::BadHeader("window is not a range"));
                }
            }
        }
        let created_at = i64::from_le_bytes(raw[148..156].try_into().expect("8 bytes"));
        if created_at == 0 {
            return Err(Error::BadHeader("created_at is zero"));
        }
        let header = Header {
            flags,
            tree_id,
            generation,
            base_seq,
            type_id,
            file_len: u64::from_le_bytes(raw[84..92].try_into().expect("8 bytes")),
            section_count: u32::from_le_bytes(raw[92..96].try_into().expect("4 bytes")),
            section_table_len: u32::from_le_bytes(raw[96..100].try_into().expect("4 bytes")),
            window,
            created_at,
            content_id,
        };
        // layout checks need the real file length, so a peek only parses; the
        // reader calls check_layout once it has the whole object
        Ok(header)
    }

    pub fn check_layout(&self, actual_len: usize) -> Result<(), Error> {
        if self.file_len as usize != actual_len {
            return Err(Error::Truncated {
                need: self.file_len as usize,
                have: actual_len,
            });
        }
        let expected = (self.section_count as usize)
            .checked_mul(ENTRY_LEN)
            .ok_or(Error::BadHeader("section count overflows the table"))?;
        if expected != self.section_table_len as usize {
            return Err(Error::BadHeader("table length disagrees with the count"));
        }
        let Some(table_end) = (HEADER_LEN as u64).checked_add(self.section_table_len as u64) else {
            return Err(Error::BadHeader("table length overflows"));
        };
        if table_end > self.file_len {
            return Err(Error::BadHeader("table runs past the file"));
        }
        Ok(())
    }
}

/// One section table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub id: u16,
    pub kind: [u8; 4],
    pub required: bool,
    pub len: u64,
}

impl Entry {
    pub fn encode(&self) -> [u8; ENTRY_LEN] {
        let mut b = [0u8; ENTRY_LEN];
        b[0..2].copy_from_slice(&self.id.to_le_bytes());
        b[2..6].copy_from_slice(&self.kind);
        b[6..8].copy_from_slice(&(self.required as u16).to_le_bytes());
        b[8..16].copy_from_slice(&self.len.to_le_bytes());
        b
    }

    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < ENTRY_LEN {
            return Err(Error::Truncated {
                need: ENTRY_LEN,
                have: raw.len(),
            });
        }
        let flags = u16::from_le_bytes([raw[6], raw[7]]);
        if flags & !1 != 0 {
            return Err(Error::BadHeader("undefined section flag"));
        }
        if raw[16..ENTRY_LEN].iter().any(|b| *b != 0) {
            return Err(Error::BadHeader(
                "section entry reserved bytes are not zero",
            ));
        }
        let mut kind = [0u8; 4];
        kind.copy_from_slice(&raw[2..6]);
        Ok(Entry {
            id: u16::from_le_bytes([raw[0], raw[1]]),
            kind,
            required: flags & 1 != 0,
            len: u64::from_le_bytes(raw[8..16].try_into().expect("8 bytes")),
        })
    }
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode a 32-character hex string into 16 bytes, for callers that persist
/// identities as text.
pub fn hex_to_bytes(s: &str, out: &mut [u8; 16]) -> Result<(), crate::Error> {
    if s.len() != 32 || !s.is_ascii() {
        return Err(crate::Error::BadHeader("hex identity has the wrong length"));
    }
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[i * 2] as char)
            .to_digit(16)
            .ok_or(crate::Error::BadHeader("hex identity is not hex"))?;
        let lo = (s.as_bytes()[i * 2 + 1] as char)
            .to_digit(16)
            .ok_or(crate::Error::BadHeader("hex identity is not hex"))?;
        *byte = ((hi << 4) | lo) as u8;
    }
    Ok(())
}

/// A 16-byte identity as 32 hex characters, the form `state.json` keeps.
pub fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
