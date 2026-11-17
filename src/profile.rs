//! A second prefix trie inside a profile section, with its own value type.
//!
//! One object holds one value type, because a reader has to know what a value is
//! before it touches the body. A profile that needs a second table with different
//! values (prefix to path attributes, prefix to a first-seen time) puts it in a
//! section of its own, and this module is the whole story of doing that without
//! naming `rkyv` or `prefix-trie`:
//!
//! ```ignore
//! let mut side = TrieSection::<u64>::new();
//! side.insert("10.0.0.0/8".parse()?, 1_763_164_800)?;
//! let body = side.to_bytes()?;
//! // body goes into `Opts::extras` as `ExtraSection { id: 16, kind: *b"SEEN", .. }`
//! ```
//!
//! and on the reading side:
//!
//! ```ignore
//! let seen = snap.section_trie::<u64>(16)?;
//! let first = seen.and_then(|t| t.lpm("10.1.2.3".parse().ok()?)?);
//! ```

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::rkyv::ArchivedPrefixMap;
use prefix_trie::PrefixMap;
use rkyv::rancor::Error as RkyvError;

use crate::{Error, SnapValue, Snapshot};

/// Where each archive starts, in a body that begins with the value type id.
///
/// The id is what makes a section type-safe: two wrappers of different widths can
/// validate against each other's bytes and then answer nonsense, so the type is
/// recorded rather than inferred from the archive's shape. Both archives are
/// 16-byte aligned for the same reason the object's sections are: an unaligned
/// `rkyv` archive is not valid, whatever its bytes say.
fn align16(n: usize) -> usize {
    n.div_ceil(16) * 16
}

/// `[u16 type id len][type id][pad to 16][u32 v4 len][u32 v6 len][pad to 16]`
fn header_len(type_id: &str) -> usize {
    align16(2 + type_id.len()) + 8
}

fn head(type_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(header_len(type_id));
    out.extend_from_slice(&(type_id.len() as u16).to_le_bytes());
    out.extend_from_slice(type_id.as_bytes());
    out.resize(align16(out.len()), 0);
    out.extend_from_slice(&[0u8; 8]);
    out
}

/// Builds the body of a profile section holding a trie of its own value type.
pub struct TrieSection<U: SnapValue> {
    v4: PrefixMap<Ipv4Net, U>,
    v6: PrefixMap<Ipv6Net, U>,
}

impl<U: SnapValue> Default for TrieSection<U> {
    fn default() -> Self {
        Self::new()
    }
}

impl<U: SnapValue> TrieSection<U> {
    /// An empty section body.
    pub fn new() -> Self {
        Self {
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
        }
    }

    /// Store `value` under `prefix`, replacing any value already there.
    ///
    /// The same rule as the main trie: a prefix with host bits set is refused, because
    /// storing it under its network address would make the key asked for and the key
    /// returned differ.
    pub fn insert(&mut self, prefix: IpNet, value: U) -> Result<(), Error> {
        if prefix.addr() != prefix.network() {
            return Err(Error::BadPrefix(prefix.to_string()));
        }
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

    /// How many prefixes the section holds.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Whether the section holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The section body, for `ExtraSection { id, kind, required, bytes }`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let v4 = rkyv::to_bytes::<RkyvError>(&self.v4).map_err(|_| Error::BadValue)?;
        let v6 = rkyv::to_bytes::<RkyvError>(&self.v6).map_err(|_| Error::BadValue)?;
        let mut out = head(U::TYPE_ID);
        let lengths_at = out.len() - 8;
        out[lengths_at..lengths_at + 4].copy_from_slice(&(v4.len() as u32).to_le_bytes());
        out[lengths_at + 4..lengths_at + 8].copy_from_slice(&(v6.len() as u32).to_le_bytes());
        out.extend_from_slice(&v4);
        out.resize(align16(out.len()), 0);
        out.extend_from_slice(&v6);
        out.resize(align16(out.len()), 0);
        Ok(out)
    }
}

/// A profile section that holds a trie, as a queryable view.
///
/// Values come back by value: the archived form stays inside this crate, so a caller
/// never names it.
pub struct ProfileTrie<'a, U: SnapValue> {
    v4: Option<&'a ArchivedPrefixMap<Ipv4Net, U>>,
    v6: Option<&'a ArchivedPrefixMap<Ipv6Net, U>>,
}

impl<U: SnapValue> ProfileTrie<'_, U>
where
    U::Archived: for<'b> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'b, RkyvError>>
        + rkyv::Deserialize<U, rkyv::api::high::HighDeserializer<RkyvError>>,
{
    /// How many prefixes the section holds.
    pub fn len(&self) -> usize {
        self.v4.map(|m| m.len()).unwrap_or(0) + self.v6.map(|m| m.len()).unwrap_or(0)
    }

    /// Whether the section holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The value stored for exactly this prefix.
    pub fn get_exact(&self, prefix: IpNet) -> Option<U> {
        let value = match prefix {
            IpNet::V4(p) => self.v4.and_then(|m| m.get(&p)),
            IpNet::V6(p) => self.v6.and_then(|m| m.get(&p)),
        }?;
        rkyv::deserialize::<U, RkyvError>(value).ok()
    }

    /// The most specific prefix that covers `prefix`.
    pub fn lpm(&self, prefix: IpNet) -> Option<(IpNet, U)> {
        match prefix {
            IpNet::V4(p) => {
                let (found, value) = self.v4?.get_lpm(&p)?;
                Some((
                    IpNet::V4(found),
                    rkyv::deserialize::<U, RkyvError>(value).ok()?,
                ))
            }
            IpNet::V6(p) => {
                let (found, value) = self.v6?.get_lpm(&p)?;
                Some((
                    IpNet::V6(found),
                    rkyv::deserialize::<U, RkyvError>(value).ok()?,
                ))
            }
        }
    }

    /// Every prefix and value in the section, IPv4 first.
    pub fn iter(&self) -> Vec<(IpNet, U)> {
        let mut out = Vec::with_capacity(self.len());
        if let Some(m) = self.v4 {
            for (p, v) in m.iter() {
                if let Ok(v) = rkyv::deserialize::<U, RkyvError>(v) {
                    out.push((IpNet::V4(p), v));
                }
            }
        }
        if let Some(m) = self.v6 {
            for (p, v) in m.iter() {
                if let Ok(v) = rkyv::deserialize::<U, RkyvError>(v) {
                    out.push((IpNet::V6(p), v));
                }
            }
        }
        out
    }
}

impl<T: SnapValue> Snapshot<T> {
    /// A profile section written by [`TrieSection`], as a queryable view.
    ///
    /// `None` when the object has no such section. The archive is byte-checked here,
    /// so a section that is not a trie of `U` is `BadArchive` rather than a panic.
    pub fn section_trie<U: SnapValue>(&self, id: u16) -> Result<Option<ProfileTrie<'_, U>>, Error>
    where
        U::Archived: for<'b> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'b, RkyvError>>
            + rkyv::Deserialize<U, rkyv::api::high::HighDeserializer<RkyvError>>,
    {
        let Some(bytes) = self.section_bytes(id) else {
            return Ok(None);
        };
        if bytes.len() < 2 {
            return Err(Error::BadArchive(id));
        }
        let id_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let type_at = 2;
        let after_id = align16(2 + id_len);
        if bytes.len() < after_id + 8 {
            return Err(Error::BadArchive(id));
        }
        // the section records which value type it was written with: two wrappers of
        // different widths can validate against each other's bytes, and the answers
        // would be meaningless rather than wrong-looking
        let written = std::str::from_utf8(&bytes[type_at..type_at + id_len])
            .map_err(|_| Error::BadArchive(id))?;
        if written != U::TYPE_ID {
            return Err(Error::ConfigMismatch(format!(
                "section {id} holds {written}, not {}",
                U::TYPE_ID
            )));
        }
        let lengths = &bytes[after_id..after_id + 8];
        let v4_len = u32::from_le_bytes([lengths[0], lengths[1], lengths[2], lengths[3]]) as usize;
        let v6_len = u32::from_le_bytes([lengths[4], lengths[5], lengths[6], lengths[7]]) as usize;
        let v4_at = after_id + 8;
        let v6_at = align16(v4_at + v4_len);
        if v6_at + v6_len > bytes.len() {
            return Err(Error::BadArchive(id));
        }
        let v4 = &bytes[v4_at..v4_at + v4_len];
        let v6 = &bytes[v6_at..v6_at + v6_len];
        let v4 = rkyv::access::<ArchivedPrefixMap<Ipv4Net, U>, RkyvError>(v4)
            .map_err(|_| Error::BadArchive(id))?;
        let v6 = rkyv::access::<ArchivedPrefixMap<Ipv6Net, U>, RkyvError>(v6)
            .map_err(|_| Error::BadArchive(id))?;
        Ok(Some(ProfileTrie {
            v4: Some(v4),
            v6: Some(v6),
        }))
    }
}
