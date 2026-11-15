//! A consumer of bgpkit-snap that lives outside the crate.
//!
//! Everything here uses only the public API. `git diff` over the parent crate's
//! `src/` after adding this file must be empty: that is the whole point of v4.

use bgpkit_snap::{Entry, ExtraSection, Opts, SnapValue, Snapshot, SnapshotView, Validator, Writer};

/// A value that points into a payload section instead of carrying the bytes.
#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct AttrRef {
    pub off: u32,
    pub len: u32,
}

impl SnapValue for AttrRef {
    const TYPE_ID: &str = "downstream.attr-ref:v1";
}

pub const ATTRS_SECTION: u16 = 32;

/// The validator that claims section 32 and checks it is present.
pub struct AttrsProfile;

impl Validator for AttrsProfile {
    fn knows(&self, entry: &Entry) -> bool {
        entry.id == ATTRS_SECTION
    }

    fn validate(&self, view: &SnapshotView<'_>) -> Result<(), bgpkit_snap::Error> {
        // kind is checked here, not in `knows`: an optional section never reaches
        // `knows`, so a kind test there would only cover the required case
        match view.entry(ATTRS_SECTION) {
            Some(s) if s.kind == bgpkit_snap::KIND_PAYLOAD => Ok(()),
            Some(_) => Err(bgpkit_snap::Error::BadSectionTable(
                "section 32 is not a payload section",
            )),
            None => Err(bgpkit_snap::Error::BadSectionTable("section 32 is missing")),
        }
    }
}

impl AttrsProfile {
    /// Resolve a handle, checking its range against the section it points into.
    pub fn resolve(snap: &Snapshot<AttrRef>, r: &AttrRef) -> Result<Vec<u8>, String> {
        let section = snap
            .section_bytes(ATTRS_SECTION)
            .ok_or("no attribute section")?;
        let start = r.off as usize;
        let end = start + r.len as usize;
        if end > section.len() {
            return Err(format!("handle {}..{} outside {} bytes", r.off, end, section.len()));
        }
        Ok(section[start..end].to_vec())
    }
}

/// Build an object from `(prefix, attributes)` pairs, interning the attributes.
pub fn build(pairs: &[(ipnet::IpNet, Vec<u8>)], created_at: i64) -> Vec<u8> {
    let mut arena: Vec<u8> = Vec::new();
    let mut writer: Writer<AttrRef> = Writer::new();
    for (prefix, attrs) in pairs {
        let off = arena.len() as u32;
        arena.extend_from_slice(attrs);
        writer.insert(
            *prefix,
            AttrRef {
                off,
                len: attrs.len() as u32,
            },
        ).expect("canonical prefix");
    }
    writer
        .finish(&Opts {
            created_at,
            stream: None,
            window: None,
            extras: &[ExtraSection {
                id: ATTRS_SECTION,
                kind: bgpkit_snap::KIND_PAYLOAD,
                required: true,
                bytes: &arena,
            }],
        })
        .expect("build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_downstream_profile_round_trips() {
        let pairs = vec![
            ("10.0.0.0/8".parse().unwrap(), b"AS_PATH 64500".to_vec()),
            ("10.9.0.0/16".parse().unwrap(), b"AS_PATH 64501".to_vec()),
        ];
        let bytes = build(&pairs, 1_794_614_400);
        let snap: Snapshot<AttrRef> =
            Snapshot::from_bytes_with(&bytes, &AttrsProfile).expect("open");
        let (_, v) = snap.search("10.0.1.1".parse().unwrap()).expect("hit");
        let r = AttrRef { off: v.off.to_native(), len: v.len.to_native() };
        assert_eq!(AttrsProfile::resolve(&snap, &r).unwrap(), b"AS_PATH 64500");
    }

    #[test]
    fn without_the_profile_the_object_is_refused() {
        let bytes = build(&[("10.0.0.0/8".parse().unwrap(), b"x".to_vec())], 1_794_614_400);
        let err = Snapshot::<AttrRef>::from_bytes(&bytes).unwrap_err();
        assert!(format!("{err}").contains("32"), "{err}");
    }
}
