//! Contract checks that do not depend on any profile.

use bgpkit_snap::{Entry, ExtraSection, Header, Opts, SnapValue, Snapshot, Validator, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct N(u32);

impl SnapValue for N {
    const TYPE_ID: &str = "test.n:v1";
}

fn build(extras: &[ExtraSection<'_>]) -> Vec<u8> {
    let mut w: Writer<N> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), N(1));
    w.insert("10.1.0.0/16".parse().unwrap(), N(2));
    w.insert("2001:db8::/32".parse().unwrap(), N(3));
    w.finish(&Opts {
        created_at: "2026-11-14T00:00:00Z",
        window: Some((1_790_000_000, 1_794_355_200)),
        stream: None,
        extras,
    })
    .expect("build")
}

#[test]
fn header_is_self_sufficient() {
    let bytes = build(&[]);
    let h = Header::parse(&bytes[..192]).expect("header");
    assert_eq!(h.type_id_str(), "test.n:v1");
    assert_eq!(h.section_count, 2);
    assert_eq!(h.window(), Some((1_790_000_000, 1_794_355_200)));
    assert_eq!(h.file_len as usize, bytes.len());
    assert_eq!(h.stream(), None);
    assert_eq!(h.content_id_hex().len(), 64);
}

#[test]
fn table_alone_enumerates_sections() {
    let bytes = build(&[]);
    let h = Header::parse(&bytes[..192]).unwrap();
    let table_end = 192 + h.section_table_len as usize;
    // a reader that wants the layout reads 192 + 128 bytes and stops
    assert_eq!(h.section_table_len, 128);
    assert!(table_end < bytes.len());
}

#[test]
fn content_id_covers_every_section() {
    let a = build(&[]);
    let extra = b"payload".to_vec();
    let b = build(&[ExtraSection {
        id: 16,
        kind: bgpkit_snap::KIND_PAYLOAD,
        required: false,
        bytes: &extra,
    }]);
    let ha = Header::parse(&a[..192]).unwrap();
    let hb = Header::parse(&b[..192]).unwrap();
    assert_ne!(ha.content_id, hb.content_id);

    // the same extras produce the same id
    let c = build(&[ExtraSection {
        id: 16,
        kind: bgpkit_snap::KIND_PAYLOAD,
        required: false,
        bytes: &extra,
    }]);
    assert_eq!(Header::parse(&c[..192]).unwrap().content_id, hb.content_id);
}

#[test]
fn one_byte_change_breaks_the_identity() {
    let mut bytes = build(&[]);
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let err = Snapshot::<N>::from_bytes(&bytes).unwrap_err();
    assert!(format!("{err}").contains("content id"), "{err}");
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = build(&[]);
    bytes.extend_from_slice(b"junk");
    let err = Snapshot::<N>::from_bytes(&bytes).unwrap_err();
    assert!(
        format!("{err}").contains("truncated") || format!("{err}").contains("end the file"),
        "{err}"
    );
}

#[test]
fn truncation_is_rejected() {
    let bytes = build(&[]);
    for cut in [1usize, 16, 100] {
        assert!(Snapshot::<N>::from_bytes(&bytes[..bytes.len() - cut]).is_err());
    }
}

#[test]
fn a_required_section_nobody_knows_is_refused_by_id() {
    let payload = b"x".to_vec();
    let bytes = build(&[ExtraSection {
        id: 16,
        kind: bgpkit_snap::KIND_PAYLOAD,
        required: true,
        bytes: &payload,
    }]);
    let err = Snapshot::<N>::from_bytes(&bytes).unwrap_err();
    assert!(matches!(
        err,
        bgpkit_snap::Error::UnknownRequiredSection(16)
    ));
    assert!(format!("{err}").contains("16"));
}

struct Knows;
impl Validator for Knows {
    fn knows(&self, _e: &Entry) -> bool {
        true
    }
}

#[test]
fn a_validator_admits_the_section_it_implements() {
    let payload = b"x".to_vec();
    let bytes = build(&[ExtraSection {
        id: 16,
        kind: bgpkit_snap::KIND_PAYLOAD,
        required: true,
        bytes: &payload,
    }]);
    let snap: Snapshot<N> = Snapshot::from_bytes_with(&bytes, &Knows).expect("open");
    assert_eq!(snap.section_bytes(16), Some(payload.as_slice()));
}

#[test]
fn the_family_tag_stops_a_cross_family_read() {
    let mut bytes = build(&[]);
    // rewrite the first table entry's kind from V4 to V6
    let entry = 192;
    bytes[entry + 2..entry + 6].copy_from_slice(&bgpkit_snap::KIND_V6);
    // keep the identity consistent so the kind check is the one that fires
    let h = Header::parse(&bytes[..192]).unwrap();
    let mut fixed = bytes.clone();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bgpkit-snap-v4\0");
    hasher.update(&fixed[..148]);
    hasher.update(&fixed[192..192 + h.section_table_len as usize]);
    let table_end = 192 + h.section_table_len as usize;
    let mut cursor = table_end;
    for i in 0..h.section_count as usize {
        let off = 192 + i * 64 + 8;
        let len = u64::from_le_bytes(fixed[off..off + 8].try_into().unwrap()) as usize;
        while !cursor.is_multiple_of(16) {
            cursor += 1;
        }
        hasher.update(&fixed[cursor..cursor + len]);
        cursor += len;
    }
    fixed[156..188].copy_from_slice(hasher.finalize().as_bytes());
    // repair the header crc so the crc check does not fire first
    let crc = crc32c::crc32c(&fixed[..188]);
    fixed[188..192].copy_from_slice(&crc.to_le_bytes());

    let err = Snapshot::<N>::from_bytes(&fixed).unwrap_err();
    assert!(format!("{err}").contains("kind"), "{err}");
}
