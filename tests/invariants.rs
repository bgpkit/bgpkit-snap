//! Contract checks that do not depend on any profile.

use bgpkit_snap::{
    header, Entry, ExtraSection, Header, Opts, SnapValue, Snapshot, Validator, Writer,
};

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

#[test]
fn verify_bytes_checks_the_container_without_the_value_type() {
    let mut w: Writer<u32> = crate::Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 1);
    w.insert("2001:db8::/32".parse().unwrap(), 2);
    let bytes = w.finish(&Opts::default()).unwrap();

    let header = bgpkit_snap::verify_bytes(&bytes).expect("a good object verifies");
    assert_eq!(header.section_count, 2);

    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0xff;
    assert!(
        bgpkit_snap::verify_bytes(&flipped).is_err(),
        "a flip must fail"
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        bgpkit_snap::verify_bytes(&trailing).is_err(),
        "trailing bytes must fail"
    );
}

#[test]
fn a_writer_cannot_emit_what_the_reader_rejects() {
    let mut w: Writer<u32> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 1);

    // epoch, reversed window and a half-zero stream are all refused at write
    let cases: [Opts; 3] = [
        Opts {
            created_at: "1970-01-01T00:00:00Z",
            ..Opts::default()
        },
        Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: Some((2_000, 1_000)),
            ..Opts::default()
        },
        Opts {
            created_at: "2026-11-14T00:00:00Z",
            stream: Some(bgpkit_snap::StreamRef {
                tree_id: [0u8; 16],
                generation: [7u8; 16],
                base_seq: 0,
            }),
            ..Opts::default()
        },
    ];
    for opts in &cases {
        let mut writer: Writer<u32> = Writer::new();
        writer.insert("10.0.0.0/8".parse().unwrap(), 1);
        assert!(
            writer.finish(opts).is_err(),
            "finish accepted a header the reader rejects"
        );
    }
}

#[test]
fn a_family_kind_at_the_wrong_id_is_refused_not_ignored() {
    let mut w: Writer<u32> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 7);
    let bytes = w.finish(&Opts::default()).unwrap();

    // the IPv4 section is at id 2; move it to 1 and fix the identity, which is
    // what a writer that never read the table of ids would produce
    let mut forged = bytes.clone();
    forged[header::HEADER_LEN..header::HEADER_LEN + 2].copy_from_slice(&1u16.to_le_bytes());
    let mut h = blake3::Hasher::new();
    h.update(b"bgpkit-snap-v4\0");
    h.update(&forged[..header::HASH_END]);
    let table_end = header::HEADER_LEN + 64;
    h.update(&forged[header::HEADER_LEN..table_end]);
    h.update(&forged[table_end..]);
    forged[156..188].copy_from_slice(h.finalize().as_bytes());
    let crc = crc32c::crc32c(&forged[..188]);
    forged[188..192].copy_from_slice(&crc.to_le_bytes());

    let opened = Snapshot::<u32>::from_bytes(&forged);
    assert!(
        opened.is_err(),
        "an IPv4 section at id 1 must be refused, not silently ignored"
    );
    assert!(bgpkit_snap::verify_bytes(&forged).is_err());
}

#[test]
fn an_extra_section_cannot_claim_a_family_kind() {
    let mut w: Writer<u32> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 1);
    let arena = [0u8; 8];
    let err = w
        .finish(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            extras: &[ExtraSection {
                id: 16,
                kind: header::KIND_V4,
                required: false,
                bytes: &arena,
            }],
            ..Opts::default()
        })
        .unwrap_err();
    assert!(format!("{err}").contains("family"), "got {err}");
}
