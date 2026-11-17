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
    w.insert("10.0.0.0/8".parse().unwrap(), N(1))
        .expect("canonical prefix");
    w.insert("10.1.0.0/16".parse().unwrap(), N(2))
        .expect("canonical prefix");
    w.insert("2001:db8::/32".parse().unwrap(), N(3))
        .expect("canonical prefix");
    w.finish(&Opts {
        created_at: 1_763_164_800,
        window: Some((1_790_000_000, 1_794_355_200)),
        stream: None,
        extras,
    })
    .expect("build")
}

#[test]
fn every_object_carries_both_family_sections() {
    // the shape of an object must not depend on its contents: a client that walks the
    // tries should never have to ask which families happen to be in this file
    for (name, prefixes) in [
        ("v4 only", vec!["10.0.0.0/8"]),
        ("v6 only", vec!["2001:db8::/32"]),
        ("empty", vec![]),
    ] {
        let mut w: Writer<N> = Writer::new();
        for prefix in &prefixes {
            w.insert(prefix.parse().unwrap(), N(1)).expect("canonical");
        }
        let bytes = w.finish(&Opts::now()).expect("build");
        let snap: Snapshot<N> = Snapshot::from_bytes(&bytes).expect("open");
        assert!(snap.v4().is_some(), "{name}: the IPv4 section is missing");
        assert!(snap.v6().is_some(), "{name}: the IPv6 section is missing");
    }
}

#[test]
fn header_is_self_sufficient() {
    let bytes = build(&[]);
    let h = Header::parse(&bytes[..192]).expect("header");
    assert_eq!(h.type_id_str(), "test.n:v1");
    // the two families in this object, plus the counts section the writer records
    assert_eq!(h.section_count, 3);
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
    // a reader that wants the layout reads 192 + 192 bytes and stops: three sections,
    // 64 bytes a row
    assert_eq!(h.section_table_len, 192);
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
    w.insert("10.0.0.0/8".parse().unwrap(), 1)
        .expect("canonical prefix");
    w.insert("2001:db8::/32".parse().unwrap(), 2)
        .expect("canonical prefix");
    let bytes = w.finish(&Opts::now()).unwrap();

    let header = bgpkit_snap::verify_bytes(&bytes).expect("a good object verifies");
    assert_eq!(header.section_count, 3);

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
    w.insert("10.0.0.0/8".parse().unwrap(), 1)
        .expect("canonical prefix");

    // an epoch, a reversed window and a half-zero stream are all refused at write
    let stamp = 1_794_614_400;
    let cases: [Opts; 3] = [
        Opts {
            created_at: 0,
            ..Opts::now()
        },
        Opts {
            created_at: stamp,
            window: Some((2_000, 1_000)),
            ..Opts::now()
        },
        Opts {
            created_at: stamp,
            stream: Some(bgpkit_snap::StreamRef {
                tree_id: [0u8; 16],
                generation: [7u8; 16],
                base_seq: 0,
            }),
            ..Opts::now()
        },
    ];
    for opts in &cases {
        let mut writer: Writer<u32> = Writer::new();
        writer
            .insert("10.0.0.0/8".parse().unwrap(), 1)
            .expect("canonical prefix");
        assert!(
            writer.finish(opts).is_err(),
            "finish accepted a header the reader rejects"
        );
    }
}

#[test]
fn a_family_kind_at_the_wrong_id_is_refused_not_ignored() {
    let mut w: Writer<u32> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 7)
        .expect("canonical prefix");
    let bytes = w.finish(&Opts::now()).unwrap();

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
    w.insert("10.0.0.0/8".parse().unwrap(), 1)
        .expect("canonical prefix");
    let arena = [0u8; 8];
    let err = w
        .finish(&Opts {
            created_at: 1_763_164_800,
            extras: &[ExtraSection {
                id: 16,
                kind: header::KIND_V4,
                required: false,
                bytes: &arena,
            }],
            ..Opts {
                created_at: 1_763_164_800,
                ..Opts::now()
            }
        })
        .unwrap_err();
    assert!(format!("{err}").contains("family"), "got {err}");
}

#[test]
fn nonzero_padding_is_refused() {
    let mut w: Writer<u32> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 1)
        .expect("canonical prefix");
    let arena = [0u8; 5]; // 5 bytes, so the next section needs 11 bytes of padding
    let bytes = w
        .finish(&Opts {
            created_at: 1_763_164_800,
            extras: &[ExtraSection {
                id: 16,
                kind: bgpkit_snap::KIND_PAYLOAD,
                required: false,
                bytes: &arena,
            }],
            ..Opts {
                created_at: 1_763_164_800,
                ..Opts::now()
            }
        })
        .unwrap();

    let count = u32::from_le_bytes(bytes[92..96].try_into().unwrap()) as usize;
    let mut off = header::HEADER_LEN + count * header::ENTRY_LEN;
    let mut pad = None;
    for i in 0..count {
        let aligned = (off + 15) & !15;
        if aligned > off {
            pad = Some(off);
            break;
        }
        let pos = header::HEADER_LEN + i * header::ENTRY_LEN + 8;
        let len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize;
        off = aligned + len;
    }
    let pad = pad.expect("this object has padding");

    // flipping padding without touching the content id must fail, and so must a
    // recomputed id: the spec says those bytes are zero
    let mut flipped = bytes.clone();
    flipped[pad] = 1;
    assert!(Snapshot::<u32>::from_bytes(&flipped).is_err());

    let mut forged = flipped.clone();
    let mut h = blake3::Hasher::new();
    h.update(b"bgpkit-snap-v4\0");
    h.update(&forged[..header::HASH_END]);
    h.update(&forged[header::HEADER_LEN..header::HEADER_LEN + count * header::ENTRY_LEN]);
    h.update(&forged[header::HEADER_LEN + count * header::ENTRY_LEN..]);
    forged[156..188].copy_from_slice(h.finalize().as_bytes());
    let crc = crc32c::crc32c(&forged[..188]);
    forged[188..192].copy_from_slice(&crc.to_le_bytes());
    assert!(
        bgpkit_snap::verify_bytes(&forged).is_err(),
        "nonzero padding must be refused even with a matching id"
    );
}

#[test]
fn bytes_the_document_fixes_to_zero_are_checked() {
    let mut w: Writer<u32> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 1)
        .expect("canonical prefix");
    let bytes = w.finish(&Opts::now()).unwrap();

    // type_id padding after the terminator
    let mut tail = bytes.clone();
    let end = tail[52..84].iter().position(|b| *b == 0).unwrap() + 52;
    tail[end + 1] = b'x';
    rehash(&mut tail);
    assert!(
        bgpkit_snap::verify_bytes(&tail).is_err(),
        "type id padding must be zero"
    );

    // reserved header block
    let mut reserved = bytes.clone();
    reserved[120] = 1;
    rehash(&mut reserved);
    assert!(bgpkit_snap::verify_bytes(&reserved).is_err());

    // section entry tail
    let mut entry = bytes.clone();
    entry[header::HEADER_LEN + 20] = 1;
    rehash(&mut entry);
    assert!(bgpkit_snap::verify_bytes(&entry).is_err());
}

fn rehash(bytes: &mut [u8]) {
    let count = u32::from_le_bytes(bytes[92..96].try_into().unwrap()) as usize;
    let table_end = header::HEADER_LEN + count * header::ENTRY_LEN;
    let mut h = blake3::Hasher::new();
    h.update(b"bgpkit-snap-v4\0");
    h.update(&bytes[..header::HASH_END]);
    h.update(&bytes[header::HEADER_LEN..table_end]);
    h.update(&bytes[table_end..]);
    bytes[156..188].copy_from_slice(h.finalize().as_bytes());
    let crc = crc32c::crc32c(&bytes[..188]);
    bytes[188..192].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn a_non_canonical_prefix_is_refused_in_every_build() {
    let mut w: Writer<u32> = Writer::new();
    let err = w
        .insert("10.1.2.3/8".parse().unwrap(), 1)
        .expect_err("a prefix with host bits set must not be stored");
    assert!(format!("{err}").contains("host bits"), "got {err}");
    // the canonical form is accepted
    w.insert("10.0.0.0/8".parse().unwrap(), 1).unwrap();
    assert_eq!(w.len(), 1);
}

#[test]
fn a_journal_checkpoint_carries_its_arena_and_nothing_else() {
    use bgpkit_snap::journal::{Journal, PayloadSection};

    let dir = std::env::temp_dir().join(format!("snap-extras-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    // an empty arena still gets a section, so a validator that requires it can open
    // the journal's own object
    let mut j: Journal<u32> = Journal::options(&dir)
        .start([31u8; 16])
        .payload(PayloadSection::payload(16))
        .open()
        .unwrap();
    j.insert("10.0.0.0/8".parse().unwrap(), 1).unwrap();
    let object = j.checkpoint(&Opts::now()).expect("checkpoint");

    let raw = std::fs::read(&object).unwrap();
    let header = Header::parse(&raw[..192]).unwrap();
    assert_eq!(
        header.section_count, 4,
        "both family sections, the records' counts, and the arena; nothing else"
    );
    let snap: Snapshot<u32> = Snapshot::from_bytes_with(&raw, &{
        struct Knows;
        impl Validator for Knows {
            fn knows(&self, entry: &Entry) -> bool {
                entry.id == 16
            }
        }
        Knows
    })
    .unwrap();
    assert_eq!(
        snap.section_bytes(16),
        Some(&[][..]),
        "an empty arena is still a section"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_crafted_object_cannot_walk_off_the_end_of_its_padding() {
    use bgpkit_snap::header::{Entry, Header, ENTRY_LEN, HEADER_LEN};
    use bgpkit_snap::ID_V4;

    // two sections, the last one ending one byte past the header and table, so the
    // alignment walk would index the byte after the file. This used to panic.
    let mut bytes = Vec::new();
    let mut type_id = [0u8; 32];
    type_id[.."snap.u64:v1".len()].copy_from_slice(b"snap.u64:v1");
    let header = Header {
        flags: 0,
        tree_id: [0u8; 16],
        generation: [0u8; 16],
        base_seq: 0,
        type_id,
        file_len: (HEADER_LEN + 2 * ENTRY_LEN + 1) as u64,
        section_count: 2,
        section_table_len: (2 * ENTRY_LEN) as u32,
        window: [0, 0],
        created_at: 1_700_000_000,
        content_id: [7u8; 32],
    };
    bytes.extend_from_slice(&header.encode());
    let first = Entry {
        id: ID_V4,
        kind: *b"V4\0\0",
        required: true,
        len: 1,
    };
    let second = Entry {
        id: 3,
        kind: *b"V6\0\0",
        required: true,
        len: 0,
    };
    bytes.extend_from_slice(&first.encode());
    bytes.extend_from_slice(&second.encode());
    bytes.push(0);

    assert!(
        bgpkit_snap::verify_bytes(&bytes).is_err(),
        "a crafted layout must be refused, not walked past"
    );
    assert!(Snapshot::<u64>::from_bytes(&bytes).is_err());
}
