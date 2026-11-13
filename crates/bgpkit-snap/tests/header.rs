//! Header contract: a single 192-byte read must identify the object, and a
//! spliced or contradictory header must be rejected.

use bgpkit_snap::header::{Header, HeaderInputs, StreamRef};
use bgpkit_snap::{Snapshot, Writer};

fn build(source: &str) -> Vec<u8> {
    let mut w = Writer::<u32>::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 1);
    w.insert("10.1.0.0/16".parse().unwrap(), 2);
    w.insert("2001:db8::/32".parse().unwrap(), 3);
    w.finish("2026-11-12T00:00:00Z", source).unwrap()
}

fn build_stream() -> Vec<u8> {
    let mut w = Writer::<u32>::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 1);
    let stream = StreamRef {
        tree_id: [0xab; 16],
        generation: [0x11; 16],
        base_seq: 4242,
    };
    w.finish_with(
        "2026-11-12T00:00:00Z",
        "test",
        HeaderInputs {
            stream: Some(stream),
            first_event_ts: 1_790_000_000,
            last_event_ts: 1_794_355_200,
        },
    )
    .unwrap()
}

/// The A decision: provenance does not move the id. Same data from two sources
/// must hash identically, or R2 dedup cannot work.
#[test]
fn content_id_ignores_provenance() {
    let a = Snapshot::<u32>::from_bytes(&build("s3://bucket/one.parquet")).unwrap();
    let b = Snapshot::<u32>::from_bytes(&build("local:roas.jsonl")).unwrap();
    assert_eq!(a.content_id(), b.content_id());
    assert_ne!(
        a.meta().pointer("/provenance/sources/0/uri"),
        b.meta().pointer("/provenance/sources/0/uri"),
        "the fixture must actually differ in provenance"
    );
}

/// A 192-byte prefix of the file answers every identity question.
#[test]
fn a_peek_read_identifies_the_object() {
    let raw = build_stream();
    let peek = Header::parse(&raw[..192]).unwrap();
    assert_eq!(peek.count_v4, 1);
    assert_eq!(peek.count_v6, 0);
    assert_eq!(peek.type_id, "snap.u32:v1");
    assert_eq!(peek.tree_id, [0xab; 16]);
    assert_eq!(peek.generation, [0x11; 16]);
    assert_eq!(peek.base_seq, 4242);
    assert_eq!(peek.first_event_ts, 1_790_000_000);
    assert_eq!(peek.last_event_ts, 1_794_355_200);
    assert_eq!(peek.file_len as usize, raw.len());
    assert_eq!(
        peek.content_id_hex(),
        Snapshot::<u32>::from_bytes(&raw).unwrap().content_id()
    );
}

/// Rewriting the header and fixing its CRC is not enough: it must also agree
/// with META, which is what stops a spliced header from describing another
/// object.
#[test]
fn a_spliced_header_is_rejected() {
    let mut raw = build_stream();
    let mut h = Header::parse(&raw).unwrap();
    h.count_v4 = 7; // lie about the entry count, then repair the CRC
    let encoded = h.encode();
    raw[..192].copy_from_slice(&encoded);
    let err = Snapshot::<u32>::from_bytes(&raw).unwrap_err();
    assert!(
        format!("{err}").contains("header disagrees with META"),
        "expected a projection mismatch, got {err}"
    );
}

#[test]
fn a_spliced_timestamp_is_rejected() {
    let mut raw = build_stream();
    let mut h = Header::parse(&raw).unwrap();
    h.last_event_ts += 1;
    raw[..192].copy_from_slice(&h.encode());
    let err = Snapshot::<u32>::from_bytes(&raw).unwrap_err();
    assert!(
        format!("{err}").contains("header disagrees with META"),
        "{err}"
    );
}

#[test]
fn a_bad_header_crc_is_rejected() {
    let mut raw = build("test");
    raw[100] ^= 0xff;
    let err = Snapshot::<u32>::from_bytes(&raw).unwrap_err();
    assert!(matches!(err, bgpkit_snap::Error::BodyHash), "{err}");
}

#[test]
fn the_header_rejects_impossible_windows_and_streams() {
    let base = Header::parse(&build("test")).unwrap();

    let mut no_window = base.clone();
    no_window.flags |= bgpkit_snap::header::FLAG_HAS_EVENTS;
    no_window.first_event_ts = 0;
    assert!(Header::parse(&no_window.encode()).is_err());

    let mut reversed = base.clone();
    reversed.flags |= bgpkit_snap::header::FLAG_HAS_EVENTS;
    reversed.first_event_ts = 10;
    reversed.last_event_ts = 5;
    assert!(Header::parse(&reversed.encode()).is_err());

    let mut stream_without_id = base.clone();
    stream_without_id.flags |= bgpkit_snap::header::FLAG_HAS_STREAM;
    stream_without_id.base_seq = 1;
    assert!(Header::parse(&stream_without_id.encode()).is_err());

    let mut id_without_stream = base;
    id_without_stream.tree_id = [1u8; 16];
    assert!(Header::parse(&id_without_stream.encode()).is_err());
}

#[test]
fn the_type_id_field_is_exactly_bounded() {
    let mut h = Header::parse(&build("test")).unwrap();
    h.type_id = "x".repeat(32);
    // a full 32-byte id is legal: no NUL is required
    let raw = h.encode();
    assert_eq!(Header::parse(&raw).unwrap().type_id.len(), 32);

    // a non-zero padding byte is not
    let mut padded = Header::parse(&build("test")).unwrap();
    padded.type_id = "snap.u32:v1".to_string();
    let mut bytes = padded.encode();
    bytes[80 + 20] = b'z';
    assert!(Header::parse(&bytes).is_err());

    // a zero-length id is not
    let mut empty = Header::parse(&build("test")).unwrap();
    empty.type_id = String::new();
    assert!(Header::parse(&empty.encode()).is_err());
}

/// A stream snapshot must carry the coordinates replay needs: tree, generation,
/// and the last reflected sequence.
#[test]
fn a_stream_snapshot_carries_replay_coordinates() {
    let raw = build_stream();
    let snap = Snapshot::<u32>::from_bytes(&raw).unwrap();
    let h = Header::parse(&raw).unwrap();
    assert_eq!(h.flags & bgpkit_snap::header::FLAG_HAS_STREAM, 1);
    assert_eq!(
        snap.meta()
            .pointer("/projection/stream/base_seq")
            .and_then(|v| v.as_u64()),
        Some(4242)
    );
    assert_eq!(
        snap.meta()
            .pointer("/projection/stream/generation")
            .and_then(|v| v.as_str()),
        Some("11111111111111111111111111111111")
    );
}
