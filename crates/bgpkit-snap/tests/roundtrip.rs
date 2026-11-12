//! Behaviour the format contract promises: round trip, determinism across
//! insertion order, and rejection of every corruption the reader checks.

use bgpkit_snap::{Error, Snapshot, Writer};
use ipnet::IpNet;

const CREATED: &str = "2026-11-12T00:00:00Z";

fn sample() -> Vec<(IpNet, u32)> {
    vec![
        ("0.0.0.0/0".parse().unwrap(), 64496),
        ("10.0.0.0/8".parse().unwrap(), 64500),
        ("10.1.0.0/16".parse().unwrap(), 64501),
        ("192.0.2.0/24".parse().unwrap(), 64502),
        ("203.0.113.0/24".parse().unwrap(), 64503),
        ("2001:db8::/32".parse().unwrap(), 64504),
        ("2001:db8:1::/48".parse().unwrap(), 64505),
    ]
}

fn build(order: &[(IpNet, u32)]) -> Vec<u8> {
    let mut w: Writer<u32> = Writer::new();
    for (p, v) in order {
        w.insert(*p, *v);
    }
    w.finish(CREATED, "test").unwrap()
}

fn built() -> Vec<u8> {
    build(&sample())
}

#[test]
fn roundtrip_keeps_every_entry() {
    let raw = built();
    let s: Snapshot<u32> = Snapshot::from_bytes(&raw).unwrap();
    assert_eq!(s.len(), sample().len());
    for (p, v) in sample() {
        match p {
            IpNet::V4(p4) => {
                let got = s.v4().unwrap().get(&p4).expect("v4 entry present");
                assert_eq!(got.to_native(), v, "{p}");
            }
            IpNet::V6(p6) => {
                let got = s.v6().unwrap().get(&p6).expect("v6 entry present");
                assert_eq!(got.to_native(), v, "{p}");
            }
        }
    }
}

#[test]
fn lpm_picks_the_longest_match() {
    let raw = built();
    let s: Snapshot<u32> = Snapshot::from_bytes(&raw).unwrap();

    let (p, v) = s.search("10.1.2.3/32".parse().unwrap()).unwrap();
    assert_eq!(p.to_string(), "10.1.0.0/16");
    assert_eq!(v.to_native(), 64501);

    let (p, v) = s.search("10.9.9.9/32".parse().unwrap()).unwrap();
    assert_eq!(p.to_string(), "10.0.0.0/8");
    assert_eq!(v.to_native(), 64500);

    // falls back to the default route
    let (p, v) = s.search("8.8.8.8/32".parse().unwrap()).unwrap();
    assert_eq!(p.to_string(), "0.0.0.0/0");
    assert_eq!(v.to_native(), 64496);

    let (p, _) = s.search("2001:db8:1::1/128".parse().unwrap()).unwrap();
    assert_eq!(p.to_string(), "2001:db8:1::/48");
}

#[test]
fn content_id_is_independent_of_insertion_order() {
    let mut reversed = sample();
    reversed.reverse();
    let mut shuffled = sample();
    shuffled.rotate_left(3);
    assert_eq!(
        built(),
        build(&reversed),
        "reversed order must give identical bytes"
    );
    assert_eq!(
        built(),
        build(&shuffled),
        "rotated order must give identical bytes"
    );

    let a: Snapshot<u32> = Snapshot::from_bytes(&built()).unwrap();
    let b: Snapshot<u32> = Snapshot::from_bytes(&build(&reversed)).unwrap();
    assert_eq!(a.content_id(), b.content_id());
}

#[test]
fn content_id_changes_when_a_value_changes() {
    let mut other = sample();
    other[1].1 = 65000;
    let a: Snapshot<u32> = Snapshot::from_bytes(&built()).unwrap();
    let b: Snapshot<u32> = Snapshot::from_bytes(&build(&other)).unwrap();
    assert_ne!(a.content_id(), b.content_id());
}

#[test]
fn a_flipped_value_byte_is_rejected() {
    let mut raw = built();
    // flip the last byte of the body, which is inside a trie section
    let footer_off = u64::from_le_bytes(raw[24..32].try_into().unwrap()) as usize;
    let target = footer_off - 1;
    raw[target] ^= 0xFF;
    let err = Snapshot::<u32>::from_bytes(&raw).unwrap_err();
    assert!(
        matches!(
            err,
            Error::SectionHash(2) | Error::SectionHash(3) | Error::BodyHash
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn truncation_is_rejected() {
    let raw = built();
    for cut in [1usize, 8, 100] {
        let err = Snapshot::<u32>::from_bytes(&raw[..raw.len() - cut]).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }), "cut {cut}: {err}");
    }
}

#[test]
fn a_misaligned_section_is_rejected() {
    let mut raw = built();
    let footer_off = u64::from_le_bytes(raw[24..32].try_into().unwrap()) as usize;
    // first entry starts at footer_off + 16; its offset field is at +8
    let off_field = footer_off + 16 + 8;
    raw[off_field] = raw[off_field].wrapping_add(8);
    let err = Snapshot::<u32>::from_bytes(&raw).unwrap_err();
    assert!(
        matches!(err, Error::SectionMisaligned(_) | Error::SectionOverlap(_)),
        "unexpected error: {err}"
    );
}

#[test]
fn declaring_the_wrong_value_type_is_rejected() {
    let raw = built();
    let err = Snapshot::<u64>::from_bytes(&raw).unwrap_err();
    assert!(
        matches!(err, Error::TypeMismatch { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn a_single_family_object_is_valid() {
    let only_v4: Vec<(IpNet, u32)> = sample()
        .into_iter()
        .filter(|(p, _)| matches!(p, IpNet::V4(_)))
        .collect();
    let raw = build(&only_v4);
    let s: Snapshot<u32> = Snapshot::from_bytes(&raw).unwrap();
    assert!(s.v4().is_some());
    assert!(s.v6().is_none());
    let families = s.meta().pointer("/families").unwrap().as_array().unwrap();
    assert_eq!(families.len(), 1);
}
