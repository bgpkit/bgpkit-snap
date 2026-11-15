//! The golden object: the same input must produce the same bytes forever.
//!
//! This is the alarm for a dependency bump that changes the archived layout of
//! `prefix-trie` or `rkyv`. A failure here means the format changed under us.

use bgpkit_snap::{Header, Opts, SnapValue, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct V(u32);

impl SnapValue for V {
    const TYPE_ID: &str = "golden.v:v1";
}

const WANT_LEN: usize = 612;
const WANT_SHA256: &str = "d0ed63727b2d9212492b09f78bb652b9eba754b004815e0c792f1b238a9b9925";
const WANT_CONTENT_ID: &str = "1a808769533d26aca6d24c918e21094e0842cfc7f14ebf270c71f58d1538224f";

fn build() -> Vec<u8> {
    let mut w: Writer<V> = Writer::new();
    for (p, v) in [
        ("10.0.0.0/8", 1u32),
        ("10.1.0.0/16", 2),
        ("192.0.2.0/24", 3),
        ("2001:db8::/32", 4),
    ] {
        w.insert(p.parse().unwrap(), V(v));
    }
    w.finish(&Opts {
        created_at: 1_794_614_400,
        window: Some((1_790_000_000, 1_794_355_200)),
        stream: None,
        extras: &[],
    })
    .unwrap()
}

#[test]
fn golden_bytes_are_stable() {
    let bytes = build();
    assert_eq!(bytes.len(), WANT_LEN, "object length changed");
    let digest = blake3::hash(&bytes).to_hex().to_string();
    assert_eq!(
        digest, WANT_SHA256,
        "object bytes drifted; prefix-trie or rkyv changed its archived layout"
    );
    let id = Header::parse(&bytes[..192]).unwrap().content_id_hex();
    assert_eq!(id, WANT_CONTENT_ID, "content id changed");
}

#[test]
fn insertion_order_does_not_change_the_object() {
    let mut forward: Vec<(&str, u32)> = vec![
        ("10.0.0.0/8", 1),
        ("10.1.0.0/16", 2),
        ("192.0.2.0/24", 3),
        ("2001:db8::/32", 4),
    ];
    let mut backward = forward.clone();
    backward.reverse();

    let make = |items: &mut Vec<(&str, u32)>| {
        let mut w: Writer<V> = Writer::new();
        for (p, v) in items.iter() {
            w.insert(p.parse().unwrap(), V(*v));
        }
        w.finish(&Opts {
            created_at: 1_794_614_400,
            window: Some((1_790_000_000, 1_794_355_200)),
            stream: None,
            extras: &[],
        })
        .unwrap()
    };
    assert_eq!(make(&mut forward), make(&mut backward));
}
