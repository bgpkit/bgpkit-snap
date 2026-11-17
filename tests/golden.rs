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

// Regenerated when the counts section (id 4, 32 bytes plus its padding) was added.
const WANT_LEN: usize = 720;
const WANT_SHA256: &str = "33e9c1e8451674685bc908cf6c9a6a852224ff557d15f94c2e663f5538c28a86";
const WANT_CONTENT_ID: &str = "0cf2460413a20a01943eab441fcf069e9a87b1a734e58483461cf4b178921172";

fn build() -> Vec<u8> {
    let mut w: Writer<V> = Writer::new();
    for (p, v) in [
        ("10.0.0.0/8", 1u32),
        ("10.1.0.0/16", 2),
        ("192.0.2.0/24", 3),
        ("2001:db8::/32", 4),
    ] {
        w.insert(p.parse().unwrap(), V(v))
            .expect("canonical prefix");
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
            w.insert(p.parse().unwrap(), V(*v))
                .expect("canonical prefix");
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
