//! A second trie in one object, with its own value type.

use bgpkit_snap::profile::TrieSection;
use bgpkit_snap::{snap_value, ExtraSection, Opts, Snapshot, Writer};

#[snap_value("test.origin:v1")]
#[derive(Debug, PartialEq)]
struct Origin(u32);

#[snap_value("test.first-seen:v1")]
#[derive(Debug, PartialEq)]
struct FirstSeen(u64);

fn build(with_side: bool) -> Vec<u8> {
    let mut w: Writer<Origin> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), Origin(64512))
        .unwrap();
    w.insert("192.0.2.0/24".parse().unwrap(), Origin(64513))
        .unwrap();

    let mut side = TrieSection::<FirstSeen>::new();
    side.insert("10.0.0.0/8".parse().unwrap(), FirstSeen(1_763_164_800))
        .unwrap();
    side.insert("10.1.0.0/16".parse().unwrap(), FirstSeen(1_763_165_000))
        .unwrap();
    side.insert("2001:db8::/32".parse().unwrap(), FirstSeen(1_763_166_000))
        .unwrap();
    let body = side.to_bytes().unwrap();

    let extras: Vec<ExtraSection> = if with_side {
        vec![ExtraSection {
            id: 16,
            kind: *b"SEEN",
            required: false,
            bytes: &body,
        }]
    } else {
        Vec::new()
    };
    w.finish(&Opts {
        created_at: 1_763_164_800,
        stream: None,
        window: None,
        extras: &extras,
    })
    .unwrap()
}

#[test]
fn a_second_trie_with_its_own_value_type_is_queryable() {
    let bytes = build(true);
    let snap: Snapshot<Origin> = Snapshot::from_bytes(&bytes).unwrap();

    let side = snap
        .section_trie::<FirstSeen>(16)
        .expect("the section is a trie")
        .expect("the section exists");
    assert_eq!(side.len(), 3);

    // longest-prefix match inside the second trie
    let (prefix, seen) = side.lpm("10.1.2.3/32".parse().unwrap()).unwrap();
    assert_eq!(prefix, "10.1.0.0/16".parse::<ipnet::IpNet>().unwrap());
    assert_eq!(seen, FirstSeen(1_763_165_000));

    // and IPv6 in the same section
    let (prefix, seen) = side.lpm("2001:db8::1/128".parse().unwrap()).unwrap();
    assert_eq!(prefix, "2001:db8::/32".parse::<ipnet::IpNet>().unwrap());
    assert_eq!(seen, FirstSeen(1_763_166_000));

    // the main trie still answers with its own type
    let main = snap.lpm("10.1.2.3/32".parse().unwrap()).unwrap();
    assert_eq!(main.0, "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap());

    // exact lookup, and a miss
    assert_eq!(
        side.get_exact("10.0.0.0/8".parse().unwrap()),
        Some(FirstSeen(1_763_164_800))
    );
    assert_eq!(side.get_exact("172.16.0.0/12".parse().unwrap()), None);
}

#[test]
fn a_section_that_is_not_the_type_asked_for_is_refused() {
    let bytes = build(true);
    let snap: Snapshot<Origin> = Snapshot::from_bytes(&bytes).unwrap();
    // the section holds FirstSeen values, so asking for another type must not be a
    // panic or a reinterpretation of the bytes
    let wrong = snap.section_trie::<Origin>(16);
    assert!(
        wrong.is_err(),
        "a section cannot be read as a type it was not written with"
    );
}

#[test]
fn an_object_without_the_section_reports_none() {
    let bytes = build(false);
    let snap: Snapshot<Origin> = Snapshot::from_bytes(&bytes).unwrap();
    assert!(snap.section_trie::<FirstSeen>(16).unwrap().is_none());
}
