//! The read API a caller actually reaches for, exercised on one object.
//!
//! These are the prefix_trie operations forwarded by `Snapshot` plus the two
//! conveniences a consumer asked for: a path instead of a `&str`, and owned
//! values instead of archived ones.

use std::path::Path;

use bgpkit_snap::{Opts, SnapValue, Snapshot, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct V(u32);

impl SnapValue for V {
    const TYPE_ID: &str = "test.api:v1";
}

fn build(path: &Path) -> Snapshot<V> {
    let mut w: Writer<V> = Writer::new();
    for (p, v) in [
        ("10.0.0.0/8", 1u32),
        ("10.1.0.0/16", 2),
        ("10.1.2.0/24", 3),
        ("192.0.2.0/24", 4),
        ("2001:db8::/32", 5),
        ("2001:db8:1::/48", 6),
    ] {
        w.insert(p.parse().unwrap(), V(v))
            .expect("canonical prefix");
    }
    let written = w
        .finish_to(path, &Opts::now())
        .expect("finish_to writes the object");
    assert!(written > 0);
    // a path, not a string: this is the whole point of the signature change
    Snapshot::open(path).expect("open takes a Path")
}

#[test]
fn the_prefix_trie_read_api_is_available_without_matching_on_family() {
    let dir = std::env::temp_dir().join(format!("snap-api-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("api.snap");
    let snap = build(&path);

    // exact
    assert_eq!(
        snap.get_exact("10.1.0.0/16".parse().unwrap())
            .map(|v| v.0.to_native()),
        Some(2)
    );
    assert!(snap.get_exact("10.2.0.0/16".parse().unwrap()).is_none());
    assert!(snap.contains_key("192.0.2.0/24".parse().unwrap()));
    assert!(!snap.contains_key("192.0.2.128/25".parse().unwrap()));
    assert_eq!(
        snap.lpm("2001:db8:1::/48".parse().unwrap())
            .map(|(p, v)| (p.to_string(), v.0.to_native())),
        Some(("2001:db8:1::/48".to_string(), 6))
    );

    // longest and least specific covering prefix, key and value together
    assert_eq!(
        snap.lpm("10.1.2.128/25".parse().unwrap())
            .map(|(p, _)| p.to_string()),
        Some("10.1.2.0/24".to_string())
    );
    assert_eq!(
        snap.spm("10.1.2.0/24".parse().unwrap())
            .map(|(p, _)| p.to_string()),
        Some("10.0.0.0/8".to_string())
    );

    // coverage
    assert!(snap.is_covered("10.9.9.0/24".parse().unwrap()));
    assert!(!snap.is_covered("11.0.0.0/8".parse().unwrap()));
    // the aggregate form asks whether the whole range is tiled by entries, which
    // 10.0.0.0/8 plus its two descendants is, and 11.0.0.0/8 is not
    assert!(snap.is_covered_in_aggregate("10.0.0.0/8".parse().unwrap()));
    assert!(!snap.is_covered_in_aggregate("11.0.0.0/8".parse().unwrap()));

    // iteration
    let all: Vec<String> = snap.keys().map(|p| p.to_string()).collect();
    assert_eq!(all.len(), 6, "every key is walked");
    assert!(all.contains(&"2001:db8:1::/48".to_string()));

    let from: Vec<String> = snap
        .iter_from("10.1.0.0/16".parse().unwrap(), true)
        .map(|(p, _)| p.to_string())
        .collect();
    // iter_from walks the trie from that point on, so it starts at the prefix
    // and continues past the subtree; the subtree itself is `children`
    assert_eq!(from.first().map(String::as_str), Some("10.1.0.0/16"));
    assert!(from.contains(&"10.1.2.0/24".to_string()), "{from:?}");

    // the cover of a prefix, which is what "who announced this" needs
    let cover: Vec<String> = snap
        .cover("10.1.2.0/24".parse().unwrap())
        .into_iter()
        .map(|(p, _)| p.to_string())
        .collect();
    assert!(cover.contains(&"10.1.0.0/16".to_string()), "{cover:?}");

    // values, and the address counts
    assert_eq!(snap.values().count(), 6);
    // the /8 plus the disjoint /24: entries are summed with overlaps counted once
    let (v4, v6) = snap.address_counts();
    assert_eq!(v4, Some(16_777_472), "one /8 plus one /24");
    assert_eq!(v6, Some(79_228_162_514_264_337_593_543_950_336));
    let empty = Snapshot::<V>::from_bytes(&build_empty()).unwrap();
    assert_eq!(empty.address_counts(), (None, None));

    // owned values: the same queries, without naming the archived type
    let owned = snap.owned();
    assert_eq!(
        owned.get_exact("10.1.2.0/24".parse().unwrap()).map(|v| v.0),
        Some(3)
    );
    let hit = owned
        .search(std::net::IpAddr::V4("10.1.2.9".parse().unwrap()))
        .expect("10.1.2.9 is inside the tree");
    assert_eq!(
        (hit.0.to_string(), hit.1 .0),
        ("10.1.2.0/24".to_string(), 3)
    );
    // and it covers the queries the old *_owned pair did not
    // the covering entries of 10.1.2.0/24 are the /8, the /16 and itself
    assert_eq!(owned.cover("10.1.2.0/24".parse().unwrap()).len(), 3);
    assert_eq!(owned.children("10.0.0.0/8".parse().unwrap()).len(), 3);
    assert_eq!(owned.iter().count(), 6);
    assert_eq!(owned.len(), 6);

    std::fs::remove_dir_all(&dir).ok();
}

/// An object with no entries at all, for the "no family" case.
fn build_empty() -> Vec<u8> {
    let w: Writer<V> = Writer::new();
    w.finish(&Opts::now()).unwrap()
}
