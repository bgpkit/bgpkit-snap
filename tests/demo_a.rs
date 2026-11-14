//! Demo A: the plain case a new user meets first.
//!
//! A value type with an order, an object written to a file, the same file opened
//! and queried, a hit and a miss, and one archived field read back.

use bgpkit_snap::{Opts, SnapValue, Snapshot, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct RoaSet(Vec<u32>);

impl SnapValue for RoaSet {
    const TYPE_ID: &str = "demo.roa-set:v1";

    fn canonicalize(&mut self) {
        self.0.sort_unstable();
        self.0.dedup();
    }
}

fn build(path: &std::path::Path) {
    let mut w: Writer<RoaSet> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), RoaSet(vec![64512, 64513]));
    w.insert("2001:db8::/32".parse().unwrap(), RoaSet(vec![64514]));

    let bytes = w
        .finish(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: Some((1_760_000_000, 1_794_355_200)),
            stream: None,
            extras: &[],
        })
        .expect("build");
    std::fs::write(path, bytes).expect("write");
}

#[test]
fn demo_a_build_write_open_search() {
    let dir = std::env::temp_dir().join(format!("snap-demo-a-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("roa.snap");
    build(&path);

    let snap: Snapshot<RoaSet> = Snapshot::open(path.to_str().unwrap()).expect("open");

    // a hit, with the archived value read back
    let (prefix, value) = snap
        .search("10.1.2.3".parse().unwrap())
        .expect("10.1.2.3 is inside 10.0.0.0/8");
    assert_eq!(prefix.to_string(), "10.0.0.0/8");
    let origins: Vec<u32> = value.0.iter().map(|v| v.to_native()).collect();
    assert_eq!(origins, vec![64512, 64513]);

    // a miss
    assert!(snap.search("192.0.2.1".parse().unwrap()).is_none());

    // a prefix query, not an address
    assert_eq!(
        snap.search_prefix("10.9.0.0/16".parse().unwrap())
            .map(|(p, _)| p.to_string()),
        Some("10.0.0.0/8".into())
    );

    // header-only facts
    assert_eq!(snap.header().type_id_str(), "demo.roa-set:v1");
    assert_eq!(snap.header().window(), Some((1_760_000_000, 1_794_355_200)));
    assert_eq!(snap.header().stream(), None);
    assert_eq!(snap.len(), 2);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn demo_a_rejects_a_different_value_type() {
    let dir = std::env::temp_dir().join(format!("snap-demo-a-type-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("roa.snap");
    build(&path);

    // u32 is a different type id, so opening as the wrong type must fail
    let err = Snapshot::<u32>::open(path.to_str().unwrap()).unwrap_err();
    assert!(format!("{err}").contains("value type"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}
