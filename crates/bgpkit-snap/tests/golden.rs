//! The golden fixture: the same input must produce the same bytes forever.
//! This is the alarm that fires if prefix-trie or rkyv ever change their
//! archived layout.

use bgpkit_snap::{Snapshot, Writer};
use ipnet::IpNet;

const CREATED: &str = "2026-11-12T00:00:00Z";
const EXPECTED_CONTENT_ID: &str =
    "9ae07d1d2078d6b2d0387b8c8d9ccd45badb65233878862e989db89789b29c79";

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("testdata")
}

#[test]
fn golden_bytes_are_stable() {
    let input = std::fs::read_to_string(root().join("fixture.jsonl")).unwrap();
    let mut w: Writer<u32> = Writer::new();
    for line in input.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let p: IpNet = v["prefix"].as_str().unwrap().parse().unwrap();
        w.insert(p, v["value"].as_u64().unwrap() as u32);
    }
    let bytes = w.finish(CREATED, "testdata/fixture.jsonl").unwrap();
    let golden = std::fs::read(root().join("v4v6-u32.snap")).unwrap();
    assert_eq!(
        bytes, golden,
        "archive bytes drifted from the checked-in fixture; \
         prefix-trie or rkyv changed its archived layout"
    );
    let s: Snapshot<u32> = Snapshot::from_bytes(&golden).unwrap();
    assert_eq!(s.content_id(), EXPECTED_CONTENT_ID);
    assert_eq!(s.len(), 180);
}
