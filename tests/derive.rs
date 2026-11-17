//! `#[derive(SnapValue)]`: the value type a caller writes without the boilerplate.
#![cfg(feature = "derive")]

use bgpkit_snap::{snap_value, Opts, SnapValue, Snapshot, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, SnapValue)]
#[snap(type_id = "test.peer-count:v1")]
struct PeerCount(u32);

// one attribute: the id is positional and Clone comes from it, the rest is the caller's
#[snap_value("test.one-attribute:v1", canonicalize = sort)]
#[derive(Debug, PartialEq)]
struct OneAttribute(Vec<u32>);

fn sort(v: &mut OneAttribute) {
    v.0.sort_unstable();
}

#[test]
fn one_attribute_makes_a_value_type() {
    assert_eq!(OneAttribute::TYPE_ID, "test.one-attribute:v1");
    let mut w: Writer<OneAttribute> = Writer::new();
    // out of order going in, canonical coming out
    w.insert("10.0.0.0/8".parse().unwrap(), OneAttribute(vec![9, 3, 7]))
        .unwrap();
    let bytes = w.finish(&Opts::now()).unwrap();
    let snap: Snapshot<OneAttribute> = Snapshot::from_bytes(&bytes).unwrap();
    let hit = snap.owned().search("10.1.2.3".parse().unwrap()).unwrap();
    assert_eq!(hit.unwrap().1, OneAttribute(vec![3, 7, 9]));
}

#[test]
fn a_derived_value_type_writes_and_reads_back() {
    assert_eq!(PeerCount::TYPE_ID, "test.peer-count:v1");

    let d = std::env::temp_dir().join(format!("snap-derive-{}", std::process::id()));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(&d).unwrap();
    let path = d.join("peers.snap");

    let mut w: Writer<PeerCount> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), PeerCount(3))
        .unwrap();
    w.finish_to(&path, &Opts::now()).unwrap();

    let snap: Snapshot<PeerCount> = Snapshot::open(&path).unwrap();
    assert_eq!(snap.len(), 1);
    // the owned view hands back the derived type itself, not the archived form
    let hit = snap.owned().search("10.1.2.3".parse().unwrap()).unwrap();
    assert_eq!(hit.unwrap().1 .0, 3);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_derived_type_is_what_the_header_records() {
    // the id the derive writes is the id a reader compares, so a second type with
    // another id must not adopt the object
    #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, SnapValue)]
    #[snap(type_id = "test.other:v1")]
    struct Other(u32);

    let d = std::env::temp_dir().join(format!("snap-derive-id-{}", std::process::id()));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(&d).unwrap();
    let path = d.join("peers.snap");

    let mut w: Writer<PeerCount> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), PeerCount(3))
        .unwrap();
    w.finish_to(&path, &Opts::now()).unwrap();

    let err = Snapshot::<Other>::open(&path).expect_err("another type must not open it");
    assert!(format!("{err}").contains("test.peer-count:v1"), "got {err}");
    std::fs::remove_dir_all(&d).ok();
}
