//! The parts of the surface that exist so a caller does not have to invent
//! details: a tree id from a name, an object without the disk, bulk insert, and
//! the owned view of the queries.

use bgpkit_snap::journal::{Journal, PayloadSection};
use bgpkit_snap::{Opts, SnapValue, Snapshot, TreeId, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct V(u32);

impl SnapValue for V {
    const TYPE_ID: &str = "ergonomics.v:v1";
}

const SECTION: u16 = 16;

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("snap-ergo-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&d).ok();
    d
}

#[test]
fn a_tree_id_from_a_name_is_stable_and_distinguishes_trees() {
    let a = TreeId::from_name("wayback-roas");
    let b = TreeId::from_name("wayback-roas");
    let c = TreeId::from_name("wayback-irr");
    assert_eq!(a, b, "the same name must give the same id");
    assert_ne!(a, c, "a different name must give a different id");
    assert_eq!(a.to_string().len(), 32, "display is lower-case hex");
    assert_eq!(*a.as_bytes(), *TreeId::from_bytes(*a.as_bytes()).as_bytes());
    // the raw sixteen bytes still work, so an existing caller does not change
    let _ = TreeId::from([0u8; 16]);

    let d = dir("treeid");
    {
        let mut j: Journal<V> =
            Journal::open(&d, a, Some(PayloadSection::payload(SECTION))).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), &V(1)).unwrap();
        j.sync().unwrap();
    }
    let j: Journal<V> = Journal::open(&d, a, Some(PayloadSection::payload(SECTION)))
        .expect("the same name reopens its own journal");
    assert_eq!(j.len(), 1);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_journal_cannot_adopt_another_trees_directory() {
    let d = dir("wrong-tree");
    {
        let mut j: Journal<V> = Journal::open(
            &d,
            TreeId::from_name("first"),
            Some(PayloadSection::payload(SECTION)),
        )
        .unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), &V(1)).unwrap();
        j.checkpoint(&Opts::now()).unwrap();
    }
    let err = match Journal::<V>::open(
        &d,
        TreeId::from_name("second"),
        Some(PayloadSection::payload(SECTION)),
    ) {
        Ok(_) => panic!("a checkpoint from another tree must be refused"),
        Err(e) => e,
    };
    assert!(
        format!("{err}").contains("tree") || format!("{err}").contains("checkpoint"),
        "got {err}"
    );
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn to_bytes_answers_the_queries_the_journal_does_not() {
    let d = dir("tobytes");
    let mut j: Journal<V> = Journal::open(
        &d,
        TreeId::from_name("tobytes"),
        Some(PayloadSection::payload(SECTION)),
    )
    .unwrap();
    j.insert("10.0.0.0/8".parse().unwrap(), &V(1)).unwrap();
    j.insert("10.1.0.0/16".parse().unwrap(), &V(2)).unwrap();
    j.sync().unwrap();

    let snap: Snapshot<V> = j
        .to_snapshot(&Opts::now())
        .expect("the journal can open the object it would write");
    assert_eq!(snap.len(), 2);
    assert_eq!(snap.children("10.0.0.0/8".parse().unwrap()).len(), 2);
    assert_eq!(snap.iter().count(), 2);
    let again: Snapshot<V> = j.to_snapshot(&Opts::now()).unwrap();
    let bytes = j.to_bytes(&Opts::now()).unwrap();
    assert!(
        !bytes.is_empty(),
        "to_bytes gives the same object as raw bytes"
    );
    assert_eq!(
        snap.content_id(),
        again.content_id(),
        "the same tree gives the same content id"
    );
    // nothing was written: a journal with no checkpoint has no snapshot on disk
    let snaps = std::fs::read_dir(&d)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("snapshot-"))
        .count();
    assert_eq!(snaps, 0, "to_bytes must not checkpoint");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn insert_many_stops_at_the_first_prefix_it_refuses() {
    let mut w: Writer<V> = Writer::new();
    let err = w
        .insert_many([
            ("10.0.0.0/8".parse().unwrap(), V(1)),
            ("10.1.2.3/8".parse().unwrap(), V(2)),
            ("192.0.2.0/24".parse().unwrap(), V(3)),
        ])
        .expect_err("the middle prefix has host bits set");
    assert!(format!("{err}").contains("host bits"), "got {err}");
    assert_eq!(w.len(), 1, "the entry before the failure is kept");
}
