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
    std::fs::create_dir_all(&d).ok();
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
            Journal::open_with_payload(&d, a, PayloadSection::payload(SECTION)).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.sync().unwrap();
    }
    let j: Journal<V> = Journal::open_with_payload(&d, a, PayloadSection::payload(SECTION))
        .expect("the same name reopens its own journal");
    assert_eq!(j.len(), 1);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_journal_cannot_adopt_another_trees_directory() {
    let d = dir("wrong-tree");
    {
        let mut j: Journal<V> = Journal::open_with_payload(
            &d,
            TreeId::from_name("first"),
            PayloadSection::payload(SECTION),
        )
        .unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.checkpoint(&Opts::now()).unwrap();
    }
    let err = match Journal::<V>::open_with_payload(
        &d,
        TreeId::from_name("second"),
        PayloadSection::payload(SECTION),
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
    let mut j: Journal<V> = Journal::open_with_payload(
        &d,
        TreeId::from_name("tobytes"),
        PayloadSection::payload(SECTION),
    )
    .unwrap();
    j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
    j.insert("10.1.0.0/16".parse().unwrap(), V(2)).unwrap();
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

#[test]
fn a_query_prefix_with_host_bits_answers_for_its_network_address() {
    let d = dir("children-canon");
    let path = d.join("o.snap");
    let mut w: Writer<V> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
    w.insert("10.1.0.0/16".parse().unwrap(), V(2)).unwrap();
    w.insert("10.1.2.0/24".parse().unwrap(), V(3)).unwrap();
    w.finish_to(&path, &Opts::now()).unwrap();
    let snap: Snapshot<V> = Snapshot::open(&path).unwrap();

    let keys: Vec<String> = snap
        .children("10.1.2.3/16".parse().unwrap())
        .into_iter()
        .map(|(p, _)| p.to_string())
        .collect();
    assert_eq!(
        keys,
        vec!["10.1.0.0/16".to_string(), "10.1.2.0/24".to_string()],
        "the query is read as its network address and every key is a stored key"
    );
    let owned: Vec<String> = snap
        .owned()
        .children("10.1.2.3/16".parse().unwrap())
        .unwrap()
        .into_iter()
        .map(|(p, _)| p.to_string())
        .collect();
    assert_eq!(owned, keys, "both views answer the same way");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_value_whose_deserialize_refuses_is_an_error_not_a_miss() {
    use bgpkit_snap::rkyv;

    // rkyv allows a Deserialize that refuses; the owned view must not turn that into
    // "no such prefix", which would make len() disagree with iter()
    #[derive(Clone, rkyv::Archive, rkyv::Serialize)]
    struct F(u32);
    impl SnapValue for F {
        const TYPE_ID: &str = "ergonomics.fallible:v1";
    }
    impl rkyv::Deserialize<F, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>> for ArchivedF {
        fn deserialize(
            &self,
            _d: &mut rkyv::api::high::HighDeserializer<rkyv::rancor::Error>,
        ) -> Result<F, rkyv::rancor::Error> {
            Err(rkyv::rancor::Source::new(std::io::Error::other("refused")))
        }
    }

    let d = dir("fallible");
    let path = d.join("o.snap");
    let mut w: Writer<F> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), F(1)).unwrap();
    w.finish_to(&path, &Opts::now()).unwrap();
    let snap: Snapshot<F> = Snapshot::open(&path).unwrap();
    assert!(
        snap.get_exact("10.0.0.0/8".parse().unwrap()).is_some(),
        "the archived view still answers"
    );
    assert!(
        snap.owned()
            .get_exact("10.0.0.0/8".parse().unwrap())
            .is_err(),
        "the owned view reports the value it could not build"
    );
    assert_eq!(snap.owned().len(), 1);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_zero_generation_is_refused_rather_than_breaking_every_checkpoint() {
    let d = dir("zero-generation");
    let err = match Journal::<V>::options(&d, TreeId::from_name("zero-gen"))
        .generation([0u8; 16])
        .open()
    {
        Ok(_) => panic!("a zero generation cannot be committed"),
        Err(e) => e,
    };
    assert!(format!("{err}").contains("generation"), "got {err}");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_checkpoint_that_holds_an_undecodable_value_is_refused_before_the_commit() {
    use bgpkit_snap::rkyv;

    // the journal decodes every value when it reopens, so committing a value its own
    // type cannot decode would make the directory unopenable for good
    #[derive(Clone, rkyv::Archive, rkyv::Serialize)]
    struct F(u32);
    impl SnapValue for F {
        const TYPE_ID: &str = "ergo.ckp-refuses:v1";
    }
    impl rkyv::Deserialize<F, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>> for ArchivedF {
        fn deserialize(
            &self,
            _d: &mut rkyv::api::high::HighDeserializer<rkyv::rancor::Error>,
        ) -> Result<F, rkyv::rancor::Error> {
            Err(rkyv::rancor::Source::new(std::io::Error::other("refused")))
        }
    }

    let d = dir("checkpoint-refuses");
    let mut j: Journal<F> = Journal::open(&d, TreeId::from_name("undecodable")).unwrap();
    j.insert("10.0.0.0/8".parse().unwrap(), F(1)).unwrap();
    let err = j
        .checkpoint(&Opts::now())
        .expect_err("an object no reader can open must not be committed");
    assert!(
        format!("{err}").to_lowercase().contains("value"),
        "got {err}"
    );
    let state = std::fs::read_to_string(d.join("state.json")).unwrap_or_default();
    assert!(
        !state.contains("checkpoint"),
        "nothing was committed: {state}"
    );
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_journal_refuses_a_value_type_or_payload_other_than_its_own() {
    let d = dir("config-mismatch");
    let tree = TreeId::from_name("config-mismatch");
    {
        let mut j: Journal<V> =
            Journal::open_with_payload(&d, tree, PayloadSection::payload(16)).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.sync().unwrap();
    }
    let err = match Journal::<V>::open_with_payload(&d, tree, PayloadSection::payload(17)) {
        Ok(_) => panic!("another payload id must not adopt the directory"),
        Err(e) => e,
    };
    assert!(format!("{err}").contains("payload section 16"), "got {err}");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn repair_refuses_a_directory_that_still_has_its_state_file() {
    let d = dir("repair-live-state");
    let tree = TreeId::from_name("repair-live");
    {
        let mut j: Journal<V> = Journal::open(&d, tree).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.checkpoint(&Opts::now()).unwrap();
    }
    let err = match Journal::<V>::repair(&d, tree, None) {
        Ok(_) => panic!("repair must not rewrite a live state file"),
        Err(e) => e,
    };
    assert!(format!("{err}").contains("state.json exists"), "got {err}");
    std::fs::remove_dir_all(&d).ok();
}
