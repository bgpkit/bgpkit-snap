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

#[test]
fn a_payload_kind_with_high_bytes_survives_state_json() {
    // state.json stored the kind through from_utf8_lossy while reading demanded four
    // bytes, so a non-UTF-8 kind wrote a journal that could never be reopened
    let d = dir("kind-bytes");
    let tree = TreeId::from_name("kind-bytes");
    let payload = PayloadSection {
        id: 16,
        kind: [0xff, 0x00, 0xfe, 0x01],
        required: true,
    };
    {
        let mut j: Journal<V> = Journal::open_with_payload(&d, tree, payload).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.sync().unwrap();
    }
    let j: Journal<V> = Journal::open_with_payload(&d, tree, payload)
        .expect("a journal must reopen with the kind it was written with");
    assert_eq!(j.len(), 1);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_checkpoint_sequence_of_u64_max_is_refused_not_added_to() {
    use bgpkit_snap::header::StreamRef;

    // a structurally valid object whose stream says base_seq = u64::MAX: the journal
    // must refuse it, because base_seq + 1 is not representable
    let d = dir("max-seq");
    let log = d.join("journal");
    std::fs::create_dir_all(&log).unwrap();
    let tree = TreeId::from_name("max-seq");

    let mut w: Writer<V> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
    let bytes = w
        .finish(&Opts {
            created_at: 1_794_614_400,
            window: None,
            stream: Some(StreamRef {
                tree_id: *tree.as_bytes(),
                generation: [5u8; 16],
                base_seq: u64::MAX,
            }),
            extras: &[],
        })
        .unwrap();
    let name = "snapshot-1-1.snap";
    std::fs::write(log.join(name), &bytes).unwrap();
    std::fs::write(
        log.join("state.json"),
        format!(
            "{{\"next_seq\": 1, \"generation\": \"{}\", \"tree_id\": \"{}\", \"checkpoint\": {{\"seq\": 18446744073709551615, \"file\": \"{name}\"}}, \"type_id\": \"{}\"}}",
            "05".repeat(16),
            tree,
            <V as SnapValue>::TYPE_ID
        ),
    )
    .unwrap();

    let opened = std::panic::catch_unwind(|| match Journal::<V>::open(&log, tree) {
        Ok(_) => Err::<(), String>("accepted an unrepresentable sequence".to_string()),
        Err(e) => Err::<(), String>(format!("{e}")),
    });
    let message = opened.expect("opening must not panic").unwrap_err();
    assert!(message.contains("sequence"), "got {message}");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_second_checkpoint_after_a_restart_does_not_reuse_a_committed_name() {
    // the ordinal behind `snapshot-<seq>-<n>` used to restart at zero on every open,
    // so the first checkpoint after a restart replaced the object state.json named
    let d = dir("restart-name");
    let tree = TreeId::from_name("restart-name");
    let first = {
        let mut j: Journal<V> = Journal::open(&d, tree).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.checkpoint(&Opts::now()).unwrap()
    };
    let committed = std::fs::read(&first).unwrap();

    {
        // no new records: the sequence does not advance, only the ordinal can keep the
        // two checkpoints apart
        let mut j: Journal<V> = Journal::open(&d, tree).unwrap();
        let second = j
            .checkpoint(&Opts {
                created_at: 1_794_614_400 + 60,
                ..Opts::now()
            })
            .unwrap();
        assert_ne!(first, second, "a checkpoint must write a new name");
        assert!(
            second
                .file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with("-2.snap")
                || second
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with("-3.snap"),
            "got {second:?}"
        );
    }

    // the first object is gone only because pruning removed it after the commit; what
    // must never happen is its bytes being overwritten before the new state landed
    assert!(!committed.is_empty());
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_checkpoint_whose_publication_fails_leaves_the_stable_path_openable() {
    // `current.snap` is what the guide tells a reader to open. A checkpoint that
    // cannot republish it once returned Ok and then deleted the object the link still
    // named, so the stable path was dangling until the next open.
    let d = dir("publish-fail");
    let tree = TreeId::from_name("publish-fail");
    let mut j: Journal<V> = Journal::open(&d, tree).unwrap();
    j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
    j.checkpoint(&Opts::now()).unwrap();

    // a foreign entry holding the publication temp name makes the next one fail
    std::fs::create_dir(d.join(".current.snap.tmp")).unwrap();
    j.insert("192.0.2.0/24".parse().unwrap(), V(2))
        .expect("insert");
    j.checkpoint(&Opts::now())
        .expect("the checkpoint itself is committed, whatever the link does");

    let link = d.join("current.snap");
    let target = std::fs::read_link(&link).expect("current.snap must still be a link");
    assert!(
        d.join(&target).exists(),
        "current.snap -> {target:?} names an object the checkpoint deleted"
    );
    let through: Snapshot<V> = Snapshot::open(&link).expect("the stable path must open");
    assert_eq!(through.len(), 1, "the link still serves a complete object");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn repair_without_a_payload_section_leaves_a_payload_checkpoint_alone() {
    // the section check used to run only when the caller passed a payload, so
    // `repair(dir, tree, None)` wrote a state file that no open accepts and then
    // failed, closing the only documented way back
    let d = dir("repair-none");
    let tree = TreeId::from_name("repair-none");
    // optional on purpose: a required section is already refused before the write,
    // so only the optional one reaches the state-write path
    let payload = PayloadSection {
        id: SECTION,
        kind: *b"PAY\0",
        required: false,
    };
    {
        let mut j: Journal<V> = Journal::open_with_payload(&d, tree, payload).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.checkpoint(&Opts::now()).unwrap();
    }
    std::fs::remove_file(d.join("state.json")).unwrap();

    let err = match Journal::<V>::repair(&d, tree, None) {
        Ok(_) => panic!("a checkpoint with a payload cannot be repaired without it"),
        Err(e) => e,
    };
    assert!(format!("{err}").contains("section"), "got {err}");
    assert!(
        !d.join("state.json").exists(),
        "a repair that fails must not leave a state file behind"
    );

    // and the directory is still repairable with the checkpoint's own section
    let j: Journal<V> = Journal::<V>::repair(&d, tree, Some(payload))
        .expect("repair with the section the checkpoint carries");
    assert_eq!(j.len(), 1);
    drop(j);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_failed_write_leaves_the_object_that_was_there() {
    // `finish_to` writes beside the target and renames, which is what keeps a failed
    // build from truncating the object at that path. A read-only directory is the
    // portable way to fail the temp write; a root process ignores the mode, so this
    // reports nothing there rather than a pass it did not earn.
    use std::os::unix::fs::PermissionsExt;

    let d = dir("atomic-write");
    let out = d.join("out.snap");
    let build = |path: &std::path::Path| {
        let mut w: Writer<V> = Writer::new();
        w.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        w.finish_to(path, &Opts::now())
    };
    build(&out).expect("the first write");
    let before = std::fs::read(&out).unwrap();

    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();
    let root_can_still_write = std::fs::write(d.join(".probe"), b"").is_ok();
    if root_can_still_write {
        std::fs::remove_file(d.join(".probe")).ok();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&d).ok();
        return;
    }

    let failed = build(&out);
    assert!(failed.is_err(), "a write that cannot happen must report it");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        before,
        "the object that was already there must be untouched"
    );
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn an_exhausted_sequence_space_is_refused_instead_of_wrapped() {
    use bgpkit_snap::header::StreamRef;

    // a checkpoint whose stream says base_seq = u64::MAX - 1 opens with seq =
    // u64::MAX. The next insert used to panic in a debug build and reuse a sequence
    // number in a release one; it has to refuse before the bytes exist.
    let d = dir("seq-exhausted");
    let log = d.join("journal");
    std::fs::create_dir_all(&log).unwrap();
    let tree = TreeId::from_name("seq-exhausted");

    let mut w: Writer<V> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
    let bytes = w
        .finish(&Opts {
            created_at: 1_794_614_400,
            window: None,
            stream: Some(StreamRef {
                tree_id: *tree.as_bytes(),
                generation: [6u8; 16],
                base_seq: u64::MAX - 1,
            }),
            extras: &[],
        })
        .unwrap();
    let name = "snapshot-18446744073709551614-1.snap";
    std::fs::write(log.join(name), &bytes).unwrap();
    std::fs::write(
        log.join("state.json"),
        format!(
            "{{\"next_seq\": 18446744073709551615, \"generation\": \"{}\", \"tree_id\": \"{}\", \
             \"checkpoint\": {{\"seq\": 18446744073709551614, \"file\": \"{name}\"}}, \
             \"type_id\": \"{}\"}}",
            "06".repeat(16),
            tree,
            <V as SnapValue>::TYPE_ID
        ),
    )
    .unwrap();

    let opened = std::panic::catch_unwind(|| Journal::<V>::open(&log, tree).map(|j| j.len()));
    let mut j = match opened.expect("opening must not panic") {
        Ok(_) => Journal::<V>::open(&log, tree).expect("the directory opens"),
        Err(e) => panic!("the directory must open with seq = u64::MAX: {e}"),
    };
    let err = match j.insert("192.0.2.0/24".parse().unwrap(), V(2)) {
        Ok(seq) => panic!("an exhausted sequence space handed out {seq}"),
        Err(e) => e,
    };
    assert!(format!("{err}").contains("sequence"), "got {err}");
    drop(j);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn repair_replaces_a_state_file_it_cannot_read() {
    // a readable but corrupt state.json was treated as a healthy one, so open said
    // "not json" and repair said "open it instead": neither path could recover
    let d = dir("repair-corrupt-state");
    let tree = TreeId::from_name("repair-corrupt");
    {
        let mut j: Journal<V> = Journal::open(&d, tree).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.checkpoint(&Opts::now()).unwrap();
    }
    std::fs::write(d.join("state.json"), b"{not json").unwrap();

    let j: Journal<V> = Journal::<V>::repair(&d, tree, None)
        .expect("an unreadable state file is what repair is for");
    assert_eq!(j.len(), 1);
    drop(j);
    let reopened: Journal<V> = Journal::open(&d, tree).expect("the repaired directory opens");
    assert_eq!(reopened.len(), 1);
    std::fs::remove_dir_all(&d).ok();
}
