//! Demo B: a handle value plus a required payload section.
//!
//! The value is eight bytes pointing into a payload section the client owns. The
//! client registers a validator, checks handle ranges when it resolves, and the
//! journal carries the newly interned bytes so a replay rebuilds the section.

use bgpkit_snap::journal::{Journal, PayloadSection};
use bgpkit_snap::{
    Entry, ExtraSection, Opts, SnapValue, Snapshot, SnapshotView, Validator, KIND_PAYLOAD,
};

const SECTION_ID: u16 = 16;

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PathRef {
    off: u32,
    len: u32,
}

impl SnapValue for PathRef {
    const TYPE_ID: &str = "demo.path-ref:v1";
}

/// Client side: knows what section 16 is and how to check it.
struct Attrs;

impl Attrs {
    fn resolve(snap: &Snapshot<PathRef>, value: &PathRef) -> Result<Vec<u8>, String> {
        let section = snap
            .section_bytes(SECTION_ID)
            .ok_or("object carries no payload section")?;
        let start = value.off as usize;
        let end = start + value.len as usize;
        if end > section.len() {
            return Err(format!(
                "handle {}+{} runs past the section ({} bytes)",
                value.off,
                value.len,
                section.len()
            ));
        }
        Ok(section[start..end].to_vec())
    }
}

impl Validator for Attrs {
    fn knows(&self, entry: &Entry) -> bool {
        entry.id == SECTION_ID && entry.kind == KIND_PAYLOAD
    }

    fn validate(&self, view: &SnapshotView<'_>) -> Result<(), bgpkit_snap::Error> {
        if view.section_bytes(SECTION_ID).is_none() {
            return Err(bgpkit_snap::Error::BadSectionTable(
                "payload section is missing",
            ));
        }
        Ok(())
    }
}

fn attrs(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[test]
fn demo_b_handle_round_trip_and_bad_range() {
    let dir = std::env::temp_dir().join(format!("snap-demo-b-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("rib.snap");

    // the client owns the arena and the offsets
    let a = attrs("AS_PATH 64500 64512");
    let b = attrs("AS_PATH 64501 64513");
    let mut arena = Vec::new();
    let off_a = arena.len() as u32;
    arena.extend_from_slice(&a);
    let off_b = arena.len() as u32;
    arena.extend_from_slice(&b);

    let mut w: bgpkit_snap::Writer<PathRef> = bgpkit_snap::Writer::new();
    w.insert(
        "10.0.0.0/8".parse().unwrap(),
        PathRef {
            off: off_a,
            len: a.len() as u32,
        },
    );
    w.insert(
        "10.1.0.0/16".parse().unwrap(),
        PathRef {
            off: off_b,
            len: b.len() as u32,
        },
    );
    // a deliberately broken handle
    w.insert(
        "10.2.0.0/16".parse().unwrap(),
        PathRef {
            off: 9_000,
            len: 40,
        },
    );

    let bytes = w
        .finish(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[ExtraSection {
                id: SECTION_ID,
                kind: KIND_PAYLOAD,
                required: true,
                bytes: &arena,
            }],
        })
        .expect("build");
    std::fs::write(&path, &bytes).unwrap();

    // without a validator the required section is refused, and the error names it
    let err = Snapshot::<PathRef>::open(path.to_str().unwrap()).unwrap_err();
    assert!(format!("{err}").contains("16"), "{err}");

    let snap: Snapshot<PathRef> =
        Snapshot::open_with(path.to_str().unwrap(), &Attrs).expect("open");
    let (_, v) = snap.search("10.9.9.9".parse().unwrap()).expect("hit");
    let hit = PathRef {
        off: v.off.to_native(),
        len: v.len.to_native(),
    };
    assert_eq!(Attrs::resolve(&snap, &hit).unwrap(), a);

    // the broken handle is caught at resolve time, not by the section check
    let (_, v) = snap.search("10.2.0.5".parse().unwrap()).expect("hit");
    let bad = PathRef {
        off: v.off.to_native(),
        len: v.len.to_native(),
    };
    assert!(Attrs::resolve(&snap, &bad).is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn demo_b_journal_carries_the_payload() {
    let dir = std::env::temp_dir().join(format!("snap-demo-b-journal-{}", std::process::id()));
    let log = dir.join("journal");
    let tree_id = [3u8; 16];

    let a = attrs("AS_PATH 64500 64512");
    let b = attrs("AS_PATH 64501 64513");

    // write
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID)))
                .expect("open journal");
        j.insert_with_blob(
            "10.0.0.0/8".parse().unwrap(),
            &PathRef {
                off: 0,
                len: a.len() as u32,
            },
            &a,
        )
        .expect("insert a");
        j.insert_with_blob(
            "10.1.0.0/16".parse().unwrap(),
            &PathRef {
                off: a.len() as u32,
                len: b.len() as u32,
            },
            &b,
        )
        .expect("insert b");
        j.sync().expect("sync");
        let snap_path = j
            .checkpoint(&Opts {
                created_at: "2026-11-14T00:00:00Z",
                window: None,
                stream: None,
                extras: &[],
            })
            .expect("checkpoint");
        let snap: Snapshot<PathRef> =
            Snapshot::open_with(snap_path.to_str().unwrap(), &Attrs).expect("open snapshot");
        let section = snap.section_bytes(SECTION_ID).expect("payload section");
        assert_eq!(section, arena_of(&[&a, &b]).as_slice());
    }

    // recover: the arena is rebuilt from the records, in order
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID)))
                .expect("reopen journal");
        assert_eq!(j.len(), 2);
        assert_eq!(j.blob_len(), a.len() + b.len());
        let snap_path = j
            .checkpoint(&Opts {
                created_at: "2026-11-14T00:00:00Z",
                window: None,
                stream: None,
                extras: &[],
            })
            .expect("second checkpoint");
        let snap: Snapshot<PathRef> =
            Snapshot::open_with(snap_path.to_str().unwrap(), &Attrs).expect("open second");
        assert_eq!(
            snap.section_bytes(SECTION_ID).expect("payload"),
            arena_of(&[&a, &b]).as_slice()
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

fn arena_of(parts: &[&Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

#[test]
fn demo_b_journal_updates_the_live_tree_and_refuses_a_second_writer() {
    let dir = std::env::temp_dir().join(format!("snap-demo-b-live-{}", std::process::id()));
    let log = dir.join("journal");
    let tree_id = [9u8; 16];

    let mut j: Journal<PathRef> =
        Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).expect("open");
    j.insert("10.0.0.0/8".parse().unwrap(), &PathRef { off: 0, len: 0 })
        .expect("insert");
    // the live tree must reflect the record immediately, before any checkpoint
    assert_eq!(j.len(), 1, "insert has to update the tree");

    // one writer per tree
    assert!(
        Journal::<PathRef>::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).is_err(),
        "a second writer must be refused"
    );

    j.sync().expect("sync");
    let snap_path = j
        .checkpoint(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[],
        })
        .expect("checkpoint");
    let snap: Snapshot<PathRef> = Snapshot::open(snap_path.to_str().unwrap()).expect("open");
    assert!(
        snap.search("10.1.2.3".parse().unwrap()).is_some(),
        "the checkpoint must contain what was inserted"
    );

    // reopening recovers the same state
    drop(j);
    let reopened: Journal<PathRef> =
        Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).expect("reopen");
    assert_eq!(reopened.len(), 1, "recovery must restore the tree");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn children_are_limited_to_the_requested_prefix() {
    let dir = std::env::temp_dir().join(format!("snap-children-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.snap");
    let arena = b"x".to_vec();
    let mut w: bgpkit_snap::Writer<PathRef> = bgpkit_snap::Writer::new();
    for p in ["10.0.0.0/8", "10.2.0.0/16", "10.3.0.0/16", "10.4.0.0/16"] {
        w.insert(p.parse().unwrap(), PathRef { off: 0, len: 1 });
    }
    let bytes = w
        .finish(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[ExtraSection {
                id: SECTION_ID,
                kind: KIND_PAYLOAD,
                required: true,
                bytes: &arena,
            }],
        })
        .unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let snap: Snapshot<PathRef> = Snapshot::open_with(path.to_str().unwrap(), &Attrs).unwrap();

    let got: Vec<String> = snap
        .children("10.2.0.0/16".parse().unwrap())
        .iter()
        .map(|(p, _)| p.to_string())
        .collect();
    assert_eq!(
        got,
        vec!["10.2.0.0/16"],
        "only the prefix and what is under it"
    );

    let siblings: Vec<String> = snap
        .children("10.0.0.0/8".parse().unwrap())
        .iter()
        .map(|(p, _)| p.to_string())
        .collect();
    assert_eq!(
        siblings.len(),
        4,
        "the prefix itself plus 10.2/16 10.3/16 10.4/16"
    );
    assert!(siblings.contains(&"10.0.0.0/8".to_string()));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn recovery_keeps_a_committed_checkpoint_when_a_segment_is_lost() {
    let dir = std::env::temp_dir().join(format!("snap-recover-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [3u8; 16];

    let seq = {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).expect("open");
        let seq = j
            .insert("10.0.0.0/8".parse().unwrap(), &PathRef { off: 0, len: 0 })
            .expect("insert");
        j.sync().expect("sync");
        j.checkpoint(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[],
        })
        .expect("checkpoint");
        seq
    };

    // simulate the post-checkpoint segment being lost: the checkpoint is the
    // state, and the next sequence number must not be handed out twice
    for entry in std::fs::read_dir(&log).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("segment-"))
        {
            std::fs::write(&path, b"").unwrap();
        }
    }

    let mut j: Journal<PathRef> =
        Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).expect("reopen");
    assert_eq!(j.len(), 1, "the checkpoint must be the recovered state");
    let next = j
        .insert("192.0.2.0/24".parse().unwrap(), &PathRef { off: 0, len: 0 })
        .expect("insert after recovery");
    assert!(next > seq, "sequence {next} reused {seq}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_empty_tree_can_be_checkpointed() {
    let dir = std::env::temp_dir().join(format!("snap-empty-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let mut j: Journal<PathRef> = Journal::open(&log, [4u8; 16], None).expect("open");
    j.insert("10.0.0.0/8".parse().unwrap(), &PathRef { off: 0, len: 0 })
        .unwrap();
    j.withdraw("10.0.0.0/8".parse().unwrap()).unwrap();
    assert!(j.is_empty());

    let path = j
        .checkpoint(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[],
        })
        .expect("an empty tree is a legal object");
    let snap: Snapshot<PathRef> = Snapshot::open(path.to_str().unwrap()).expect("open");
    assert_eq!(snap.len(), 0);

    std::fs::remove_dir_all(&dir).ok();
}
