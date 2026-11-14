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

#[test]
fn a_torn_tail_costs_only_the_uncommitted_record() {
    let dir = std::env::temp_dir().join(format!("snap-torn-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [7u8; 16];

    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).expect("open");
        for p in ["10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24"] {
            j.insert(p.parse().unwrap(), &PathRef { off: 0, len: 0 })
                .unwrap();
        }
        j.sync().expect("sync");
    }

    // a half-written record: length and crc written, payload cut short
    let mut segment = std::fs::read_dir(&log)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.to_string_lossy().contains("segment-"))
        .unwrap();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap();
        f.write_all(&64u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&[0u8; 20]).unwrap();
    }

    let j: Journal<PathRef> =
        Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).expect("reopen");
    assert_eq!(j.len(), 3, "the three committed records must survive");

    // a checkpoint after a torn tail must cover what is left, and then the
    // segment it covers is the one that may go
    drop(j);
    let mut j: Journal<PathRef> =
        Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).expect("reopen");
    j.checkpoint(&Opts {
        created_at: "2026-11-14T00:00:00Z",
        window: None,
        stream: None,
        extras: &[],
    })
    .expect("checkpoint over a torn tail");
    let leftovers: Vec<String> = std::fs::read_dir(&log)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("segment-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "every covered segment is gone: {leftovers:?}"
    );

    // the next record starts a new segment at the next number
    j.insert(
        "203.0.113.0/24".parse().unwrap(),
        &PathRef { off: 0, len: 0 },
    )
    .unwrap();
    j.sync().unwrap();
    let after: Vec<String> = std::fs::read_dir(&log)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("segment-"))
        .collect();
    assert_eq!(after.len(), 1, "one segment for the new record: {after:?}");
    segment.pop();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_hole_in_the_middle_is_an_error_not_a_shorter_tree() {
    let dir = std::env::temp_dir().join(format!("snap-hole-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [5u8; 16];

    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
        for p in ["10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24"] {
            j.insert(p.parse().unwrap(), &PathRef { off: 0, len: 0 })
                .unwrap();
        }
        j.sync().unwrap();
    }

    // remove the middle record: the frame after it must not be replayed as if
    // the sequence numbers were contiguous
    let segment = std::fs::read_dir(&log)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.to_string_lossy().contains("segment-"))
        .unwrap();
    let raw = std::fs::read(&segment).unwrap();
    let first_len = u32::from_le_bytes(raw[48..52].try_into().unwrap()) as usize;
    let second_len = u32::from_le_bytes(raw[52 + first_len..56 + first_len].try_into().unwrap());
    let drop = 4 + second_len as usize;
    let mut hole = raw[..52 + first_len].to_vec();
    hole.extend_from_slice(&raw[52 + first_len + drop..]);
    std::fs::write(&segment, &hole).unwrap();

    let opened = Journal::<PathRef>::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID)));
    match opened {
        Err(e) => assert!(format!("{e}").contains("sequence"), "got {e}"),
        Ok(j) => panic!("a missing record must not read as {} entries", j.len()),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_blob_without_a_payload_section_is_refused() {
    let dir = std::env::temp_dir().join(format!("snap-noblob-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let mut j: Journal<PathRef> = Journal::open(&log, [6u8; 16], None).unwrap();
    let err = j
        .insert_with_blob(
            "10.0.0.0/8".parse().unwrap(),
            &PathRef { off: 0, len: 0 },
            b"x",
        )
        .unwrap_err();
    assert!(format!("{err}").contains("payload"), "got {err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_corrupt_state_file_is_not_treated_as_absent() {
    let dir = std::env::temp_dir().join(format!("snap-state-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [8u8; 16];
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), &PathRef { off: 0, len: 0 })
            .unwrap();
        j.sync().unwrap();
        j.checkpoint(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[],
        })
        .unwrap();
    }
    std::fs::write(log.join("state.json"), b"{not json").unwrap();
    assert!(
        Journal::<PathRef>::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).is_err(),
        "a corrupt state file must stop recovery, not reset it"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_snapshot_no_state_file_names_is_cleaned_up() {
    let dir = std::env::temp_dir().join(format!("snap-orphan-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [9u8; 16];
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), &PathRef { off: 0, len: 0 })
            .unwrap();
        j.sync().unwrap();
        j.checkpoint(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[],
        })
        .unwrap();
    }
    // a snapshot that no state file names, as a crash just before the rename
    std::fs::write(log.join("snapshot-99.snap"), b"orphan").unwrap();
    let kept = std::fs::read_dir(&log)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.starts_with("snapshot-"))
        .count();
    assert_eq!(kept, 2, "one named plus one orphan before the reopen");

    let _j: Journal<PathRef> =
        Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
    let after: Vec<String> = std::fs::read_dir(&log)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.starts_with("snapshot-"))
        .collect();
    assert_eq!(after.len(), 1, "the orphan is gone: {after:?}");
    assert_eq!(after[0], "snapshot-2.snap", "the named checkpoint survives");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_checkpoint_is_not_adopted_without_its_configuration() {
    let dir = std::env::temp_dir().join(format!("snap-cfg-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [12u8; 16];
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
        j.insert_with_blob(
            "10.0.0.0/8".parse().unwrap(),
            &PathRef { off: 0, len: 4 },
            b"abcd",
        )
        .unwrap();
        j.sync().unwrap();
        j.checkpoint(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[],
        })
        .unwrap();
    }
    // reopening without the payload section would silently drop the arena
    let opened = Journal::<PathRef>::open(&log, tree_id, None);
    assert!(
        opened.is_err(),
        "a checkpoint with a payload section must not be adopted without it"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn checkpoints_without_a_state_file_are_refused() {
    let dir = std::env::temp_dir().join(format!("snap-nostate-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [13u8; 16];
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), &PathRef { off: 0, len: 0 })
            .unwrap();
        j.sync().unwrap();
        j.checkpoint(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[],
        })
        .unwrap();
    }
    std::fs::remove_file(log.join("state.json")).unwrap();
    assert!(
        Journal::<PathRef>::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).is_err(),
        "a checkpoint nobody names is not a state to recover from"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_journal_holding_blobs_cannot_reopen_without_its_payload_section() {
    let dir = std::env::temp_dir().join(format!("snap-blobnone-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [21u8; 16];
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
        j.insert_with_blob(
            "10.0.0.0/8".parse().unwrap(),
            &PathRef { off: 0, len: 4 },
            b"abcd",
        )
        .unwrap();
        j.sync().unwrap();
        // no checkpoint yet: the arena lives only in the segments
    }
    let opened = Journal::<PathRef>::open(&log, tree_id, None);
    assert!(
        opened.is_err(),
        "reopening without the payload section would drop the arena at the next checkpoint"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_malformed_checkpoint_field_is_an_error() {
    let dir = std::env::temp_dir().join(format!("snap-badcp-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [31u8; 16];
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), &PathRef { off: 0, len: 0 })
            .unwrap();
        j.sync().unwrap();
        j.checkpoint(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: None,
            stream: None,
            extras: &[],
        })
        .unwrap();
    }

    // keep the journal's real identity and drop only checkpoint.file, so the
    // reopen reaches the state parsing rather than failing on the identity
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(log.join("state.json")).unwrap()).unwrap();
    let broken = serde_json::json!({
        "next_seq": state["next_seq"],
        "generation": state["generation"],
        "tree_id": state["tree_id"],
        "checkpoint": { "seq": state["checkpoint"]["seq"] }
    });
    std::fs::write(log.join("state.json"), serde_json::to_vec(&broken).unwrap()).unwrap();

    let before = snapshots(&log);
    assert_eq!(before.len(), 1, "one snapshot before the reopen");
    let opened = Journal::<PathRef>::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID)));
    assert!(
        opened.is_err(),
        "a checkpoint missing its file must not read as no checkpoint"
    );
    assert_eq!(snapshots(&log), before, "the snapshot must not be deleted");
    std::fs::remove_dir_all(&dir).ok();
}

fn snapshots(log: &std::path::Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(log)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.starts_with("snapshot-"))
        .collect();
    out.sort();
    out
}

#[test]
fn a_damaged_segment_header_is_not_an_empty_journal() {
    let dir = std::env::temp_dir().join(format!("snap-magic-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [41u8; 16];
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
        for p in ["10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24"] {
            j.insert(p.parse().unwrap(), &PathRef { off: 0, len: 0 })
                .unwrap();
        }
        j.sync().unwrap();
    }
    // both faults at once: the state file is gone and the segment header is junk
    std::fs::remove_file(log.join("state.json")).unwrap();
    let segment = std::fs::read_dir(&log)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.to_string_lossy().contains("segment-"))
        .unwrap();
    let mut raw = std::fs::read(&segment).unwrap();
    raw[..8].copy_from_slice(b"NOTALOG!");
    std::fs::write(&segment, &raw).unwrap();

    assert!(
        Journal::<PathRef>::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).is_err(),
        "an unreadable segment must not read as an empty tree"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_long_random_op_sequence_survives_recovery_unchanged() {
    let dir = std::env::temp_dir().join(format!("snap-random-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    let tree_id = [51u8; 16];

    // a deterministic generator keeps the test reproducible without a dependency
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let mut expected: std::collections::BTreeMap<String, u32> = Default::default();
    let opts = Opts {
        created_at: "2026-11-14T00:00:00Z",
        window: None,
        stream: None,
        extras: &[],
    };
    {
        let mut j: Journal<PathRef> =
            Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
        for _ in 0..400 {
            let r = next();
            let prefix = format!("10.{}.{}.0/24", (r >> 8) % 4, (r >> 16) % 4);
            if r % 3 == 0 {
                j.withdraw(prefix.parse().unwrap()).unwrap();
                expected.remove(&prefix);
            } else {
                let off = (r % 32) as u32;
                j.insert(prefix.parse().unwrap(), &PathRef { off, len: 4 })
                    .unwrap();
                expected.insert(prefix, off);
            }
            if r % 17 == 0 {
                j.sync().unwrap();
            }
        }
        j.sync().unwrap();
        j.checkpoint(&opts).unwrap();
    }

    // recover from disk, checkpoint again, and compare every value
    let mut j: Journal<PathRef> =
        Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
    assert_eq!(
        j.len(),
        expected.len(),
        "the recovered tree has a different size"
    );
    let path = j.checkpoint(&opts).unwrap();
    let snap: Snapshot<PathRef> = Snapshot::open(path.to_str().unwrap()).unwrap();
    for (prefix, off) in &expected {
        let (_, value) = snap
            .search_prefix(prefix.parse().unwrap())
            .unwrap_or_else(|| panic!("recovery lost {prefix}"));
        assert_eq!(value.off, *off, "wrong value for {prefix}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_segment_header_with_unknown_fields_is_refused() {
    for (offset, value) in [(8usize, 5u8), (10, 1), (44, 1)] {
        let dir = std::env::temp_dir().join(format!("snap-hdr-{offset}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let log = dir.join("journal");
        let tree_id = [61u8; 16];
        {
            let mut j: Journal<PathRef> =
                Journal::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID))).unwrap();
            j.insert("10.0.0.0/8".parse().unwrap(), &PathRef { off: 0, len: 0 })
                .unwrap();
            j.sync().unwrap();
        }
        let segment = std::fs::read_dir(&log)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .find(|p| p.to_string_lossy().contains("segment-"))
            .unwrap();
        let mut raw = std::fs::read(&segment).unwrap();
        raw[offset] = value;
        std::fs::write(&segment, &raw).unwrap();
        assert!(
            Journal::<PathRef>::open(&log, tree_id, Some(PayloadSection::payload(SECTION_ID)))
                .is_err(),
            "byte {offset} = {value} must be refused"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
