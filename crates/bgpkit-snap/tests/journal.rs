//! Journal: replay must reproduce the tree state a live process reached, and a
//! damaged tail must not be applied.

use std::io::{Read, Write};

use bgpkit_snap::journal::{self, Journal, Tree};
use bgpkit_snap::{Snapshot, Writer};

fn base_snapshot(dir: &std::path::Path) -> Snapshot<u32> {
    let mut w = Writer::<u32>::new();
    w.insert("10.0.0.0/8".parse().unwrap(), 1);
    w.insert("10.1.0.0/16".parse().unwrap(), 2);
    w.insert("2001:db8::/32".parse().unwrap(), 3);
    let bytes = w.finish("2026-11-12T00:00:00Z", "journal-test").unwrap();
    let path = dir.join("base.snap");
    std::fs::write(&path, &bytes).unwrap();
    Snapshot::open(path.to_str().unwrap()).unwrap()
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bgpkit-snap-journal-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn replay_reproduces_the_live_tree() {
    let dir = tmpdir("replay");
    let base = base_snapshot(&dir);
    let tree_id = [7u8; 16];
    let log_dir = dir.join("journal");

    // live tree: start from a snapshot, apply updates, journal each one
    let mut live = Tree::open(&base).unwrap();
    let mut journal = Journal::open(&log_dir, tree_id).unwrap();

    live.insert("10.2.0.0/16".parse().unwrap(), 42);
    journal
        .insert("10.2.0.0/16".parse().unwrap(), &42u32, 0)
        .unwrap();
    live.insert("2001:db8:1::/48".parse().unwrap(), 43);
    journal
        .insert("2001:db8:1::/48".parse().unwrap(), &43u32, 0)
        .unwrap();
    live.withdraw("10.1.0.0/16".parse().unwrap());
    journal.withdraw("10.1.0.0/16".parse().unwrap(), 0).unwrap();
    // overwrite an existing key
    live.insert("10.0.0.0/8".parse().unwrap(), 99);
    journal
        .insert("10.0.0.0/8".parse().unwrap(), &99u32, 0)
        .unwrap();
    journal.sync().unwrap();

    let snap_dir = dir.join("snaps");
    journal
        .checkpoint(&live, &snap_dir, "2026-11-12T01:00:00Z", "journal-test")
        .unwrap();
    let live_bytes = tree_bytes(&live);
    let live_id = Snapshot::<u32>::from_bytes(&live_bytes)
        .unwrap()
        .content_id()
        .to_string();

    // replay path: base snapshot + journal
    let mut replayed = Tree::open(&base).unwrap();
    let cp = journal::read_checkpoint(&snap_dir)
        .unwrap()
        .expect("checkpoint written");
    let stats = journal::replay(&mut replayed, &log_dir, 0, tree_id).unwrap();
    assert_eq!(stats.applied, 4, "every record applies from an empty base");
    let replayed_bytes = tree_bytes(&replayed);
    let replayed_id = Snapshot::<u32>::from_bytes(&replayed_bytes)
        .unwrap()
        .content_id()
        .to_string();

    assert_eq!(
        live_id, replayed_id,
        "replay must land on the same content id"
    );
    assert_eq!(cp.base_seq, 4, "base_seq is the last reflected sequence");
    assert_eq!(replayed.len(), 4);

    std::fs::remove_dir_all(&dir).ok();
}

fn tree_bytes(tree: &Tree<u32>) -> Vec<u8> {
    tree.to_writer()
        .finish("2026-11-12T01:00:00Z", "journal-test")
        .unwrap()
}

#[test]
fn torn_tail_is_reported_and_not_applied() {
    let dir = tmpdir("torn");
    let tree_id = [9u8; 16];
    let log_dir = dir.join("journal");
    {
        let mut j = Journal::open(&log_dir, tree_id).unwrap();
        for (i, p) in ["10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16"]
            .iter()
            .enumerate()
        {
            j.insert(p.parse().unwrap(), &(i as u32 + 1), 0).unwrap();
        }
        j.sync().unwrap();
    }

    // cut the last record in half, as a crash mid-write would
    let seg = std::fs::read_dir(&log_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|e| e == "log"))
        .unwrap();
    let len = std::fs::metadata(&seg).unwrap().len();
    let file = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
    file.set_len(len - 6).unwrap();
    drop(file);

    let mut tree = Tree::<u32>::new();
    let stats = journal::replay(&mut tree, &log_dir, 0, tree_id).unwrap();
    assert_eq!(stats.applied, 2, "the torn record is not applied");
    assert!(stats.torn_bytes > 0, "the torn bytes are reported");
    assert_eq!(tree.len(), 2);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn corrupted_record_stops_the_scan() {
    let dir = tmpdir("crc");
    let tree_id = [3u8; 16];
    let log_dir = dir.join("journal");
    {
        let mut j = Journal::open(&log_dir, tree_id).unwrap();
        for (i, p) in ["10.0.0.0/8", "10.1.0.0/16"].iter().enumerate() {
            j.insert(p.parse().unwrap(), &(i as u32 + 1), 0).unwrap();
        }
        j.sync().unwrap();
    }

    let seg = std::fs::read_dir(&log_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|e| e == "log"))
        .unwrap();
    let mut raw = Vec::new();
    std::fs::File::open(&seg)
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    // flip a byte inside the first record's payload
    let idx = bgpkit_snap::journal::SEGMENT_HEADER_LEN + 12;
    raw[idx] ^= 0xff;
    let mut f = std::fs::File::create(&seg).unwrap();
    f.write_all(&raw).unwrap();
    drop(f);

    let mut tree = Tree::<u32>::new();
    let stats = journal::replay(&mut tree, &log_dir, 0, tree_id).unwrap();
    assert_eq!(
        stats.applied, 0,
        "a record that fails its CRC is never applied"
    );
    assert!(stats.torn_bytes > 0);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_foreign_segment_is_rejected() {
    let dir = tmpdir("treeid");
    let log_dir = dir.join("journal");
    {
        let mut j = Journal::open(&log_dir, [1u8; 16]).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), &7u32, 0).unwrap();
        j.sync().unwrap();
    }
    let mut tree = Tree::<u32>::new();
    let err = journal::replay(&mut tree, &log_dir, 0, [2u8; 16]).unwrap_err();
    assert!(
        matches!(err, bgpkit_snap::Error::TypeMismatch { .. }),
        "{err}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_first_record_after_a_checkpoint_survives_replay() {
    // the crash window: checkpoint, then one more update, then a restart
    let dir = tmpdir("after-checkpoint");
    let base = base_snapshot(&dir);
    let tree_id = [5u8; 16];
    let log_dir = dir.join("journal");
    let snap_dir = dir.join("snaps");

    let mut live = Tree::open(&base).unwrap();
    let mut j = Journal::open(&log_dir, tree_id).unwrap();
    for (i, p) in ["10.9.0.0/16", "10.10.0.0/16"].iter().enumerate() {
        let v = i as u32 + 20;
        live.insert(p.parse().unwrap(), v);
        j.insert(p.parse().unwrap(), &v, 0).unwrap();
    }
    j.sync().unwrap();
    j.checkpoint(&live, &snap_dir, "2026-11-12T02:00:00Z", "journal-test")
        .unwrap();

    let late = "10.11.0.0/16".parse().unwrap();
    live.insert(late, 77u32);
    j.insert(late, &77u32, 0).unwrap();
    j.sync().unwrap();

    let cp = journal::read_checkpoint(&snap_dir)
        .unwrap()
        .expect("checkpoint");
    let base_snap =
        Snapshot::<u32>::open(snap_dir.join(&cp.snapshot_file).to_str().unwrap()).unwrap();
    let mut replayed = Tree::open(&base_snap).unwrap();
    let stats = journal::replay(&mut replayed, &log_dir, cp.base_seq, tree_id).unwrap();

    assert_eq!(
        stats.applied, 1,
        "the record written after the checkpoint must apply"
    );
    assert!(
        replayed.get(late).is_some(),
        "post-checkpoint update is lost"
    );
    assert_eq!(
        Snapshot::<u32>::from_bytes(&tree_bytes(&replayed))
            .unwrap()
            .content_id(),
        Snapshot::<u32>::from_bytes(&tree_bytes(&live))
            .unwrap()
            .content_id()
    );

    std::fs::remove_dir_all(&dir).ok();
}
