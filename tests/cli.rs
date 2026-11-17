//! The CLI as a caller meets it: an object built from JSON lines, a symlink the
//! caller already had in place, and a failure that must not leave debris. The binary
//! is `bgpkit-snap`, not `snap`, which is Ubuntu's.
//!
//! Gated on the `cli` feature, because the binary only exists with it. `snap build`
//! used to write with `fs::write`; round 9 found that the atomic replacement had
//! changed what happens to a symlink at the output path, and that a failed rename
//! left the temporary object behind. Both are pinned here, through the binary.
#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_bgpkit-snap")
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("snap-cli-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn input(d: &Path) -> PathBuf {
    let path = d.join("in.jsonl");
    let body: String = (0..8)
        .map(|i| format!("{{\"prefix\": \"10.0.{i}.0/24\", \"value\": {i}}}\n"))
        .collect();
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn a_build_writes_an_object_and_verify_reads_it_back() {
    let d = dir("build");
    let out = d.join("out.snap");
    let built = Command::new(bin())
        .arg("build")
        .arg(input(&d))
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let line = String::from_utf8_lossy(&built.stdout);
    assert!(line.contains("wrote"), "got {line}");

    let verified = Command::new(bin())
        .arg("verify")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_build_through_a_symlink_updates_its_target() {
    // `fs::write` followed the link; an atomic replace must not swap the link for a
    // regular file, because a reader that opens the link would keep the old object
    let d = dir("symlink");
    let target = d.join("real.snap");
    std::fs::write(&target, b"old").unwrap();
    let link = d.join("out.snap");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let built = Command::new(bin())
        .arg("build")
        .arg(input(&d))
        .arg("--out")
        .arg(&link)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    let meta = std::fs::symlink_metadata(&link).unwrap();
    assert!(
        meta.file_type().is_symlink(),
        "the output path is no longer a symlink"
    );
    let through_link = Command::new(bin())
        .arg("verify")
        .arg(&link)
        .output()
        .unwrap();
    assert!(
        through_link.status.success(),
        "the link does not serve a valid object: {}",
        String::from_utf8_lossy(&through_link.stderr)
    );
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn json_output_is_one_object_per_command() {
    // the CLI is also a tool for programs: every command has to answer in one JSON
    // object, not in prose a caller would have to scrape
    let d = dir("json");
    let out = d.join("out.snap");
    let built = Command::new(bin())
        .arg("build")
        .arg(input(&d))
        .arg("--out")
        .arg(&out)
        .arg("--json")
        .output()
        .unwrap();
    assert!(built.status.success());
    let built_json: serde_json::Value =
        serde_json::from_slice(&built.stdout).expect("build --json is one object");
    assert_eq!(built_json["entries"], 8);

    let info = Command::new(bin())
        .args(["--json", "info"])
        .arg(&out)
        .output()
        .unwrap();
    let info_json: serde_json::Value =
        serde_json::from_slice(&info.stdout).expect("info --json is one object");
    assert_eq!(info_json["type_id"], "snap.u32:v1");
    assert_eq!(info_json["consistent"], true);
    // the input is all IPv4, so the object carries one family section
    assert_eq!(info_json["sections"], 1);

    let verify = Command::new(bin())
        .args(["--json", "verify"])
        .arg(&out)
        .output()
        .unwrap();
    let verify_json: serde_json::Value =
        serde_json::from_slice(&verify.stdout).expect("verify --json is one object");
    assert_eq!(verify_json["ok"], true);
    assert_eq!(verify_json["bodies_checked"], true);
    assert_eq!(verify_json["entries"], 8);

    let search = Command::new(bin())
        .args(["--json", "search"])
        .arg(&out)
        .arg("10.0.1.1")
        .output()
        .unwrap();
    let search_json: serde_json::Value =
        serde_json::from_slice(&search.stdout).expect("search --json is one object");
    assert_eq!(search_json["match"]["prefix"], "10.0.1.0/24");
    assert_eq!(search_json["match"]["value"], 1);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_u64_object_can_be_built_and_searched() {
    // the CLI used to speak only snap.u32:v1, so an object built with u64 could be
    // verified but never queried
    let d = dir("u64");
    let path = d.join("in.jsonl");
    std::fs::write(&path, "{\"prefix\":\"10.0.0.0/8\",\"value\":4294967296}\n").unwrap();
    let out = d.join("out.snap");
    let built = Command::new(bin())
        .arg("build")
        .arg(&path)
        .arg("--out")
        .arg(&out)
        .arg("--value")
        .arg("u64")
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "build failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let found = Command::new(bin())
        .arg("search")
        .arg(&out)
        .arg("10.1.2.3")
        .output()
        .unwrap();
    assert!(found.status.success());
    assert_eq!(
        String::from_utf8_lossy(&found.stdout).trim(),
        "10.0.0.0/8 -> 4294967296"
    );
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_foreign_value_type_says_what_to_do() {
    // the object's value type is the caller's: the CLI cannot decode it, and the
    // error has to say so and name both ways out instead of only the mismatch
    #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct Origin(u32);
    impl bgpkit_snap::SnapValue for Origin {
        const TYPE_ID: &str = "cli-test.origin:v1";
    }

    let d = dir("foreign");
    let out = d.join("origin.snap");
    let mut w: bgpkit_snap::Writer<Origin> = bgpkit_snap::Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), Origin(64512))
        .unwrap();
    w.finish_to(&out, &bgpkit_snap::Opts::now()).unwrap();

    let search = Command::new(bin())
        .arg("search")
        .arg(&out)
        .arg("10.1.2.3")
        .output()
        .unwrap();
    assert!(!search.status.success());
    let err = String::from_utf8_lossy(&search.stderr);
    assert!(err.contains("cli-test.origin:v1"), "got {err}");
    assert!(err.contains("snap build"), "the error must name a way out");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_journal_folds_into_one_object() {
    // writing a journal is the application's job; what a caller needs from the CLI is
    // the readable object, and folding is one call
    #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct PeerCount(u32);
    impl bgpkit_snap::SnapValue for PeerCount {
        const TYPE_ID: &str = "snap.u32:v1";
    }

    let d = dir("fold");
    let log = d.join("journal");
    {
        let mut j: bgpkit_snap::journal::Journal<PeerCount> =
            bgpkit_snap::journal::Journal::open(&log, bgpkit_snap::TreeId::from_name("snap"))
                .unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), PeerCount(7))
            .unwrap();
        j.insert("192.0.2.0/24".parse().unwrap(), PeerCount(9))
            .unwrap();
        j.sync().unwrap();
    }

    let out = d.join("folded.snap");
    let folded = Command::new(bin())
        .args(["--json", "fold"])
        .arg(&log)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        folded.status.success(),
        "fold failed: {}",
        String::from_utf8_lossy(&folded.stderr)
    );
    let folded: serde_json::Value = serde_json::from_slice(&folded.stdout).unwrap();
    assert_eq!(folded["entries"], 2);
    assert_eq!(folded["seq"], 3);
    assert_eq!(folded["type_id"], "snap.u32:v1");

    // the folded object is an ordinary snapshot
    let hit = Command::new(bin())
        .args(["--json", "search"])
        .arg(&out)
        .arg("10.1.2.3")
        .output()
        .unwrap();
    let hit: serde_json::Value = serde_json::from_slice(&hit.stdout).unwrap();
    assert_eq!(hit["match"]["prefix"], "10.0.0.0/8");
    assert_eq!(hit["match"]["value"], 7);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn folding_with_the_wrong_value_type_names_the_journal() {
    #[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    struct Big(u64);
    impl bgpkit_snap::SnapValue for Big {
        const TYPE_ID: &str = "snap.u64:v1";
    }

    let d = dir("fold-type");
    let log = d.join("journal");
    {
        let mut j: bgpkit_snap::journal::Journal<Big> =
            bgpkit_snap::journal::Journal::open(&log, bgpkit_snap::TreeId::from_name("snap"))
                .unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), Big(7)).unwrap();
        j.sync().unwrap();
    }
    let folded = Command::new(bin())
        .arg("fold")
        .arg(&log)
        .arg("--out")
        .arg(d.join("x.snap"))
        .output()
        .unwrap();
    assert!(
        !folded.status.success(),
        "the default u32 must not fold u64"
    );
    let err = String::from_utf8_lossy(&folded.stderr);
    assert!(err.contains("snap.u64:v1"), "got {err}");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_failed_build_leaves_no_temporary_object() {
    // an output path that is a directory cannot be replaced: the build must fail and
    // must not leave the complete temp object beside it
    let d = dir("rename-fail");
    let out = d.join("out.snap");
    std::fs::create_dir(&out).unwrap();

    let built = Command::new(bin())
        .arg("build")
        .arg(input(&d))
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        !built.status.success(),
        "a build onto a directory must fail"
    );

    let leftovers: Vec<String> = std::fs::read_dir(&d)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "left behind {leftovers:?}");
    std::fs::remove_dir_all(&d).ok();
}
