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
    // the input is all IPv4: one family section plus the recorded counts
    assert_eq!(info_json["sections"], 2);

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

    let stats = Command::new(bin())
        .args(["--json", "stats"])
        .arg(&out)
        .output()
        .unwrap();
    let stats_json: serde_json::Value =
        serde_json::from_slice(&stats.stdout).expect("stats --json is one object");
    assert_eq!(stats_json["entries"], 8);
    assert_eq!(stats_json["type_id"], "snap.u32:v1");
    assert!(stats_json["sections"]
        .as_array()
        .is_some_and(|s| !s.is_empty()));
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_u64_object_can_be_built_and_counted() {
    // the CLI used to speak only snap.u32:v1, so a u64 object could not be read at all
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
    let stats = Command::new(bin())
        .args(["--json", "stats"])
        .arg(&out)
        .output()
        .unwrap();
    let stats: serde_json::Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["type_id"], "snap.u64:v1");
    assert_eq!(stats["entries"], 1);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_foreign_value_type_is_counted_from_the_recorded_section() {
    // the count lives in the object, not in the reader: a trie's layout depends on the
    // value type, but three u64s written beside it do not
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
    w.insert("192.0.2.0/24".parse().unwrap(), Origin(64513))
        .unwrap();
    w.finish_to(&out, &bgpkit_snap::Opts::now()).unwrap();

    let stats = Command::new(bin())
        .args(["--json", "stats"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        stats.status.success(),
        "stats failed on a foreign type: {}",
        String::from_utf8_lossy(&stats.stderr)
    );
    let stats: serde_json::Value = serde_json::from_slice(&stats.stdout).unwrap();
    assert_eq!(stats["type_id"], "cli-test.origin:v1");
    assert_eq!(stats["entries"], 2, "the recorded count works for any type");
    assert_eq!(stats["v4_entries"], 2);
    assert_eq!(stats["v6_entries"], 0);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_recorded_count_that_disagrees_with_the_body_fails_verify() {
    // the count is a claim about the body, so verify compares it to the decoded count;
    // an object whose two halves disagree is broken, not merely odd
    let d = dir("count-mismatch");
    let path = d.join("in.jsonl");
    std::fs::write(&path, "{\"prefix\":\"10.0.0.0/8\",\"value\":1}\n").unwrap();
    let out = d.join("out.snap");
    let built = Command::new(bin())
        .arg("build")
        .arg(&path)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(built.status.success());

    // the counts section is the last section, so its body ends the file: rewrite the
    // entries field, then reseal the content id so the container check cannot be what
    // catches this. Without the reseal the object is refused one layer earlier, which is
    // its own proof that the container is self-checking.
    let mut raw = std::fs::read(&out).unwrap();
    let entries_at = raw.len() - 32 + 8;
    raw[entries_at..entries_at + 8].copy_from_slice(&9u64.to_le_bytes());
    std::fs::write(&out, &raw).unwrap();
    let caught_by_content_id = Command::new(bin())
        .arg("verify")
        .arg(&out)
        .output()
        .unwrap();
    assert!(!caught_by_content_id.status.success());
    assert!(
        String::from_utf8_lossy(&caught_by_content_id.stderr).contains("content id"),
        "the container check should be the first to notice"
    );

    // reseal: the same hash the writer computes, over the header prefix, the table and
    // every section body, written back into the content-id bytes
    let mut raw = std::fs::read(&out).unwrap();
    // section_count is a u32 at offset 92 in the v4 header
    let section_count = u32::from_le_bytes(raw[92..96].try_into().unwrap()) as usize;
    let mut h = blake3::Hasher::new();
    h.update(b"bgpkit-snap-v4\0");
    h.update(&raw[..bgpkit_snap::header::HASH_END]);
    let table_end =
        bgpkit_snap::header::HEADER_LEN + section_count * bgpkit_snap::header::ENTRY_LEN;
    h.update(&raw[bgpkit_snap::header::HEADER_LEN..table_end]);
    let mut cursor = table_end;
    for i in 0..section_count {
        let at = bgpkit_snap::header::HEADER_LEN + i * bgpkit_snap::header::ENTRY_LEN;
        let len = u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap()) as usize;
        while !cursor.is_multiple_of(16) {
            cursor += 1;
        }
        h.update(&raw[cursor..cursor + len]);
        cursor += len;
    }
    raw[156..188].copy_from_slice(h.finalize().as_bytes());
    // and the header's own crc32c, which covers bytes 0..188
    let crc = crc32c::crc32c(&raw[..188]);
    raw[188..192].copy_from_slice(&crc.to_le_bytes());
    std::fs::write(&out, &raw).unwrap();

    let verified = Command::new(bin())
        .arg("verify")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        !verified.status.success(),
        "verify accepted an object whose count contradicts its body"
    );
    let err = String::from_utf8_lossy(&verified.stderr);
    assert!(err.contains("the body holds 1 entries"), "got {err}");
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
