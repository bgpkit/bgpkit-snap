//! The CLI as a caller meets it: an object built from JSON lines, a symlink the
//! caller already had in place, and a failure that must not leave debris.
//!
//! Gated on the `cli` feature, because the binary only exists with it. `snap build`
//! used to write with `fs::write`; round 9 found that the atomic replacement had
//! changed what happens to a symlink at the output path, and that a failed rename
//! left the temporary object behind. Both are pinned here, through the binary.
#![cfg(feature = "cli")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_snap")
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
