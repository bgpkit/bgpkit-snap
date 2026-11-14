//! Prints the byte layout of a two-record journal so the spec can carry a test
//! vector instead of a description nobody can check.

use bgpkit_snap::journal::{Journal, PayloadSection};
use bgpkit_snap::Opts;

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct V(u32);

impl bgpkit_snap::SnapValue for V {
    const TYPE_ID: &str = "example.vector:v1";
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join("snap-journal-vector");
    std::fs::remove_dir_all(&dir).ok();
    let log = dir.join("journal");
    // a fixed generation, so the bytes below are the same on every run
    let mut j: Journal<V> = Journal::open_with(
        &log,
        [0x11; 16],
        Some(PayloadSection::payload(16)),
        Some([0x22; 16]),
    )?;
    j.insert("10.0.0.0/8".parse()?, &V(7))?;
    j.insert_with_blob("192.0.2.0/24".parse()?, &V(9), b"payload")?;
    j.sync()?;
    j.checkpoint(&Opts {
        created_at: "2026-11-14T00:00:00Z",
        ..Opts::default()
    })?;
    drop(j);

    let mut segments: Vec<_> = std::fs::read_dir(&log)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.to_string_lossy().contains("segment-"))
        .collect();
    segments.sort();
    let raw = std::fs::read(&segments[0])?;
    println!("segment file {} bytes", raw.len());
    println!("header {}", hex(&raw[..48]));
    let mut off = 48;
    while off + 8 <= raw.len() {
        let len = u32::from_le_bytes(raw[off..off + 4].try_into()?) as usize;
        if len < 56 || off + 4 + len > raw.len() {
            break;
        }
        println!(
            "record {} bytes: {}",
            4 + len,
            hex(&raw[off..off + 4 + len])
        );
        off += 4 + len;
    }
    println!("state {}", std::fs::read_to_string(log.join("state.json"))?);
    Ok(())
}
