//! The quick start from the README, kept as a compiled example so the docs
//! cannot drift from the API.

use bgpkit_snap::{Opts, SnapValue, Snapshot, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct RoaSet(Vec<u32>);

impl SnapValue for RoaSet {
    const TYPE_ID: &str = "example.roa-set:v1";

    fn canonicalize(&mut self) {
        self.0.sort_unstable();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // build
    let mut w: Writer<RoaSet> = Writer::new();
    w.insert("10.0.0.0/8".parse()?, RoaSet(vec![64512]));
    w.insert("2001:db8::/32".parse()?, RoaSet(vec![64513]));
    let bytes = w.finish(&Opts {
        created_at: "2026-11-14T00:00:00Z",
        window: None,
        stream: None,
        extras: &[],
    })?;
    std::fs::write("/tmp/example.snap", &bytes)?;

    // read
    let snap: Snapshot<RoaSet> = Snapshot::open("/tmp/example.snap")?;
    let (prefix, value) = snap
        .search("10.1.2.3".parse()?)
        .ok_or("10.1.2.3 is not covered")?;
    println!(
        "{} prefixes, id {}, 10.1.2.3 -> {} with {} origin",
        snap.len(),
        snap.content_id(),
        prefix,
        value.0.len()
    );
    Ok(())
}
