//! A service that already has a snapshot loaded and an incoming feed.
//!
//! The split is: `Snapshot<T>` is the read side and never changes; `Journal<T>` is the
//! write side and holds the base plus the changes since. They are two handles on the
//! same lineage, and only a checkpoint moves the reader to the next object.
//!
//! Run with `cargo run --example live --features derive`.

use bgpkit_snap::journal::Journal;
use bgpkit_snap::{snap_value, Opts, Snapshot, Writer};
use ipnet::IpNet;

#[snap_value("example.origin:v1")]
#[derive(Debug, PartialEq)]
struct Origin(u32);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "bgpkit-snap-live-{}-{}",
        std::process::id(),
        std::time::UNIX_EPOCH.elapsed()?.subsec_nanos()
    ));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir)?;

    let opts = Opts::now();
    let base = dir.join("table.snap");
    let log_dir = dir.join("table.journal");

    // 1. the object the service starts with: built once, from a RIB, a dump, a crawl
    {
        let mut w: Writer<Origin> = Writer::new();
        w.insert("10.0.0.0/8".parse()?, Origin(64512))?;
        w.finish_to(&base, &opts)?;
    }
    println!("base: {} bytes", std::fs::metadata(&base)?.len());

    // 2. the read side. Opening is one validated pass; after that, queries never touch
    //    the disk and never take a lock.
    let mut current: Snapshot<Origin> = Snapshot::open(&base)?;
    assert!(current
        .owned()
        .lpm("192.0.2.1/32".parse::<IpNet>()?)?
        .is_none());

    // 3. the write side: one journal over that same object. Opening it costs a read of
    //    the base and a replay of the log, not a rebuild.
    let mut log: Journal<Origin> = Journal::attach(&base, &log_dir)?;

    // 4. data arrives. Each change is one record; `sync` is where it becomes durable.
    log.insert("192.0.2.0/24".parse()?, Origin(64512))?;
    log.withdraw("10.0.0.0/8".parse()?)?;
    log.sync()?;

    // 5. the loaded snapshot still answers with the old state, because it is one
    //    immutable object and nothing has republished it.
    assert!(current
        .owned()
        .lpm("192.0.2.1/32".parse::<IpNet>()?)?
        .is_none());
    assert_eq!(
        current
            .owned()
            .lpm("10.1.2.3/32".parse::<IpNet>()?)?
            .map(|(p, v)| (p, v.0)),
        Some(("10.0.0.0/8".parse::<IpNet>()?, 64512))
    );

    // 6. the writer sees its own pending changes: same queries, base plus log.
    assert_eq!(
        log.lpm("192.0.2.1/32".parse::<IpNet>()?)
            .map(|(p, v)| (p, v.0)),
        Some(("192.0.2.0/24".parse::<IpNet>()?, 64512))
    );
    assert!(log.lpm("10.1.2.3/32".parse::<IpNet>()?).is_none());

    // 7. a queryable object that includes the pending changes, without publishing
    //    anything: for a caller that wants to answer from a consistent object.
    let with_pending: Snapshot<Origin> = log.to_snapshot(&opts)?;
    assert_eq!(
        with_pending
            .owned()
            .lpm("192.0.2.1/32".parse::<IpNet>()?)?
            .map(|(p, _)| p),
        Some("192.0.2.0/24".parse::<IpNet>()?)
    );

    // 8. checkpoint publishes the next object inside the journal directory and names it
    //    in state.json. The reader moves when it reopens; nothing updates in place.
    let next = log.checkpoint(&opts)?;
    current = Snapshot::open(&next)?;
    assert_eq!(
        current
            .owned()
            .lpm("192.0.2.1/32".parse::<IpNet>()?)?
            .map(|(p, v)| (p, v.0)),
        Some(("192.0.2.0/24".parse::<IpNet>()?, 64512))
    );
    assert!(current
        .owned()
        .lpm("10.1.2.3/32".parse::<IpNet>()?)?
        .is_none());
    println!("checkpoint: {}", next.display());

    // 9. the base object is untouched: a reader that opened it earlier sees exactly
    //    what it saw before, which is what makes an old object safe to serve.
    let still_base: Snapshot<Origin> = Snapshot::open(&base)?;
    assert!(still_base
        .owned()
        .lpm("192.0.2.1/32".parse::<IpNet>()?)?
        .is_none());
    println!("base unchanged: {} bytes", std::fs::metadata(&base)?.len());

    // 10. and `current.snap` is the stable path a different process reads.
    let via_link: Snapshot<Origin> = Snapshot::open(log_dir.join("current.snap"))?;
    assert_eq!(via_link.len(), current.len());
    println!("reopened through current.snap: {} entries", via_link.len());

    drop(log);
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}
