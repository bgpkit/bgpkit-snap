//! How a service uses this crate, end to end.
//!
//! Three jobs, in the order a real deployment does them:
//!
//! 1. a feed appends to a journal and checkpoints it;
//! 2. one object per source, merged into the day's object;
//! 3. the served object answers lookups.
//!
//! Run with `cargo run --example service`.

use bgpkit_snap::journal::Journal;
use bgpkit_snap::{Count, Opts, SnapValue, Snapshot, TreeId, Writer};
use std::collections::BTreeMap;

/// What the service stores per prefix: how many peers announced it.
#[derive(Clone, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug))]
struct Peers(u32);

impl SnapValue for Peers {
    const TYPE_ID: &str = "example.peers:v1";
}

type Day = BTreeMap<bgpkit_snap::ipnet::IpNet, u32>;

fn parse(lines: &str) -> Day {
    lines
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (prefix, peers) = line.split_once(' ').expect("prefix then count");
            (
                prefix.parse().expect("a prefix"),
                peers.parse().expect("a peer count"),
            )
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join("snap-service-example");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir)?;

    // 1. a feed: one collector's view, appended as it changes.
    //
    //    The tree id names the tree. The same name reopens the same journal, and a
    //    typo gives a different journal instead of adopting this one.
    let tree = TreeId::from_name("collector-routeviews-2");
    let mut journal: Journal<Peers> = Journal::open(dir.join("feed"), tree)?;
    for (prefix, peers) in parse("10.0.0.0/8 3\n192.0.2.0/24 1\n2001:db8::/32 2") {
        journal.insert(prefix, Peers(peers))?;
    }
    journal.sync()?; // durable here, without a checkpoint
    let checkpoint = journal.checkpoint(&Opts::now())?;
    println!(
        "feed      {} prefixes -> {}",
        journal.len(),
        checkpoint.display()
    );

    // 2. the day: one object per source, merged. `merge_last_wins` is the plain
    //    case; `merge_with` takes a closure when overlaps need arithmetic.
    let mut as_a: Writer<Peers> = Writer::new();
    for (prefix, peers) in parse("10.0.0.0/8 3\n203.0.113.0/24 4") {
        as_a.insert(prefix, Peers(peers))?;
    }
    let mut as_b: Writer<Peers> = Writer::new();
    for (prefix, peers) in parse("10.0.0.0/8 5\n198.51.100.0/24 1") {
        as_b.insert(prefix, Peers(peers))?;
    }
    let source_a: Snapshot<Peers> = Snapshot::from_bytes(&as_a.finish(&Opts::now())?)?;
    let source_b: Snapshot<Peers> = Snapshot::from_bytes(&as_b.finish(&Opts::now())?)?;

    // two sources, one prefix in common: keep the larger peer count
    let daily = Snapshot::merge_with(&[&source_a, &source_b], &Opts::now(), |_, a, b| {
        Some(Peers(a.0.max(b.0)))
    })?;
    std::fs::write(dir.join("daily.snap"), &daily)?;

    // 3. serve it: open once, answer many.
    let day: Snapshot<Peers> = Snapshot::open(dir.join("daily.snap"))?;
    println!(
        "daily     {} prefixes, id {}",
        day.len(),
        &day.content_id()[..16]
    );
    for query in ["10.1.2.3", "203.0.113.9", "198.51.100.7", "8.8.8.8"] {
        match day.search(query.parse()?) {
            Some((prefix, peers)) => println!("  {query:<15} -> {prefix} with {} peers", peers.0),
            None => println!("  {query:<15} -> not covered"),
        }
    }
    let counts = day.address_counts();
    if let Count::Exact(covered) = counts.v4 {
        println!("coverage  {covered} IPv4 addresses");
    }
    for (prefix, peers) in day.owned().children("198.51.0.0/16".parse()?)? {
        println!("  under     {prefix} -> {} peers", peers.0);
    }

    // and the journal's own checkpoint answers the same way, without a separate open
    let served: Snapshot<Peers> = journal.to_snapshot(&Opts::now())?;
    println!(
        "journal   {} prefixes, lpm of 10.9.9.9 = {:?}",
        served.len(),
        served
            .lpm("10.9.9.9/32".parse()?)
            .map(|(p, _)| p.to_string())
    );
    Ok(())
}
