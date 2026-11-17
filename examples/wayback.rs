//! A downstream tool over a `.snap` object: the wayback ROA archive.
//!
//! This is the pattern a project with its own value type follows. `bgpkit-snap`'s own
//! CLI reads and writes integer-valued objects and inspects any container, but a
//! `bgpkit.roa-set:v1` value only means something to the program that declares it, so
//! the domain binary lives with the type. Here it is 120 lines, and it opens the real
//! dump:
//!
//! ```sh
//! cargo run --example wayback -- <roas.snap> 8.8.8.8
//! cargo run --example wayback -- <roas.snap> 8.8.8.8 --date 2023-06-24
//! ```
//!
//! The two questions the archive exists for: which ROA covers this netblock, and which
//! one was valid on a given day.

use bgpkit_snap::{SnapValue, Snapshot};
use std::time::Instant;

/// One ROA: the max length it authorizes, its origin, and the days it was valid.
#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct RoaRecord {
    max_len: u8,
    origin: u32,
    dates: Vec<(i64, i64)>,
}

/// Every ROA for one netblock, in a canonical order.
#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct RoaSet(Vec<RoaRecord>);

impl SnapValue for RoaSet {
    const TYPE_ID: &str = "bgpkit.roa-set:v1";

    fn canonicalize(&mut self) {
        self.0.sort_by_key(|r| (r.max_len, r.origin));
        for r in &mut self.0 {
            r.dates.sort();
        }
    }
}

fn day(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn parse_day(text: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let d = chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d")?;
    Ok(d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let Some(cmd) = args.get(1) else {
        eprintln!("usage: wayback <snap> <address-or-prefix> [--date YYYY-MM-DD]");
        std::process::exit(2);
    };
    if cmd == "--help" || cmd == "help" {
        println!("wayback <snap> <address-or-prefix> [--date YYYY-MM-DD]");
        println!("  prints every ROA covering the query, and with --date only the ones");
        println!("  that were valid that day");
        return Ok(());
    }
    let snap_path = cmd;
    let query = args.get(2).ok_or("a query is required")?;
    let date = match args.iter().position(|a| a == "--date") {
        Some(i) => Some(parse_day(args.get(i + 1).ok_or("--date wants a date")?)?),
        None => None,
    };

    let t = Instant::now();
    let snap: Snapshot<RoaSet> = Snapshot::open(snap_path)?;
    let opened = t.elapsed();

    let hit = if query.contains('/') {
        snap.lpm(query.parse()?)
    } else {
        snap.search(query.parse()?)
    };
    let looked = t.elapsed();

    match hit {
        None => println!("{query}: no ROA covers this"),
        Some((prefix, archived)) => {
            // the archived form is the bytes on disk; the owned view decodes this one value
            let value: RoaSet = rkyv::deserialize::<RoaSet, rkyv::rancor::Error>(archived)?;
            let valid: Vec<&RoaRecord> = value
                .0
                .iter()
                .filter(|r| match date {
                    Some(ts) => r.dates.iter().any(|(s, e)| *s <= ts && ts <= *e),
                    None => true,
                })
                .collect();
            println!(
                "{query} -> {prefix} ({} ROAs on record, {} in scope)",
                value.0.len(),
                valid.len()
            );
            for r in valid {
                // with --date, show the span that covers that day rather than the history
                let spans: Vec<String> = r
                    .dates
                    .iter()
                    .filter(|(s, e)| match date {
                        Some(ts) => *s <= ts && ts <= *e,
                        None => true,
                    })
                    .map(|(s, e)| format!("{}..{}", day(*s), day(*e)))
                    .collect();
                println!(
                    "  max_len {:>3}  origin AS{:<6}  {}",
                    r.max_len,
                    r.origin,
                    spans.join(", ")
                );
            }
        }
    }
    println!(
        "\nopened {} entries in {:.1} ms, looked up in {:.1} us",
        snap.len(),
        opened.as_secs_f64() * 1000.0,
        (looked - opened).as_secs_f64() * 1e6
    );
    Ok(())
}
