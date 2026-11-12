use std::io::Write;

use clap::{Parser, Subcommand};
use ipnet::IpNet;
use snaptrie::{Snapshot, Writer};

#[derive(Parser)]
#[command(name = "snap", about = "bgpkit-snap PoC CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build a .snap from a JSON lines file of {"prefix": "...", "value": n}
    Build {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        out: String,
        #[arg(long, default_value = "generated")]
        source: String,
        /// Fixed RFC 3339 timestamp, for reproducible bytes
        #[arg(long)]
        created_at: Option<String>,
    },
    /// Print META as JSON
    Info { file: String },
    /// Re-open and run every check the reader performs
    Verify { file: String },
    /// Longest-prefix match for a prefix
    Search { file: String, prefix: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build {
            input,
            out,
            source,
            created_at,
        } => {
            let mut w: Writer<u32> = Writer::new();
            let text = std::fs::read_to_string(&input)?;
            let mut n = 0usize;
            for (lineno, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let v: serde_json::Value =
                    serde_json::from_str(line).map_err(|e| format!("line {}: {e}", lineno + 1))?;
                let p: IpNet = v["prefix"]
                    .as_str()
                    .ok_or("missing prefix")?
                    .parse()
                    .map_err(|e| format!("line {}: {e}", lineno + 1))?;
                let value = v["value"].as_u64().ok_or("missing value")? as u32;
                w.insert(p, value);
                n += 1;
            }
            let created = created_at.unwrap_or_else(|| {
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            });
            let distinct = w.len();
            let bytes = w.finish(&created, &source)?;
            std::fs::write(&out, &bytes)?;
            println!(
                "built {} ({} input rows, {} distinct entries, {} bytes)",
                out,
                n,
                distinct,
                bytes.len()
            );
        }
        Cmd::Info { file } => {
            let s: Snapshot<u32> = Snapshot::open(&file)?;
            println!("{}", serde_json::to_string_pretty(s.meta())?);
            println!("content_id: {}", s.content_id());
        }
        Cmd::Verify { file } => {
            let s: Snapshot<u32> = Snapshot::open(&file)?;
            let mut h = std::io::stdout();
            writeln!(h, "magic ok, major ok, footer ok")?;
            writeln!(h, "section hashes ok, body hash ok, content_id ok")?;
            writeln!(
                h,
                "counts ok (v4 {} v6 {}), probes ok",
                s.v4().map(|m| m.len()).unwrap_or(0),
                s.v6().map(|m| m.len()).unwrap_or(0)
            )?;
            writeln!(h, "content_id {}", s.content_id())?;
        }
        Cmd::Search { file, prefix } => {
            let s: Snapshot<u32> = Snapshot::open(&file)?;
            let q: IpNet = prefix.parse()?;
            match s.search(q) {
                Some((p, v)) => println!("{p} -> {}", v.to_native()),
                None => {
                    println!("no match");
                    std::process::exit(2);
                }
            }
        }
    }
    Ok(())
}
