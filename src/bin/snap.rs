//! The `snap` CLI: build, info, verify, search.
//!
//! `info` reads the 192-byte header and nothing else, which is the point of the
//! fixed header: identification is one small read.

use std::process::exit;

use bgpkit_snap::{header::HEADER_LEN, Header, Snapshot, Writer};
use clap::{Parser, Subcommand};
use ipnet::IpNet;

#[derive(Parser)]
#[command(name = "snap", version, about = "bgpkit-snap object tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build an object from a JSON lines file of {"prefix": .., "value": n}
    Build {
        input: String,
        #[arg(short, long)]
        out: String,
        #[arg(long, default_value = "2026-01-01T00:00:00Z")]
        created_at: String,
        #[arg(long)]
        window: Option<String>,
    },
    /// Print what the 192-byte header says
    Info { file: String },
    /// Verify the whole object
    Verify { file: String },
    /// Longest-prefix match for an address or prefix
    Search { file: String, query: String },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Build {
            input,
            out,
            created_at,
            window,
        } => match build(&input, &out, &created_at, window.as_deref()) {
            Ok(n) => println!("wrote {out}: {n} entries"),
            Err(e) => fail(&format!("{e}")),
        },
        Cmd::Info { file } => match info(&file) {
            Ok(()) => {}
            Err(e) => fail(&format!("{e}")),
        },
        Cmd::Verify { file } => match verify(&file) {
            Ok(n) => println!("ok: {n} entries"),
            Err(e) => fail(&format!("{e}")),
        },
        Cmd::Search { file, query } => match search(&file, &query) {
            Ok(()) => {}
            Err(e) => fail(&format!("{e}")),
        },
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("snap: {msg}");
    exit(1)
}

fn build(
    input: &str,
    out: &str,
    created_at: &str,
    window: Option<&str>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(input)?;
    let mut w: Writer<u32> = Writer::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let prefix: IpNet = v["prefix"].as_str().unwrap_or_default().parse()?;
        w.insert(prefix, v["value"].as_u64().unwrap_or(0) as u32);
    }
    let parsed_window = match window {
        Some(spec) => {
            let (from, to) = spec
                .split_once(',')
                .ok_or_else(|| std::io::Error::other("--window wants FROM,TO unix seconds"))?;
            Some((from.trim().parse()?, to.trim().parse()?))
        }
        None => None,
    };
    let bytes = w.finish(&bgpkit_snap::Opts {
        created_at,
        stream: None,
        window: parsed_window,
        extras: &[],
    })?;
    let n = bytes.len();
    std::fs::write(out, bytes)?;
    Ok(n)
}

fn info(file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = [0u8; HEADER_LEN];
    {
        use std::io::Read;
        std::fs::File::open(file)?.read_exact(&mut raw)?;
    }
    let h = Header::parse(&raw)?;
    println!("type_id    {}", h.type_id_str());
    println!("content_id {}", h.content_id_hex());
    println!("file_len   {}", h.file_len);
    println!("sections   {}", h.section_count);
    println!("created_at {}", h.created_at);
    match h.window() {
        Some((a, b)) => println!("window     {a}..{b}"),
        None => println!("window     none"),
    }
    match h.stream() {
        Some(s) => println!("stream     tree {:?} seq {}", &s.tree_id[..4], s.base_seq),
        None => println!("stream     none"),
    }
    Ok(())
}

fn verify(file: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let snap: Snapshot<u32> = Snapshot::open(file)?;
    Ok(snap.len())
}

fn search(file: &str, query: &str) -> Result<(), Box<dyn std::error::Error>> {
    let snap: Snapshot<u32> = Snapshot::open(file)?;
    let hit = match query.parse::<IpNet>() {
        Ok(net) => snap.search_prefix(net),
        Err(_) => snap.search(query.parse()?),
    };
    match hit {
        Some((prefix, value)) => println!("{prefix} -> {}", u32::from_archived(value)),
        None => println!("no match"),
    }
    Ok(())
}

trait FromArchived {
    fn from_archived(v: &<u32 as rkyv::Archive>::Archived) -> u32;
}

impl FromArchived for u32 {
    fn from_archived(v: &<u32 as rkyv::Archive>::Archived) -> u32 {
        v.to_native()
    }
}
