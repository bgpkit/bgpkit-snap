//! The `snap` CLI: build, info, verify, search.
//!
//! `info` reads the 192-byte header and nothing else, which is the point of the
//! fixed header: identification is one small read.

use std::process::exit;

use bgpkit_snap::{header::HEADER_LEN, Header, SnapValue, Snapshot, Writer};
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
        /// unix seconds UTC; defaults to now
        #[arg(long)]
        created_at: Option<i64>,
        /// Coverage claim as FROM,TO in unix seconds
        #[arg(long)]
        window: Option<String>,
    },
    /// Print what the 192-byte header says
    Info { file: String },
    /// Verify the container, and the bodies when the type is snap.u32:v1
    Verify { file: String },
    /// Longest-prefix match for an address or prefix, in a snap.u32:v1 object
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
        } => match build(&input, &out, created_at, window.as_deref()) {
            Ok((entries, bytes)) => println!("wrote {out}: {entries} entries, {bytes} bytes"),
            Err(e) => fail(&format!("{e}")),
        },
        Cmd::Info { file } => match info(&file) {
            Ok(()) => {}
            Err(e) => fail(&format!("{e}")),
        },
        Cmd::Verify { file } => match verify(&file) {
            Ok(msg) => println!("ok: {msg}"),
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
    created_at: Option<i64>,
    window: Option<&str>,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(input)?;
    let mut w: Writer<u32> = Writer::new();
    for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let (prefix, value) = parse_line(line)
            .map_err(|e| std::io::Error::other(format!("{}, line {}", e, i + 1)))?;
        w.insert(prefix, value).expect("canonical prefix");
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
    let entries = w.len();
    let bytes = w.finish(&bgpkit_snap::Opts {
        created_at: created_at.unwrap_or_else(|| chrono::Utc::now().timestamp()),
        stream: None,
        window: parsed_window,
        extras: &[],
    })?;
    let len = bytes.len();
    std::fs::write(out, bytes)?;
    Ok((entries, len))
}

/// An epoch second as UTC, which is what a person comparing two objects wants;
/// the file keeps the raw integer.
fn stamp(ts: i64) -> String {
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(t) => t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => ts.to_string(),
    }
}

fn info(file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = [0u8; HEADER_LEN];
    {
        use std::io::Read;
        std::fs::File::open(file)?.read_exact(&mut raw)?;
    }
    let h = Header::parse(&raw)?;
    // the header is a claim about the file, so say when the file disagrees
    let on_disk = std::fs::metadata(file)?.len();
    if on_disk != h.file_len {
        println!(
            "unverified the header claims {} bytes, the file has {on_disk}",
            h.file_len
        );
    }
    println!("type_id    {}", h.type_id_str());
    println!("content_id {}", h.content_id_hex());
    println!("file_len   {}", h.file_len);
    println!("sections   {}", h.section_count);
    println!("created_at {}", stamp(h.created_at));
    match h.window() {
        Some((a, b)) => println!("window     {}..{}", stamp(a), stamp(b)),
        None => println!("window     none"),
    }
    match h.stream() {
        Some(s) => println!(
            "stream     tree {} gen {} base_seq {}",
            bgpkit_snap::header::hex16(&s.tree_id),
            bgpkit_snap::header::hex16(&s.generation),
            s.base_seq
        ),
        None => println!("stream     none"),
    }
    Ok(())
}

fn verify(file: &str) -> Result<String, Box<dyn std::error::Error>> {
    let raw = std::fs::read(file)?;
    // container level: header, layout, table, content id. Needs no value type.
    let header = bgpkit_snap::verify_bytes(&raw)?;
    if header.type_id_str() == <u32 as SnapValue>::TYPE_ID {
        let snap: Snapshot<u32> = Snapshot::from_bytes(&raw)?;
        return Ok(format!("{} entries, bodies checked", snap.len()));
    }
    Ok(format!(
        "container ok, {} sections, bodies not checked (type {} is not this binary's)",
        header.section_count,
        header.type_id_str()
    ))
}

fn search(file: &str, query: &str) -> Result<(), Box<dyn std::error::Error>> {
    let snap: Snapshot<u32> = Snapshot::open(file)?;
    let hit = match query.parse::<IpNet>() {
        Ok(net) => snap.lpm(net),
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

/// One input line. A value that is missing, not an unsigned integer, or wider
/// than the value type is an error: writing 0 instead would invent data.
fn parse_line(line: &str) -> Result<(IpNet, u32), String> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let prefix: IpNet = v["prefix"]
        .as_str()
        .ok_or("missing \"prefix\"")?
        .parse()
        .map_err(|e: ipnet::AddrParseError| e.to_string())?;
    let raw = v["value"]
        .as_u64()
        .ok_or("\"value\" must be an unsigned integer")?;
    let value = u32::try_from(raw).map_err(|_| format!("\"value\" {raw} does not fit in u32"))?;
    Ok((prefix, value))
}

#[cfg(test)]
mod tests {
    use super::parse_line;

    #[test]
    fn a_value_is_never_silently_truncated_or_invented() {
        assert!(parse_line(r#"{"prefix":"10.0.0.0/8","value":1}"#).is_ok());
        assert!(parse_line(r#"{"prefix":"10.0.0.0/8","value":4294967296}"#).is_err());
        assert!(parse_line(r#"{"prefix":"10.0.0.0/8"}"#).is_err());
        assert!(parse_line(r#"{"prefix":"10.0.0.0/8","value":"1"}"#).is_err());
        assert!(parse_line(r#"{"prefix":"nonsense","value":1}"#).is_err());
    }
}
