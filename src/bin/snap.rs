//! The `snap` CLI: build, info, verify, search.
//!
//! `info` reads the 192-byte header and nothing else, which is the point of the
//! fixed header: identification is one small read.
//!
//! Every command takes `--json` and prints one JSON object instead of text, so a
//! program (or an agent) can read the answer without parsing prose. The text form
//! stays for people.

use std::path::{Path, PathBuf};
use std::process::exit;

use bgpkit_snap::{header::HEADER_LEN, Header, Snapshot, Writer};
use clap::{Parser, Subcommand, ValueEnum};
use ipnet::IpNet;

#[derive(Parser)]
#[command(name = "snap", version, about = "bgpkit-snap object tool")]
struct Cli {
    /// Print one JSON object instead of text
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

/// The value types this binary can decode. A caller's own `SnapValue` type needs the
/// program that defines it; the two here are what `build` writes and `search` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ValueType {
    U32,
    U64,
}

impl ValueType {
    fn from_type_id(id: &str) -> Option<Self> {
        match id {
            "snap.u32:v1" => Some(Self::U32),
            "snap.u64:v1" => Some(Self::U64),
            _ => None,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Build an object from a JSON lines file of {"prefix": .., "value": n}
    Build {
        input: String,
        #[arg(short, long)]
        out: String,
        /// Value type the object stores; the input's integers are checked against it
        #[arg(long, value_enum, default_value = "u32")]
        value: ValueType,
        /// unix seconds UTC; defaults to now
        #[arg(long)]
        created_at: Option<i64>,
        /// Coverage claim as FROM,TO in unix seconds
        #[arg(long)]
        window: Option<String>,
    },
    /// Print what the 192-byte header says
    Info { file: String },
    /// Verify the container, and the bodies when the value type is u32 or u64
    Verify { file: String },
    /// Longest-prefix match for an address or prefix, in a u32 or u64 object
    Search { file: String, query: String },
}

fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    match cli.cmd {
        Cmd::Build {
            input,
            out,
            value,
            created_at,
            window,
        } => match build(&input, &out, value, created_at, window.as_deref()) {
            Ok((entries, bytes)) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"out": out, "entries": entries, "bytes": bytes})
                    );
                } else {
                    println!("wrote {out}: {entries} entries, {bytes} bytes");
                }
            }
            Err(e) => fail(&format!("{e}")),
        },
        Cmd::Info { file } => match info(&file, json) {
            Ok(()) => {}
            Err(e) => fail(&format!("{e}")),
        },
        Cmd::Verify { file } => match verify(&file, json) {
            Ok(()) => {}
            Err(e) => fail(&format!("{e}")),
        },
        Cmd::Search { file, query } => match search(&file, &query, json) {
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
    value: ValueType,
    created_at: Option<i64>,
    window: Option<&str>,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(input)?;
    let parsed_window = match window {
        Some(spec) => {
            let (from, to) = spec
                .split_once(',')
                .ok_or_else(|| std::io::Error::other("--window wants FROM,TO unix seconds"))?;
            Some((from.trim().parse()?, to.trim().parse()?))
        }
        None => None,
    };
    let opts = bgpkit_snap::Opts {
        created_at: created_at.unwrap_or_else(|| chrono::Utc::now().timestamp()),
        stream: None,
        window: parsed_window,
        extras: &[],
    };
    // `fs::write`, the previous writer, followed a symlink at the output path; renaming
    // into place would replace the link instead, so resolve one level and update the
    // object the link names
    let target = resolve_symlink(Path::new(out));
    // `finish_to` writes beside the target and renames, so a build that fails on a
    // full disk leaves the object already at `out` untouched instead of truncating it
    macro_rules! build_with {
        ($t:ty) => {{
            let mut w: Writer<$t> = Writer::new();
            for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
                let (prefix, raw) = parse_line(line, value)
                    .map_err(|e| std::io::Error::other(format!("{e}, line {}", i + 1)))?;
                let v: $t = raw.try_into().map_err(|_| {
                    std::io::Error::other(format!("{raw} does not fit, line {}", i + 1))
                })?;
                w.insert(prefix, v)
                    .map_err(|e| std::io::Error::other(format!("{e}, line {}", i + 1)))?;
            }
            let entries = w.len();
            let len = w.finish_to(&target, &opts)?;
            (entries, len as usize)
        }};
    }
    Ok(match value {
        ValueType::U32 => build_with!(u32),
        ValueType::U64 => build_with!(u64),
    })
}

/// One level of symlink at `path`, so an atomic replace updates the target a caller
/// linked to instead of replacing the link itself.
fn resolve_symlink(path: &Path) -> PathBuf {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return path.to_path_buf();
    };
    if !meta.file_type().is_symlink() {
        return path.to_path_buf();
    }
    match std::fs::read_link(path) {
        Ok(target) if target.is_absolute() => target,
        Ok(target) => path.parent().unwrap_or(Path::new(".")).join(target),
        Err(_) => path.to_path_buf(),
    }
}

/// An epoch second as UTC, which is what a person comparing two objects wants;
/// the file keeps the raw integer.
fn stamp(ts: i64) -> String {
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(t) => t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        None => ts.to_string(),
    }
}

fn info(file: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut raw = [0u8; HEADER_LEN];
    {
        use std::io::Read;
        std::fs::File::open(file)?.read_exact(&mut raw)?;
    }
    let h = Header::parse(&raw)?;
    // the header is a claim about the file, so say when the file disagrees
    let on_disk = std::fs::metadata(file)?.len();
    let consistent = on_disk == h.file_len;
    if json {
        let stream = h.stream().map(|s| {
            serde_json::json!({
                "tree_id": bgpkit_snap::header::hex16(&s.tree_id),
                "generation": bgpkit_snap::header::hex16(&s.generation),
                "base_seq": s.base_seq,
            })
        });
        let window = h.window().map(|(a, b)| serde_json::json!([a, b]));
        println!(
            "{}",
            serde_json::json!({
                "type_id": h.type_id_str(),
                "content_id": h.content_id_hex(),
                "file_len": h.file_len,
                "file_len_on_disk": on_disk,
                "consistent": consistent,
                "sections": h.section_count,
                "created_at": stamp(h.created_at),
                "created_at_unix": h.created_at,
                "window": window,
                "stream": stream,
            })
        );
        return Ok(());
    }
    if !consistent {
        println!(
            "warning    the header claims {} bytes, the file has {on_disk}",
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

fn verify(file: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read(file)?;
    // container level: header, layout, table, content id. Needs no value type.
    let header = bgpkit_snap::verify_bytes(&raw)?;
    let typed = ValueType::from_type_id(&header.type_id_str());
    let entries = match typed {
        Some(ValueType::U32) => Some(Snapshot::<u32>::from_bytes(&raw)?.len()),
        Some(ValueType::U64) => Some(Snapshot::<u64>::from_bytes(&raw)?.len()),
        None => None,
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "type_id": header.type_id_str(),
                "sections": header.section_count,
                "bodies_checked": entries.is_some(),
                "entries": entries,
            })
        );
        return Ok(());
    }
    match entries {
        Some(n) => println!("ok: {n} entries, bodies checked"),
        None => println!(
            "ok: container ok, {} sections, bodies not checked (type {} is not one this binary decodes)",
            header.section_count,
            header.type_id_str()
        ),
    }
    Ok(())
}

fn search(file: &str, query: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let header = file_header(file)?;
    let Some(ty) = ValueType::from_type_id(&header.type_id_str()) else {
        // say what the object holds and both ways out: a caller who meant to query
        // their own type needs the program that declares it, not a hex dump
        return Err(std::io::Error::other(format!(
            "this object holds {}, which `snap search` cannot decode; it decodes \
             snap.u32:v1 and snap.u64:v1. Query it from a program that defines that \
             SnapValue type (`Snapshot::open` in the developer guide), or rebuild it \
             with `snap build --value u32`",
            header.type_id_str()
        ))
        .into());
    };
    let query_ip: Option<std::net::IpAddr> = query.parse().ok();
    let query_net: Option<IpNet> = query.parse().ok();
    if query_ip.is_none() && query_net.is_none() {
        return Err(std::io::Error::other(format!("{query} is not an address or a prefix")).into());
    }
    // the owned view decodes the one value a lookup lands on, so both widths come back
    // as a plain u128 here without a per-width branch in the printing code
    macro_rules! find {
        ($t:ty) => {{
            let snap: Snapshot<$t> = Snapshot::open(file)?;
            let owned = snap.owned();
            let hit = match (query_net, query_ip) {
                (Some(net), _) => owned.lpm(net)?,
                (None, Some(addr)) => owned.search(addr)?,
                (None, None) => unreachable!("checked above"),
            };
            hit.map(|(prefix, value)| (prefix, value as u128))
        }};
    }
    let hit = match ty {
        ValueType::U32 => find!(u32),
        ValueType::U64 => find!(u64),
    };
    match hit {
        Some((prefix, value)) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "query": query,
                        "type_id": header.type_id_str(),
                        "match": {"prefix": prefix.to_string(), "value": value},
                    })
                );
            } else {
                println!("{prefix} -> {value}");
            }
        }
        None => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"query": query, "type_id": header.type_id_str(), "match": null})
                );
            } else {
                println!("no match");
            }
        }
    }
    Ok(())
}

fn file_header(file: &str) -> Result<Header, Box<dyn std::error::Error>> {
    let mut raw = [0u8; HEADER_LEN];
    {
        use std::io::Read;
        std::fs::File::open(file)?.read_exact(&mut raw)?;
    }
    Ok(Header::parse(&raw)?)
}

/// One input line. A value that is missing, not an unsigned integer, or wider
/// than the chosen value type is an error: writing 0 would invent data.
fn parse_line(line: &str, value: ValueType) -> Result<(IpNet, u64), String> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let prefix: IpNet = v["prefix"]
        .as_str()
        .ok_or("missing \"prefix\"")?
        .parse()
        .map_err(|e: ipnet::AddrParseError| e.to_string())?;
    let raw = v["value"]
        .as_u64()
        .ok_or("\"value\" must be an unsigned integer")?;
    match value {
        ValueType::U32 => u32::try_from(raw)
            .map(|n| (prefix, n as u64))
            .map_err(|_| format!("\"value\" {raw} does not fit in u32")),
        ValueType::U64 => Ok((prefix, raw)),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_line, ValueType};

    #[test]
    fn a_value_is_never_silently_truncated_or_invented() {
        let u32v = ValueType::U32;
        assert!(parse_line(r#"{"prefix":"10.0.0.0/8","value":1}"#, u32v).is_ok());
        assert!(parse_line(r#"{"prefix":"10.0.0.0/8","value":4294967296}"#, u32v).is_err());
        assert!(parse_line(r#"{"prefix":"10.0.0.0/8"}"#, u32v).is_err());
        assert!(parse_line(r#"{"prefix":"10.0.0.0/8","value":"1"}"#, u32v).is_err());
        assert!(parse_line(r#"{"prefix":"nonsense","value":1}"#, u32v).is_err());
    }

    #[test]
    fn a_u64_object_takes_values_u32_would_refuse() {
        let big = r#"{"prefix":"10.0.0.0/8","value":4294967296}"#;
        assert!(parse_line(big, ValueType::U64).is_ok());
        assert!(parse_line(big, ValueType::U32).is_err());
    }
}
