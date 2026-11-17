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

use bgpkit_snap::journal::{recorded_type_id, Journal};
use bgpkit_snap::{
    header::{ENTRY_LEN, HEADER_LEN},
    Header, Opts, Snapshot, Writer,
};
use clap::{Parser, Subcommand, ValueEnum};
use ipnet::IpNet;

#[derive(Parser)]
#[command(name = "bgpkit-snap", version, about = "bgpkit-snap object tool")]
struct Cli {
    /// Print one JSON object instead of text
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

/// The value types this binary can read and write: every integer width the crate
/// implements. Anything else is a `SnapValue` type of the caller's, which only the
/// program that declares it can decode, so the CLI says so by name and stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ValueType {
    U8,
    U16,
    U32,
    U64,
    U128,
}

impl ValueType {
    fn from_type_id(id: &str) -> Option<Self> {
        match id {
            "snap.u8:v1" => Some(Self::U8),
            "snap.u16:v1" => Some(Self::U16),
            "snap.u32:v1" => Some(Self::U32),
            "snap.u64:v1" => Some(Self::U64),
            "snap.u128:v1" => Some(Self::U128),
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
    /// Verify the container, and the bodies when the value type is an integer
    Verify { file: String },
    /// What the object holds: sections, sizes, and counts when the value type is ours
    Stats { file: String },
    /// Keep a snapshot current: a journal is a log of changes over one object
    Journal {
        #[command(subcommand)]
        cmd: JournalCmd,
    },
}

#[derive(Subcommand)]
enum JournalCmd {
    /// Adopt an object as the base of a new journal in this directory
    Init {
        /// The object the log keeps current
        base: String,
        /// The directory the journal lives in
        dir: String,
    },
    /// Append records to the log: one JSON object per line
    ///
    /// `{"prefix": "10.0.0.0/8", "value": 5}` inserts or replaces a value, and
    /// `{"prefix": "10.0.0.0/8", "withdraw": true}` removes one.
    Append { dir: String, records: String },
    /// Fold the log into a new object inside the journal directory
    Checkpoint {
        dir: String,
        /// unix seconds UTC for the object; defaults to now
        #[arg(long)]
        created_at: Option<i64>,
    },
    /// What the log holds: its base, its sequence, its last checkpoint
    Status { dir: String },
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
        Cmd::Stats { file } => match stats(&file, json) {
            Ok(()) => {}
            Err(e) => fail(&format!("{e}")),
        },
        Cmd::Journal { cmd } => {
            let outcome = match cmd {
                JournalCmd::Init { base, dir } => journal_init(&base, &dir, json),
                JournalCmd::Append { dir, records } => journal_append(&dir, &records, json),
                JournalCmd::Checkpoint { dir, created_at } => {
                    journal_checkpoint(&dir, created_at, json)
                }
                JournalCmd::Status { dir } => journal_status(&dir, json),
            };
            if let Err(e) = outcome {
                fail(&format!("{e}"));
            }
        }
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("bgpkit-snap: {msg}");
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
        ValueType::U8 => build_with!(u8),
        ValueType::U16 => build_with!(u16),
        ValueType::U32 => build_with!(u32),
        ValueType::U64 => build_with!(u64),
        ValueType::U128 => build_with!(u128),
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
        Some(ValueType::U8) => Some(Snapshot::<u8>::from_bytes(&raw)?.len()),
        Some(ValueType::U16) => Some(Snapshot::<u16>::from_bytes(&raw)?.len()),
        Some(ValueType::U32) => Some(Snapshot::<u32>::from_bytes(&raw)?.len()),
        Some(ValueType::U64) => Some(Snapshot::<u64>::from_bytes(&raw)?.len()),
        Some(ValueType::U128) => Some(Snapshot::<u128>::from_bytes(&raw)?.len()),
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
    if let (Some(decoded), Some(recorded)) = (entries, bgpkit_snap::recorded_counts(&raw)?) {
        if decoded as u64 != recorded.entries {
            return Err(std::io::Error::other(format!(
                "the body holds {decoded} entries, the object records {}",
                recorded.entries
            ))
            .into());
        }
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

/// What the object holds, as opposed to what its header claims: the section table and,
/// when this binary decodes the value type, the number of prefixes. The header's own
/// fields (content id, creation time, coverage window) belong to `info`, and printing
/// them here as well would make two commands answer the same question.
fn stats(file: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read(file)?;
    let header = bgpkit_snap::verify_bytes(&raw)?;
    let mut sections = Vec::with_capacity(header.section_count as usize);
    for i in 0..header.section_count as usize {
        let at = HEADER_LEN + i * ENTRY_LEN;
        let entry = bgpkit_snap::header::Entry::parse(&raw[at..at + ENTRY_LEN])?;
        sections.push(entry);
    }
    // the writer records the count in the object, so it is available whatever the value
    // type is; an object written before that section existed has none
    let counts = bgpkit_snap::recorded_counts(&raw)?;
    let section_bytes: u64 = sections.iter().map(|s| s.len).sum();
    if json {
        let table: Vec<_> = sections
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "kind": bgpkit_snap::header::hex4(&s.kind),
                    "required": s.required,
                    "bytes": s.len,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "file": file,
                "type_id": header.type_id_str(),
                "sections": table,
                "section_bytes": section_bytes,
                "entries": counts.map(|c| c.entries),
                "v4_entries": counts.map(|c| c.v4),
                "v6_entries": counts.map(|c| c.v6),
            })
        );
        return Ok(());
    }
    println!("file          {file}");
    println!("type_id       {}", header.type_id_str());
    println!("sections      {}", sections.len());
    for s in &sections {
        println!(
            "  id {:>3}  kind {}{}  {:>12} bytes",
            s.id,
            bgpkit_snap::header::hex4(&s.kind),
            if s.required { " required" } else { "         " },
            s.len
        );
    }
    println!("section_bytes {section_bytes}");
    match counts {
        Some(c) => {
            println!("entries       {} (v4 {}, v6 {})", c.entries, c.v4, c.v6);
        }
        None => println!(
            "entries       not recorded (written before section 4 existed, or by another \
             writer)"
        ),
    }
    Ok(())
}

/// Turn a journal into one object. Writing a journal is the application's job; what a
/// caller needs from the CLI is the readable, distributable result.
/// `journal init`: adopt an object as the base of a new journal.
fn journal_init(base: &str, dir: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    // the base's own header says which value type it holds, so the caller does not
    // have to repeat what the file already records
    let raw = std::fs::read(base)?;
    let header = Header::parse(&raw)?;
    let type_id = header.type_id_str();
    let value = ValueType::from_type_id(&type_id).ok_or_else(|| {
        std::io::Error::other(format!(
            "{base} holds {type_id}, which this binary cannot decode: a value type belongs to \
             the program that declares it, and that program opens the journal itself"
        ))
    })?;
    macro_rules! init_as {
        ($t:ty) => {{
            let journal: Journal<$t> = Journal::attach(base, dir)?;
            (journal.len(), journal.seq(), journal.generation())
        }};
    }
    let (entries, seq, generation) = match value {
        ValueType::U8 => init_as!(u8),
        ValueType::U16 => init_as!(u16),
        ValueType::U32 => init_as!(u32),
        ValueType::U64 => init_as!(u64),
        ValueType::U128 => init_as!(u128),
    };
    let content_id = bgpkit_snap::header::hex32(&header.content_id);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "dir": dir,
                "base": base,
                "base_content_id": content_id,
                "type_id": type_id,
                "generation": bgpkit_snap::header::hex16(&generation),
                "entries": entries,
                "seq": seq,
            })
        );
    } else {
        println!("journal in {dir}: base {base} ({content_id}), {entries} entries at seq {seq}");
    }
    Ok(())
}

/// `journal append`: add records to the log, then make them durable.
fn journal_append(dir: &str, records: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let value = journal_value_type(dir)?;
    let text = std::fs::read_to_string(records)?;
    macro_rules! append_as {
        ($t:ty) => {{
            let mut journal: Journal<$t> = Journal::open(dir)?;
            let (mut inserts, mut withdrawals) = (0usize, 0usize);
            for (i, line) in text.lines().filter(|l| !l.trim().is_empty()).enumerate() {
                let v: serde_json::Value = serde_json::from_str(line)
                    .map_err(|e| std::io::Error::other(format!("{e}, line {}", i + 1)))?;
                let prefix: IpNet = v["prefix"]
                    .as_str()
                    .ok_or_else(|| {
                        std::io::Error::other(format!("missing prefix, line {}", i + 1))
                    })?
                    .parse()
                    .map_err(|e: ipnet::AddrParseError| {
                        std::io::Error::other(format!("{e}, line {}", i + 1))
                    })?;
                if v.get("withdraw").and_then(|w| w.as_bool()).unwrap_or(false) {
                    journal
                        .withdraw(prefix)
                        .map_err(|e| std::io::Error::other(format!("{e}, line {}", i + 1)))?;
                    withdrawals += 1;
                } else {
                    let (_, raw) = parse_line(line, value)
                        .map_err(|e| std::io::Error::other(format!("{e}, line {}", i + 1)))?;
                    let value: $t = raw.try_into().map_err(|_| {
                        std::io::Error::other(format!("{raw} does not fit, line {}", i + 1))
                    })?;
                    journal
                        .insert(prefix, value)
                        .map_err(|e| std::io::Error::other(format!("{e}, line {}", i + 1)))?;
                    inserts += 1;
                }
            }
            journal.sync()?;
            (journal.len(), journal.seq(), inserts, withdrawals)
        }};
    }
    let (entries, seq, inserts, withdrawals) = match value {
        ValueType::U8 => append_as!(u8),
        ValueType::U16 => append_as!(u16),
        ValueType::U32 => append_as!(u32),
        ValueType::U64 => append_as!(u64),
        ValueType::U128 => append_as!(u128),
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "dir": dir,
                "inserts": inserts,
                "withdrawals": withdrawals,
                "entries": entries,
                "next_seq": seq,
            })
        );
    } else {
        println!(
            "appended to {dir}: {inserts} inserts, {withdrawals} withdrawals, {entries} entries, \
             next seq {seq}"
        );
    }
    Ok(())
}

/// `journal checkpoint`: fold the log into a new object inside the directory.
fn journal_checkpoint(
    dir: &str,
    created_at: Option<i64>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let value = journal_value_type(dir)?;
    let opts = Opts {
        created_at: created_at.unwrap_or_else(|| chrono::Utc::now().timestamp()),
        stream: None,
        window: None,
        extras: &[],
    };
    macro_rules! checkpoint_as {
        ($t:ty) => {{
            let mut journal: Journal<$t> = Journal::open(dir)?;
            let entries = journal.len();
            let seq = journal.seq();
            let path = journal.checkpoint(&opts)?;
            (entries, seq, path)
        }};
    }
    let (entries, seq, path) = match value {
        ValueType::U8 => checkpoint_as!(u8),
        ValueType::U16 => checkpoint_as!(u16),
        ValueType::U32 => checkpoint_as!(u32),
        ValueType::U64 => checkpoint_as!(u64),
        ValueType::U128 => checkpoint_as!(u128),
    };
    // the object it just wrote is the answer, so report its own header rather than
    // the arguments this call was made with
    let raw = std::fs::read(&path)?;
    let header = Header::parse(&raw)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "dir": dir,
                "object": path.display().to_string(),
                "content_id": bgpkit_snap::header::hex32(&header.content_id),
                "entries": entries,
                "base_seq": header.stream().map(|s| s.base_seq),
                "next_seq": seq,
                "bytes": raw.len(),
            })
        );
    } else {
        println!(
            "checkpointed {dir}: {} entries at seq {}, object {} ({} bytes)",
            entries,
            seq,
            path.display(),
            raw.len()
        );
    }
    Ok(())
}

/// `journal status`: what the log holds and where it is anchored.
fn journal_status(dir: &str, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let value = journal_value_type(dir)?;
    macro_rules! status_as {
        ($t:ty) => {{
            let journal: Journal<$t> = Journal::open(dir)?;
            (
                journal.len(),
                journal.seq(),
                journal.base().cloned(),
                journal.last_checkpoint().cloned(),
                journal.generation(),
            )
        }};
    }
    let (entries, seq, base, checkpoint, generation) = match value {
        ValueType::U8 => status_as!(u8),
        ValueType::U16 => status_as!(u16),
        ValueType::U32 => status_as!(u32),
        ValueType::U64 => status_as!(u64),
        ValueType::U128 => status_as!(u128),
    };
    let base_content_id = base.as_ref().map(|(id, _)| id.clone());
    let base_path = base.as_ref().map(|(_, p)| p.clone());
    let checkpoint =
        checkpoint.map(|(covered, file)| serde_json::json!({ "base_seq": covered, "file": file }));
    if json {
        println!(
            "{}",
            serde_json::json!({
                "dir": dir,
                "type_id": type_id_of(value),
                "generation": bgpkit_snap::header::hex16(&generation),
                "base_content_id": base_content_id,
                "base_path": base_path,
                "entries": entries,
                "next_seq": seq,
                "checkpoint": checkpoint,
            })
        );
    } else {
        match (&base_content_id, &base_path) {
            (Some(id), Some(path)) => println!("base: {path} ({id})"),
            _ => println!("base: none recorded"),
        }
        match &checkpoint {
            Some(c) => println!(
                "checkpoint: {} covering up to seq {}",
                c["file"], c["base_seq"]
            ),
            None => println!("checkpoint: none yet, the tree comes from the base"),
        }
        println!(
            "entries: {entries}, next seq: {seq}, generation: {}",
            bgpkit_snap::header::hex16(&generation)
        );
    }
    Ok(())
}

/// The value type a journal directory records, so a verb can pick its `T` without the
/// caller repeating what the directory already says.
fn journal_value_type(dir: &str) -> Result<ValueType, Box<dyn std::error::Error>> {
    let type_id = recorded_type_id(dir)?.ok_or_else(|| {
        std::io::Error::other(format!(
            "{dir} holds no journal: start one with journal init <base.snap> {dir}"
        ))
    })?;
    match ValueType::from_type_id(&type_id) {
        Some(v) => Ok(v),
        None => Err(Box::new(std::io::Error::other(format!(
            "{dir} holds {type_id}, which this binary cannot decode: a value type belongs to \
             the program that declares it, and that program opens the journal itself"
        ))) as Box<dyn std::error::Error>),
    }
}

fn type_id_of(ty: ValueType) -> &'static str {
    match ty {
        ValueType::U8 => "snap.u8:v1",
        ValueType::U16 => "snap.u16:v1",
        ValueType::U32 => "snap.u32:v1",
        ValueType::U64 => "snap.u64:v1",
        ValueType::U128 => "snap.u128:v1",
    }
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
        ValueType::U8 => u8::try_from(raw)
            .map(|n| (prefix, n as u64))
            .map_err(|_| format!("\"value\" {raw} does not fit in u8")),
        ValueType::U16 => u16::try_from(raw)
            .map(|n| (prefix, n as u64))
            .map_err(|_| format!("\"value\" {raw} does not fit in u16")),
        ValueType::U32 => u32::try_from(raw)
            .map(|n| (prefix, n as u64))
            .map_err(|_| format!("\"value\" {raw} does not fit in u32")),
        // a u128 object can be read and searched; `build` writes what its input can
        // express, and a JSON integer here is a u64
        ValueType::U64 | ValueType::U128 => Ok((prefix, raw)),
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
