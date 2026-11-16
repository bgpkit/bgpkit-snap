//! The reader takes untrusted bytes. Nothing here may panic: a wrong byte is an
//! `Err`, never an abort.
//!
//! Deterministic by construction: fixed inputs, a fixed LCG, no time or randomness,
//! so a failure is reproducible from the test name alone.

use bgpkit_snap::{Opts, SnapValue, Snapshot, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct V(u32);

impl SnapValue for V {
    const TYPE_ID: &str = "robust.v:v1";
}

fn object() -> Vec<u8> {
    let mut w: Writer<V> = Writer::new();
    for (prefix, value) in [
        ("10.0.0.0/8", 1u32),
        ("10.1.0.0/16", 2),
        ("192.0.2.0/24", 3),
        ("2001:db8::/32", 4),
    ] {
        w.insert(prefix.parse().unwrap(), V(value)).unwrap();
    }
    w.finish(&Opts::now()).unwrap()
}

/// Run both readers over `bytes`; a panic is a test failure with the bytes' length
/// and the case, which is what makes a mutation crash reproducible.
fn readers_must_not_panic(bytes: &[u8], case: &str) {
    let verify = std::panic::catch_unwind(|| bgpkit_snap::verify_bytes(bytes).is_ok());
    assert!(verify.is_ok(), "verify_bytes panicked on {case}");
    let open = std::panic::catch_unwind(|| Snapshot::<V>::from_bytes(bytes).is_ok());
    assert!(
        open.is_ok(),
        "Snapshot::from_bytes panicked on {case} (len {})",
        bytes.len()
    );
}

#[test]
fn every_single_byte_mutation_is_a_refusal_not_a_panic() {
    let base = object();
    for i in 0..base.len() {
        for bit in [0x01u8, 0x80] {
            let mut bytes = base.clone();
            bytes[i] ^= bit;
            readers_must_not_panic(&bytes, &format!("byte {i} bit {bit:#x}"));
        }
    }
}

#[test]
fn every_truncation_is_a_refusal_not_a_panic() {
    let base = object();
    for len in 0..base.len() {
        readers_must_not_panic(&base[..len], &format!("truncated to {len}"));
    }
}

#[test]
fn trailing_garbage_is_a_refusal_not_a_panic() {
    let base = object();
    for extra in 1..=64 {
        let mut bytes = base.clone();
        bytes.extend(std::iter::repeat_n(0xA5u8, extra));
        readers_must_not_panic(&bytes, &format!("{extra} trailing bytes"));
    }
}

#[test]
fn arbitrary_bytes_are_a_refusal_not_a_panic() {
    // a fixed LCG keeps this reproducible without a dependency
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u8
    };
    for case in 0..2000 {
        let len = 1 + (case % 1024);
        let bytes: Vec<u8> = (0..len).map(|_| next()).collect();
        readers_must_not_panic(&bytes, &format!("random case {case}"));
    }
    // and the same bytes behind a valid header, which is the harder path
    let base = object();
    for case in 0..500 {
        let cut = 192 + (case * 7) % (base.len() - 192);
        let mut bytes = base[..cut].to_vec();
        for byte in bytes[192..].iter_mut().take(8) {
            *byte = next();
        }
        readers_must_not_panic(&bytes, &format!("valid header, mutated body {case}"));
    }
}

#[test]
fn a_damaged_journal_segment_is_an_error_not_a_panic() {
    let dir = std::env::temp_dir().join(format!("snap-robust-journal-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let tree = bgpkit_snap::TreeId::from_name("robust");
    {
        let mut j: bgpkit_snap::journal::Journal<V> =
            bgpkit_snap::journal::Journal::open(&dir, tree).unwrap();
        j.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
        j.sync().unwrap();
    }
    let segment = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("segment-"))
        })
        .expect("a segment was written");

    let healthy = std::fs::read(&segment).unwrap();
    let mut state: u64 = 12345;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (state >> 33) as u8
    };
    for case in 0..200 {
        let mut bytes = healthy.clone();
        // damage inside the record area, past the segment header
        let at = 32 + (case * 13) % (bytes.len() - 32);
        bytes[at] ^= next() | 1;
        std::fs::write(&segment, &bytes).unwrap();
        let opened = std::panic::catch_unwind(|| {
            match bgpkit_snap::journal::Journal::<V>::open(&dir, tree) {
                Ok(_) | Err(_) => (),
            }
        });
        assert!(
            opened.is_ok(),
            "journal open panicked on damage at byte {at}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// Recompute the content id and header crc after a body mutation, so the object is
/// still a valid container and the reader has to reach the archive checks.
fn reseal(bytes: &mut [u8]) {
    let header = bgpkit_snap::Header::parse(&bytes[..192]).expect("header");
    let table_end = 192 + header.section_table_len as usize;
    let table = &bytes[192..table_end];
    let mut h = blake3::Hasher::new();
    h.update(b"bgpkit-snap-v4\0");
    h.update(&bytes[..148]);
    h.update(table);
    let mut cursor = table_end;
    for i in 0..header.section_count as usize {
        let entry = bgpkit_snap::Entry::parse(&table[i * 64..(i + 1) * 64]).expect("entry");
        while !cursor.is_multiple_of(16) {
            cursor += 1;
        }
        h.update(&bytes[cursor..cursor + entry.len as usize]);
        cursor += entry.len as usize;
    }
    bytes[156..188].copy_from_slice(h.finalize().as_bytes());
    let crc = crc32c::crc32c(&bytes[..188]);
    bytes[188..192].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn a_resealed_object_with_a_corrupt_body_is_refused_by_the_archive_check() {
    let base = object();
    let mut reached_archive = 0;
    let mut state: u64 = 99;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (state >> 33) as u8
    };
    for case in 0..500 {
        let mut bytes = base.clone();
        // mutate inside the v4 trie body, past the header and table
        let header = bgpkit_snap::Header::parse(&bytes[..192]).unwrap();
        let body_start = 192 + header.section_table_len as usize;
        let at = body_start + (case * 31) % (bytes.len() - body_start - 1);
        bytes[at] ^= next() | 1;
        reseal(&mut bytes);

        // the container now passes, so the reader must decide on the archive itself
        let verify = std::panic::catch_unwind(|| bgpkit_snap::verify_bytes(&bytes).is_ok());
        assert!(
            verify.is_ok(),
            "verify_bytes panicked on resealed case {case}"
        );
        let opened = std::panic::catch_unwind(|| Snapshot::<V>::from_bytes(&bytes).is_ok());
        assert!(
            opened.is_ok(),
            "from_bytes panicked on resealed case {case}"
        );
        if !opened.unwrap() {
            reached_archive += 1;
        }
    }
    assert!(
        reached_archive > 0,
        "a resealed corrupt body must be refused by the archive check, not before it"
    );
}
