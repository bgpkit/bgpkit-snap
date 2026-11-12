//! Deterministic fixture generator: a few hundred prefixes in a shuffled
//! order, so the same logical set can be produced in different insertion
//! orders and must still yield one `content_id`.

use ipnet::IpNet;

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 33
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut out = String::from("testdata/fixture.jsonl");
    let mut n: usize = 200;
    let mut seed: u64 = 7;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out = args.next().unwrap(),
            "--n" => n = args.next().unwrap().parse().unwrap(),
            "--seed" => seed = args.next().unwrap().parse().unwrap(),
            other => panic!("unknown arg {other}"),
        }
    }

    // A handful of supernets first, then more specifics, so LPM has something
    // to choose between.
    let mut rows: Vec<(IpNet, u32)> = vec![
        ("10.0.0.0/8".parse().unwrap(), 64500),
        ("10.1.0.0/16".parse().unwrap(), 64501),
        ("192.0.2.0/24".parse().unwrap(), 64502),
        ("2001:db8::/32".parse().unwrap(), 64503),
        ("2001:db8:1::/48".parse().unwrap(), 64504),
        ("0.0.0.0/0".parse().unwrap(), 64496),
    ];

    let mut state = seed;
    while rows.len() < n {
        let r = lcg(&mut state);
        if r.is_multiple_of(3) {
            let a = 10u8.wrapping_add((r >> 8) as u8);
            let b = (r >> 16) as u8;
            let len = 16 + (r % 9) as u8;
            if let Ok(net) = ipnet::Ipv4Net::new(std::net::Ipv4Addr::new(a, b, 0, 0), len) {
                rows.push((IpNet::V4(net), 64500 + (r % 500) as u32));
            }
        } else {
            let seg = (r >> 8) as u16;
            let len = 32 + (r % 17) as u8;
            if let Ok(net) = ipnet::Ipv6Net::new(
                std::net::Ipv6Addr::new(0x2001, 0xdb8, seg, 0, 0, 0, 0, 0),
                len,
            ) {
                rows.push((IpNet::V6(net), 64500 + (r % 500) as u32));
            }
        }
    }

    // shuffle so the file order is not the canonical order
    for i in (1..rows.len()).rev() {
        let j = (lcg(&mut state) as usize) % (i + 1);
        rows.swap(i, j);
    }

    if let Some(dir) = std::path::Path::new(&out).parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    let mut text = String::new();
    for (p, v) in &rows {
        text.push_str(&format!("{{\"prefix\":\"{p}\",\"value\":{v}}}\n"));
    }
    std::fs::write(&out, text).unwrap();
    println!("wrote {} rows to {}", rows.len(), out);
}
