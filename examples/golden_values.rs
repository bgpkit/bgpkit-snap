//! Print the pinned values for tests/golden.rs.
use bgpkit_snap::{Header, Opts, SnapValue, Writer};

#[derive(Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct V(u32);
impl SnapValue for V {
    const TYPE_ID: &str = "golden.v:v1";
}

fn main() {
    let mut w: Writer<V> = Writer::new();
    for (p, v) in [
        ("10.0.0.0/8", 1u32),
        ("10.1.0.0/16", 2),
        ("192.0.2.0/24", 3),
        ("2001:db8::/32", 4),
    ] {
        w.insert(p.parse().unwrap(), V(v));
    }
    let bytes = w
        .finish(&Opts {
            created_at: "2026-11-14T00:00:00Z",
            window: Some((1_790_000_000, 1_794_355_200)),
            stream: None,
            extras: &[],
        })
        .unwrap();
    let h = Header::parse(&bytes[..192]).unwrap();
    println!("len {}", bytes.len());
    println!("sha256 {}", blake3::hash(&bytes).to_hex());
    println!("content_id {}", h.content_id_hex());
}
