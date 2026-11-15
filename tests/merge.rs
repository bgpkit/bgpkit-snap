//! Merging is the daily-merge story: one object per source, folded into one.

use bgpkit_snap::{Opts, SnapValue, Snapshot, Writer};

#[derive(Clone, PartialEq, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct V(u32);

impl SnapValue for V {
    const TYPE_ID: &str = "merge.v:v1";
}

fn object(entries: &[(&str, u32)], window: Option<(i64, i64)>) -> Snapshot<V> {
    let mut w: Writer<V> = Writer::new();
    for (prefix, value) in entries {
        w.insert(prefix.parse().unwrap(), V(*value)).unwrap();
    }
    let bytes = w
        .finish(&Opts {
            created_at: 1_794_614_400,
            window,
            stream: None,
            extras: &[],
        })
        .unwrap();
    Snapshot::from_bytes(&bytes).unwrap()
}

fn opts() -> Opts<'static> {
    Opts {
        created_at: 1_794_614_400,
        window: None,
        stream: None,
        extras: &[],
    }
}

#[test]
fn later_inputs_win_where_they_overlap() {
    let a = object(&[("10.0.0.0/8", 1), ("192.0.2.0/24", 2)], None);
    let b = object(&[("10.0.0.0/8", 9), ("2001:db8::/32", 3)], None);
    let bytes = Snapshot::merge_last_wins(&[&a, &b], &opts()).expect("merge");
    let merged: Snapshot<V> = Snapshot::from_bytes(&bytes).unwrap();
    assert_eq!(merged.len(), 3);
    assert_eq!(
        merged
            .get_exact("10.0.0.0/8".parse().unwrap())
            .map(|v| v.0.to_native()),
        Some(9),
        "the later input wins"
    );
    assert_eq!(
        merged
            .get_exact("192.0.2.0/24".parse().unwrap())
            .map(|v| v.0.to_native()),
        Some(2)
    );
    assert_eq!(
        merged
            .get_exact("2001:db8::/32".parse().unwrap())
            .map(|v| v.0.to_native()),
        Some(3)
    );
}

#[test]
fn a_combine_closure_can_add_values_or_drop_the_prefix() {
    let a = object(&[("10.0.0.0/8", 1), ("192.0.2.0/24", 5)], None);
    let b = object(&[("10.0.0.0/8", 4), ("192.0.2.0/24", 7)], None);

    // sum the two sides, and drop 192.0.2.0/24 entirely
    let bytes = Snapshot::merge_with(&[&a, &b], &opts(), |earlier, later| {
        if earlier.0 == 5 {
            return None;
        }
        Some(V(earlier.0 + later.0))
    })
    .expect("merge");
    let merged: Snapshot<V> = Snapshot::from_bytes(&bytes).unwrap();
    assert_eq!(merged.len(), 1, "the dropped prefix is gone");
    assert_eq!(
        merged
            .get_exact("10.0.0.0/8".parse().unwrap())
            .map(|v| v.0.to_native()),
        Some(5),
        "1 + 4"
    );
}

#[test]
fn a_merge_takes_the_union_of_the_windows_it_was_given() {
    let a = object(&[("10.0.0.0/8", 1)], Some((100, 200)));
    let b = object(&[("192.0.2.0/24", 2)], Some((150, 300)));
    let bytes = Snapshot::merge_last_wins(&[&a, &b], &opts()).expect("merge");
    let header = bgpkit_snap::verify_bytes(&bytes).unwrap();
    assert_eq!(header.window(), Some((100, 300)));

    // one input without a window means the merge cannot claim one either
    let c = object(&[("2001:db8::/32", 3)], None);
    let bytes = Snapshot::merge_last_wins(&[&a, &c], &opts()).expect("merge");
    assert_eq!(
        bgpkit_snap::verify_bytes(&bytes).unwrap().window(),
        None,
        "no invented coverage claim"
    );
}

#[test]
fn a_merge_is_its_inputs_contents_not_their_order() {
    let a = object(&[("10.0.0.0/8", 1)], None);
    let b = object(&[("192.0.2.0/24", 2)], None);
    let forward = Snapshot::merge_last_wins(&[&a, &b], &opts()).unwrap();
    let backward = Snapshot::merge_last_wins(&[&b, &a], &opts()).unwrap();
    assert_eq!(
        forward, backward,
        "disjoint inputs give the same bytes in either order"
    );

    let empty: Vec<&Snapshot<V>> = Vec::new();
    let bytes =
        Snapshot::merge_last_wins(&empty, &opts()).expect("an empty merge is an empty object");
    let merged: Snapshot<V> = Snapshot::from_bytes(&bytes).unwrap();
    assert_eq!(merged.len(), 0);
    assert_eq!(merged.address_counts().v4, bgpkit_snap::Count::NoEntries);
}
