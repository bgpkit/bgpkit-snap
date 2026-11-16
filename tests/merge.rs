//! Merging is the daily-merge story: one object per source, folded into one.

use bgpkit_snap::{ExtraSection, Opts, SnapValue, Snapshot, Writer};

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
    let bytes = Snapshot::merge_with(&[&a, &b], &opts(), |_, earlier, later| {
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

    // disjoint spans cannot claim one continuous window
    let far = object(&[("203.0.113.0/24", 9)], Some((300, 400)));
    let bytes = Snapshot::merge_last_wins(&[&a, &far], &opts()).expect("merge");
    assert_eq!(
        bgpkit_snap::verify_bytes(&bytes).unwrap().window(),
        None,
        "nobody observed the hole between the two spans"
    );

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
    // both sides fold into one HashMap and then into one Writer, so this pins the
    // input order only; that the writer's own insertion order does not matter is
    // tests/golden.rs's job
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

#[test]
fn a_merge_refuses_inputs_that_carry_their_own_section() {
    // a value whose handle points into a payload section: merging it away would leave
    // the handle pointing at nothing while the object still opened cleanly
    let mut w: Writer<V> = Writer::new();
    w.insert("10.0.0.0/8".parse().unwrap(), V(1)).unwrap();
    let arena = [1u8, 2, 3, 4];
    let bytes = w
        .finish(&Opts {
            created_at: 1_794_614_400,
            window: None,
            stream: None,
            extras: &[ExtraSection {
                id: 16,
                kind: bgpkit_snap::KIND_PAYLOAD,
                required: true,
                bytes: &arena,
            }],
        })
        .unwrap();
    struct Knows;
    impl bgpkit_snap::Validator for Knows {
        fn knows(&self, entry: &bgpkit_snap::Entry) -> bool {
            entry.id == 16
        }
    }
    let with_section: Snapshot<V> = Snapshot::from_bytes_with(&bytes, &Knows).unwrap();
    let plain = object(&[("192.0.2.0/24", 2)], None);

    let err = Snapshot::merge_last_wins(&[&with_section, &plain], &opts())
        .expect_err("an object with a payload section must not be merged");
    assert!(format!("{err}").contains("its own section"), "got {err}");

    // and a caller section on the merge itself is refused for the same reason
    let side = [7u8; 4];
    let err = Snapshot::merge_last_wins(
        &[&plain],
        &Opts {
            created_at: 1_794_614_400,
            window: None,
            stream: None,
            extras: &[ExtraSection {
                id: 32,
                kind: bgpkit_snap::KIND_PAYLOAD,
                required: false,
                bytes: &side,
            }],
        },
    )
    .expect_err("a merge cannot carry a caller section");
    assert!(format!("{err}").contains("caller section"), "got {err}");
}

#[test]
fn a_dropped_prefix_can_come_back_from_a_later_input() {
    // documented semantics: `None` drops the prefix from that fold, it is not a
    // tombstone, and absence never reaches the closure
    let a = object(&[("10.0.0.0/8", 1)], None);
    let b = object(&[("10.0.0.0/8", 2)], None);
    let c = object(&[("10.0.0.0/8", 3), ("192.0.2.0/24", 4)], None);
    let bytes = Snapshot::merge_with(&[&a, &b, &c], &opts(), |_, earlier, _| {
        if earlier.0 == 1 {
            return None;
        }
        Some(V(earlier.0 * 10))
    })
    .expect("merge");
    let merged: Snapshot<V> = Snapshot::from_bytes(&bytes).unwrap();
    assert_eq!(
        merged
            .get_exact("10.0.0.0/8".parse().unwrap())
            .map(|v| v.0.to_native()),
        Some(3),
        "the third input puts the prefix back"
    );
}
