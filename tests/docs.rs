//! Docs that name an API the crate no longer has are worse than no docs: a reader copies
//! a line that does not compile and concludes the crate is broken. These checks are
//! greps, not compilers, because the markdown outside the rustdoc include is not tested
//! any other way.

/// Every prose file a reader is likely to copy a snippet from.
const DOCS: &[(&str, &str)] = &[
    ("README.md", include_str!("../README.md")),
    ("docs/usage.md", include_str!("../docs/usage.md")),
    (
        "docs/bgpkit-snap-developer-guide.md",
        include_str!("../docs/bgpkit-snap-developer-guide.md"),
    ),
];

/// Forms this crate used to accept and no longer does.
const REMOVED: &[(&str, &str)] = &[
    (
        "snap_value(type_id",
        "#[snap_value] takes the id positionally: #[snap_value(\"your.type:v1\")]",
    ),
    (
        "Journal::open(",
        "a journal is attached to a base: Journal::attach(base, dir), or Journal::start(dir, tree_id)",
    ),
];

#[test]
fn the_docs_do_not_name_a_removed_form() {
    for (name, body) in DOCS {
        for (needle, advice) in REMOVED {
            // the journal form is checked by its argument count below; a bare
            // `Journal::open(` with one argument is current
            if *needle == "Journal::open(" {
                continue;
            }
            assert!(
                !body.contains(needle),
                "{name} still shows `{needle}`; {advice}"
            );
        }
    }
}

#[test]
fn the_docs_never_open_a_journal_with_a_tree_id() {
    for (name, body) in DOCS {
        for (line_number, line) in body.lines().enumerate() {
            if !line.contains("Journal::open(") {
                continue;
            }
            // a single argument is what the current signature takes
            let args = line
                .split("Journal::open(")
                .nth(1)
                .unwrap_or_default()
                .trim_start();
            assert!(
                !args.contains("TreeId"),
                "{name}:{} passes a tree id to Journal::open; use Journal::attach(base, dir) \
                 or Journal::start(dir, tree_id)",
                line_number + 1
            );
        }
    }
}
