//! H5 T9 fallback: no existing pinned FILE-body delete fixture.
//!
//! No test or fixture door in `crates/oneiron/tests` or
//! `crates/oneiron/src/test_doors` sets up a file-owning record with a reader
//! pin to hold across a delete. This test gives `remaining_after_delete` two
//! files left and checks the one `files_still_in_use` entry's code and text.
//!
//! `cargo test --locked -p oneiron-records --all-features --test remaining_files_still_in_use`.

use oneiron_records::memory::claims::remaining_after_delete;

#[test]
fn a_pinned_body_file_is_listed_as_still_in_use() {
    let remaining = remaining_after_delete(None, false, 2);
    assert_eq!(remaining.len(), 1, "{remaining:?}");
    assert_eq!(remaining[0].code, "files_still_in_use", "{remaining:?}");
    assert_eq!(
        remaining[0].text, "2 of its files are still in use and will be removed later.",
        "{remaining:?}"
    );
}
