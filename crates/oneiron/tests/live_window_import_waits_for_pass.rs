//! L7-45 (ARCH-0023b `#tombstone-index-built`, the H15 follow-up: "serialize
//! live-window imports with indexed passes"). A pass's tombstone index reads a
//! case-shifted alias key from a snapshot taken when the index is built. A peer
//! import into a live window from another thread therefore waits until an
//! indexed pass over that window ends, so the pass never reads a carrier whose
//! tombstone its index cannot see.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::time::Duration;

use oneiron::test_doors::live_window_import::forward_pass_meets_peer_import;

#[test]
fn a_peer_import_waits_for_the_indexed_pass_over_its_window() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let raced = forward_pass_meets_peer_import(dir.path(), Duration::from_secs(2))
        .expect("the pass and the import run");

    assert!(raced.resident_landed, "the window's own carrier lands");
    assert!(
        raced.import_landed,
        "the peer import lands once the pass ends"
    );
    assert!(
        !raced.tombstoned_landed,
        "a carrier tombstoned in its own import is no row"
    );
    assert_eq!(
        raced.rows_written, raced.rows_written_alone,
        "the pass writes only what it writes over the window's own carrier: it never \
         admits, then purges, a carrier whose tombstone its index could not see"
    );
    assert!(
        !raced.import_landed_mid_pass,
        "the import waits until the indexed pass has ended"
    );
}
