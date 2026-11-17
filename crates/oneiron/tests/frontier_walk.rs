//! Setting stage 7b-1: every read of an authority register's frontier is one walk
//! (`authority::world_strength::frontier_walk`), and the world privacy meet and a grant's travel
//! meet are two users of it, with no change in what either reads.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::frontier_walk::{
    travel_reads_match_before, walk_order, world_reads_match_before,
};

/// The live edits come first in hash order. A weak edit's replaced edits follow, each once,
/// newest pending first. The edits that only a full-strength edit replaced (g) are not walked.
/// A weak edit that replaced nothing (f, a), or a disputed one (e), brings in the default.
#[test]
fn the_walk_takes_each_edit_once_and_stops_at_full_strength() {
    assert_eq!(
        walk_order(),
        [
            "d", "e", "f", "default", "default", "c", "a", "default", "b"
        ]
    );
}

#[test]
fn a_world_reads_as_it_did_before_the_walk() {
    assert_eq!(world_reads_match_before(0x7b1, 4000), Ok(4000));
}

#[test]
fn a_grants_travel_fields_read_as_they_did_before_the_walk() {
    assert_eq!(travel_reads_match_before(0x7b1, 4000), Ok(4000));
}
