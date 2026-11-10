//! Task verb tests: a consult with no party fact gives nobody standing.
//!
//! This file held the open-time consult party backfill test. That migration was removed by
//! db9f1965541 (#4246, FIX 11758); its first half, the live refusal below, stays
//! (`TaskAuthorityState::consult_standing`, task_authority/mod.rs).

use super::consult_party::{approve, party_facts, unlink_below_doors, working};
use super::support::*;
use super::*;

/// F24 round 3 (H219): a consult whose party facts are gone moves for nobody, not even its
/// addressed party.
#[test]
fn a_consult_with_no_party_fact_gives_nobody_standing() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, _question) = open_consult(&vault);
    seed_ladder_state(&vault, task_ref, &working());
    for fact_ref in party_facts(&vault, task_ref) {
        unlink_below_doors(&vault, fact_ref, task_ref);
    }
    assert!(
        vault
            .memory(peer, EdgeActorClass::Agent)
            .compare_and_set_consult_ladder(task_ref, &working(), approve(0xB7))
            .is_err(),
        "a consult with no party fact gives nobody standing"
    );
}
