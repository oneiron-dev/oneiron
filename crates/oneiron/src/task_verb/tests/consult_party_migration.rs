//! Task verb tests: the one-time open migration that gives a consult minted
//! before party facts existed the fact its creation would have minted.

use super::consult_party::{approve, party_facts, unlink_below_doors, working};
use super::support::*;
use super::*;

/// F24 round 3 (H219), the pre-GA switch: a consult minted without a party
/// fact gets the one its creation would have minted when its vault opens,
/// so its addressed party moves it again.
#[test]
fn a_consult_minted_before_party_facts_gets_its_fact_on_open() {
    let (dir, vault) = open_vault();
    let (task_ref, peer, _question) = open_consult(&vault);
    seed_ladder_state(&vault, task_ref, &working());
    for fact_ref in party_facts(&vault, task_ref) {
        unlink_below_doors(&vault, fact_ref, task_ref);
    }
    vault
        .with_write_txn(|wtxn| {
            crate::task_verb::consult_party_backfill::BACKFILLED.delete(&vault.store, wtxn, &())
        })
        .expect("as a vault written before the migration");
    assert!(
        vault
            .memory(peer, EdgeActorClass::Agent)
            .compare_and_set_consult_ladder(task_ref, &working(), approve(0xB7))
            .is_err(),
        "a consult with no party fact gives nobody standing"
    );
    drop(vault);

    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen");
    assert_eq!(party_facts(&vault, task_ref).len(), 1);
    vault
        .memory(peer, EdgeActorClass::Agent)
        .compare_and_set_consult_ladder(task_ref, &working(), approve(0xB8))
        .expect("the addressed party moves the migrated consult");
}
