//! FIX 22346: an image binding whose live policy is absent reads to no one
//! and never travels. This guard is expected to pass without a production fix.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::source_audience_binding::{bound_row, reads, remove_policy_row, travels};
use oneiron::{EntityId, Vault, VaultConfig};

#[test]
fn restored_binding_without_live_policy_reads_to_no_one() {
    let dir = tempfile::tempdir().expect("temporary source-audience binding vault");
    let vault =
        Vault::open(dir.path(), VaultConfig::device()).expect("open source-audience binding vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let reader = EntityId::now();
    let (row, policy) = bound_row(&vault, reader).expect("land source-bound row");

    assert!(
        reads(&vault, row, &[reader]).expect("read bound row before policy removal"),
        "precondition: the policy's named reader must read the landed row",
    );
    assert!(
        travels(&vault, row).expect("judge full-owner travel before policy removal"),
        "precondition: the live policy publishes and the row has no restricted lineage",
    );

    remove_policy_row(&vault, policy).expect("remove only the live policy row");

    assert!(
        !reads(&vault, row, &[reader]).expect("read unresolved binding as reader"),
        "a binding whose policy is absent must deny its former reader",
    );
    assert!(
        !reads(&vault, row, &[owner]).expect("read unresolved binding as embedded owner"),
        "the embedded owner must not bypass an unresolved source-audience binding",
    );
    assert!(
        !travels(&vault, row).expect("judge full-owner travel with unresolved policy"),
        "a row whose bound policy cannot publish must not travel on the full owner window",
    );
}
