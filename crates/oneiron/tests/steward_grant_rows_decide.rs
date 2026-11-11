//! The grant rows decide a base agent's reach (ruling S63-P13-STATE = A,
//! Engine 11 Nov; review of #6913 and #6914). The grant in force was named
//! by a table local to one node, and so were the opt-out and the
//! system-critical mark. Grant rows reach each of the owner's linked
//! machines; that table did not. So a machine that had stood its own default
//! kept reading by it after the owner narrowed or revoked the grant on
//! another, a machine that had stood none read by the shipped manifest rows,
//! and neither showed the warning.
//!
//! Now the reach is the meet of every Steward grant row that stands naming
//! the agent. A row another machine stood can only narrow it. An opt-out is
//! a standing row with no verbs. The warning comes from what the agent is.
//!
//! A row "arrives" here through a door that writes the row alone, as a peer's
//! row lands: no act, no local table. The tests run one vault, not two
//! machines over a sync link.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_grant_rows_decide`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::federation::{SystemAgentGrantNarrowing, SystemFunction};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, STEWARD_VERBS, WeaveReach, dreamer, drop_dreamer_rows,
    open_owner_carrier_vault, owner, receive_steward_grant_row, steward_grant_rows, weave_reach,
};

const READS_AND_LANDS: WeaveReach = WeaveReach {
    reads: true,
    lands_auto: true,
};
const READS_ONLY: WeaveReach = WeaveReach {
    reads: true,
    lands_auto: false,
};
const NOTHING: WeaveReach = WeaveReach {
    reads: false,
    lands_auto: false,
};

fn read_alone() -> BTreeSet<String> {
    BTreeSet::from([STEWARD_READ_VERB.to_owned()])
}

#[test]
fn a_narrower_row_from_another_machine_narrows_the_reach() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    vault.provision_system_agent_grants().expect("first mint");
    assert_eq!(weave_reach(&vault).expect("reach"), READS_AND_LANDS);

    // On another machine the owner narrowed the grant to `read`; its row
    // arrives beside this machine's own default.
    receive_steward_grant_row(&vault, dreamer, &[STEWARD_READ_VERB]).expect("the narrower row");
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        READS_ONLY,
        "the reach is what every standing row gives: `read` alone"
    );
}

#[test]
fn an_opt_out_from_another_machine_holds_here() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    vault.provision_system_agent_grants().expect("first mint");
    assert_eq!(weave_reach(&vault).expect("reach"), READS_AND_LANDS);

    // On another machine the owner revoked the grant whole; the row that
    // records it arrives here.
    receive_steward_grant_row(&vault, dreamer, &[]).expect("the opt-out's row");
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        NOTHING,
        "the owner's opt-out holds on this machine too"
    );
}

#[test]
fn a_machine_that_stood_no_grant_reads_by_the_rows_it_receives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");

    // No host stood a grant on this machine (a second machine, or the new
    // home after a move); the narrowed row arrives from the one that did.
    let row =
        receive_steward_grant_row(&vault, dreamer, &[STEWARD_READ_VERB]).expect("the narrowed row");
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        READS_ONLY,
        "the row decides here, not the shipped manifest rows"
    );

    // This machine then opens as a host: a grant row stands, so the engine
    // stands no default of its own beside it.
    vault
        .provision_system_agent_grants()
        .expect("open as a host");
    assert_eq!(
        steward_grant_rows(&vault, dreamer).expect("rows"),
        [(row, vec![STEWARD_READ_VERB.to_owned()])],
        "the engine stands no default where a grant row already stands"
    );
    assert_eq!(weave_reach(&vault).expect("reach"), READS_ONLY);
}

#[test]
fn the_warning_shows_on_a_machine_that_stood_no_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let owner = owner(&vault).expect("owner proof");
    // The whole default another machine stood arrives; this one stood none.
    receive_steward_grant_row(&vault, dreamer, &STEWARD_VERBS).expect("the default's row");
    assert_eq!(weave_reach(&vault).expect("reach"), READS_AND_LANDS);

    let keep = read_alone();
    let SystemAgentGrantNarrowing::ConfirmRequired {
        breaks, confirm, ..
    } = vault
        .narrow_system_agent_grant(&owner, dreamer, &keep, None)
        .expect("the narrowing door")
    else {
        panic!("narrowing the Dreamer's grant warns first, on any machine");
    };
    assert_eq!(
        breaks,
        [SystemFunction::Consolidation, SystemFunction::RecallUpkeep],
        "the breaks are the Dreamer's functions, by what the agent is"
    );
    assert!(matches!(
        vault
            .narrow_system_agent_grant(&owner, dreamer, &keep, Some(confirm))
            .expect("the confirmed narrowing"),
        SystemAgentGrantNarrowing::Narrowed { grant: Some(_), .. }
    ));
    let rows = steward_grant_rows(&vault, dreamer).expect("rows");
    assert_eq!(
        rows.iter()
            .map(|(_, verbs)| verbs.as_slice())
            .collect::<Vec<_>>(),
        [[STEWARD_READ_VERB.to_owned()].as_slice()],
        "the row that arrived is revoked: one row stands, `read` alone"
    );
    assert_eq!(weave_reach(&vault).expect("reach"), READS_ONLY);
}

#[test]
fn a_whole_revoke_leaves_one_row_with_no_verbs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let owner = owner(&vault).expect("owner proof");
    vault.provision_system_agent_grants().expect("first mint");

    let none = BTreeSet::new();
    let SystemAgentGrantNarrowing::ConfirmRequired { confirm, .. } = vault
        .narrow_system_agent_grant(&owner, dreamer, &none, None)
        .expect("the narrowing door")
    else {
        panic!("a whole revoke warns first");
    };
    assert!(matches!(
        vault
            .narrow_system_agent_grant(&owner, dreamer, &none, Some(confirm))
            .expect("the confirmed revoke"),
        SystemAgentGrantNarrowing::Narrowed { grant: None, .. }
    ));
    let rows = steward_grant_rows(&vault, dreamer).expect("rows");
    assert_eq!(
        rows.iter()
            .map(|(_, verbs)| verbs.len())
            .collect::<Vec<_>>(),
        [0],
        "the opt-out is one standing row with no verbs: the record that reaches his other machines"
    );
    assert_eq!(weave_reach(&vault).expect("reach"), NOTHING);

    // A default another machine stood before it saw the revoke arrives late:
    // it cannot widen the reach.
    receive_steward_grant_row(&vault, dreamer, &STEWARD_VERBS).expect("a late default");
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        NOTHING,
        "a late default does not undo the owner's opt-out"
    );

    // The owner's grant back revokes every row that stands and mints one.
    assert!(
        vault
            .grant_dreamer_weave(&owner, 1)
            .expect("the owner's grant back")
    );
    let rows = steward_grant_rows(&vault, dreamer).expect("rows");
    assert_eq!(
        rows.iter()
            .map(|(_, verbs)| verbs.len())
            .collect::<Vec<_>>(),
        [STEWARD_VERBS.len()],
        "one row stands after the grant back, with the whole default"
    );
    assert_eq!(weave_reach(&vault).expect("reach"), READS_AND_LANDS);
}

#[test]
fn the_first_mint_records_an_opt_out_as_a_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    // The owner removed every row that names the Dreamer before any host
    // opened the vault.
    drop_dreamer_rows(&vault).expect("no Dreamer rows");
    vault.provision_system_agent_grants().expect("first mint");
    let rows = steward_grant_rows(&vault, dreamer).expect("rows");
    assert_eq!(
        rows.iter()
            .map(|(_, verbs)| verbs.len())
            .collect::<Vec<_>>(),
        [0],
        "the first mint records the opt-out as one standing row with no verbs"
    );
    assert_eq!(weave_reach(&vault).expect("reach"), NOTHING);
}
