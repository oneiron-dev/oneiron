//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, part 2a: the writers of
//! carried acts attach the owner key's proof on the owner's own act. Past
//! its owner reserve, install B lands only the owner's work
//! (`authority/log_budget.rs` `owner_work`), and an act install A carries
//! reaches B signed by A's install key. Since #9892 the fold takes one owner
//! key's proof beside that signature on every carried op; here the writers
//! sign it: an agent grant act and a grant's travel choice, each the
//! owner's own act at an owner door (`Vault::owner_act_proof_signer`), and
//! the install join an owner act names when A's frontier is wider than one
//! entry names (`FrontierSigner::install`), which carries the proof of the
//! act it leads to.
//!
//! Each test takes A's history to a second install B, floods B until its
//! door holds a row at the reserve (`owner_reserve/two_installs.rs`), then
//! acts on A, and B imports what A wrote.
//!
//! Red at the base (#9892 head 1f48908b, the writers sign no proof): B's
//! import of A's agent grant act, of A's travel choice, and of the join
//! before A's removal refuses with `AuthorityLogFull`. The control, an
//! agent grant act from an A that holds no owner key, waits at B on both.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_writers`.

use std::collections::BTreeSet;

use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityLogEntry, AuthorityOp, MachineRole,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::inquiry::InquiryEdgeRequest;
use oneiron::share_travel::{BornWithField, TravelChoice};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, ErrorKind};
use oneiron_authority::authority::{FrontierJoinFamily, MAX_PARENTS};
use serde_json::json;

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    AT, Rooted, Second, admit_flooder, flood_row, heads_of_a, hold_owner_key, removes, rooted,
    second_install_at_its_reserve, second_install_at_its_reserve_from, the_row_a_wrote,
    written_since,
};

/// A company vault no fixture opens: the inquiry edge mints before any pact.
const UNOPENED_COMPANY: oneiron::authority::AuthorityVaultId = [0xac; 32];

/// How many concurrent heads the flooder signs on A: one more than one
/// entry names, so an owner act on A joins them first.
const WIDE_HEADS: u64 = MAX_PARENTS as u64 + 1;

/// An agent the owner defines on A, before B takes A's history.
fn agent_defined_on_a(rooted: &Rooted) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        &rooted.vault,
        &rooted.proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "reserve_reader",
                "desc": "Read-only agent of the owner-reserve writer tests",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("the agent's definition"),
        },
    )
    .expect("FIXTURE: the owner defines the agent on A");
    agent
}

/// The owner mints `agent` a read Grant on A, at the owner's door.
fn mint_read_grant_on_a(rooted: &Rooted, agent: EntityId) {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &rooted.vault,
        &rooted.proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner mints the agent's Grant on A");
    assert!(minted.grant.confers, "the agent's Grant is live at A");
}

/// B imports `rows`, what A wrote since B took its history, and counts the
/// act `hash`; A signed `entry` with one owner key's proof beside its
/// install key.
fn b_lands_the_proven_act(
    second: &Second,
    rows: &[Vec<u8>],
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) {
    assert_eq!(
        entry.cosigns.len(),
        1,
        "A signed the act with one owner key's proof beside its install key"
    );
    assert_ne!(
        entry.cosigns[0].public_key, entry.signer.public_key,
        "the proof is not A's install key"
    );
    second
        .vault
        .import_signed_authority_history(rows, &std::collections::BTreeMap::new())
        .expect("B lands the act A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the act"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
}

/// The owner mints an agent's Grant on A, where A holds an owner key: the
/// agent grant act carries the proof, and B, past its owner reserve, lands
/// it.
#[test]
fn the_owners_agent_grant_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let agent = agent_defined_on_a(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    mint_read_grant_on_a(&rooted, agent);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| {
        matches!(op, AuthorityOp::AgentGrantAct(_))
    });
    b_lands_the_proven_act(&second, &rows, &entry, hash);
}

/// The same mint from an A that holds no owner key: A carries the act
/// unproven, and it waits at B's door (`AuthorityLogFull`), as before.
#[test]
fn the_owners_agent_grant_another_install_carries_unproven_waits_past_this_installs_reserve() {
    let rooted = rooted();
    let flooder = admit_flooder(&rooted);
    let agent = agent_defined_on_a(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    mint_read_grant_on_a(&rooted, agent);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| {
        matches!(op, AuthorityOp::AgentGrantAct(_))
    });
    assert!(
        entry.cosigns.is_empty(),
        "A holds no owner key, so it carries the act unproven"
    );
    let import = second
        .vault
        .import_signed_authority_history(&rows, &std::collections::BTreeMap::new());
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven act at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(!fold.valid_entries.contains(&hash), "B does not count it");
}

/// The owner sets a live federation grant's travel on A, where A holds an
/// owner key: the choice carries the proof, and B, past its owner reserve,
/// lands it.
#[test]
fn the_owners_grant_travel_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let edge = rooted
        .vault
        .mint_inquiry_edge(
            &rooted.proof,
            &InquiryEdgeRequest::member_defaults(UNOPENED_COMPANY, "Acme"),
        )
        .expect("FIXTURE: the owner mints a federation grant on A");
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let choice = TravelChoice {
        born_with: BTreeSet::from([BornWithField::Why]),
    };
    let set = rooted
        .vault
        .set_federation_grant_travel_as(
            &rooted.proof,
            ActSurface::ThisInstall,
            &edge.grant,
            Some(choice.clone()),
            None,
            rooted.vault.now_recorded_at(),
        )
        .expect("the owner sets the grant's travel on A");
    assert_eq!(set.map(|travel| travel.travel), Some(choice));
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| {
        matches!(op, AuthorityOp::GrantTravelSet(_))
    });
    b_lands_the_proven_act(&second, &rows, &entry, hash);
}

/// The flooder signs one more concurrent head on A than one entry names,
/// each its own world edit on its admission, and B takes them, below its
/// reserve. The owner then removes the flooder on A, where A holds an owner
/// key: A joins the wide frontier first, and the join carries the removal's
/// proof, so B, past its reserve, lands the join and the removal on it.
#[test]
fn the_owners_removal_past_a_wide_frontier_lands_with_its_join_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let mut last = flooder.admission;
    for seq in 1..=WIDE_HEADS {
        let row = flood_row(&rooted, &flooder, EntityId::now(), seq, flooder.admission);
        rooted
            .vault
            .put_authority_log_entry(&row, AT, 1)
            .expect("FIXTURE: A stores the flooder's concurrent world edit");
        last = oneiron::authority::authority_entry_hash(&row).expect("hash");
    }
    let heads = heads_of_a(&rooted).len();
    assert!(
        heads > MAX_PARENTS,
        "FIXTURE: A's frontier is wider than one entry names: {heads} heads"
    );
    let second = second_install_at_its_reserve_from(&rooted, &flooder, (last, WIDE_HEADS + 1));
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            flooder.machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the flooding machine on A")
        .into_standing()
        .expect("the owner's removal stands at A");
    let written = written_since(&rooted, &second);
    let joins: Vec<&AuthorityLogEntry> = written
        .iter()
        .map(|(_, entry)| entry)
        .filter(|entry| {
            matches!(&entry.op, AuthorityOp::FrontierJoin(join)
                if matches!(join.family, FrontierJoinFamily::Install(_)))
        })
        .collect();
    let [join] = joins.as_slice() else {
        panic!("A joined its wide frontier once before the removal: {joins:?}");
    };
    assert!(
        join.parent_hashes.len() > MAX_PARENTS && join.cosigns.len() == 1,
        "A's join names every head and carries the owner key's proof: {} parents, {} cosigns",
        join.parent_hashes.len(),
        join.cosigns.len()
    );
    let join_hash = oneiron::authority::authority_entry_hash(join).expect("hash");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| removes(op, flooder.machine));
    assert_eq!(
        entry.parent_hashes,
        vec![join_hash],
        "the removal names the join alone"
    );
    b_lands_the_proven_act(&second, &rows, &entry, hash);
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&join_hash),
        "B's fold counts the join"
    );
    assert!(
        fold.machine(flooder.machine).is_some_and(|machine| machine
            .chains()
            .any(|(_, head)| head.entry == hash && head.removed)),
        "B reads the flooding machine removed by A's removal"
    );
}
