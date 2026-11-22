//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, part 2g: the vault
//! owner's own membership change carries the owner key's proof on its
//! membership execution record. Past its owner reserve, install B lands only
//! the owner's work (`authority/log_budget.rs`), and the `MembershipExecution`
//! record install A signs, as the carrier of a change no host issuer signed,
//! reaches B signed by A's install key. Since #9892 the fold takes one owner
//! key's proof beside that signature; here the owner's proof, revalidated in
//! the change's writer as his own write before the change applies, makes the
//! record, and the install join it names when A's frontier is wider than one
//! entry names, carry it (`Vault::owner_act_proof_signer`).
//!
//! Before B takes A's history, the owner admits a second machine on A (the
//! flooder), makes A's vault a shared vault with an Admin, onboards a member
//! with a roster actor, and mints that actor an owner-agent Grant: a Grant
//! an owner's signed mint made. B then takes A's history and is flooded
//! until its door holds a row at the reserve (`owner_reserve/two_installs.rs`).
//! A removes the member: A holds no host issuer, so the removal withdraws
//! the actor's Grant with no signed withdrawal, and A signs the record of it
//! in the removal's writer, its one authority row. B imports what A wrote
//! since.
//!
//! Red at the base (#9979 head dc96b775, a membership execution record is
//! carried unproven): A's record, and the join before it, carry no proof, so
//! the first and fourth tests fail. The controls, the owner's removal on an
//! A that holds no owner key and the Admin's removal on an A that holds one,
//! carry the record unproven and it waits at B on both.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_membership_execution`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityLogEntry, AuthorityOp, authority_entry_hash,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, base_world_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    FederationGrantPreset, FederationGrantRole as Role, InitialSharedMember, Scope, ScopeAxis,
    ScopeId, SharedActExecutionReceipt,
};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{
    CompanionBirthIntent, CompanionChoice, EntityId, ErrorKind, MemberGrantBundle,
    MemberOnboardingIntent, TimeRange, Vault, WorkspaceRosterPreset, WriteActor,
};
use oneiron_authority::authority::{FrontierJoinFamily, MAX_PARENTS, MembershipExecutionCause};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    AT, Flooder, Rooted, Second, admit_flooder, flood_row, heads_of_a, hold_owner_key, rooted,
    second_install_at_its_reserve, second_install_at_its_reserve_from, the_row_a_wrote,
    written_since,
};

/// How many concurrent heads the flooder signs on A: one more than one
/// entry names, so the record on A joins them first.
const WIDE_HEADS: u64 = MAX_PARENTS as u64 + 1;

/// A's shared vault. Not 7, the own-device residence scope's id, whose
/// Owner grants read as device access.
const SHARED: u64 = 41;

const WORKSPACE: &str = "owner-reserve-membership-execution";

/// What A holds before B takes its history: the flooder, the onboarded
/// member and its roster actor, the actor's owner-agent Grant, and the
/// shared vault's Admin.
struct Prepared {
    flooder: Flooder,
    member: EntityId,
    grant: EntityId,
    admin: EntityId,
}

/// A plain row of `entity_type`, as a host's own import writes one.
fn seed_row(vault: &Vault, entity_type: u8) -> EntityId {
    let row = EntityId::now();
    vault
        .put_entity(
            &row,
            entity_type,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"owner reserve membership execution fixture",
        )
        .expect("FIXTURE: a plain row");
    row
}

/// `person`'s own proof, carried by no credential.
fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: a person proof")
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "owner reserve membership execution fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from(agent_id),
        )]),
        None,
        true,
        None,
    )
}

/// The owner onboards one member with a work companion into `preset`: the
/// member PERSON and its roster actor. Returns both.
fn onboard_member(rooted: &Rooted, preset: &WorkspaceRosterPreset) -> (EntityId, EntityId) {
    let vault = &rooted.vault;
    let member = seed_row(vault, ENTITY_TYPE_PERSON);
    let member_facet = seed_row(vault, ENTITY_TYPE_FACET);
    let companion_facet = seed_row(vault, ENTITY_TYPE_FACET);
    let profile_grant = EntityId::now();
    let actor = EntityId::now();
    let intent = MemberOnboardingIntent {
        onboarding_id: "owner-reserve-membership-execution-member".to_owned(),
        workspace: preset.clone(),
        person_ref: member,
        actor_ref: actor,
        actor_definition: definition("owner.reserve.member.actor"),
        work_facet_ref: member_facet,
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: EntityId::now(),
            role: Role::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: Some(profile_grant),
        },
        companion: CompanionChoice::Work(CompanionBirthIntent {
            person_ref: EntityId::now(),
            actor_ref: EntityId::now(),
            work_facet_ref: companion_facet,
            profile_grant_ref: profile_grant,
            actor_definition: definition("owner.reserve.member.companion"),
            display_name: "companion".to_owned(),
        }),
        delegated_mailbox: None,
        occurred_at: vault.now_recorded_at(),
    };
    let outcome = vault
        .onboard_workspace_member(
            intent,
            &WriteActor::new(rooted.owner, EdgeActorClass::Human),
            None,
        )
        .expect("FIXTURE: the member onboards");
    assert_eq!(
        (outcome.person_ref, outcome.actor_ref),
        (member, actor),
        "FIXTURE: the outcome names the member and its roster actor"
    );
    (member, actor)
}

/// The owner mints `agent` a Grant that reads the base world alone: an
/// owner-agent Grant, which only a signed withdrawal ends. Returns its id.
fn mint_world_read_grant(rooted: &Rooted, agent: EntityId) -> EntityId {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &rooted.vault,
        &rooted.proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("FIXTURE: the owner mints the actor a one-world read Grant");
    assert!(
        minted.grant.confers,
        "FIXTURE: the actor's Grant is live: {minted:?}"
    );
    minted.grant.grant_ref
}

/// The owner admits the flooder, makes A's vault a shared vault whose
/// Admin accepts, onboards a member and mints its roster actor an
/// owner-agent Grant.
fn prepare(rooted: &Rooted) -> Prepared {
    let flooder = admit_flooder(rooted);
    let vault = &rooted.vault;
    let admin = seed_row(vault, ENTITY_TYPE_PERSON);
    vault
        .initialize_shared_vault(
            &rooted.proof,
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: admin,
                role: Some(Role::Admin),
            }],
            vault.now_recorded_at(),
        )
        .expect("FIXTURE: a shared vault with the owner its Owner");
    let admin_proof = proof(vault, admin);
    let invitation = vault
        .shared_invitations(&admin_proof, SHARED)
        .expect("FIXTURE: the Admin's invitations")
        .into_iter()
        .find(|open| open.role == Role::Admin)
        .expect("FIXTURE: the Admin's founding invitation");
    vault
        .accept_shared_invitation(&admin_proof, SHARED, &invitation.id)
        .expect("FIXTURE: the Admin accepts");
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .expect("FIXTURE: the seeded agents read")
        .expect("FIXTURE: sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: SHARED,
        org_ref: seed_row(vault, ENTITY_TYPE_ORG),
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    let (member, actor) = onboard_member(rooted, &preset);
    let grant = mint_world_read_grant(rooted, actor);
    Prepared {
        flooder,
        member,
        grant,
        admin,
    }
}

/// `remover` removes the member on A with no slips: A holds no host issuer
/// (asserted), so the actor's Grant is withdrawn with no signed withdrawal
/// and A signs the record of it in the removal's writer.
fn removes_the_member_on_a(
    rooted: &Rooted,
    remover: &AuthenticatedOwner,
    prepared: &Prepared,
) -> SharedActExecutionReceipt {
    assert!(
        rooted.vault.load_host_slip_issuer().is_err(),
        "FIXTURE: A holds no host issuer of its own"
    );
    rooted
        .vault
        .remove_shared_member(remover, SHARED, prepared.member, None)
        .expect("the member's removal applies on A")
}

fn is_membership_execution(op: &AuthorityOp) -> bool {
    matches!(op, AuthorityOp::MembershipExecution(_))
}

/// The record `entry` A signed for the removal by `person` names the
/// member's withdrawn Grant, and the receipt names it as counted.
fn the_record_names_the_removal(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    (person, prepared): (EntityId, &Prepared),
    receipt: &SharedActExecutionReceipt,
) {
    let AuthorityOp::MembershipExecution(record) = &entry.op else {
        panic!("FIXTURE: a membership execution record: {:?}", entry.op);
    };
    assert_eq!(
        (record.cause, record.person, record.member),
        (
            MembershipExecutionCause::RemoveMember,
            person,
            prepared.member
        ),
        "FIXTURE: the record is the removal's"
    );
    assert_eq!(
        record.withdrawn_grants,
        vec![prepared.grant],
        "FIXTURE: the record withdraws the actor's owner-agent Grant"
    );
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(
        receipt.authority_entry.as_deref() == Some(hex.as_str())
            && !receipt.authority_record_pending,
        "FIXTURE: the removal's writer signed the record: {receipt:?}"
    );
}

/// B imports `rows`, what A wrote since B took its history, and counts the
/// record `hash`; A signed `entry` with one owner key's proof beside its
/// install key.
fn b_lands_the_proven_record(
    second: &Second,
    rows: &[Vec<u8>],
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) {
    assert_eq!(
        entry.cosigns.len(),
        1,
        "A signed the membership execution record with one owner key's proof beside its install key"
    );
    assert_ne!(
        entry.cosigns[0].public_key, entry.signer.public_key,
        "the proof is not A's install key"
    );
    second
        .vault
        .import_signed_authority_history(rows, &std::collections::BTreeMap::new())
        .expect("B lands the record A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the membership execution record"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
}

/// A carried the record `entry` unproven, and B's door holds it at its
/// reserve (`AuthorityLogFull`), as before.
fn b_holds_the_unproven_record(
    second: &Second,
    rows: &[Vec<u8>],
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
) {
    assert!(
        entry.cosigns.is_empty(),
        "A carries the membership execution record unproven: {} cosigns",
        entry.cosigns.len()
    );
    let import = second
        .vault
        .import_signed_authority_history(rows, &std::collections::BTreeMap::new());
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven record at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(!fold.valid_entries.contains(&hash), "B does not count it");
}

/// The record is the one row A wrote since B took its history, so B's
/// door judges that row alone.
fn the_record_is_all_a_wrote(rows: &[Vec<u8>]) {
    assert_eq!(
        rows.len(),
        1,
        "FIXTURE: the removal's record is the one authority row A wrote since B took its history"
    );
}

/// The owner removes the member on A, where A holds an owner key: the
/// record carries the proof, and B, past its owner reserve, lands it.
#[test]
fn the_owners_membership_record_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let prepared = prepare(&rooted);
    let second = second_install_at_its_reserve(&rooted, &prepared.flooder);
    let receipt = removes_the_member_on_a(&rooted, &rooted.proof, &prepared);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_membership_execution);
    the_record_is_all_a_wrote(&rows);
    the_record_names_the_removal(&entry, hash, (rooted.owner, &prepared), &receipt);
    b_lands_the_proven_record(&second, &rows, &entry, hash);
}

/// The same removal on an A that holds no owner key: A carries the record
/// unproven, and it waits at B's door, as before.
#[test]
fn the_owners_membership_record_another_install_carries_unproven_waits_past_this_installs_reserve()
{
    let rooted = rooted();
    let prepared = prepare(&rooted);
    let second = second_install_at_its_reserve(&rooted, &prepared.flooder);
    let receipt = removes_the_member_on_a(&rooted, &rooted.proof, &prepared);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_membership_execution);
    the_record_is_all_a_wrote(&rows);
    the_record_names_the_removal(&entry, hash, (rooted.owner, &prepared), &receipt);
    b_holds_the_unproven_record(&second, &rows, &entry, hash);
}

/// The shared vault's Admin removes the member on an A that holds an owner
/// key: the Admin is no Owner of the vault, so the change is not the
/// owner's own write, and the record is carried unproven and waits at B's
/// door. The host key is bound to the Admin before B takes A's history, as
/// a rooted vault admits only a bound writer.
#[test]
fn an_admins_membership_record_carries_unproven_and_waits_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let prepared = prepare(&rooted);
    oneiron::test_support::bind_host_actor(
        &rooted.vault,
        &oneiron::test_support::test_host_issuer(),
        prepared.admin,
        "human",
    )
    .expect("FIXTURE: the host key bound to the Admin");
    let second = second_install_at_its_reserve(&rooted, &prepared.flooder);
    let admin = proof(&rooted.vault, prepared.admin);
    let receipt = removes_the_member_on_a(&rooted, &admin, &prepared);
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_membership_execution);
    the_record_is_all_a_wrote(&rows);
    the_record_names_the_removal(&entry, hash, (prepared.admin, &prepared), &receipt);
    b_holds_the_unproven_record(&second, &rows, &entry, hash);
}

/// The flooder signs one more concurrent head on A than one entry names,
/// each its own world edit on its admission, and B takes them, below its
/// reserve. The owner then removes the member on A, where A holds an owner
/// key: A joins the wide frontier first, and the join carries the record's
/// proof, so B, past its reserve, lands the join and the record on it.
#[test]
fn the_owners_membership_record_past_a_wide_frontier_lands_with_its_join_past_this_installs_reserve()
 {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let prepared = prepare(&rooted);
    let flooder = &prepared.flooder;
    let mut last = flooder.admission;
    for seq in 1..=WIDE_HEADS {
        let row = flood_row(&rooted, flooder, EntityId::now(), seq, flooder.admission);
        rooted
            .vault
            .put_authority_log_entry(&row, AT, 1)
            .expect("FIXTURE: A stores the flooder's concurrent world edit");
        last = authority_entry_hash(&row).expect("hash");
    }
    let heads = heads_of_a(&rooted).len();
    assert!(
        heads > MAX_PARENTS,
        "FIXTURE: A's frontier is wider than one entry names: {heads} heads"
    );
    let second = second_install_at_its_reserve_from(&rooted, flooder, (last, WIDE_HEADS + 1));
    let receipt = removes_the_member_on_a(&rooted, &rooted.proof, &prepared);
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
        panic!("A joined its wide frontier once before the record: {joins:?}");
    };
    assert!(
        join.parent_hashes.len() > MAX_PARENTS && join.cosigns.len() == 1,
        "A's join names every head and carries the owner key's proof: {} parents, {} cosigns",
        join.parent_hashes.len(),
        join.cosigns.len()
    );
    let join_hash = authority_entry_hash(join).expect("hash");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, is_membership_execution);
    assert_eq!(
        entry.parent_hashes,
        vec![join_hash],
        "the record names the join alone"
    );
    the_record_names_the_removal(&entry, hash, (rooted.owner, &prepared), &receipt);
    b_lands_the_proven_record(&second, &rows, &entry, hash);
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&join_hash),
        "B's fold counts the join"
    );
}
