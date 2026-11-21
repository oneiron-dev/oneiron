// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [DELETE-WIDENS-VALUE-RESTRICTION-CLAIMS] and
//! [CLAIM-CLASS-DESCRIPTOR-DELETE-WIDENS]: the lead's RULING
//! WORLD-ACCESS-GRANT-DELETE = A (15 Nov: "deleting a restriction IS a
//! widening") leaves a record that restricts someone's access or authority
//! to a live owner's delete. The delete authority told such records by their
//! predicate alone (`tests/world_access_state_change.rs`). The records here
//! restrict by their value, by their kind, or by the state of the rows
//! beside them, and DEL-2 let an Admin delete them in scope:
//! - a `comm.reachable_via` of `reachable: false`: sends skip that channel;
//! - a paused, suppressed or exited `campaign.member`: the campaign holds its
//!   sends to that person;
//! - a `disclosure.import_audience` of only me or a project: the topic's
//!   later imports leave the audience their source shared them with;
//! - a claim-class descriptor: a synced row may be stricter than the
//!   compiled one;
//! - a revoked or opted-out counterparty contact, and its
//!   `counterparty_contact.counterparty` head: the send gate finds a party's
//!   contacts by that head.
//!
//! Each red is an Admin of a shared vault deleting one such record in scope.
//! Each control is the same Admin deleting a record of the same kind that
//! restricts nothing. A descriptor has no such record: every one is the
//! owner's to delete, and the owner's arm is not changed.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test delete_widens_values`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::comm::{CommClaimValue, claim_class_descriptor_id};
use oneiron::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyOptOutReason,
    PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
};
use oneiron::disclosure::PREDICATE_DISCLOSURE_IMPORT_AUDIENCE;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, SafeDeleteReason};
use oneiron::registry::{ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::comm_claim_rows::put_comm_claim_row;
use oneiron::test_support::bind_host_owner;
use oneiron::write_envelope::cohort_claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    encode_campaign_member_value,
};
use oneiron::write_envelope::communication::PREDICATE_COMM_OPT_OUT;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

const LEARNED_AT: u64 = 1_780_000_000;

/// The shared vault id the Admin's tests share the vault under.
const SHARED_WITH_ADMIN: u64 = 46;

/// The refusal a delete below the owner gives a record that is authority.
const AUTHORITY_ROW: &str = "authority_row:";

/// A rooted shared vault (as `tests/world_access_state_change.rs` shares
/// one): its owner and an Admin, who acts by the live `human` credential
/// this host mints it.
struct AdminFixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    admin: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl AdminFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        // A delete signs its receipt with this install's key.
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let admin = a_person(&vault);
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        vault
            .initialize_shared_vault(
                &owner_proof,
                SHARED_WITH_ADMIN,
                None,
                &[
                    InitialSharedMember {
                        member_ref: owner,
                        role: Some(FederationGrantRole::Owner),
                    },
                    InitialSharedMember {
                        member_ref: admin,
                        role: Some(FederationGrantRole::Admin),
                    },
                ],
                1,
            )
            .expect("a shared vault with an Admin");
        let admin_proof = vault
            .authenticate_owner(admin, &admin.to_hex(), true, GateDecisionId::now())
            .expect("the Admin's person proof");
        let invitation = vault
            .shared_invitations(&admin_proof, SHARED_WITH_ADMIN)
            .expect("the Admin's invitations")
            .into_iter()
            .find(|open| open.role == FederationGrantRole::Admin)
            .expect("the Admin's founding invitation");
        vault
            .accept_shared_invitation(&admin_proof, SHARED_WITH_ADMIN, &invitation.id)
            .expect("the Admin accepts");
        let facet = vault.default_facet().expect("default facet");
        Self {
            vault,
            issuer,
            admin,
            facet,
            _directory: directory,
        }
    }

    /// The Admin deletes `id` over the live `human` credential this host
    /// mints it, verified as a transport verifies the slip a request
    /// presents.
    fn admin_deletes(&self, id: EntityId) -> Result<bool, MemoryError> {
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip");
        let issued_at = self.vault.capability_slip_now().expect("slip clock");
        let mut claims = root.claims;
        claims.slip_id = [0x5b; 32];
        claims.holder_ref = self.admin.to_hex();
        claims.actor_class = Some("human".into());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + 3_600;
        claims.ttl_secs = 3_600;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the Admin's credential");
        let challenge = b"delete-widens-values";
        let proof = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        let credential: VerifiedSlip = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
            .expect("a verified credential");
        self.vault
            .memory(self.admin, EdgeActorClass::Human)
            .with_transport_invocation()
            .with_read_proof(&credential)
            .safe_delete(&id.to_hex(), SafeDeleteReason::UserDelete)
            .map(|receipt| receipt.existed)
    }

    /// The Admin's delete of `id`, which restricts someone: refused as
    /// authority, and `id` still stands. `what` names the record.
    fn admin_never_deletes(&self, id: EntityId, what: &str) {
        let result = self.admin_deletes(id);

        assert!(
            !deleted(&self.vault, id),
            "{what} still stands (delete: {result:?})"
        );
        let refused = result.expect_err("an Admin never deletes a restriction");
        assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{what}: {refused:?}");
        assert!(
            refused.message.starts_with(AUTHORITY_ROW),
            "{what}: the refusal names its reason: {refused:?}"
        );
    }

    /// The Admin's delete of `id`, which restricts no one: admitted in scope,
    /// as DEL-2 allows, and `id` is a deleted shell. `what` names the record.
    fn admin_deletes_in_scope(&self, id: EntityId, what: &str) {
        let existed = self
            .admin_deletes(id)
            .unwrap_or_else(|error| panic!("an Admin deletes {what} in scope: {error:?}"));

        assert!(existed, "{what} existed");
        assert!(deleted(&self.vault, id), "{what} is a deleted shell");
    }
}

/// A live PERSON.
fn a_person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            at(LEARNED_AT),
            LEARNED_AT,
            b"human",
        )
        .expect("a live person");
    person
}

/// `body` in `facet`, on the owner's raw door, as an Auto row (an Approved
/// raw put parks at the criticality floor). Returns its id.
fn put_in_facet(vault: &Vault, facet: EntityId, mut body: ClaimBody) -> EntityId {
    body.scope_facet = facet;
    let predicate = body.predicate.clone();
    let id = EntityId::now();
    vault
        .put_claim(&id, &body, at(LEARNED_AT), LEARNED_AT)
        .unwrap_or_else(|error| panic!("a {predicate} claim lands: {error:?}"));
    id
}

/// An Auto, Active claim of `predicate` about `subject` holding `value`.
fn claim_about(predicate: &str, subject: EntityId, value: Value) -> ClaimBody {
    ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap_or_else(|error| panic!("a {predicate} body: {error:?}"))
}

/// A `comm.reachable_via` on email about a new PERSON, in `facet`, Approved,
/// through the cfg door that lands a `comm.*` row as written here: the raw
/// put door keeps the criticality floor on a `comm.*` claim, Auto or
/// Approved, and no typed door writes this one (tiebreak
/// muse/l2-wa-fixture-tiebreak).
fn reachable_via(vault: &Vault, facet: EntityId, reachable: bool) -> EntityId {
    let party = a_person(vault);
    let mut body = CommClaimValue::ReachableVia {
        party_ref: party,
        channel_class: "email".to_owned(),
        reachable,
    }
    .claim_body()
    .expect("a comm.reachable_via body");
    body.source = None;
    body.scope = None;
    body.approval = ClaimApprovalStatus::Approved;
    body.scope_facet = facet;
    let id = EntityId::now();
    put_comm_claim_row(vault, &id, &body, at(LEARNED_AT), LEARNED_AT)
        .unwrap_or_else(|error| panic!("a comm.reachable_via claim lands: {error:?}"));
    id
}

/// A `campaign.member` of a new PERSON in a campaign, on email, in `state`,
/// in `facet`.
fn campaign_member(vault: &Vault, facet: EntityId, state: CampaignMemberState) -> EntityId {
    let person = a_person(vault);
    let value = encode_campaign_member_value(&CampaignMemberValue {
        campaign: EntityId::now(),
        state,
        channels: vec![CampaignMemberChannel {
            channel: "email".to_owned(),
            basis_evidence: EntityId::now(),
            sender_ref: EntityId::now(),
        }],
        derivation: None,
    });
    put_in_facet(
        vault,
        facet,
        claim_about(PREDICATE_CAMPAIGN_MEMBER, person, value),
    )
}

/// A `disclosure.import_audience` row about a new topic, naming `audience`
/// in its value (`only_me`, `source`, or a project id), in `facet`.
fn import_audience(vault: &Vault, facet: EntityId, audience: Value) -> EntityId {
    let topic = a_person(vault);
    let value = Value::Map(vec![
        (
            Value::from("topic"),
            Value::Binary(topic.as_bytes().to_vec()),
        ),
        (Value::from("audience"), audience),
        (Value::from("ask"), Value::from(1_u64)),
    ]);
    put_in_facet(
        vault,
        facet,
        claim_about(PREDICATE_DISCLOSURE_IMPORT_AUDIENCE, topic, value),
    )
}

/// How a contact stands when the test deletes.
#[derive(Clone, Copy, Debug)]
enum ContactStanding {
    Active,
    Revoked,
    OptedOut,
}

/// A counterparty contact for `counterparty`, through a new identity id,
/// left in `standing`. Returns the contact's id and its live
/// `counterparty_contact.counterparty` head.
fn contact(vault: &Vault, counterparty: &str, standing: ContactStanding) -> (EntityId, EntityId) {
    let id = EntityId::now();
    let record =
        CounterpartyContactRecord::user_introduction(EntityId::now(), counterparty, LEARNED_AT)
            .expect("a valid contact record");
    vault
        .create_counterparty_contact(&id, &record)
        .expect("the contact lands");
    match standing {
        ContactStanding::Active => {}
        ContactStanding::Revoked => {
            vault
                .revoke_counterparty_contact(&id, LEARNED_AT + 1)
                .expect("the contact is revoked");
        }
        ContactStanding::OptedOut => {
            vault
                .opt_out_counterparty_contact(
                    &id,
                    CounterpartyOptOutReason::Unsubscribe,
                    LEARNED_AT + 1,
                )
                .expect("the contact opts out");
        }
    }
    let head = vault
        .claims_for_subject(&id)
        .expect("the contact's claims")
        .into_iter()
        .find(|claim| {
            vault
                .get_claim(claim)
                .expect("claim read")
                .is_some_and(|body| {
                    body.predicate == PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY
                        && body.lifecycle == ClaimLifecycleStatus::Active
                        && !body.stale
                })
        })
        .expect("the contact's live counterparty head");
    (id, head)
}

fn deleted(vault: &Vault, id: EntityId) -> bool {
    vault.is_deleted_shell(&id).expect("shell read")
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// (a) `comm.reachable_via` false: sends to that party skip the channel
/// (human_task/followup.rs, outbound/weave_digest_send.rs). Before this
/// change DEL-2's in-scope delete landed, and the channel was open again.
#[test]
fn an_admin_never_deletes_an_unreachable_channel_in_scope() {
    let f = AdminFixture::new();
    let unreachable = reachable_via(&f.vault, f.facet, false);

    f.admin_never_deletes(unreachable, "the unreachable channel");
}

/// Control for (a): a channel marked reachable restricts nothing.
#[test]
fn the_admin_deletes_a_reachable_channel_in_scope() {
    let f = AdminFixture::new();
    let reachable = reachable_via(&f.vault, f.facet, true);

    f.admin_deletes_in_scope(reachable, "the reachable channel");
}

/// (b) a paused, suppressed or exited `campaign.member`: the campaign's
/// runner sends only while the member reads enrolled or holds no head
/// (campaign/enrollment/runner.rs `membership_sends`). Before this change
/// DEL-2's in-scope delete landed, and the campaign sent to that person.
#[test]
fn an_admin_never_deletes_a_held_campaign_member_in_scope() {
    let f = AdminFixture::new();
    for (state, what) in [
        (
            CampaignMemberState::Paused {
                until: Some(LEARNED_AT + 3_600),
                new_trigger: None,
            },
            "the paused member",
        ),
        (CampaignMemberState::Suppressed, "the suppressed member"),
        (CampaignMemberState::Exited, "the exited member"),
    ] {
        let member = campaign_member(&f.vault, f.facet, state);

        f.admin_never_deletes(member, what);
    }
}

/// Control for (b): an enrolled member restricts nothing.
#[test]
fn the_admin_deletes_an_enrolled_campaign_member_in_scope() {
    let f = AdminFixture::new();
    let member = campaign_member(&f.vault, f.facet, CampaignMemberState::Enrolled);

    f.admin_deletes_in_scope(member, "the enrolled member");
}

/// (c) a `disclosure.import_audience` of only me or a project: the topic's
/// later imports are stamped into that audience
/// (federation/record_scope/stamping.rs `stamp_import_audience_birth`).
/// Before this change DEL-2's in-scope delete landed, and they kept their
/// source's audience.
#[test]
fn an_admin_never_deletes_a_narrowing_import_audience_in_scope() {
    let f = AdminFixture::new();
    let only_me = import_audience(&f.vault, f.facet, Value::from("only_me"));
    let project = import_audience(
        &f.vault,
        f.facet,
        Value::Binary(EntityId::now().as_bytes().to_vec()),
    );

    f.admin_never_deletes(only_me, "the only-me audience");
    f.admin_never_deletes(project, "the project audience");
}

/// Control for (c): a source audience is the same as no rule.
#[test]
fn the_admin_deletes_a_source_import_audience_in_scope() {
    let f = AdminFixture::new();
    let source = import_audience(&f.vault, f.facet, Value::from("source"));

    f.admin_deletes_in_scope(source, "the source audience");
}

/// (d) the counterparty head of a revoked contact: the send gate finds a
/// party's contacts by that head (counterparty_contact/storage.rs), so with
/// it gone the revocation no longer held sends. Before this change DEL-2's
/// in-scope delete landed.
#[test]
fn an_admin_never_deletes_a_revoked_contacts_counterparty_head_in_scope() {
    let f = AdminFixture::new();
    let (_, head) = contact(&f.vault, "owen@example.com", ContactStanding::Revoked);

    f.admin_never_deletes(head, "the revoked contact's counterparty head");
}

/// (d) the revoked contact itself: its delete retires every head it holds,
/// the revocation with them.
#[test]
fn an_admin_never_deletes_a_revoked_contact_in_scope() {
    let f = AdminFixture::new();
    let (revoked, _) = contact(&f.vault, "owen@example.com", ContactStanding::Revoked);

    f.admin_never_deletes(revoked, "the revoked contact");
}

/// (d) an opted-out contact itself: its delete retires its opt-out head.
#[test]
fn an_admin_never_deletes_an_opted_out_contact_in_scope() {
    let f = AdminFixture::new();
    let (opted_out, _) = contact(&f.vault, "yuki@example.com", ContactStanding::OptedOut);

    f.admin_never_deletes(opted_out, "the opted-out contact");
}

/// Control for (d): an active contact's counterparty head restricts nothing.
/// The publish judges the head as its last live read found it, though the
/// delete's own scrub leaves the contact without that head.
#[test]
fn the_admin_deletes_an_active_contacts_counterparty_head_in_scope() {
    let f = AdminFixture::new();
    let (_, head) = contact(&f.vault, "owen@example.com", ContactStanding::Active);

    f.admin_deletes_in_scope(head, "the active contact's counterparty head");
}

/// (e) a claim-class descriptor: a synced row may be stricter than the
/// compiled one, which the vault reads once the row is gone
/// (comm/descriptor.rs `claim_class_descriptor_in_txn`). Before this change
/// DEL-2's in-scope delete landed. The open seeds the compiled rows.
#[test]
fn an_admin_never_deletes_a_claim_class_descriptor_in_scope() {
    let f = AdminFixture::new();
    let descriptor = claim_class_descriptor_id(PREDICATE_COMM_OPT_OUT).expect("descriptor id");
    assert_eq!(
        f.vault.get_entity_type(&descriptor).expect("type read"),
        Some(ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR),
        "the open seeded the comm.opt_out descriptor"
    );

    f.admin_never_deletes(descriptor, "the comm.opt_out descriptor");
}
