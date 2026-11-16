// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! [RESTRICTION-CLAIM-OVERWRITE-AND-SELF-RETRACT] and the Engine's RULING
//! RESTRICTION-FIX-SCOPE = A (15 Nov): "deleting a restriction IS a
//! widening" (the lead's RULING WORLD-ACCESS-GRANT-DELETE = A) holds at
//! every door that takes a restricting row out of its readers' fold below
//! the owner, not only at delete:
//! - F1, a put over the row's id: the lane's stored-target check
//!   (`put_target_admitted_in`) admitted any row its lane reads, so a
//!   Proposed row or a row of another predicate replaced a paused,
//!   suppressed or exited `campaign.member` or a delivery window;
//! - F2, its author's own retract, stale mark or weakening: the self-grant
//!   admitted the close, so an agent lifted the hold it wrote;
//! - a code run's `vault.claims.put` at the row's id: its candidate writer
//!   checked authorship alone, then put over the row or closed it behind a
//!   Proposed successor (Astra review on #8153 F1);
//! - a `campaign.member` head at a fresh key through the generic claim door,
//!   an import door or a raw put outranked an exit the fold had settled: the
//!   typed doors write that family now (`refuse_typed_claim_family`,
//!   `ingest::admission::imported_candidate` for every import door, and the
//!   raw put and claim candidate preflights).
//!
//! Each red is the agent's write; each control is the same door taking a
//! row that restricts no one, or the owner lifting the restriction. The
//! vault is rooted under a host, with the shipped default manifest; the
//! owner grants the agent read over the whole vault and an Auto ceiling (as
//! `tests/world_access_grant_row_guard.rs` sets one up), so the agent's lane
//! reads each row it puts over: each F1 test asserts that first.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test restriction_removal_doors`.
#![cfg(oneiron_test_support)]

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::HostSlipIssuer;
use oneiron::ingest::JSONL_TRANSCRIPT_SOURCE_ID;
use oneiron::memory::{
    AdmitImportedClaimInput, ClaimDemoteActionInput, ClaimDemoteRequest, ClaimDemoteView,
    ClaimInput, CommitReceipt, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MemoryResult,
    resolve_entity_ref,
};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::code_run_claim_put::put_claim_as_code_run;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::write_envelope::cohort_claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    encode_campaign_member_value,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    Error, RawEntityPut, TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

const LEARNED_AT: u64 = 1_780_000_000;

/// The predicate of the agent's own rows. The shipped manifest rates
/// `profile.` normal, so the agent's Auto ceiling lands it Auto.
const NOTE: &str = "profile.note";

/// A delivery window: it holds interrupts while its condition holds.
const DELIVERY_WINDOW_CONTEXT: &str = "delivery_window.context";

/// The refusal of a retract or a stale mark that lifts a restriction.
const LIFTS_A_RESTRICTION: &str = "a claim that restricts someone's access";

/// A vault rooted under a host (an owner's native Grant needs a rooted
/// vault) with the shipped default manifest, its owner, and an agent the
/// owner granted read over the whole vault and an Auto ceiling.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let issuer =
            HostSlipIssuer::from_secret(b"restriction-removal").expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        let agent = vault
            .ensure_agent_principal("restriction-removal-agent")
            .expect("agent");
        let facet = vault.default_facet().expect("default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        vault
            .grant_agent_principal(&owner_proof, &agent.to_hex(), AgentCeiling::Auto)
            .expect("the owner grants the agent read and an Auto ceiling");
        Self {
            vault,
            owner,
            agent,
            facet,
            _directory: directory,
        }
    }

    /// A live PERSON.
    fn person(&self) -> EntityId {
        let person = EntityId::now();
        self.vault
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

    /// `body` on the owner's raw door in the default facet, an Auto row with
    /// no source and no declared scope. Returns its id.
    fn owner_puts(&self, mut body: ClaimBody) -> EntityId {
        body.source = None;
        body.scope = None;
        body.scope_facet = self.facet;
        let predicate = body.predicate.clone();
        let id = EntityId::now();
        self.vault
            .put_claim(&id, &body, at(LEARNED_AT), LEARNED_AT)
            .unwrap_or_else(|error| panic!("the owner's {predicate} claim lands: {error:?}"));
        id
    }

    /// A `campaign.member` of a new PERSON in `state`, as the owner's row.
    fn campaign_member(&self, state: CampaignMemberState) -> EntityId {
        let person = self.person();
        self.owner_puts(claim_about(
            PREDICATE_CAMPAIGN_MEMBER,
            person,
            member_value(state),
        ))
    }

    /// A delivery window about a new PERSON, as the owner's row.
    fn delivery_window(&self) -> EntityId {
        let person = self.person();
        self.owner_puts(claim_about(
            DELIVERY_WINDOW_CONTEXT,
            person,
            Value::Map(vec![
                (Value::from("schema_version"), Value::from(1_u64)),
                (Value::from("applies_to"), Value::from("interrupt")),
                (Value::from("when"), Value::from("asleep")),
            ]),
        ))
    }

    /// `actor`'s raw put, through its own bound handle, of a sourceless
    /// Auto row about the agent at `id`, in the default facet.
    fn puts_a_note_at(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        id: EntityId,
    ) -> MemoryResult<()> {
        self.raw_puts(
            actor,
            class,
            id,
            claim_about(NOTE, self.agent, Value::from("a note")),
        )
    }

    /// `actor`'s raw put of `body` at `id` through its own bound handle,
    /// sourceless, in the default facet.
    fn raw_puts(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        id: EntityId,
        mut body: ClaimBody,
    ) -> MemoryResult<()> {
        body.source = None;
        body.scope_facet = self.facet;
        let data = encode_claim_body(&body).unwrap();
        self.vault
            .memory(actor, class)
            .raw_put_entity(RawEntityPut {
                id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: at(LEARNED_AT),
                learned_at: LEARNED_AT,
                data: &data,
            })
    }

    /// Whether the agent's own lane reads the row at `id` by id.
    fn agent_reads_by_id(&self, id: EntityId) -> bool {
        self.vault
            .memory(self.agent, EdgeActorClass::Agent)
            .get_entity(&id.to_hex())
            .expect("the agent's read by id")
            .value
            .is_some()
    }

    /// The agent writes a claim of `predicate` about itself holding `value`
    /// through `vault.claims.upsert`'s door. Returns the receipt.
    fn agent_writes(
        &self,
        predicate: &str,
        value: serde_json::Value,
    ) -> MemoryResult<CommitReceipt> {
        self.vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_upsert(&ClaimInput {
                id: None,
                predicate: predicate.to_owned(),
                subject_ref: self.agent.to_hex(),
                value,
                confidence: 1.0,
                confidence_details: None,
                source: "observed".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: Some(json!({ "facet": self.facet.to_hex() })),
                valid_from: None,
                valid_to: None,
                occurred_at: None,
                learned_at: None,
                salience: None,
            })
    }

    /// [`Self::agent_writes`], landed Auto: the agent's own admitted row.
    /// Returns its id.
    fn agent_lands(&self, predicate: &str, value: serde_json::Value) -> EntityId {
        let receipt = self
            .agent_writes(predicate, value)
            .unwrap_or_else(|error| panic!("the agent's {predicate} claim lands: {error:?}"));
        assert_eq!(
            receipt.approval, "auto",
            "the agent's {predicate} claim lands Auto"
        );
        resolve_entity_ref(&self.vault, &receipt.claim_short_id).expect("the claim's id")
    }

    /// The agent's own delivery window: it holds the agent's interrupts.
    fn agent_lands_a_delivery_window(&self) -> EntityId {
        self.agent_lands(
            DELIVERY_WINDOW_CONTEXT,
            json!({ "schema_version": 1, "applies_to": "interrupt", "when": "asleep" }),
        )
    }

    /// `actor`'s `vault.claims.retract` of `id` on its own handle.
    fn retracts(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        id: EntityId,
    ) -> MemoryResult<CommitReceipt> {
        self.vault.memory(actor, class).claim_retract(&id.to_hex())
    }

    /// `actor`'s `vault.claims.demote` of `id` to the stale rung on its own
    /// handle.
    fn marks_stale(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        id: EntityId,
    ) -> MemoryResult<ClaimDemoteView> {
        self.demotes(actor, class, id, ClaimDemoteActionInput::Stale)
    }

    /// `actor`'s `vault.claims.demote` of `id` by `action` on its own handle.
    fn demotes(
        &self,
        actor: EntityId,
        class: EdgeActorClass,
        id: EntityId,
        action: ClaimDemoteActionInput,
    ) -> MemoryResult<ClaimDemoteView> {
        self.vault
            .memory(actor, class)
            .claim_demote(&ClaimDemoteRequest {
                claim_ref: id.to_hex(),
                action,
            })
    }

    /// The agent's code-run `vault.claims.put` at `id` of a `profile.note`
    /// about itself, through the candidate writer the dispatcher lands it
    /// by. Returns the id that landed.
    fn code_run_puts_a_note_at(&self, id: EntityId) -> Result<EntityId, Error> {
        put_claim_as_code_run(
            &self.vault,
            WriteActor::new(self.agent, EdgeActorClass::Agent),
            id,
            NOTE,
            self.agent,
            Value::from("a code run's note"),
            LEARNED_AT,
        )
    }

    /// The row stored at `id`.
    fn stored(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("claim read")
            .expect("the row stands")
    }
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

/// A `campaign.member` value in `state` for a new campaign, on email.
fn member_value(state: CampaignMemberState) -> Value {
    encode_campaign_member_value(&CampaignMemberValue {
        campaign: EntityId::now(),
        state,
        channels: vec![CampaignMemberChannel {
            channel: "email".to_owned(),
            basis_evidence: EntityId::now(),
            sender_ref: EntityId::now(),
        }],
        derivation: None,
    })
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// The agent puts its own row over the id of `held`, a row that restricts
/// someone, which its lane reads: refused, and `held` still stands under
/// `predicate`. `what` names the row.
fn the_agents_put_never_replaces(f: &Fixture, held: EntityId, predicate: &str, what: &str) {
    assert!(
        f.agent_reads_by_id(held),
        "the agent's lane reads {what} by id (the FIX row's precondition)"
    );

    let put = f.puts_a_note_at(f.agent, EdgeActorClass::Agent, held);

    assert_eq!(
        f.stored(held).predicate,
        predicate,
        "{what} still stands (put: {put:?})"
    );
    assert!(put.is_err(), "the put over {what} is refused: {put:?}");
}

/// F1: a put over a paused, suppressed or exited `campaign.member`. The
/// campaign's runner sends only while the member reads enrolled or holds no
/// admitted head (campaign/enrollment/runner.rs `membership_sends`), so a
/// Proposed row or a row of another predicate there sent to that person
/// again.
#[test]
fn an_agents_put_over_a_held_campaign_member_never_lifts_the_hold() {
    let f = Fixture::new();
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
        let member = f.campaign_member(state);

        the_agents_put_never_replaces(&f, member, PREDICATE_CAMPAIGN_MEMBER, what);
    }
}

/// F1: a put over a delivery window, which holds interrupts.
#[test]
fn an_agents_put_over_a_delivery_window_never_lifts_it() {
    let f = Fixture::new();
    let window = f.delivery_window();

    the_agents_put_never_replaces(&f, window, DELIVERY_WINDOW_CONTEXT, "the delivery window");
}

/// Control for F1: an enrolled member restricts no one, and the agent's put
/// over it lands as before.
#[test]
fn an_agents_put_over_an_enrolled_campaign_member_lands() {
    let f = Fixture::new();
    let member = f.campaign_member(CampaignMemberState::Enrolled);
    assert!(
        f.agent_reads_by_id(member),
        "the agent's lane reads the member by id"
    );

    f.puts_a_note_at(f.agent, EdgeActorClass::Agent, member)
        .expect("the agent's put over an enrolled member lands");

    assert_eq!(f.stored(member).predicate, NOTE);
}

/// Control for F1: the owner lifts a hold through its own bound handle.
#[test]
fn the_owner_still_puts_over_a_held_campaign_member() {
    let f = Fixture::new();
    let member = f.campaign_member(CampaignMemberState::Suppressed);

    f.puts_a_note_at(f.owner, EdgeActorClass::Human, member)
        .expect("the owner's put over a held member lands");

    assert_eq!(f.stored(member).predicate, NOTE);
}

/// F2: the agent retracts the delivery window it wrote. Its authorship
/// admitted the close, and a retracted window holds nothing.
#[test]
fn an_agent_never_retracts_its_own_delivery_window() {
    let f = Fixture::new();
    let window = f.agent_lands_a_delivery_window();

    let retracted = f.retracts(f.agent, EdgeActorClass::Agent, window);

    assert_eq!(
        f.stored(window).lifecycle,
        ClaimLifecycleStatus::Active,
        "the delivery window still holds (retract: {retracted:?})"
    );
    let refused = retracted.expect_err("an agent never lifts the restriction it wrote");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.contains(LIFTS_A_RESTRICTION),
        "the refusal names its reason: {refused:?}"
    );
}

/// F2, the stale mark: the same self-grant admitted it, and a stale window
/// leaves every surfaceable read.
#[test]
fn an_agent_never_marks_its_own_delivery_window_stale() {
    let f = Fixture::new();
    let window = f.agent_lands_a_delivery_window();

    let marked = f.marks_stale(f.agent, EdgeActorClass::Agent, window);

    assert!(
        !f.stored(window).stale,
        "the delivery window is not stale (stale mark: {marked:?})"
    );
    let refused = marked.expect_err("an agent never lifts the restriction it wrote");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.contains(LIFTS_A_RESTRICTION),
        "the refusal names its reason: {refused:?}"
    );
}

/// Control for F2: the agent's own row that restricts no one is still its
/// to retract.
#[test]
fn an_agent_still_retracts_its_own_note() {
    let f = Fixture::new();
    let note = f.agent_lands(NOTE, json!("a note"));

    f.retracts(f.agent, EdgeActorClass::Agent, note)
        .expect("the agent retracts its own note");
}

/// Control for F2: the owner lifts the agent's delivery window.
#[test]
fn the_owner_still_retracts_an_agents_delivery_window() {
    let f = Fixture::new();
    let window = f.agent_lands_a_delivery_window();

    f.retracts(f.owner, EdgeActorClass::Human, window)
        .expect("the owner retracts the agent's delivery window");

    assert_eq!(f.stored(window).lifecycle, ClaimLifecycleStatus::Retracted);
}

/// The agent's `campaign.member` through `vault.claims.upsert`'s door. A
/// head at a fresh key never meets the stored one, and the fold ranks an
/// enrolled head above an exit (campaign/enrollment/reconcile.rs
/// `state_rank`), so the campaign sent to a person it had let go.
/// `vault.campaign.enroll` and the saved-query derivation write the family.
#[test]
fn an_agents_generic_campaign_member_write_is_refused() {
    let f = Fixture::new();
    let channel = json!({
        "channel": "email",
        "basis_evidence": EntityId::now().to_hex(),
        "sender_ref": EntityId::now().to_hex(),
    });

    let written = f.agent_writes(
        PREDICATE_CAMPAIGN_MEMBER,
        json!({
            "campaign": EntityId::now().to_hex(),
            "state": { "kind": "enrolled" },
            "channels": [channel],
        }),
    );

    let refused = written.expect_err("the generic door never writes a campaign membership");
    assert_eq!(refused.code, MEMORY_CODE_INVALID_STATE, "{refused:?}");
    assert!(
        refused.message.contains("vault.campaign.enroll"),
        "the refusal names the typed door: {refused:?}"
    );
}

/// The agent's `campaign.member` through the import door
/// (`Memory::admit_imported_claim`, a registered source). Every import door
/// builds its candidate in `ingest::admission::imported_candidate`, which
/// held only expression preferences to their typed door, so an imported
/// head at a fresh key met the same fold as the generic one.
#[test]
fn an_agents_imported_campaign_member_is_refused() {
    let f = Fixture::new();
    let person = f.person();

    let imported = f
        .vault
        .memory(f.agent, EdgeActorClass::Agent)
        .admit_imported_claim(&AdmitImportedClaimInput {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID.to_owned(),
            source_record_id: "campaign-member-row".to_owned(),
            id: None,
            subject_ref: person.to_hex(),
            predicate: PREDICATE_CAMPAIGN_MEMBER.to_owned(),
            value: json!({
                "campaign": EntityId::now().to_hex(),
                "state": { "kind": "enrolled" },
                "channels": [{
                    "channel": "email",
                    "basis_evidence": EntityId::now().to_hex(),
                    "sender_ref": EntityId::now().to_hex(),
                }],
            }),
            occurred_at: LEARNED_AT,
            learned_at: None,
        });

    let refused = imported.expect_err("an import never writes a campaign membership");
    assert!(
        refused.message.contains("vault.campaign.enroll"),
        "the refusal names the typed door: {refused:?}"
    );
}

/// Astra review on #8153 F1: the agent's code-run `vault.claims.put` at the
/// id of the delivery window it wrote. The candidate writer checked only
/// the agent's authorship, then closed the window behind a Proposed
/// successor, and the window held nothing.
#[test]
fn an_agents_code_run_put_never_lifts_its_own_delivery_window() {
    let f = Fixture::new();
    let window = f.agent_lands_a_delivery_window();

    let put = f.code_run_puts_a_note_at(window);

    let stored = f.stored(window);
    assert_eq!(
        (stored.predicate.as_str(), stored.lifecycle),
        (DELIVERY_WINDOW_CONTEXT, ClaimLifecycleStatus::Active),
        "the delivery window still holds (put: {put:?})"
    );
    let refused = put.expect_err("an agent never lifts the restriction it wrote");
    assert!(
        refused.to_string().contains(LIFTS_A_RESTRICTION),
        "the refusal names its reason: {refused:?}"
    );
}

/// Control for Astra F1: the agent's code-run put over its own note lands.
#[test]
fn an_agents_code_run_put_over_its_own_note_lands() {
    let f = Fixture::new();
    let note = f.agent_lands(NOTE, json!("a note"));

    f.code_run_puts_a_note_at(note)
        .expect("the agent's code-run put over its own note lands");
}

/// Astra review on #8153 F5: the agent weakens the delivery window it
/// wrote. The weakening closes it behind a Generated successor, and a
/// Generated Auto window holds nothing (delivery_window/claims.rs).
#[test]
fn an_agent_never_weakens_its_own_delivery_window() {
    let f = Fixture::new();
    let window = f.agent_lands_a_delivery_window();
    // The weakening rung follows a decay, which moves only the window's
    // weight; its outcome is not under test.
    let decayed = f.demotes(
        f.agent,
        EdgeActorClass::Agent,
        window,
        ClaimDemoteActionInput::Decay {
            new_claim_of_weight: 0.5,
        },
    );

    let weakened = f.demotes(
        f.agent,
        EdgeActorClass::Agent,
        window,
        ClaimDemoteActionInput::Weaken {
            new_confidence: 0.5,
        },
    );

    assert_eq!(
        f.stored(window).lifecycle,
        ClaimLifecycleStatus::Active,
        "the delivery window still holds (decay: {decayed:?}; weaken: {weakened:?})"
    );
    let refused = weakened.expect_err("an agent never lifts the restriction it wrote");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(
        refused.message.contains(LIFTS_A_RESTRICTION),
        "the refusal names its reason: {refused:?}"
    );
}

/// Astra review on #8153 F4: the agent's raw put of an enrolled
/// `campaign.member` head at a fresh key. The raw door's preflight held
/// only expression preferences to their typed door, so the head met the
/// fold as the generic door's did.
#[test]
fn an_agents_raw_campaign_member_put_is_refused() {
    let f = Fixture::new();
    let person = f.person();

    let put = f.raw_puts(
        f.agent,
        EdgeActorClass::Agent,
        EntityId::now(),
        claim_about(
            PREDICATE_CAMPAIGN_MEMBER,
            person,
            member_value(CampaignMemberState::Enrolled),
        ),
    );

    let refused = put.expect_err("a raw put never writes a campaign membership");
    assert!(
        refused.message.contains("vault.campaign.enroll"),
        "the refusal names the typed door: {refused:?}"
    );
}
