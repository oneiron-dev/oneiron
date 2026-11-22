//! The tray close of a parked supersession names the settle's closer (FIX
//! OWNER-SUPERSEDE-TRAY-CLOSE-RECEIPTS-PROPOSAL-AUTHOR, the twin of
//! OWNER-RETRACT-ROUTE-NAMES-NO-CLOSER, #10097). A replacement that parks a
//! supersession of its head waits in the owner's tray. When the settle that
//! completes the supersession runs with the replacement's tray row still
//! open, the deferred Supersede arm closes that row with a terminal
//! `superseded` receipt. The receipt named the proposal's author; it names
//! the settling door's verified closer, as the retract arm does.
//!
//! The one door that completes a parked supersession while its tray row is
//! still open is the critical confirmation's Clear: it completes the deferred
//! action before it removes the row (`gate/confirm.rs`). The claim settle, the
//! bundle approve, the inbox accept and the highway take each close or redeem
//! the row first, so their Supersede arm finds no row to close. The case: an
//! agent holding an Auto ceiling writes an observed head; a trusted policy
//! then declares the head's predicate critical; the agent's upsert of a new
//! value parks as a critical replacement of the head. The owner reads the
//! pending confirmation and clears it through the owner's ceremony
//! (`Memory::critical_write_confirm_clear_as_owner`), which settles with the
//! revalidated owner as the closer.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_supersede_tray_close_closer`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimInput, CriticalWriteConfirmPendingRequest, CriticalWriteConfirmRequest, resolve_entity_ref,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::{GateDecisionId, GateDecisionRecord};
use oneiron::test_doors::consolidation::declare_predicate_critical;
use oneiron::{
    ClaimLifecycleStatus, CriticalWriteConfirmResolution, EdgeActorClass, EntityId, TimeRange,
    Vault, VaultConfig,
};
use serde_json::json;

/// The shipped manifest declares the `profile.` class normal, so the agent's
/// observed head lands Auto before the policy declares it critical.
const PREDICATE: &str = "profile.name";
/// The reason of a parked critical replacement's tray row.
const CRITICAL_CONFIRM_ATTACHED: &str = "gate.pending.critical_confirm_attached";
/// The reason of the terminal receipt the Supersede arm writes.
const CONTRADICTION_CLOSURE: &str = "gate.supersede.contradiction_closure";
/// When the subject was learned.
const LEARNED_AT: u64 = 100;

struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    agent: EntityId,
    subject: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault rooted under a host, whose root binds the embedded owner, with
    /// an agent the owner granted read and an Auto ceiling.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("FIXTURE: vault dir");
        let vault =
            Vault::open(directory.path(), VaultConfig::device()).expect("FIXTURE: open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("FIXTURE: load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("FIXTURE: owner");
        let issuer = HostSlipIssuer::from_secret(b"supersede-tray-close-closer")
            .expect("FIXTURE: host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("FIXTURE: the host root binds the owner");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("FIXTURE: the engine's machine signers");
        let agent = vault
            .ensure_agent_principal("supersede-tray-close-agent")
            .expect("FIXTURE: agent");
        let facet = vault.default_facet().expect("FIXTURE: default facet");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: owner proof");
        vault
            .grant_agent_principal(&owner_proof, &agent.to_hex(), AgentCeiling::Auto)
            .expect("FIXTURE: the owner grants the agent read and an Auto ceiling");
        let subject = EntityId::now();
        vault
            .put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: LEARNED_AT,
                    end: LEARNED_AT,
                },
                LEARNED_AT,
                b"human",
            )
            .expect("FIXTURE: a live person");
        Self {
            vault,
            issuer,
            owner,
            owner_proof,
            agent,
            subject,
            facet,
            _directory: directory,
        }
    }

    /// The agent's observed upsert of the subject's name: the receipt's
    /// approval and the claim's id.
    fn agent_upserts(&self, value: &str) -> (String, EntityId) {
        let input = ClaimInput {
            id: None,
            predicate: PREDICATE.to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!(value),
            confidence: 1.0,
            confidence_details: None,
            source: "observed".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": self.facet.to_hex() })),
            valid_from: Some(LEARNED_AT),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        };
        let receipt = self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .claim_upsert(&input)
            .unwrap_or_else(|error| panic!("FIXTURE: the agent's upsert of {value}: {error:?}"));
        let id = resolve_entity_ref(&self.vault, &receipt.claim_short_id)
            .expect("FIXTURE: the claim's id");
        (receipt.approval, id)
    }

    fn lifecycle(&self, id: EntityId) -> ClaimLifecycleStatus {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("the claim remains stored")
            .lifecycle
    }

    /// Every Gate decision the ledger holds about `claim`, newest first.
    fn decisions_about(&self, claim: EntityId) -> Vec<GateDecisionRecord> {
        self.vault
            .gate_decisions(4096)
            .expect("read the Gate decisions")
            .into_iter()
            .filter(|record| record.claim_id == Some(*claim.as_bytes()))
            .collect()
    }
}

#[test]
fn the_owners_clear_of_a_parked_critical_replacement_receipts_its_tray_close_as_the_owner() {
    let fixture = Fixture::new();
    let (approval, head) = fixture.agent_upserts("Yuki");
    assert_eq!(approval, "auto", "FIXTURE: the agent's observed head lands");
    declare_predicate_critical(&fixture.vault, PREDICATE)
        .expect("FIXTURE: the policy declares the head's predicate critical");
    let (approval, replacement) = fixture.agent_upserts("Yuki Tanaka");
    assert_eq!(
        approval, "proposed",
        "FIXTURE: the agent's replacement of a critical head parks"
    );
    assert_eq!(
        fixture
            .vault
            .pending_claim_supersession(&replacement)
            .expect("read the parked supersession"),
        Some(head),
        "FIXTURE: the replacement waits to supersede the head"
    );
    let held = fixture
        .vault
        .pending_gate_consents(4096)
        .expect("read the tray")
        .into_iter()
        .find(|row| row.claim_id == *replacement.as_bytes())
        .expect("FIXTURE: the replacement waits in the tray");
    assert!(
        held.reason_codes
            .iter()
            .any(|reason| reason == CRITICAL_CONFIRM_ATTACHED),
        "FIXTURE: the parked replacement carries a critical confirmation: {held:?}"
    );

    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let pending = memory
        .critical_write_confirm_pending_as_owner(
            &fixture.owner_proof,
            &CriticalWriteConfirmPendingRequest {
                pending_operation: format!("gate:{}", held.decision_id.to_hex()),
            },
        )
        .expect("the owner reads the pending confirmation")
        .expect("the replacement's confirmation is pending");
    let settled = memory
        .critical_write_confirm_clear_as_owner(
            &fixture.owner_proof,
            &fixture.issuer,
            &CriticalWriteConfirmRequest {
                pending_operation: pending.pending_operation.clone(),
                nonce: pending.nonce.clone(),
                read_frontier_hash: pending.read_frontier_hash.clone(),
            },
        )
        .expect("the owner clears the confirmation");
    assert_eq!(
        settled.resolution,
        CriticalWriteConfirmResolution::Cleared,
        "the owner's clear completes the replacement"
    );
    assert_eq!(
        fixture.lifecycle(head),
        ClaimLifecycleStatus::Superseded,
        "the clear completes the parked supersession of the head"
    );
    assert_eq!(
        fixture.lifecycle(replacement),
        ClaimLifecycleStatus::Active,
        "the replacement stands in the head's place"
    );

    let decisions = fixture.decisions_about(replacement);
    let terminal: Vec<_> = decisions
        .iter()
        .filter(|record| {
            record.outcome == "superseded"
                && record
                    .reason_codes
                    .iter()
                    .any(|reason| reason == CONTRADICTION_CLOSURE)
        })
        .collect();
    let [terminal] = terminal.as_slice() else {
        panic!("the replacement's tray row closes with one terminal receipt: {decisions:?}");
    };
    let owner_ref = fixture.owner.to_hex();
    assert_eq!(
        (terminal.actor_class.as_str(), terminal.actor_ref.as_deref()),
        ("human", Some(owner_ref.as_str())),
        "the tray row's close is receipted as the owner who cleared it, not as the agent {}: \
         {terminal:?}",
        fixture.agent.to_hex()
    );
}
