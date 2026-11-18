// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FIX [RESTRICTION-CLOSE-BY-NATIVE-DEMOTION] (Astra census-l2-derive-recheck
//! F4 on #8238). The native demotion door, `Vault::apply_claim_demotion`,
//! takes no actor and no owner proof, and it held only a critical target
//! for the owner. So a host caller could decay a noncritical Observed Auto
//! delivery window and then weaken it. The weakening closed the window
//! behind the Dreamer's Generated successor, and a Generated Auto window
//! holds nothing (delivery_window/claims.rs). A stale mark took the window
//! out of every surfaceable read the same way.
//!
//! Lifting a restriction is a live vault owner's act (the Engine's RULING
//! RESTRICTION-FIX-SCOPE = A; the lead's RULING WORLD-ACCESS-GRANT-DELETE =
//! A: "deleting a restriction IS a widening"). The Memory door
//! (`vault.claims.demote`) already judges it by
//! `federation::claim_removal_widens_in`. The native door now refuses a
//! weakening or a stale mark of a claim that restricts someone, by the same
//! rule.
//!
//! The two reds are the native weakening and the native stale mark of the
//! agent's delivery window. The three controls are a native decay of the
//! window (it moves only the weight), a native decay and weakening of a note
//! that restricts no one, and the owner's own `vault.claims.demote`
//! weakening of the window. The vault is rooted under a host, with the
//! shipped default manifest and the engine's machine identities (the
//! Dreamer signs a weakening's successor). The owner grants the agent read
//! over the whole vault and an Auto ceiling, as
//! `tests/restriction_removal_doors.rs` sets it up, so the agent's own rows
//! land Observed and Auto.
//!
//! Run: `cargo test --locked -p oneiron --all-features --no-fail-fast --test
//! restriction_native_demotion`.
#![cfg(feature = "test-support")]

use oneiron::agent_def::AgentCeiling;
use oneiron::authority::HostSlipIssuer;
use oneiron::error::ClaimError;
use oneiron::memory::{
    ClaimDemoteActionInput, ClaimDemoteRequest, ClaimDemoteView, ClaimInput, MemoryResult,
    resolve_entity_ref,
};
use oneiron::store::GateDecisionId;
use oneiron::write_envelope::claim_body::{ClaimDemotion, ClaimDemotionAction, ClaimDemotionRung};
use oneiron::{
    ClaimBody, ClaimLifecycleStatus, ClaimSource, EdgeActorClass, EntityId, Error, Vault,
    VaultConfig,
};
use serde_json::json;

/// The predicate of the agent's note. The shipped manifest rates `profile.`
/// normal, so the agent's Auto ceiling lands it Auto.
const NOTE: &str = "profile.note";

/// A delivery window: it holds interrupts while its condition holds.
const DELIVERY_WINDOW_CONTEXT: &str = "delivery_window.context";

/// The native door's refusal of a weakening or a stale mark that lifts a
/// restriction.
const LIFTS_A_RESTRICTION: &str = "a claim that restricts someone's access";

/// A vault rooted under a host (an owner's native Grant needs a rooted
/// vault) with the shipped default manifest and the engine's machine
/// identities, its owner, and an agent the owner granted read over the
/// whole vault and an Auto ceiling.
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
        let issuer = HostSlipIssuer::from_secret(b"restriction-native-demotion")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("the Dreamer can sign a weakening's successor");
        let agent = vault
            .ensure_agent_principal("restriction-native-demotion-agent")
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

    /// The agent writes an Observed claim of `predicate` about itself holding
    /// `value` through `vault.claims.upsert`'s door, and it lands Auto.
    /// Returns its id.
    fn agent_lands(&self, predicate: &str, value: serde_json::Value) -> EntityId {
        let receipt = self
            .vault
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

    /// The native door's demotion of `id` by `action`, with no actor.
    fn native_demotes(
        &self,
        id: EntityId,
        action: ClaimDemotionAction,
    ) -> oneiron::Result<ClaimDemotion> {
        self.vault.apply_claim_demotion(&id, action, now_seconds())
    }

    /// The owner's `vault.claims.demote` of `id` by `action` on the owner's
    /// own handle.
    fn owner_demotes(
        &self,
        id: EntityId,
        action: ClaimDemoteActionInput,
    ) -> MemoryResult<ClaimDemoteView> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_demote(&ClaimDemoteRequest {
                claim_ref: id.to_hex(),
                action,
            })
    }

    /// The row stored at `id`.
    fn stored(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("claim read")
            .expect("the row stands")
    }
}

/// A decay to the ClaimOf weight `weight`.
fn decay(weight: f32) -> ClaimDemotionAction {
    ClaimDemotionAction::Decay {
        new_claim_of_weight: weight,
    }
}

/// A weakening to the confidence `confidence`.
fn weaken(confidence: f32) -> ClaimDemotionAction {
    ClaimDemotionAction::Weaken {
        new_confidence: confidence,
    }
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs()
}

/// `result` is the native door's refusal of a lift: the claim-authority
/// error naming the restriction.
fn assert_refused_as_a_lift(result: oneiron::Result<ClaimDemotion>) {
    match result {
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })) => assert!(
            reason.contains(LIFTS_A_RESTRICTION),
            "the refusal names its reason: {reason}"
        ),
        other => panic!("the native door refuses to lift the restriction; got {other:?}"),
    }
}

/// Red: the host decays the agent's delivery window and then weakens it
/// through the native door. The weakening closed the window behind a
/// Generated successor, which holds nothing.
#[test]
fn a_native_weakening_never_lifts_a_delivery_window() {
    let f = Fixture::new();
    let window = f.agent_lands_a_delivery_window();
    let decayed = f
        .native_demotes(window, decay(0.5))
        .expect("a decay only moves the window's weight");
    assert_eq!(decayed.rung, ClaimDemotionRung::Decayed);

    let weakened = f.native_demotes(window, weaken(0.5));

    assert_eq!(
        f.stored(window).lifecycle,
        ClaimLifecycleStatus::Active,
        "the delivery window still holds (weaken: {weakened:?})"
    );
    assert_refused_as_a_lift(weakened);
}

/// Red: the host marks the agent's delivery window stale through the native
/// door. The stale mark took the window out of every surfaceable read.
#[test]
fn a_native_stale_mark_never_lifts_a_delivery_window() {
    let f = Fixture::new();
    let window = f.agent_lands_a_delivery_window();

    let marked = f.native_demotes(window, ClaimDemotionAction::MarkStale);

    let stored = f.stored(window);
    assert!(
        !stored.stale && stored.lifecycle == ClaimLifecycleStatus::Active,
        "the delivery window still holds (stale mark: {marked:?})"
    );
    assert_refused_as_a_lift(marked);
}

/// Control: a native decay of the delivery window lands. It moves only the
/// window's ClaimOf weight, and the window still holds.
#[test]
fn a_native_decay_of_a_delivery_window_still_lands() {
    let f = Fixture::new();
    let window = f.agent_lands_a_delivery_window();

    let decayed = f
        .native_demotes(window, decay(0.5))
        .expect("the native decay lands");

    assert_eq!(decayed.rung, ClaimDemotionRung::Decayed);
    assert_eq!(decayed.claim, window, "a decay writes in place");
    let stored = f.stored(window);
    assert!(!stored.stale, "a decay is no stale mark");
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
}

/// Control: a note restricts no one, so the native door decays and then
/// weakens it as before. The weakening closes the note behind the Dreamer's
/// Generated successor.
#[test]
fn a_native_weakening_of_a_note_still_lands() {
    let f = Fixture::new();
    let note = f.agent_lands(NOTE, json!("a note"));
    f.native_demotes(note, decay(0.5))
        .expect("the native decay of the note lands");

    let weakened = f
        .native_demotes(note, weaken(0.5))
        .expect("the native weakening of the note lands");

    assert_eq!(weakened.rung, ClaimDemotionRung::Weakened);
    assert_ne!(weakened.claim, note, "a weakening supersedes");
    assert_eq!(f.stored(note).lifecycle, ClaimLifecycleStatus::Superseded);
    let successor = f.stored(weakened.claim);
    assert_eq!(successor.source, Some(ClaimSource::Generated));
    assert_eq!(successor.lifecycle, ClaimLifecycleStatus::Active);
}

/// Control: the live owner still lifts the restriction, through
/// `vault.claims.demote` on the owner's own handle: a decay and then a
/// weakening of the agent's delivery window land.
#[test]
fn the_owner_still_weakens_a_delivery_window() {
    let f = Fixture::new();
    let window = f.agent_lands_a_delivery_window();
    f.owner_demotes(
        window,
        ClaimDemoteActionInput::Decay {
            new_claim_of_weight: 0.5,
        },
    )
    .expect("the owner's decay lands");

    let weakened = f
        .owner_demotes(
            window,
            ClaimDemoteActionInput::Weaken {
                new_confidence: 0.5,
            },
        )
        .expect("the owner's weakening lands");

    assert_eq!(weakened.rung, "weakened");
    assert_ne!(
        weakened.claim_ref,
        window.to_hex(),
        "a weakening supersedes"
    );
    assert_eq!(f.stored(window).lifecycle, ClaimLifecycleStatus::Superseded);
}
