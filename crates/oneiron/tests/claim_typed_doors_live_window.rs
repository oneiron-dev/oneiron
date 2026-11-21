//! A claim demotion, an expression-preference set or retract through the
//! typed doors reaches the loaded window that carries it, through the live
//! mirror, without waiting for the window's next cold open (FIX
//! CLAIM-RAW-TXN-DOORS-DROP-LIVE-WINDOW-ROWS).
//!
//! `Vault::apply_claim_demotion`, `Vault::set_expression_preference` and
//! `Vault::retract_expression_preference` committed on a bare write
//! transaction with no post-commit owner, so the rows they wrote reached no
//! loaded live window. A loaded window kept the claim as it was before the
//! write until the window was built from the store again.
//!
//! The machine-history adopt and carry doors get the same fix with no test
//! here: the signed handoff they take is built with
//! `HostSlipIssuer::sign_entry` and `HostSlipIssuer::sign_claim_handoff`,
//! which are crate-private.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_typed_doors_live_window`.
#![cfg(all(feature = "sync", feature = "test-support"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use oneiron::agent_def::AgentCeiling;
use oneiron::authority::HostSlipIssuer;
use oneiron::claim::{ExpressionPreferenceOrigin, ExpressionPreferenceValue};
use oneiron::error::GateError;
use oneiron::memory::{ClaimInput, ExpressionPreferenceInput, resolve_entity_ref};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::residence_window_for_blob;
use oneiron::sync::window::LoadedWindow;
use oneiron::write_envelope::claim_body::{ClaimDemotionAction, ClaimDemotionRung};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use oneiron_keystore::MemoryKeystore;
use rmpv::Value;
use serde_json::json;

/// 2026-03-15 00:00 UTC: the demotion fixture's rows are learned then, so all
/// of them ride the base window of March 2026.
const T0: u64 = 1_773_532_800;
/// The live mirror carries a committed row on its own thread: the test looks
/// every `POLL`, at most `POLLS` times (30 s of sleep), with no clock read.
const POLL: Duration = Duration::from_millis(20);
const POLLS: u32 = 1_500;

/// The gate's reason for a demotion it parks for the owner's Clear.
const CRITICALITY_FLOOR: &str = "gate.pending.criticality_floor";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// A vault with an install signer, as a host opens one.
fn open_vault(dir: &std::path::Path) -> Arc<Vault> {
    let vault = Vault::open(dir, VaultConfig::device()).expect("the vault opens");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    Arc::new(vault)
}

/// The bytes the window's doc carries for `id`'s row.
fn carrier(doc: &LoroDoc, id: &EntityId) -> Option<Vec<u8>> {
    match doc.get_map("entities").get(&id.to_hex())? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// Waits until the window carries `id`'s row as the store holds it now.
fn wait_until_carried(vault: &Vault, window: &LoadedWindow, id: &EntityId, what: &str) {
    for _ in 0..POLLS {
        let stored = vault
            .get_raw(id)
            .expect("read the row")
            .expect("the row is stored");
        if carrier(&window.doc, id).as_deref() == Some(stored.as_slice()) {
            return;
        }
        std::thread::sleep(POLL);
    }
    panic!("after {POLLS} looks the loaded window still carries {what} as it was before the write");
}

/// The window that holds `id`'s row, opened and kept loaded.
fn loaded_window_for(vault: &Arc<Vault>, id: &EntityId) -> (Arc<WindowManager>, Arc<LoadedWindow>) {
    let raw = vault
        .get_raw(id)
        .expect("read the row")
        .expect("the row is stored");
    let key = residence_window_for_blob(&raw).expect("the row's window");
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "owner",
    ));
    let window = manager.open_window(&key).expect("the window opens");
    (manager, window)
}

/// A vault holding one active, UserStated claim on a normal predicate, born
/// at the default ClaimOf weight 1.0.
struct DemotionFixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    claim: EntityId,
}

impl DemotionFixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault");
        let vault = open_vault(dir.path());
        let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
        let subject = EntityId::now();
        for id in [actor.entity_ref(), subject] {
            vault
                .put_entity(&id, ENTITY_TYPE_PERSON, at(T0), T0, b"")
                .expect("put person");
        }
        // A normal predicate avoids the critical-confirm hold.
        let envelope = WriteEnvelope::new(
            actor,
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("typed doors fixture")).expect("provenance"),
            ClaimApprovalStatus::Auto,
        );
        let claim = EntityId::now();
        vault
            .batch()
            .claim_candidate(
                &claim,
                ClaimCandidate::new(
                    "profile.decay_fixture",
                    ClaimSubject::Entity(subject),
                    Value::from("fact"),
                    1.0,
                ),
                &envelope,
                at(T0),
                T0,
            )
            .commit()
            .expect("write the claim");
        Self {
            _dir: dir,
            vault,
            claim,
        }
    }
}

/// A decay's row reaches the loaded window that carries the claim.
///
/// Red on main a1dc3dd3c27b: `apply_claim_demotion` commits on a bare
/// transaction, which queues no row, so the loaded window keeps the
/// pre-decay bytes.
#[test]
fn a_decay_reaches_the_loaded_window_that_carries_the_claim() {
    let fixture = DemotionFixture::open();
    let (_manager, window) = loaded_window_for(&fixture.vault, &fixture.claim);
    assert!(
        carrier(&window.doc, &fixture.claim).is_some(),
        "fixture: the window carries the claim"
    );

    let demotion = fixture
        .vault
        .apply_claim_demotion(
            &fixture.claim,
            ClaimDemotionAction::Decay {
                new_claim_of_weight: 0.4,
            },
            T0 + 60,
        )
        .expect("the decay lands");
    assert_eq!(
        demotion.rung,
        ClaimDemotionRung::Decayed,
        "the store holds the claim decayed"
    );

    wait_until_carried(&fixture.vault, &window, &fixture.claim, "the decayed claim");
    assert_eq!(
        carrier(&window.doc, &fixture.claim).as_deref(),
        fixture
            .vault
            .get_raw(&fixture.claim)
            .expect("read the row")
            .as_deref(),
        "the loaded window carries the decayed row"
    );
}

/// A stale mark's row reaches the loaded window that carries the claim.
///
/// Red on main a1dc3dd3c27b: `apply_claim_demotion` commits on a bare
/// transaction, which queues no row, so the loaded window keeps the
/// pre-stale bytes.
#[test]
fn a_stale_mark_reaches_the_loaded_window_that_carries_the_claim() {
    let fixture = DemotionFixture::open();
    let (_manager, window) = loaded_window_for(&fixture.vault, &fixture.claim);
    assert!(
        carrier(&window.doc, &fixture.claim).is_some(),
        "fixture: the window carries the claim"
    );

    let demotion = fixture
        .vault
        .apply_claim_demotion(&fixture.claim, ClaimDemotionAction::MarkStale, T0 + 60)
        .expect("the stale mark lands");
    assert_eq!(
        demotion.rung,
        ClaimDemotionRung::Stale,
        "the store holds the claim stale"
    );

    wait_until_carried(&fixture.vault, &window, &fixture.claim, "the stale claim");
    assert_eq!(
        carrier(&window.doc, &fixture.claim).as_deref(),
        fixture
            .vault
            .get_raw(&fixture.claim)
            .expect("read the row")
            .as_deref(),
        "the loaded window carries the stale row"
    );
}

/// One typed preference set through the owner's Memory door.
fn set_preference(
    vault: &Vault,
    owner: EntityId,
    subject: EntityId,
    value: &str,
    valid_from: u64,
    now: u64,
) -> EntityId {
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .set_expression_preference(&ExpressionPreferenceInput {
            subject_ref: subject.to_hex(),
            value: ExpressionPreferenceValue::Language(value.to_owned()),
            origin: ExpressionPreferenceOrigin::ExplicitUser,
            valid_from,
            occurred_at: Some(now),
        })
        .unwrap_or_else(|error| panic!("the preference set lands: {error:?}"));
    resolve_entity_ref(vault, &receipt.claim_short_id).expect("the head's id")
}

/// A set preference's new head reaches the loaded window.
///
/// Red on main a1dc3dd3c27b: `set_expression_preference` commits on a bare
/// transaction, which queues no row, so the loaded window never carries the
/// new head.
#[test]
fn a_set_preference_head_reaches_the_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    // One timestamp for every row, so all of them ride one window.
    let now = vault.now_recorded_at();
    let subject = EntityId::now();
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at(now), now, b"someone")
        .expect("the person");
    let (_manager, window) = loaded_window_for(&vault, &subject);

    let head = set_preference(&vault, owner, subject, "en-US", now, now);
    assert_eq!(
        vault
            .get_claim(&head)
            .expect("read the claim")
            .expect("the head is stored")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "the store holds the new head active"
    );

    wait_until_carried(&vault, &window, &head, "the new head");
    assert_eq!(
        carrier(&window.doc, &head).as_deref(),
        vault.get_raw(&head).expect("read the row").as_deref(),
        "the loaded window carries the new head"
    );
}

/// A retracted head and its restored predecessor reach the loaded window.
///
/// Red on main a1dc3dd3c27b: `retract_expression_preference` commits on a
/// bare transaction, which queues no row, so the loaded window keeps both
/// the head and the predecessor as they were before the retract.
#[test]
fn a_retract_and_its_restored_predecessor_reach_the_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    // One timestamp for every row, so all of them ride one window.
    let now = vault.now_recorded_at();
    let subject = EntityId::now();
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at(now), now, b"someone")
        .expect("the person");
    let (_manager, window) = loaded_window_for(&vault, &subject);

    // The second set outranks the first on `valid_from`, so a predecessor
    // exists to restore.
    let first = set_preference(&vault, owner, subject, "en-US", now - 100, now);
    let head = set_preference(&vault, owner, subject, "fr-FR", now, now);
    assert_ne!(first, head, "the two sets mint two heads");
    assert_eq!(
        vault
            .get_claim(&first)
            .expect("read the claim")
            .expect("the first head is stored")
            .lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the second set outranks the first"
    );
    vault
        .memory(owner, EdgeActorClass::Human)
        .retract_expression_preference(&head.to_hex())
        .unwrap_or_else(|error| panic!("the retract lands: {error:?}"));
    assert_eq!(
        vault
            .get_claim(&head)
            .expect("read the claim")
            .expect("the head is stored")
            .lifecycle,
        ClaimLifecycleStatus::Retracted,
        "the store holds the head retracted"
    );
    assert_eq!(
        vault
            .get_claim(&first)
            .expect("read the claim")
            .expect("the predecessor is stored")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "the store holds the predecessor restored"
    );

    wait_until_carried(&vault, &window, &head, "the retracted head");
    assert_eq!(
        carrier(&window.doc, &head).as_deref(),
        vault.get_raw(&head).expect("read the row").as_deref(),
        "the loaded window carries the head retracted"
    );
    wait_until_carried(&vault, &window, &first, "the restored predecessor");
    assert_eq!(
        carrier(&window.doc, &first).as_deref(),
        vault.get_raw(&first).expect("read the row").as_deref(),
        "the loaded window carries the predecessor active"
    );
}

/// A vault rooted under a host with the shipped default manifest, its owner,
/// and an agent the owner granted read over the whole vault and an Auto
/// ceiling.
struct ParkFixture {
    vault: Vault,
    agent: EntityId,
    facet: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl ParkFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let issuer = HostSlipIssuer::from_secret(b"typed-doors-park").expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the host root binds the owner");
        let agent = vault
            .ensure_agent_principal("typed-doors-park-agent")
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
}

/// The critical park commits its pending row and then refuses with the typed
/// pending error, leaving the target claim untouched.
///
/// Stays green on main a1dc3dd3c27b: it pins the park's commit-then-refuse
/// shape through the write-door reshape, not the live-window fix.
#[test]
fn the_critical_park_commits_the_pending_row_and_refuses() {
    // The shipped manifest rates a delivery window critical by its default.
    let fixture = ParkFixture::new();
    let window = fixture.agent_lands(
        "delivery_window.context",
        json!({ "schema_version": 1, "applies_to": "interrupt", "when": "asleep" }),
    );

    let parked = fixture.vault.apply_claim_demotion(
        &window,
        ClaimDemotionAction::Decay {
            new_claim_of_weight: 0.4,
        },
        fixture.vault.now_recorded_at(),
    );

    match parked {
        Err(Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        })) => {
            assert_eq!(outcome, "pending", "the demotion parks");
            assert_eq!(
                reason_codes,
                [CRITICALITY_FLOOR],
                "at the criticality floor"
            );
        }
        other => panic!("the critical demotion parks for the owner's Clear; got {other:?}"),
    }
    match fixture
        .vault
        .pending_claim_demotion(&window)
        .expect("read the parked row")
    {
        Some(ClaimDemotionAction::Decay {
            new_claim_of_weight,
        }) => assert_eq!(new_claim_of_weight, 0.4, "the parked row is this decay"),
        other => panic!("the critical park commits the pending decay row; got {other:?}"),
    }
    let stored = fixture
        .vault
        .get_claim(&window)
        .expect("claim read")
        .expect("the row stands");
    assert!(!stored.stale, "a parked decay writes no rung on the target");
    assert_eq!(
        stored.lifecycle,
        ClaimLifecycleStatus::Active,
        "the parked target still holds"
    );
}
