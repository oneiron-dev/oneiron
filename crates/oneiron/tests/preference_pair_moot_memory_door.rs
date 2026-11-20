//! A preference conflict opened by `Memory::claim_upsert` is no longer open
//! once the owner restates the answer or approves an agreeing observation.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test preference_pair_moot_memory_door`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::{ConflictSettlement, OpenConflict};
use oneiron::memory::{ClaimInput, MEMORY_CODE_BAD_REQUEST, Memory, resolve_entity_ref};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_support::provision_engine_machines;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

const PREDICATE: &str = "preference.drink";
const STATED_ANSWER: &str = "black coffee";
const OBSERVED_ANSWER: &str = "green tea";
const RESTATED_ANSWER: &str = "oolong tea";

/// A device vault with its embedded owner and the PERSON the drink preference is about.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    subject: EntityId,
    facet: EntityId,
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// Opens the vault with a serving install profile and the authenticated embedded owner.
    fn rooted() -> Self {
        let directory = tempfile::tempdir().expect("The vault directory should be created.");
        let vault = Vault::open(directory.path(), VaultConfig::device())
            .expect("The device vault should open.");
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("The vault should have a live serving install profile.");
        let (owner, proof) =
            embedded_owner(&vault).expect("The embedded owner should authenticate.");
        let subject = vault
            .new_entity_id()
            .expect("The subject should have a fresh ID.");
        let now = vault.now_recorded_at();
        vault
            .put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"Drink preference subject",
            )
            .expect("The subject should exist before the claims are written.");
        let facet = vault
            .default_facet()
            .expect("The vault should have a default facet.");
        Self {
            vault,
            owner,
            proof,
            subject,
            facet,
            _directory: directory,
        }
    }

    fn owner_memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// One `preference.drink` input about the subject with `answer`, declared as `source`.
    fn input(&self, source: &str, answer: &str) -> ClaimInput {
        ClaimInput {
            id: None,
            predicate: PREDICATE.to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!(answer),
            confidence: 1.0,
            confidence_details: None,
            source: source.to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": self.facet.to_hex(), "sensitivity": "private" })),
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        }
    }

    fn claim_id(&self, reference: &str) -> EntityId {
        resolve_entity_ref(&self.vault, reference).expect("The claim reference should resolve.")
    }

    fn claim(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("The claim should be readable.")
            .expect("The claim should exist.")
    }

    fn assert_standing(
        &self,
        id: EntityId,
        source: ClaimSource,
        approval: ClaimApprovalStatus,
        answer: &str,
    ) {
        let claim = self.claim(id);
        assert_eq!(
            claim.lifecycle,
            ClaimLifecycleStatus::Active,
            "Claim {id:?} should be active."
        );
        assert_eq!(
            claim.approval, approval,
            "Claim {id:?} should have the expected approval."
        );
        assert_eq!(
            claim.source,
            Some(source),
            "Claim {id:?} should retain its source."
        );
        assert_eq!(
            claim.value.as_str(),
            Some(answer),
            "Claim {id:?} should hold the expected answer."
        );
        assert_eq!(
            claim.valid_to, None,
            "Claim {id:?} should not have a validity end."
        );
    }

    /// The subject's open conflicts as the owner's list shows them.
    fn open_conflicts(&self) -> Vec<OpenConflict> {
        self.owner_memory()
            .open_conflicts(Some(&self.proof), Some(self.subject), usize::MAX)
            .expect("The owner should be able to list the subject's open conflicts.")
    }

    /// Lands the owner's stated answer and a differing observation through
    /// `Memory::claim_upsert`, and returns both claims with the marker the
    /// second write opened.
    fn disagreeing_pair(&self) -> (EntityId, EntityId, EntityId) {
        let owner = self.owner_memory();
        let stated = owner
            .claim_upsert(&self.input("user_stated", STATED_ANSWER))
            .expect("The owner's stated preference should land.");
        let observed = owner
            .claim_upsert(&self.input("observed", OBSERVED_ANSWER))
            .expect("The observation should land beside the stated preference.");
        let stated = self.claim_id(&stated.claim_short_id);
        let observed = self.claim_id(&observed.claim_short_id);
        self.assert_standing(
            stated,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Auto,
            STATED_ANSWER,
        );
        self.assert_standing(
            observed,
            ClaimSource::Observed,
            ClaimApprovalStatus::Auto,
            OBSERVED_ANSWER,
        );

        let open = self.open_conflicts();
        let [conflict] = open.as_slice() else {
            panic!(
                "The owner should see exactly one open conflict, but saw {}.",
                open.len()
            );
        };
        assert_eq!(
            conflict.body.predicate, "core.conflict.open",
            "The conflict should be a stored open marker."
        );
        assert_eq!(
            conflict.predicates,
            [PREDICATE.to_owned()],
            "The marker should contest the drink preference."
        );
        assert_eq!(
            conflict.members,
            [observed, stated],
            "The marker should name the observation first and the statement second."
        );
        (stated, observed, conflict.marker)
    }
}

/// The owner replaces the stated answer: the marker leaves the owner's list and
/// a settlement of it is refused, though the two standing answers still differ.
#[test]
fn a_restated_answer_through_the_memory_door_leaves_no_open_conflict() {
    let fixture = Fixture::rooted();
    let (stated, observed, marker) = fixture.disagreeing_pair();

    let mut input = fixture.input("user_stated", RESTATED_ANSWER);
    input.id = Some(stated.to_hex());
    let receipt = fixture
        .owner_memory()
        .claim_upsert(&input)
        .expect("The owner's restatement should land immediately.");
    let corrected = fixture.claim_id(&receipt.claim_short_id);
    assert_ne!(
        corrected, stated,
        "The changed answer should receive a fresh claim ID."
    );
    let prior = receipt
        .superseded_short_id
        .as_deref()
        .expect("The restatement should name the claim it superseded.");
    assert_eq!(
        fixture.claim_id(prior),
        stated,
        "The restatement should replace the stated claim, not the observation."
    );
    fixture.assert_standing(
        corrected,
        ClaimSource::UserStated,
        ClaimApprovalStatus::Auto,
        RESTATED_ANSWER,
    );
    assert_eq!(
        fixture.claim(stated).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "The first stated claim should be superseded."
    );
    fixture.assert_standing(
        observed,
        ClaimSource::Observed,
        ClaimApprovalStatus::Auto,
        OBSERVED_ANSWER,
    );
    assert!(
        !fixture
            .open_conflicts()
            .iter()
            .any(|conflict| conflict.marker == marker),
        "The owner should no longer see the marker for the replaced statement."
    );

    let refusal = fixture
        .owner_memory()
        .settle_conflict(
            Some(&fixture.proof),
            marker,
            ConflictSettlement::Dismiss,
            fixture.vault.now_recorded_ms(),
        )
        .expect_err("The owner should not be able to settle a marker whose pair no longer stands.");
    assert_eq!(
        refusal.code, MEMORY_CODE_BAD_REQUEST,
        "Opening the moot marker for settlement should be a bad request."
    );
    assert!(
        refusal
            .message
            .contains("the conflict's pair no longer stands"),
        "The refusal should explain why the marker will not open: {}.",
        refusal.message
    );
}

/// A later observation that agrees with the stated answer replaces the first
/// observation once approved: the marker stays open until then and is gone after.
#[test]
fn an_agreeing_later_observation_through_the_memory_door_leaves_no_open_conflict() {
    let fixture = Fixture::rooted();
    let (stated, observed, marker) = fixture.disagreeing_pair();

    let receipt = fixture
        .owner_memory()
        .claim_upsert(&fixture.input("observed", STATED_ANSWER))
        .expect("The agreeing observation should land as a proposed replacement.");
    let later = fixture.claim_id(&receipt.claim_short_id);
    assert_eq!(
        fixture.claim(later).approval,
        ClaimApprovalStatus::Proposed,
        "The later observation should wait for approval."
    );
    assert_eq!(
        fixture
            .vault
            .pending_claim_supersession(&later)
            .expect("The pending replacement should be readable."),
        Some(observed),
        "The later observation should propose replacing the first observation."
    );
    let open = fixture.open_conflicts();
    let [conflict] = open.as_slice() else {
        panic!(
            "Only the original conflict should be open before approval, but {} were open.",
            open.len()
        );
    };
    assert_eq!(
        conflict.marker, marker,
        "The original marker should stay open until approval."
    );

    let unchanged = fixture
        .vault
        .get(&later)
        .expect("The proposed observation should be readable.")
        .expect("The proposed observation should have a stored body.");
    fixture
        .vault
        .approve_inbox_member_with_edit_at(&later, &unchanged, fixture.vault.now_recorded_at())
        .expect("The vault should approve the replacement without changing its answer.");

    fixture.assert_standing(
        later,
        ClaimSource::Observed,
        ClaimApprovalStatus::Approved,
        STATED_ANSWER,
    );
    assert_eq!(
        fixture.claim(observed).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "The first observation should be superseded after approval."
    );
    fixture.assert_standing(
        stated,
        ClaimSource::UserStated,
        ClaimApprovalStatus::Auto,
        STATED_ANSWER,
    );
    assert!(
        !fixture
            .open_conflicts()
            .iter()
            .any(|conflict| conflict.marker == marker),
        "The owner should no longer see the marker for the replaced observation."
    );
}
