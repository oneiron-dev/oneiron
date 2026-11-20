//! Row CHECK-IN-LEGAL-HOLD-RESTARTED-ACT-NO-DECISION (P2.5 2k2a; FIX 9781,
//! 10401): in a shared vault with two Owners an explicit lift-and-erase waits
//! out its veto window on its own `erase` act, and that act records the
//! confirm's check-in decision. When the confirm's writer committed and its
//! act start did not follow, as on a crash between the two, the legal-hold
//! pass starts the act. The restarted act records the same decision: the
//! Owner on their own proof, with the approved check-in the confirm applied
//! and its asker.
//!
//! - A confirm whose act is lost: the pass's act records its decision.
//! - The same request confirmed again while its act never started: the new
//!   confirm starts its own act with its own decision, and a restart after
//!   that act is lost records the newer decision, which spent the check-in.
//! - A hard erase of the asker while the erase waits with no act takes their
//!   id out of the decision the waiting erase keeps, as the shared-act scrub
//!   takes it out of a pending act (P24-SHAPE Q7 = A): the act the pass
//!   restarts names the erased marker; the basis and the spent check-in stay.
//!
//! On main (e8ba377d6ec4) each test fails at its last assert: the pass starts
//! the act with no decision.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_legal_hold_restarted_act`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::check_in::{ActClass, CheckInDecision, legal_hold_erase_effect_digest};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{BlobArtifactInput, Memory};
use oneiron::receipt::ERASED_CALL_IDENTITY;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::legal_hold_erase_act::{forget_waiting_erase_act, waiting_erase_act};
use oneiron::verbs::{
    LegalHoldEraseState, LegalHoldLiftAndEraseRequest, LegalHoldLiftAndErased,
    OwnerConfirmPreviewRequest, lift_legal_hold_and_erase_as, preview_owner_confirm,
};
use oneiron::{DeleteReason, EdgeActorClass, EntityId, TimeRange, Vault};
use owner_apply_fixture::{approved, owner_decision, proof, rooted, spent};

const SHARED: u64 = 43;
const LIFT_AND_ERASE: &str = "vault.legal_holds.lift_and_erase";

/// `id` as a live person of `vault`.
fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

/// A rooted vault whose shared vault has two live Owners, so an owner's
/// erase waits out its veto window (FIX 9781).
struct TwoOwners {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl TwoOwners {
    fn new() -> Self {
        let (dir, vault, owner, owner_proof) = rooted();
        let second = EntityId::now();
        person(&vault, second);
        let member = |member_ref| InitialSharedMember {
            member_ref,
            role: Some(Role::Owner),
        };
        vault
            .initialize_shared_vault(
                &owner_proof,
                SHARED,
                None,
                &[member(owner), member(second)],
                1,
            )
            .expect("a shared vault with two Owners");
        let second_proof = proof(&vault, second);
        let invitation = vault
            .shared_invitations(&second_proof, SHARED)
            .expect("invitations")
            .into_iter()
            .find(|open| open.role == Role::Owner)
            .expect("the founding invitation");
        vault
            .accept_shared_invitation(&second_proof, SHARED, &invitation.id)
            .expect("the second Owner accepts");
        Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
        }
    }

    fn memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// An artifact the owner writes.
    fn artifact(&self) -> EntityId {
        let put = self
            .memory()
            .put_blob_artifact(&BlobArtifactInput {
                id: None,
                name: "restarted erase act fixture".to_owned(),
                media_type: "text/plain".to_owned(),
                occurred_at: 1,
                learned_at: None,
            })
            .expect("the owner writes an artifact");
        EntityId::from_hex(&put.id_hex).expect("an artifact id")
    }

    /// The owner previews the lift-and-erase of `record` through the shared
    /// preview (L8-49), then confirms it with that preview's confirm, naming
    /// `check_in_ref` when given. It waits out the veto window.
    fn confirm(&self, record: EntityId, check_in_ref: Option<EntityId>) -> LegalHoldLiftAndErased {
        let input = LegalHoldLiftAndEraseRequest {
            records: vec![record],
            claim_free_partition: false,
            confirm: None,
            check_in_ref: check_in_ref.map(|id| id.to_hex()),
        };
        let preview = preview_owner_confirm(
            &self.memory(),
            &self.owner_proof,
            OwnerConfirmPreviewRequest {
                verb: LIFT_AND_ERASE.to_owned(),
                input: serde_json::to_value(&input).expect("the erase input encodes"),
            },
        )
        .expect("the owner previews the lift-and-erase");
        let erased = lift_legal_hold_and_erase_as(
            &self.vault,
            &self.owner_proof,
            LegalHoldLiftAndEraseRequest {
                confirm: Some(preview.confirm),
                ..input
            },
        )
        .expect("the owner confirms");
        assert!(
            erased.records.len() == 1
                && matches!(
                    erased.records[0].status,
                    LegalHoldEraseState::CompletionPending { .. }
                ),
            "two Owners: the erase waits out its veto window: {erased:?}"
        );
        erased
    }

    /// The `erase` act the waiting erase of `record` names.
    fn waiting_act(&self, record: &EntityId) -> String {
        waiting_erase_act(&self.vault, record)
            .expect("read the waiting erase")
            .unwrap_or_else(|| panic!("the waiting erase of {} names its act", record.to_hex()))
    }

    /// The decision act `id` records.
    fn act_decision(&self, id: &str) -> Option<CheckInDecision> {
        self.vault
            .pending_authority_act(id)
            .expect("read the act")
            .unwrap_or_else(|| panic!("act {id} is stored"))
            .check_in
    }

    /// The act `lost` the waiting erase of `record` named is lost, as on a
    /// crash between the confirm's writer and its act start.
    fn forget_act(&self, record: &EntityId, lost: &str) {
        assert_eq!(
            forget_waiting_erase_act(&self.vault, record).expect("forget the act"),
            Some(lost.to_owned()),
            "the waiting erase named this act"
        );
        assert!(
            self.vault
                .pending_authority_act(lost)
                .expect("read the act")
                .is_none(),
            "the act is gone"
        );
    }

    /// The legal-hold pass runs after act `lost` was lost. The act it starts
    /// for the waiting erase of `record`.
    fn run_the_pass(&self, record: &EntityId, lost: &str) -> String {
        self.vault
            .maintain_legal_holds()
            .expect("the legal-hold pass runs");
        let restarted = self.waiting_act(record);
        assert_ne!(restarted, lost, "the pass starts a new act");
        restarted
    }
}

#[test]
fn a_restarted_erase_act_records_the_confirms_decision() {
    let fx = TwoOwners::new();
    let record = fx.artifact();
    let digest = legal_hold_erase_effect_digest(&[record], false);
    let (asked, asker) = approved(
        &fx.vault,
        fx.owner,
        &fx.owner_proof,
        LIFT_AND_ERASE,
        ActClass::Erase,
        &digest,
    );
    let decision = owner_decision(ActClass::Erase, Some(asked), Some(asker));

    let erased = fx.confirm(record, Some(asked));
    assert_eq!(
        erased.check_in,
        Some(decision.clone()),
        "the answer names the check-in it applied and its asker"
    );
    assert!(
        spent(&fx.vault, &asked),
        "the confirm's writer spent the check-in"
    );
    let first = fx.waiting_act(&record);
    assert_eq!(
        fx.act_decision(&first),
        Some(decision.clone()),
        "the confirm's act records its decision"
    );

    fx.forget_act(&record, &first);
    let restarted = fx.run_the_pass(&record, &first);
    assert_eq!(
        fx.act_decision(&restarted),
        Some(decision),
        "the act the pass restarts records the confirm's decision"
    );
}

#[test]
fn a_restart_after_a_repeated_confirm_records_the_newer_decision() {
    let fx = TwoOwners::new();
    let record = fx.artifact();
    let own = fx.confirm(record, None);
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::Erase, None, None)),
        "the Owner's own confirm records their own proof"
    );
    let first = fx.waiting_act(&record);
    fx.forget_act(&record, &first);

    // The same request again, now applying an approved ask: its own act.
    let digest = legal_hold_erase_effect_digest(&[record], false);
    let (asked, asker) = approved(
        &fx.vault,
        fx.owner,
        &fx.owner_proof,
        LIFT_AND_ERASE,
        ActClass::Erase,
        &digest,
    );
    let decision = owner_decision(ActClass::Erase, Some(asked), Some(asker));
    let applied = fx.confirm(record, Some(asked));
    assert_eq!(
        applied.check_in,
        Some(decision.clone()),
        "the answer names the check-in it applied and its asker"
    );
    assert!(
        spent(&fx.vault, &asked),
        "the confirm's writer spent the check-in"
    );
    let second = fx.waiting_act(&record);
    assert_ne!(second, first, "the repeated confirm starts its own act");
    assert_eq!(
        fx.act_decision(&second),
        Some(decision.clone()),
        "its act records its decision"
    );

    fx.forget_act(&record, &second);
    let restarted = fx.run_the_pass(&record, &second);
    assert_eq!(
        fx.act_decision(&restarted),
        Some(decision),
        "the act the pass restarts records the newer confirm's decision, which spent the check-in"
    );
}

#[test]
fn erasing_the_asker_takes_their_id_out_of_the_waiting_erase() {
    let fx = TwoOwners::new();
    let record = fx.artifact();
    let digest = legal_hold_erase_effect_digest(&[record], false);
    let (asked, asker) = approved(
        &fx.vault,
        fx.owner,
        &fx.owner_proof,
        LIFT_AND_ERASE,
        ActClass::Erase,
        &digest,
    );
    // The asker is a person of this vault: their hard erase runs the actor
    // sweep.
    person(&fx.vault, asker);
    fx.confirm(record, Some(asked));
    let first = fx.waiting_act(&record);
    fx.forget_act(&record, &first);

    fx.vault
        .delete_entity_with_reason(&asker, DeleteReason::UserHardDelete)
        .expect("the asker is hard-erased");

    let restarted = fx.run_the_pass(&record, &first);
    let mut erased = owner_decision(ActClass::Erase, Some(asked), None);
    erased.requester = Some(ERASED_CALL_IDENTITY.to_owned());
    assert_eq!(
        fx.act_decision(&restarted),
        Some(erased),
        "the restarted act names the erased marker where it named the asker; \
         the Owner's own proof and the spent check-in stay"
    );
}
