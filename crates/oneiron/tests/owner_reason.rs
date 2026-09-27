//! Public confirm → unsure re-ask → reconfirm → undo contract.
//! This integration target can run independently of unrelated library test targets.

use oneiron::consent::{
    ActionClass, ActionEnvelope, ActorBound, ComposedEffect, EffectFacts, GrantBound,
    OwnerReasonConfirm, OwnerReasonVerdict, ReasonMatchConfidence,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

fn setup() -> (
    tempfile::TempDir,
    Vault,
    oneiron::consent::AuthenticatedOwner,
) {
    let dir = tempfile::tempdir().expect("valid owner-reason fixture");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("valid owner-reason fixture");
    let id = EntityId::from_bytes([0x52; 16]).expect("valid owner-reason fixture");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .expect("valid owner-reason fixture");
    let owner = vault
        .authenticate_owner(id, "principal:owner", true, GateDecisionId::now())
        .expect("valid owner-reason fixture");
    (dir, vault, owner)
}

fn bound(class: &str, selector: &str) -> GrantBound {
    GrantBound::action(
        ActorBound::new("agent-a").expect("valid owner-reason fixture"),
        ActionClass::new(class).expect("valid owner-reason fixture"),
        ActionEnvelope::new([selector.to_owned()]).expect("valid owner-reason fixture"),
    )
    .expect("valid owner-reason fixture")
}

fn effect(bound: GrantBound) -> ComposedEffect {
    ComposedEffect::new(
        EffectFacts::new("channel.send")
            .expect("valid owner-reason fixture")
            .with_external_observers(true),
    )
    .with_action_requirement(bound)
    .expect("valid owner-reason fixture")
}

#[test]
fn unsure_reask_reconfirms_prefilled_or_edited_reason_and_retires_old_undo() {
    let (_dir, vault, owner) = setup();
    let required = bound("send", "channel:team");
    let effect = effect(required.clone());
    let first = vault
        .confirm_owner_reason(
            &owner,
            &effect,
            &required,
            OwnerReasonConfirm {
                reason: Some("team only"),
                notice_text: "Remembered",
            },
        )
        .expect("valid owner-reason fixture");
    let first_undo = first.undo.expect("valid owner-reason fixture");
    let prefill = match vault
        .evaluate_owner_reason(&effect, ReasonMatchConfidence::Unsure)
        .expect("valid owner-reason fixture")
    {
        OwnerReasonVerdict::Ask {
            prefill: Some(reason),
        } => reason,
        other => panic!("expected unsure prefill, got {other:?}"),
    };
    let second = vault
        .confirm_owner_reason(
            &owner,
            &effect,
            &required,
            OwnerReasonConfirm {
                reason: Some(&prefill),
                notice_text: "Still remembered",
            },
        )
        .expect("valid owner-reason fixture");
    let second_undo = second.undo.expect("valid owner-reason fixture");
    assert_ne!(second_undo.rule_decision_id, first_undo.rule_decision_id);
    assert!(vault.undo_owner_reason(&owner, &first_undo).is_err());
    assert!(
        vault
            .consent_grant(&second_undo.grant_ref)
            .expect("valid owner-reason fixture")
            .expect("valid owner-reason fixture")
            .is_active()
    );

    let edited = "team updates, not personal data";
    let third = vault
        .confirm_owner_reason(
            &owner,
            &effect,
            &required,
            OwnerReasonConfirm {
                reason: Some(edited),
                notice_text: "Updated",
            },
        )
        .expect("valid owner-reason fixture");
    let third_undo = third.undo.expect("valid owner-reason fixture");
    assert!(vault.undo_owner_reason(&owner, &second_undo).is_err());
    let receipt = match vault
        .evaluate_owner_reason(&effect, ReasonMatchConfidence::Confident)
        .expect("valid owner-reason fixture")
    {
        OwnerReasonVerdict::Auto {
            reason, receipt, ..
        } => {
            assert_eq!(reason, edited);
            receipt
        }
        other => panic!("expected confident reuse, got {other:?}"),
    };
    let gate = vault
        .gate_decisions(64)
        .expect("valid owner-reason fixture")
        .into_iter()
        .find(|row| row.decision_id == receipt.decision_id())
        .expect("valid owner-reason fixture");
    assert_eq!(gate.system_notices[0].body, edited);
    assert_eq!(
        gate.system_notices[0].row_ref.as_deref(),
        Some(third_undo.rule_decision_id.to_hex().as_str())
    );
    vault
        .undo_owner_reason(&owner, &third_undo)
        .expect("valid owner-reason fixture");
    assert!(
        !vault
            .consent_grant(&third_undo.grant_ref)
            .expect("valid owner-reason fixture")
            .expect("valid owner-reason fixture")
            .is_active()
    );
    assert_eq!(
        vault
            .evaluate_owner_reason(&effect, ReasonMatchConfidence::Confident)
            .expect("valid owner-reason fixture"),
        OwnerReasonVerdict::Ask { prefill: None }
    );
}

#[test]
fn active_grant_without_a_live_owner_reason_cannot_be_reconfirmed() {
    let (_dir, vault, owner) = setup();
    let required = bound("send", "channel:team");
    vault
        .create_standing_grant(&owner, required.clone())
        .expect("mint unrelated grant");
    let before = vault.gate_decisions(64).expect("read decisions").len();
    let response = vault.confirm_owner_reason(
        &owner,
        &effect(required.clone()),
        &required,
        OwnerReasonConfirm {
            reason: Some("not a derived reason"),
            notice_text: "Saved",
        },
    );
    assert!(response.is_err());
    assert_eq!(
        vault.gate_decisions(64).expect("read decisions").len(),
        before
    );
    assert!(
        vault
            .consent_grant(&required.digest().to_hex())
            .expect("read grant")
            .expect("grant exists")
            .is_active()
    );
    assert_eq!(
        vault
            .evaluate_owner_reason(&effect(required), ReasonMatchConfidence::Confident)
            .expect("evaluate"),
        OwnerReasonVerdict::Ask { prefill: None }
    );
}
