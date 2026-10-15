use super::super::*;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::GateDecisionId;
use crate::temporal::TimeRange;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

fn setup() -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let id = entity(0x52);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .unwrap();
    let owner = vault
        .authenticate_owner(id, "principal:owner", true, GateDecisionId::now())
        .unwrap();
    (dir, vault, owner)
}

fn bound(class: &str, selector: &str) -> GrantBound {
    GrantBound::action(
        ActorBound::new("agent-a").unwrap(),
        ActionClass::new(class).unwrap(),
        ActionEnvelope::new([selector.to_owned()]).unwrap(),
    )
    .unwrap()
}

fn effect(bound: GrantBound) -> ComposedEffect {
    ComposedEffect::new(
        EffectFacts::new("channel.send")
            .unwrap()
            .with_external_observers(true),
    )
    .with_action_requirement(bound)
    .unwrap()
}

#[test]
fn confirm_without_reason_only_approves_once_and_untrusted_or_stale_acts_cannot_mint() {
    let (_dir, vault, owner) = setup();
    let required = bound("send", "channel:team");
    let op = effect(required.clone());
    let reply = vault
        .confirm_owner_reason(
            &owner,
            &op,
            &required,
            OwnerReasonConfirm {
                reason: None,
                notice_text: "",
            },
        )
        .unwrap();
    assert!(reply.undo.is_none());
    assert!(matches!(
        reply.receipt,
        ConsentReceipt::Approved {
            grant: ConsentGrant::ApproveOnce(_),
            ..
        }
    ));
    assert_eq!(
        vault
            .evaluate_owner_reason(&op, ReasonMatchConfidence::Confident)
            .unwrap(),
        OwnerReasonVerdict::Ask { prefill: None }
    );
    assert!(
        vault
            .confirm_owner_reason(
                &owner,
                &op,
                &bound("pay", "channel:team"),
                OwnerReasonConfirm {
                    reason: Some("wrong class"),
                    notice_text: "Saved"
                }
            )
            .is_err()
    );
    assert!(
        vault
            .confirm_owner_reason(
                &owner,
                &op,
                &required,
                OwnerReasonConfirm {
                    reason: Some(" "),
                    notice_text: "Saved"
                }
            )
            .is_err()
    );
    let granted = vault
        .confirm_owner_reason(
            &owner,
            &op,
            &required,
            OwnerReasonConfirm {
                reason: Some("team only"),
                notice_text: "Saved",
            },
        )
        .unwrap();
    let unrelated = bound("pay", "channel:team");
    vault
        .create_standing_grant(&owner, unrelated.clone())
        .unwrap();
    assert!(
        vault
            .confirm_owner_reason(
                &owner,
                &effect(unrelated.clone()),
                &unrelated,
                OwnerReasonConfirm {
                    reason: Some("do not replace it"),
                    notice_text: "Saved"
                },
            )
            .is_err()
    );
    assert!(
        vault
            .consent_grant(&unrelated.digest().to_hex())
            .unwrap()
            .unwrap()
            .is_active()
    );
    let mut forged = granted.undo.unwrap();
    forged.rule_decision_id = GateDecisionId::now();
    assert!(vault.undo_owner_reason(&owner, &forged).is_err());
    assert!(
        vault
            .consent_grant(&forged.grant_ref)
            .unwrap()
            .unwrap()
            .is_active()
    );
}

#[test]
fn reason_does_not_override_catastrophe_or_authentication() {
    let (_dir, vault, owner) = setup();
    let required = bound("send", "channel:team");
    let op = effect(required.clone());
    assert!(
        vault
            .authenticate_owner(
                owner.actor(),
                "principal:owner",
                false,
                GateDecisionId::now()
            )
            .is_err()
    );
    let catastrophic = ComposedEffect::new(
        EffectFacts::new("channel.send")
            .unwrap()
            .with_catastrophe(CatastropheClass::MassSecretExport),
    )
    .with_action_requirement(required.clone())
    .unwrap();
    assert!(
        vault
            .confirm_owner_reason(
                &owner,
                &catastrophic,
                &required,
                OwnerReasonConfirm {
                    reason: Some("never auto"),
                    notice_text: "Saved"
                }
            )
            .is_err()
    );
    vault
        .confirm_owner_reason(
            &owner,
            &op,
            &required,
            OwnerReasonConfirm {
                reason: Some("team only"),
                notice_text: "Saved",
            },
        )
        .unwrap();
    assert_eq!(
        vault
            .evaluate_owner_reason(&catastrophic, ReasonMatchConfidence::Confident)
            .unwrap(),
        OwnerReasonVerdict::Ask {
            prefill: Some("team only".into())
        }
    );
}

#[test]
fn stale_authenticated_owner_cannot_confirm_with_or_without_reason() {
    let (_dir, vault, owner) = setup();
    let survivor = entity(0x53);
    vault
        .put_entity(
            &survivor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"survivor",
        )
        .unwrap();
    vault
        .apply_identity_topology_op(
            &crate::identity_topology::IdentityTopologyOp::Merge(
                crate::identity_topology::MergeOp {
                    sources: vec![owner.actor()],
                    survivor,
                    evidence: crate::identity_topology::IdentityOpEvidence {
                        refs: Vec::new(),
                        rationale: "fixture merge".into(),
                    },
                    survivorship_plan: crate::identity_topology::SurvivorshipPlan::ReadThrough,
                },
            ),
            &crate::identity_topology::IdentityOpWrite {
                source: crate::claim::ClaimSource::Inferred,
                approval: crate::claim::ClaimApprovalStatus::Auto,
                confidence: 1.0,
                actor: None,
            },
            200,
        )
        .unwrap();
    let before = vault.store.gate_decisions(100).unwrap().len();
    let requirement = bound("send", "channel:team");
    let operation = effect(requirement.clone());
    for reason in [None, Some("team only")] {
        assert_eq!(
            vault
                .confirm_owner_reason(
                    &owner,
                    &operation,
                    &requirement,
                    OwnerReasonConfirm {
                        reason,
                        notice_text: "Saved"
                    }
                )
                .unwrap_err()
                .kind(),
            crate::error::ErrorKind::ConsentOwnerNotAuthenticated
        );
    }
    assert!(
        vault
            .consent_grant(&requirement.digest().to_hex())
            .unwrap()
            .is_none()
    );
    assert_eq!(vault.store.gate_decisions(100).unwrap().len(), before);
    assert_eq!(
        vault
            .evaluate_owner_reason(&operation, ReasonMatchConfidence::Confident)
            .unwrap(),
        OwnerReasonVerdict::Ask { prefill: None }
    );
}

#[test]
fn same_authentication_regrant_retires_old_reason_and_blocks_old_undo() {
    let (_dir, vault, owner) = setup();
    let requirement = bound("send", "channel:team");
    let operation = effect(requirement.clone());
    let old = vault
        .confirm_owner_reason(
            &owner,
            &operation,
            &requirement,
            OwnerReasonConfirm {
                reason: Some("team only"),
                notice_text: "Saved",
            },
        )
        .unwrap();
    let cloned_owner = owner.clone();
    vault
        .create_standing_grant(&cloned_owner, requirement.clone())
        .unwrap();
    assert_eq!(cloned_owner.decision_id(), owner.decision_id());
    let undo = old.undo.unwrap();
    assert!(vault.undo_owner_reason(&owner, &undo).is_err());
    assert!(
        vault
            .consent_grant(&undo.grant_ref)
            .unwrap()
            .unwrap()
            .is_active()
    );
    assert_eq!(
        vault
            .evaluate_owner_reason(&operation, ReasonMatchConfidence::Confident)
            .unwrap(),
        OwnerReasonVerdict::Ask { prefill: None }
    );
    vault.revoke_consent_grant(&owner, &undo.grant_ref).unwrap();
    let fresh = vault
        .confirm_owner_reason(
            &owner,
            &operation,
            &requirement,
            OwnerReasonConfirm {
                reason: Some("new ruling"),
                notice_text: "Saved",
            },
        )
        .unwrap();
    assert!(vault.undo_owner_reason(&owner, &undo).is_err());
    assert!(
        vault
            .consent_grant(&fresh.undo.unwrap().grant_ref)
            .unwrap()
            .unwrap()
            .is_active()
    );
    assert!(
        matches!(vault.evaluate_owner_reason(&operation, ReasonMatchConfidence::Confident).unwrap(),
        OwnerReasonVerdict::Auto { reason, .. } if reason == "new ruling")
    );
}
