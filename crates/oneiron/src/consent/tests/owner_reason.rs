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
fn confirm_reason_rule_auto_unsure_prefill_no_reason_and_undo() {
    let (_dir, vault, owner) = setup();
    let required = bound("send", "channel:team");
    let op = effect(required.clone());
    assert_eq!(
        vault
            .evaluate_owner_reason(&op, ReasonMatchConfidence::Confident)
            .unwrap(),
        OwnerReasonVerdict::Ask { prefill: None }
    );
    let reply = vault
        .confirm_owner_reason(
            &owner,
            &op,
            &required,
            OwnerReasonConfirm {
                reason: Some("Only send team updates here"),
                notice_text: "Saved for team updates. Undo?",
            },
        )
        .unwrap();
    assert_eq!(
        reply.notice_text.as_deref(),
        Some("Saved for team updates. Undo?")
    );
    let undo = reply.undo.unwrap();
    assert_eq!(undo.command, OWNER_REASON_UNDO_COMMAND);
    assert!(
        vault
            .consent_grant(&undo.grant_ref)
            .unwrap()
            .unwrap()
            .is_active()
    );
    assert!(
        matches!(vault.evaluate_owner_reason(&op, ReasonMatchConfidence::Unsure).unwrap(),
        OwnerReasonVerdict::Ask { prefill: Some(reason) } if reason == "Only send team updates here")
    );
    let receipt = match vault
        .evaluate_owner_reason(&op, ReasonMatchConfidence::Confident)
        .unwrap()
    {
        OwnerReasonVerdict::Auto {
            rung,
            reason,
            receipt,
        } => {
            assert_eq!(rung, crate::llm::decision::DecisionRung::Rule);
            assert_eq!(reason, "Only send team updates here");
            receipt
        }
        other => panic!("expected auto, got {other:?}"),
    };
    let gate = vault
        .store
        .gate_decisions(20)
        .unwrap()
        .into_iter()
        .find(|record| record.decision_id == receipt.decision_id())
        .unwrap();
    assert!(gate.reason_codes.contains(&format!(
        "gate.consent.owner_reason.{}",
        undo.rule_decision_id.to_hex()
    )));
    assert_eq!(gate.grant_ref.as_deref(), Some(undo.grant_ref.as_str()));
    assert_eq!(gate.system_notices[0].body, "Only send team updates here");
    assert_eq!(
        vault
            .evaluate_owner_reason(
                &effect(bound("send", "channel:other")),
                ReasonMatchConfidence::Confident
            )
            .unwrap(),
        OwnerReasonVerdict::Ask {
            prefill: Some("Only send team updates here".into())
        }
    );
    assert_eq!(
        vault
            .evaluate_owner_reason(
                &effect(bound("pay", "channel:team")),
                ReasonMatchConfidence::Confident
            )
            .unwrap(),
        OwnerReasonVerdict::Ask { prefill: None }
    );
    vault.undo_owner_reason(&owner, &undo).unwrap();
    assert!(
        !vault
            .consent_grant(&undo.grant_ref)
            .unwrap()
            .unwrap()
            .is_active()
    );
    assert_eq!(
        vault
            .evaluate_owner_reason(&op, ReasonMatchConfidence::Confident)
            .unwrap(),
        OwnerReasonVerdict::Ask { prefill: None }
    );
    assert!(vault.undo_owner_reason(&owner, &undo).is_err());
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
    assert!(
        vault
            .confirm_owner_reason(
                &owner,
                &op,
                &required,
                OwnerReasonConfirm {
                    reason: Some("replace it"),
                    notice_text: "Saved"
                }
            )
            .is_err()
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
fn registry_revoke_retires_rule_even_if_the_same_bound_is_later_regranted() {
    let (_dir, vault, owner) = setup();
    let required = bound("send", "channel:team");
    let op = effect(required.clone());
    let first = vault
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
    let undo = first.undo.unwrap();
    vault.revoke_consent_grant(&owner, &undo.grant_ref).unwrap();
    assert_eq!(
        vault
            .evaluate_owner_reason(&op, ReasonMatchConfidence::Confident)
            .unwrap(),
        OwnerReasonVerdict::Ask { prefill: None }
    );
    assert!(vault.undo_owner_reason(&owner, &undo).is_err());
    vault.create_standing_grant(&owner, required).unwrap();
    // A new grant cannot revive a retired reason from an older approval.
    assert_eq!(
        vault
            .evaluate_owner_reason(&op, ReasonMatchConfidence::Confident)
            .unwrap(),
        OwnerReasonVerdict::Ask { prefill: None }
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
fn owner_bound_contains_narrow_match_but_replacement_grant_cannot_be_undone_by_stale_action() {
    let (_dir, vault, owner) = setup();
    let wide = GrantBound::action(
        ActorBound::new("agent-a").unwrap(),
        ActionClass::new("send").unwrap(),
        ActionEnvelope::new(["channel:team".to_owned(), "channel:ops".to_owned()]).unwrap(),
    )
    .unwrap();
    let original = effect(wide.clone());
    let reply = vault
        .confirm_owner_reason(
            &owner,
            &original,
            &wide,
            OwnerReasonConfirm {
                reason: Some("team and ops"),
                notice_text: "Saved",
            },
        )
        .unwrap();
    let narrow = effect(bound("send", "channel:team"));
    assert!(
        matches!(vault.evaluate_owner_reason(&narrow, ReasonMatchConfidence::Confident).unwrap(),
        OwnerReasonVerdict::Auto { reason, .. } if reason == "team and ops")
    );
    let replacement_owner = vault
        .authenticate_owner(
            owner.actor(),
            "principal:owner",
            true,
            GateDecisionId::now(),
        )
        .unwrap();
    vault
        .create_standing_grant(&replacement_owner, wide)
        .unwrap();
    assert!(
        vault
            .undo_owner_reason(&owner, &reply.undo.unwrap())
            .is_err()
    );
    assert_eq!(
        vault
            .evaluate_owner_reason(&narrow, ReasonMatchConfidence::Confident)
            .unwrap(),
        OwnerReasonVerdict::Ask { prefill: None }
    );
}

#[test]
fn unsure_prefill_prefers_the_same_class_rule_with_shared_envelope() {
    let (_dir, vault, owner) = setup();
    for (selector, reason) in [("channel:ops", "ops only"), ("channel:team", "team only")] {
        let requirement = bound("send", selector);
        vault
            .confirm_owner_reason(
                &owner,
                &effect(requirement.clone()),
                &requirement,
                OwnerReasonConfirm {
                    reason: Some(reason),
                    notice_text: "Saved",
                },
            )
            .unwrap();
    }
    let ask = effect(
        GrantBound::action(
            ActorBound::new("agent-a").unwrap(),
            ActionClass::new("send").unwrap(),
            ActionEnvelope::new(["channel:team".to_owned(), "channel:new".to_owned()]).unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        vault
            .evaluate_owner_reason(&ask, ReasonMatchConfidence::Unsure)
            .unwrap(),
        OwnerReasonVerdict::Ask {
            prefill: Some("team only".into())
        }
    );
}
