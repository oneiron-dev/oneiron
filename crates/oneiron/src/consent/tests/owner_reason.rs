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

#[test]
fn disclosure_reason_matches_a_mixed_effect_and_disclosure_only_effect() {
    let (_dir, vault, owner) = setup();
    let action = bound("send", "channel:team");
    let disclosure = GrantBound::disclosure(
        AudienceBound::singleton("person:recipient").unwrap(),
        DisclosureClass::new("health").unwrap(),
        DisclosureEnvelope::new(["facet:health".to_owned()]).unwrap(),
    )
    .unwrap();
    let facts = EffectFacts::new("channel.send")
        .unwrap()
        .with_external_observers(true);
    let mixed = ComposedEffect::new(facts.clone())
        .with_action_requirement(action.clone())
        .unwrap()
        .with_disclosure_requirement(disclosure.clone())
        .unwrap();
    vault.create_standing_grant(&owner, action).unwrap();
    vault
        .confirm_owner_reason(
            &owner,
            &mixed,
            &disclosure,
            OwnerReasonConfirm {
                reason: Some("share health only with recipient"),
                notice_text: "Saved",
            },
        )
        .unwrap();
    assert_eq!(
        vault
            .evaluate_owner_reason(&mixed, ReasonMatchConfidence::Unsure)
            .unwrap(),
        OwnerReasonVerdict::Ask {
            prefill: Some("share health only with recipient".into())
        }
    );
    assert!(
        matches!(vault.evaluate_owner_reason(&mixed, ReasonMatchConfidence::Confident).unwrap(),
        OwnerReasonVerdict::Auto { reason, .. } if reason == "share health only with recipient")
    );
    let disclosure_only = ComposedEffect::new(facts)
        .with_disclosure_requirement(disclosure)
        .unwrap();
    assert!(
        matches!(vault.evaluate_owner_reason(&disclosure_only, ReasonMatchConfidence::Confident).unwrap(),
        OwnerReasonVerdict::Auto { reason, .. } if reason == "share health only with recipient")
    );
}

#[test]
fn unsure_prefill_ranks_all_containing_rules_by_exactness_and_target() {
    let (_dir, vault, owner) = setup();
    let narrow = bound("send", "channel:team");
    // Choose a wider digest that sorts BEFORE the narrow one, so a
    // first-containing-match implementation visibly selects the wrong row.
    let wide = (0..256)
        .map(|n| {
            GrantBound::action(
                ActorBound::new("agent-a").unwrap(),
                ActionClass::new("send").unwrap(),
                ActionEnvelope::new(["channel:team".to_owned(), format!("channel:ops{n}")])
                    .unwrap(),
            )
            .unwrap()
        })
        .find(|candidate| candidate.digest().to_hex() < narrow.digest().to_hex())
        .unwrap();
    for (requirement, reason) in [(&wide, "wide reason"), (&narrow, "narrow reason")] {
        vault
            .confirm_owner_reason(
                &owner,
                &effect(requirement.clone()),
                requirement,
                OwnerReasonConfirm {
                    reason: Some(reason),
                    notice_text: "Saved",
                },
            )
            .unwrap();
    }
    assert_eq!(
        vault
            .evaluate_owner_reason(&effect(narrow), ReasonMatchConfidence::Unsure)
            .unwrap(),
        OwnerReasonVerdict::Ask {
            prefill: Some("narrow reason".into())
        }
    );

    let untargeted = bound("pay", "channel:team");
    let targeted = (0..256)
        .map(|n| {
            GrantBound::action(
                ActorBound::new("agent-a").unwrap(),
                ActionClass::new("pay").unwrap(),
                ActionEnvelope::new(["channel:team".to_owned()])
                    .unwrap()
                    .with_target(format!("recipient:{n}"))
                    .unwrap(),
            )
            .unwrap()
        })
        .find(|candidate| untargeted.digest().to_hex() < candidate.digest().to_hex())
        .unwrap();
    for (requirement, reason) in [
        (&untargeted, "any recipient"),
        (&targeted, "that recipient"),
    ] {
        vault
            .confirm_owner_reason(
                &owner,
                &effect(requirement.clone()),
                requirement,
                OwnerReasonConfirm {
                    reason: Some(reason),
                    notice_text: "Saved",
                },
            )
            .unwrap();
    }
    assert_eq!(
        vault
            .evaluate_owner_reason(&effect(targeted), ReasonMatchConfidence::Unsure)
            .unwrap(),
        OwnerReasonVerdict::Ask {
            prefill: Some("that recipient".into())
        }
    );
}
