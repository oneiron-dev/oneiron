use super::*;
use crate::error::RecordError;
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};

pub(super) fn assert_mailbox_lifecycle_receipt(
    vault: &Vault,
    identity: EntityId,
    result: &ChannelIdentityLifecycleResult,
    verb: &str,
    gate_outcome: Option<&str>,
) -> Result<()> {
    let stored = vault.get_channel_identity(&identity)?.expect("identity");
    assert_eq!(result.identity.as_ref(), Some(&stored));
    assert!(!stored.may_send());
    if gate_outcome == Some("allow") || gate_outcome.is_none() {
        assert_eq!(result.outcome, stored.state.as_str());
    }
    let receipt = vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::IdentityLifecycle))?
        .into_iter()
        .find(|r| r.receipt_id == result.receipt_id)
        .expect("lifecycle receipt");
    let field = |key: &str| receipt.fields.get(key).map(String::as_str);
    assert_eq!(receipt.outcome, result.outcome);
    assert_eq!(
        receipt.trigger_ref,
        Some(format!("entity:{}", identity.to_hex()))
    );
    assert_eq!(field("verb"), Some(verb));
    assert_eq!(field("state"), Some(stored.state.as_str()));
    assert_eq!(
        field("fulfillment_mode"),
        stored
            .pending_fulfillment
            .map(crate::channel_identity::ChannelIdentityFulfillment::as_str)
    );
    assert_eq!(
        field("gate_decision_ref"),
        result.gate_receipt_id.as_deref()
    );
    if let Some(outcome) = gate_outcome {
        let gate_ref = result.gate_receipt_id.as_ref().expect("real gate decision");
        let gate = vault
            .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?
            .into_iter()
            .find(|r| &r.receipt_id == gate_ref)
            .expect("gate receipt");
        assert_eq!(gate.outcome, outcome);
        assert_eq!(gate.actor, receipt.actor);
        assert_eq!(
            gate.fields.get("content_kind").map(String::as_str),
            Some("external_effect")
        );
        assert_eq!(field("intent_kind"), Some("BindIntent"));
        assert_eq!(receipt.occurred_at, AT + 1);
    } else {
        assert_eq!(
            result.gate_receipt_id, None,
            "fulfillment is not a gated verb"
        );
        assert_eq!(field("intent_kind"), Some("FulfillmentReceipt"));
        assert_eq!(receipt.occurred_at, AT + 2);
    }
    Ok(())
}

pub(super) fn register_mailbox_custody(
    vault: &Vault,
    mailbox: &DelegatedMailboxOnboarding,
    subject_address: &str,
) -> Result<EntityId> {
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: mailbox.custody_name.clone(),
        class: CustodyClass::CrossVault,
        device_only: true,
        value_bytes: b"test-only-oauth-bytes".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: AT,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: "connector:gmail".to_owned(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: crate::channel_identity::delegated_custody_scopes(
                &mailbox.channel,
                subject_address,
            ),
        }],
        manifest_ref: String::new(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })
}

#[test]
fn missing_custody_leaves_resumable_journal_and_no_identity() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let requested = mailbox();
    intent.delegated_mailbox = Some(requested.clone());
    let err = vault
        .onboard_workspace_member(
            intent.clone(),
            &writer(WRITER),
            Some(&mailbox_owner(&vault)?),
        )
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::SecretRefNotFound);
    assert!(
        vault
            .get_channel_identity(&requested.identity_ref)?
            .is_none()
    );
    let journal = read_journal(&vault, &onboarding_key(&intent.onboarding_id))?
        .expect("fixture value exists");
    assert_eq!(journal.step, MemberOnboardingStep::CompanionBorn);
    assert_eq!(journal.completed_at, None);
    register_mailbox_custody(&vault, &requested, &requested.address)?;
    let err = vault
        .onboard_workspace_member(intent, &writer(WRITER), Some(&mailbox_owner(&vault)?))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::WorkspaceMailboxAutonomyNotReady);
    assert!(
        vault
            .get_channel_identity(&requested.identity_ref)?
            .is_some()
    );
    Ok(())
}

#[test]
fn custody_for_another_mailbox_is_not_authority() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let requested = mailbox();
    register_mailbox_custody(&vault, &requested, "other@example.test")?;
    intent.delegated_mailbox = Some(requested.clone());
    let err = vault
        .onboard_workspace_member(intent, &writer(WRITER), Some(&mailbox_owner(&vault)?))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::SecretBindingDenied);
    assert!(
        vault
            .get_channel_identity(&requested.identity_ref)?
            .is_none()
    );
    Ok(())
}

#[test]
fn an_occupied_identity_id_cannot_be_adopted() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let requested = mailbox();
    let existing =
        vault.create_own_app_channel_identity(&requested.identity_ref, entity(OUTSIDER), AT)?;
    intent.delegated_mailbox = Some(requested.clone());
    let err = vault
        .onboard_workspace_member(intent, &writer(WRITER), Some(&mailbox_owner(&vault)?))
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(
        vault.get_channel_identity(&requested.identity_ref)?,
        Some(existing)
    );
    Ok(())
}

#[test]
fn existing_actor_composition_must_match_without_overwriting_owner_edits() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let mut existing = intent.actor_definition.clone();
    existing.display_name = Some("Owner chosen name".to_owned());
    existing.enabled = false;
    vault.define_agent(
        &intent.actor_ref,
        &existing,
        TimeRange { start: AT, end: AT },
        AT,
    )?;
    vault.onboard_workspace_member(intent.clone(), &writer(WRITER), None)?;
    assert_eq!(
        vault.get_agent_definition(&intent.actor_ref)?,
        Some(existing)
    );

    let (_dir2, other, intent2) = fixture("Antevon");
    other.define_agent(
        &intent2.actor_ref,
        &definition("unrelated.actor"),
        TimeRange { start: AT, end: AT },
        AT,
    )?;
    let err = other
        .onboard_workspace_member(intent2, &writer(WRITER), None)
        .expect_err("request must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    Ok(())
}

#[test]
fn a_second_onboarding_id_cannot_replace_a_principals_companion() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let birth = companion_birth();
    intent.grant_bundle.companion_profile_grant_ref = Some(birth.profile_grant_ref);
    intent.companion_birth = Some(birth);
    vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &writer(WRITER),
        None,
        MemberOnboardingStep::ActorLinked,
    )?;
    let mut changed = intent.clone();
    changed.onboarding_id = "second-onboarding".to_owned();
    changed.actor_ref = entity(0xD1);
    changed.grant_bundle.federation_grant_ref = entity(0xD2);
    let err = vault
        .onboard_workspace_member(changed, &writer(WRITER), None)
        .expect_err("principal slot belongs to the unfinished journal");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert!(vault.get_entity_type(&entity(0xD1))?.is_none());
    vault.onboard_workspace_member(intent, &writer(WRITER), None)?;
    assert_eq!(vault.workspace_roster("antevon-slack", AT)?.len(), 2);
    Ok(())
}

#[test]
fn owner_house_name_override_is_runtime_data() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    intent.workspace.house_display_name = Some("Owner named house".to_owned());
    vault.onboard_workspace_member(intent, &writer(WRITER), None)?;
    assert_eq!(
        vault.workspace_roster("antevon-slack", AT)?[0].display_name,
        "Owner named house"
    );
    Ok(())
}

#[test]
fn minted_kind_collision_is_rejected_before_the_first_effect() -> Result<()> {
    let (_dir, vault, mut intent) = fixture("Antevon");
    let occupied = seed_plain(&vault, 0xD3, ENTITY_TYPE_PERSON);
    intent.grant_bundle.federation_grant_ref = occupied;
    let err = vault
        .onboard_workspace_member(intent.clone(), &writer(WRITER), None)
        .expect_err("maintenance grant id cannot alias a person");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert!(read_journal(&vault, &onboarding_key(&intent.onboarding_id))?.is_none());
    assert!(actor_subject_anchor(&vault, &intent.workspace.house_actor_ref, AT)?.is_none());
    Ok(())
}

#[test]
fn resumed_onboarding_requires_current_admin_authority() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    vault.onboard_workspace_member_halting_after(
        intent.clone(),
        &writer(WRITER),
        None,
        MemberOnboardingStep::ActorLinked,
    )?;
    seed_federation_grant(
        &vault,
        ADMIN_GRANT,
        &FederationGrant::new(
            FederationGrantScope::vault(VAULT_ID),
            entity(WRITER),
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
    );
    let err = vault
        .onboard_workspace_member(intent.clone(), &writer(WRITER), None)
        .expect_err("a demoted writer cannot resume membership minting");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert!(
        vault
            .get_entity_type(&intent.grant_bundle.federation_grant_ref)?
            .is_none()
    );
    assert_eq!(
        read_journal(&vault, &onboarding_key(&intent.onboarding_id))?
            .expect("journal survives refusal")
            .step,
        MemberOnboardingStep::ActorLinked
    );
    Ok(())
}

#[test]
fn existing_grant_must_match_exactly_and_is_never_rewritten() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let occupied = FederationGrant::new(
        FederationGrantScope::vault(VAULT_ID),
        entity(OUTSIDER),
        FederationGrantRole::Admin,
        FederationGrantPreset::Admin,
    );
    seed_federation_grant(&vault, MEMBER_GRANT, &occupied);
    let err = vault
        .onboard_workspace_member(intent, &writer(WRITER), None)
        .expect_err("an occupied grant id is not an invitation to overwrite it");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    let txn = vault.store.env.read_txn()?;
    assert_eq!(
        read_federation_grant_in_txn(&vault, &txn, &entity(MEMBER_GRANT))?,
        Some(occupied)
    );
    Ok(())
}

#[test]
fn house_name_can_be_owner_edited_without_rewriting_the_seed_or_replay() -> Result<()> {
    let (_dir, vault, intent) = fixture("Antevon");
    let seed_before = vault.get_agent_definition(&intent.workspace.house_actor_ref)?;
    let outcome = vault.onboard_workspace_member(intent.clone(), &writer(WRITER), None)?;
    vault.set_workspace_house_display_name(
        "antevon-slack",
        Some("Renamed house".to_owned()),
        &writer(WRITER),
    )?;
    assert_eq!(
        vault.workspace_roster("antevon-slack", AT)?[0].display_name,
        "Renamed house"
    );
    assert_eq!(
        vault.get_agent_definition(&intent.workspace.house_actor_ref)?,
        seed_before
    );
    assert_eq!(
        vault.onboard_workspace_member(intent, &writer(WRITER), None)?,
        outcome
    );
    let err = vault
        .set_workspace_house_display_name("antevon-slack", None, &writer(OUTSIDER))
        .expect_err("outsider cannot rename the house");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(
        vault.workspace_roster("antevon-slack", AT)?[0].display_name,
        "Renamed house"
    );
    vault.set_workspace_house_display_name("antevon-slack", None, &writer(WRITER))?;
    assert_eq!(
        vault.workspace_roster("antevon-slack", AT)?[0].display_name,
        "Antevon"
    );
    Ok(())
}

#[test]
fn mailbox_crash_resume_reopens_after_provision_lifecycle_apply_and_journal() -> Result<()> {
    for checkpoint in 0..5 {
        let (dir, vault, intent, owner) = mailbox_fixture()?;
        let requested = intent.delegated_mailbox.as_ref().expect("mailbox");
        assert_mailbox_waiting(&vault, &intent, &owner)?;
        if checkpoint >= 1 {
            bind_mailbox(&vault, requested.identity_ref)?;
        }
        if checkpoint >= 2 {
            fulfill_mailbox(&vault, requested.identity_ref)?;
        }
        let applied = if checkpoint >= 3 {
            Some(vault.apply_channel_identity_autonomy(&requested.autonomy, &owner)?)
        } else {
            None
        };
        if checkpoint == 4 {
            assert!(
                vault
                    .onboard_workspace_member_halting_after(
                        intent.clone(),
                        &writer(WRITER),
                        Some(&owner),
                        MemberOnboardingStep::MailboxBound,
                    )?
                    .is_none()
            );
        }
        let before =
            read_journal(&vault, &onboarding_key(&intent.onboarding_id))?.expect("journal");
        assert_eq!(before.completed_at, None);
        assert_eq!(
            before.step,
            if checkpoint == 4 {
                MemberOnboardingStep::MailboxBound
            } else {
                MemberOnboardingStep::CompanionBorn
            }
        );
        let identity = vault
            .get_channel_identity(&requested.identity_ref)?
            .expect("identity");
        assert!(!identity.may_send());
        let policy = {
            let txn = vault.store.env.read_txn()?;
            crate::gate::resolve_policy_manifest(&vault.store, &txn)?.read_frontier_hash()?
        };
        let receipts =
            vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::IdentityLifecycle))?;
        let gates = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
        drop(vault);
        let mut cfg = VaultConfig::device();
        cfg.map_size = 32 * 1024 * 1024;
        cfg.dimensions = 4;
        cfg.embedding_model = None;
        let vault = Vault::open(dir.path(), cfg)?;
        let owner = mailbox_owner(&vault)?;
        {
            let txn = vault.store.env.read_txn()?;
            assert_eq!(
                crate::gate::resolve_policy_manifest(&vault.store, &txn)?.read_frontier_hash()?,
                policy,
                "checkpoint {checkpoint}: reopening must not change policy"
            );
        }
        assert_eq!(
            read_journal(&vault, &onboarding_key(&intent.onboarding_id))?,
            Some(before)
        );
        assert_eq!(
            vault.get_channel_identity(&requested.identity_ref)?,
            Some(identity)
        );
        assert_eq!(
            vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::IdentityLifecycle))?,
            receipts
        );
        assert_eq!(
            vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?,
            gates
        );
        if let Some(applied) = &applied {
            assert_eq!(
                &vault.verify_channel_identity_autonomy(&requested.autonomy, &owner)?,
                applied
            );
            assert_eq!(
                applied
                    .action_grant
                    .as_ref()
                    .expect("draft grant")
                    .read_frontier_hash,
                policy
            );
        }
        if checkpoint < 2 {
            assert_mailbox_waiting(&vault, &intent, &owner)?;
            if checkpoint == 0 {
                bind_mailbox(&vault, requested.identity_ref)?;
            }
            fulfill_mailbox(&vault, requested.identity_ref)?;
        }
        let outcome =
            vault.onboard_workspace_member(intent.clone(), &writer(WRITER), Some(&owner))?;
        let state = vault.verify_channel_identity_autonomy(&requested.autonomy, &owner)?;
        if let Some(applied) = applied {
            assert_eq!(state, applied, "resume must preserve existing exact grants");
        }
        let journal =
            read_journal(&vault, &onboarding_key(&intent.onboarding_id))?.expect("journal");
        assert_eq!(journal.step, MemberOnboardingStep::Complete);
        assert_eq!(journal.completed_at, Some(outcome.completed_at));
        assert_eq!(
            vault
                .workspace_roster(&intent.workspace.workspace_ref, AT)?
                .len(),
            2
        );
        assert!(
            !vault
                .get_channel_identity(&requested.identity_ref)?
                .expect("identity")
                .may_send()
        );
        assert_eq!(type_count(&vault, ENTITY_TYPE_CHANNEL_IDENTITY), 1);
        assert_eq!(type_count(&vault, ENTITY_TYPE_COMPANION_REGISTER), 1);
        assert_eq!(type_count(&vault, ENTITY_TYPE_ACCESS_GRANT), 2);
        assert_eq!(
            type_count(&vault, crate::registry::ENTITY_TYPE_OUTBOUND_GRANT),
            1
        );
        let revision = vault.store.env.info().last_txn_id;
        assert_eq!(
            vault.onboard_workspace_member(intent, &writer(WRITER), Some(&owner))?,
            outcome
        );
        assert_eq!(vault.store.env.info().last_txn_id, revision);
    }
    Ok(())
}

#[test]
fn every_autonomy_request_axis_is_digest_pinned_on_incomplete_and_complete_replay() -> Result<()> {
    for complete in [false, true] {
        let (_dir, vault, intent, owner) = mailbox_fixture()?;
        assert!(matches!(
            vault.onboard_workspace_member(intent.clone(), &writer(WRITER), Some(&owner)),
            Err(Error::Record(
                RecordError::WorkspaceMailboxAutonomyNotReady { .. }
            ))
        ));
        if complete {
            activate_mailbox(&vault, entity(MAILBOX_IDENTITY))?;
            vault.onboard_workspace_member(intent.clone(), &writer(WRITER), Some(&owner))?;
        }
        let revision = vault.store.env.info().last_txn_id;
        for axis in 0..14 {
            let mut changed = intent.clone();
            let desired = &mut changed
                .delegated_mailbox
                .as_mut()
                .expect("mailbox")
                .autonomy;
            match axis {
                0 => desired.actor_ref = entity(OUTSIDER),
                1 => desired.read_envelope.identity_ref = entity(OUTSIDER),
                2 => {
                    desired
                        .read_envelope
                        .label_allowlist
                        .push("archive".to_owned());
                }
                3 => desired.read_envelope.thread_allowlist.clear(),
                4 => desired.read_envelope.not_before = None,
                5 => desired.read_envelope.not_after = Some(AT + 120),
                6 => desired.rung = ChannelIdentityAutonomyRung::SendWithApproval,
                7 => {
                    desired.relationship_context = RelationshipContext::SchedulingLogistics;
                    desired
                        .action_envelope
                        .as_mut()
                        .expect("action")
                        .relationship_context = RelationshipContext::SchedulingLogistics;
                }
                8 => {
                    desired
                        .action_envelope
                        .as_mut()
                        .expect("action")
                        .identity_ref = entity(OUTSIDER);
                }
                9 => {
                    desired
                        .action_envelope
                        .as_mut()
                        .expect("action")
                        .relationship_context = RelationshipContext::PersonalFriends;
                }
                10 => {
                    desired
                        .action_envelope
                        .as_mut()
                        .expect("action")
                        .counterparty_class = None;
                }
                11 => {
                    desired
                        .action_envelope
                        .as_mut()
                        .expect("action")
                        .max_actions += 1;
                }
                12 => {
                    desired
                        .action_envelope
                        .as_mut()
                        .expect("action")
                        .window_secs += 1;
                }
                13 => {
                    desired.rung = ChannelIdentityAutonomyRung::ScopedRead;
                    desired.action_envelope = None;
                }
                _ => unreachable!(),
            }
            let err = vault
                .onboard_workspace_member(changed, &writer(WRITER), Some(&owner))
                .expect_err("changed desired bounds cannot replay");
            if !matches!(axis, 0 | 1 | 8 | 9) {
                assert_eq!(err.kind(), ErrorKind::InvalidClaimBody, "axis {axis}");
            }
            assert_eq!(vault.store.env.info().last_txn_id, revision, "axis {axis}");
        }
    }
    Ok(())
}

#[test]
fn authenticated_mailbox_apply_verify_and_exact_replay() -> Result<()> {
    for rung in [
        ChannelIdentityAutonomyRung::ScopedRead,
        ChannelIdentityAutonomyRung::DraftOnly,
        ChannelIdentityAutonomyRung::SendWithApproval,
    ] {
        let (_dir, vault, mut intent, owner) = mailbox_fixture()?;
        let requested = intent.delegated_mailbox.as_mut().expect("mailbox");
        requested.autonomy.rung = rung;
        if rung == ChannelIdentityAutonomyRung::ScopedRead {
            requested.autonomy.action_envelope = None;
        }
        let requested = requested.clone();
        let waiting = assert_mailbox_waiting(&vault, &intent, &owner)?;
        let identity = vault
            .get_channel_identity(&requested.identity_ref)?
            .expect("identity");
        assert_eq!(identity.state, ChannelIdentityState::Requested);
        for (outcome, gate_outcome) in [("denied", "deny"), ("held", "pending")] {
            let mut request = mailbox_bind_request(requested.identity_ref, &owner);
            if outcome == "denied" {
                request.actor.actor_entity_ref = None;
            } else {
                // A live human without the scoped Bind grant must still wait,
                // even with opted-in/permission booleans set to true.
                request.actor.actor_ref = Some(entity(OUTSIDER).to_hex());
                request.actor.actor_entity_ref = Some(entity(OUTSIDER));
            }
            let result = vault.apply_channel_identity_lifecycle_intent(request)?;
            assert_eq!(result.outcome, outcome);
            assert_mailbox_lifecycle_receipt(
                &vault,
                requested.identity_ref,
                &result,
                "bind",
                Some(gate_outcome),
            )?;
            assert_eq!(
                vault.get_channel_identity(&requested.identity_ref)?,
                Some(identity.clone())
            );
            assert_eq!(assert_mailbox_waiting(&vault, &intent, &owner)?, waiting);
        }
        bind_mailbox(&vault, requested.identity_ref)?;
        assert_eq!(assert_mailbox_waiting(&vault, &intent, &owner)?, waiting);
        fulfill_mailbox(&vault, requested.identity_ref)?;
        let first =
            vault.onboard_workspace_member(intent.clone(), &writer(WRITER), Some(&owner))?;
        let state = vault.verify_channel_identity_autonomy(&requested.autonomy, &owner)?;
        assert_eq!(state.mode.rung, rung);
        assert_eq!(state.read_envelope, requested.autonomy.read_envelope);
        assert_eq!(state.action_envelope, requested.autonomy.action_envelope);
        assert_eq!(state.read_grant.principal_ref, intent.actor_ref);
        assert_eq!(first.delegated_identity_ref, Some(requested.identity_ref));
        assert!(
            !vault
                .get_channel_identity(&requested.identity_ref)?
                .expect("identity")
                .may_send()
        );
        assert_eq!(type_count(&vault, ENTITY_TYPE_ACCESS_GRANT), 2);
        let revision = vault.store.env.info().last_txn_id;
        assert_eq!(
            vault.onboard_workspace_member(intent.clone(), &writer(WRITER), Some(&owner))?,
            first
        );
        assert_eq!(
            vault.store.env.info().last_txn_id,
            revision,
            "replay writes no rows or receipts"
        );
        let journal =
            read_journal(&vault, &onboarding_key(&intent.onboarding_id))?.expect("journal");
        assert_eq!(journal.step, MemberOnboardingStep::Complete);
        assert_eq!(
            vault
                .workspace_roster(&intent.workspace.workspace_ref, AT)?
                .len(),
            2
        );
        let read_ref = state.mode.read_grant_ref.expect("read grant");
        let candidate = crate::channel_identity_autonomy::MailboxReadCandidate {
            identity_ref: requested.identity_ref,
            label: Some("inbox".to_owned()),
            thread_ref: Some("thread:1".to_owned()),
            occurred_at: AT + 30,
        };
        assert!(vault.authorize_channel_identity_scoped_read(
            &read_ref,
            &intent.actor_ref,
            &candidate
        )?);
        let mut outside = candidate;
        outside.occurred_at = AT + 61;
        assert!(!vault.authorize_channel_identity_scoped_read(
            &read_ref,
            &intent.actor_ref,
            &outside
        )?);
        if let Some(action_ref) = state.mode.action_grant_ref {
            let mut effect = crate::channel_identity_autonomy::ChannelIdentityEffectCandidate {
                identity_ref: requested.identity_ref,
                relationship_context: RelationshipContext::WorkDeal,
                verb_class: "mail.send".to_owned(),
                counterparty_class: Some("known".to_owned()),
                effect_key: [1; 32],
            };
            assert!(!vault.authorize_and_consume_channel_identity_grant(&action_ref, &effect)?);
            effect.verb_class = "mail.draft".to_owned();
            assert!(vault.authorize_and_consume_channel_identity_grant(&action_ref, &effect)?);
            assert_eq!(
                type_count(&vault, crate::registry::ENTITY_TYPE_OUTBOUND_GRANT),
                1
            );
        } else {
            assert_eq!(
                type_count(&vault, crate::registry::ENTITY_TYPE_OUTBOUND_GRANT),
                0
            );
        }
    }
    Ok(())
}
