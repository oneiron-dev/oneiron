//! The setting-row writer doors reject invalid owner calls before device presence.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::affect::state_index::{ENGAGEMENT, GOAL_VELOCITY, StateIndexEvidence};
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::code_run::{GatedActorWrite, SelfCall, SelfDispatcher, SelfMemoryPutClaimCall};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
};
use oneiron::dreamer_runner::maintenance::MaintenanceTarget;
use oneiron::dreamer_runner::maintenance::digest::{
    PROACTIVITY_POLICY_REQUEST_PREDICATE, ProactivityCadence, ProactivityPolicyRequest,
    ProactivityPresentation,
};
use oneiron::error::{GateError, OwnerPresenceRefusal, RecordError};
use oneiron::federation::{Scope, ScopeId};
use oneiron::llm::model_pack::{ModelPackRevertBlock, ModelPackRevertRequest, ModelPackSetting};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_TURN};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallStatus};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::action_mode_pass::run_action_mode_pass;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_support::{provision_engine_machines, put_policy_manifest_bytes};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimCandidate, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, EdgeActorClass, EntityId, Error, GateConsentBundle, GateConsentBundleAction,
    HostingPrivacyPosture, TimeRange, Vad, VadAnnotation, VadAnnotationSource, Vault, VaultConfig,
    WriteActor, WriteEnvelope, WriteProvenance,
};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PresenceError, PresenceGate, PresenceWindow,
    ScriptedPresence,
};
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const NOW: u64 = 1_790_000_000;
const AT: TimeRange = TimeRange {
    start: NOW,
    end: NOW,
};
const MODEL_PACK_REVERT_REASON: &str = "switch back to the earlier AI model pack";
const PROACTIVITY_POLICY_REASON: &str = "change how your digest is delivered";
const POLICY_RUN: &str = "setting-writer-policy-run";
const OLDER_PACK: &str = "setting-writer.pack-a";
const NEWER_PACK: &str = "setting-writer.pack-b";

struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn hosted() -> Self {
        let (vault, dir) = open_vault(HostingPrivacyPosture::Hosted);
        let (_, owner) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            vault,
            owner,
            _dir: dir,
        }
    }

    fn rooted() -> Self {
        let (vault, dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
        let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner = vault
            .authenticate_owner(
                actor,
                &actor.to_hex(),
                true,
                GateDecisionId::from_bytes([2; 16]),
            )
            .expect("owner proof");
        Self {
            vault,
            owner,
            _dir: dir,
        }
    }

    fn authority_rows(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .len()
    }

    fn model_pack_setting(&self) -> ModelPackSetting {
        self.vault
            .model_pack_setting_as_owner(&self.owner)
            .expect("model pack setting")
    }

    fn review_bundle(&self) -> oneiron::Result<GateConsentBundle> {
        self.vault.review_gate_consent_bundle(
            &WriteActor::new(self.owner.actor(), EdgeActorClass::Human),
            POLICY_RUN,
        )
    }
}

fn open_vault(posture: HostingPrivacyPosture) -> (Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = posture;
    config.store_clock = ManualClock::new(NOW).bundle();
    let vault = if posture == HostingPrivacyPosture::Hosted {
        Vault::open(dir.path(), config)
    } else {
        Vault::open_owned(dir.path(), config)
    }
    .expect("vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile under the host root");
    (vault, dir)
}

fn scripted_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    let gate = PresenceGate::new(presence.clone(), window);
    vault.install_presence_gate(Arc::new(gate));
    presence
}

fn missing_change() -> ModelPackRevertRequest {
    ModelPackRevertRequest {
        change_ref: "a change no notice names".to_owned(),
    }
}

fn assert_declined<T: std::fmt::Debug>(result: oneiron::Result<T>) {
    assert!(
        matches!(
            result,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined,
            }))
        ),
        "the confirm is declined: {result:?}"
    );
}

fn install_model_pack(served: &ServedVault, name: &str, day: u32) {
    let manifest = format!(
        "---\nname: {name}\ndescription: Test model pack {name}.\nversion: 1.0.0\nkind: model\n---\nA data-only seasonal model stack.\n"
    );
    let models = json!({
        "format": 1,
        "season": "setting-writer-season",
        "released_epoch_day": day,
        "roles": {"generative_reasoner": [{
            "access": {"kind": "hosted", "provider": "dials-provider"},
            "model": "dials-provider/dials-model@r1",
            "when": "Default pick for the test role."
        }]}
    });
    let outcome = served
        .vault
        .put_pack(
            &served.owner,
            vec![
                HubFile::new("PACK.md", manifest),
                HubFile::new("knowledge/model-pack.json", models.to_string()),
            ],
        )
        .expect("owner installs a model pack");
    assert!(matches!(outcome, PackInstallDisposition::Installed(receipt)
        if receipt.pack_name == name && receipt.status == PackInstallStatus::Active));
}

fn policy_candidate(owner: EntityId) -> ClaimCandidate {
    let request = ProactivityPolicyRequest {
        cadence: ProactivityCadence {
            period_secs: 300,
            group_by_facet: true,
            urgent_breakthrough: false,
        },
        presentation: ProactivityPresentation {
            group_aliases: Default::default(),
            group_template: "{group}\n".to_owned(),
            item_template: "{summary} [{ref}]\n".to_owned(),
            voice_style: "gentle".to_owned(),
            urgent_groups: Vec::new(),
        },
    };
    ClaimCandidate::new(
        PROACTIVITY_POLICY_REQUEST_PREDICATE,
        ClaimSubject::Entity(owner),
        RmpValue::from(request.claim_value().expect("valid policy request")),
        0.9,
    )
}

fn propose_policy(served: &ServedVault) -> EntityId {
    let vault = &served.vault;
    let agent = vault.new_entity_id().expect("agent id");
    vault
        .put_entity(&agent, ENTITY_TYPE_PERSON, AT, NOW, b"policy agent")
        .expect("the agent's record");
    let dispatcher = GatedActorWrite::new(
        vault,
        WriteActor::new(agent, EdgeActorClass::Agent),
        "policy-request",
    )
    .expect("policy request dispatcher");
    let claim = vault.new_entity_id().expect("policy claim id");
    dispatcher
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            claim,
            policy_candidate(served.owner.actor()),
            AT,
            NOW,
        )))
        .expect("the agent proposes a policy");
    claim
}

fn park_policy_request(served: &ServedVault) -> (EntityId, [u8; 32]) {
    let vault = &served.vault;
    let opener = define_agent(vault, "setting-writer-bundle-opener").expect("bundle opener");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let grant = mint_agent_grant_as(
        vault,
        &served.owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: opener,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: Default::default(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner grants the bundle opener base reach");
    assert!(grant.grant.confers);
    let turn = vault.new_entity_id().expect("turn id");
    vault
        .put_entity(&turn, ENTITY_TYPE_TURN, AT, NOW, b"what was said")
        .expect("the cited turn");
    let evidence = encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs: vec![turn],
        chain: Vec::new(),
        source_meet: ClaimSource::Generated,
    });
    let envelope = WriteEnvelope::new(
        WriteActor::new(opener, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(RmpValue::Map(vec![
            (RmpValue::from("runner"), RmpValue::from("dreamer")),
            (RmpValue::from("run_id"), RmpValue::from(POLICY_RUN)),
        ]))
        .expect("run provenance"),
        ClaimApprovalStatus::Proposed,
    );
    let claim_id = vault.new_entity_id().expect("bundle member id");
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            policy_candidate(served.owner.actor()).with_evidence(evidence),
            &envelope,
            AT,
            NOW,
        )
        .commit()
        .expect("the run parks the policy request");
    let bundle = served
        .review_bundle()
        .expect("the owner reviews the live policy bundle");
    assert_eq!(bundle.members.len(), 1);
    assert_eq!(bundle.members[0].claim_id, claim_id);
    vault
        .proactivity_policy_proposal(&served.owner, claim_id)
        .expect("the member is a policy proposal");
    (claim_id, bundle.bundle_id)
}

fn declare_action_mode_predicates(vault: &Vault) {
    let id_and_manifest = vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("policy manifests")
        .into_iter()
        .find_map(|id| {
            let bytes = vault.get(&id).expect("policy manifest read")?;
            let manifest: Value = rmp_serde::from_slice(&bytes).expect("decode policy manifest");
            (manifest["pack_id"] == "oneiron-default-policy").then_some((id, manifest))
        });
    let (id, mut manifest) = id_and_manifest.expect("shipped manifest");
    let rules = manifest
        .as_object_mut()
        .expect("policy manifest map")
        .entry("rules")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("policy rules list");
    for prefix in ["state.", "dreamer.action_mode."] {
        let entry = rules.iter().position(|rule| rule["prefix"] == prefix);
        let index = entry.unwrap_or_else(|| {
            rules.push(json!({ "prefix": prefix }));
            rules.len() - 1
        });
        rules[index]["axes"] = json!({ "criticality": "normal", "sensitivity": "normal" });
    }
    put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("encode policy manifest"),
    )
    .expect("declare action-mode predicates normal");
}

fn apply_non_policy_maintenance(served: &ServedVault) -> MaintenanceTarget {
    let vault = &served.vault;
    declare_action_mode_predicates(vault);
    let agent = define_agent(vault, "setting-writer-action-mode-agent").expect("action-mode agent");
    let set = vault.set_setting(SettingCaller::Owner(&served.owner), SetSetting::vault_value(
        "dreamer.action_mode.policy", json!({
            "window": { "window_secs": 604_800, "expected_goal_completions": 5, "expected_engaged_days": 4 },
            "rules": [{ "mode": "delegate", "min_index": 0.0, "max_index": 1.0,
                "effect": { "agent": agent.to_hex(), "ceiling": "auto" } }],
        }),
    )).expect("action-mode policy");
    assert!(matches!(
        set,
        SetSettingOutcome::Applied {
            sequence: Some(_),
            ..
        }
    ));

    let turn = vault.new_entity_id().expect("turn id");
    vault
        .put_entity(&turn, ENTITY_TYPE_TURN, AT, NOW, b"turn")
        .expect("turn");
    let vad = Vad {
        valence: 0.5,
        arousal: 0.6,
        dominance: 0.9,
    };
    vault
        .annotate_turn_vad(
            &turn,
            VadAnnotation::new(vad, VadAnnotationSource::UserSelfReport, NOW).expect("annotation"),
        )
        .expect("annotated turn");
    let facet = vault.default_facet().expect("vault default facet");
    let signal = |predicate: &str, value: f32| {
        let id = vault.new_entity_id().expect("signal id");
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(served.owner.actor()),
            RmpValue::F32(value),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("state signal");
        body.source = Some(ClaimSource::Observed);
        body.scope_facet = facet;
        vault.put_claim(&id, &body, AT, NOW).expect("record signal");
        id
    };
    let evidence = StateIndexEvidence {
        vad_turns: vec![turn],
        goal_velocity: signal(GOAL_VELOCITY, 0.7),
        engagement: signal(ENGAGEMENT, 0.8),
    };
    vault
        .derive_state_index(&served.owner.actor(), &evidence, NOW)
        .expect("derive state index");
    let finding = run_action_mode_pass(vault, NOW + 60)
        .expect("action-mode pass")
        .expect("the index falls in the policy band");
    let target = MaintenanceTarget::Finding(finding);
    assert!(
        vault
            .applied_dreamer_maintenance(&served.owner, 10)
            .expect("applied maintenance")
            .iter()
            .any(|row| row.target == target && row.kind == "finding" && row.reverted.is_none())
    );
    target
}

/// A model pack revert with no live change returns its block without a prompt.
#[test]
fn a_model_pack_revert_that_cannot_run_is_answered_without_the_prompt() {
    let served = ServedVault::hosted();
    let before = served.model_pack_setting();
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let reverted = served
        .vault
        .revert_model_pack_change_as_owner(&served.owner, &missing_change())
        .expect("a missing prior change returns a block");
    assert_eq!(reverted.blocked, Some(ModelPackRevertBlock::Superseded));
    assert_eq!(reverted.setting, before);
    assert_eq!(presence.prompts(), 0);
}

/// Each setting-row writer refuses another vault's proof before asking.
#[test]
fn an_owner_proof_of_another_vault_never_raises_the_prompt_at_a_setting_row_writer() {
    let served = ServedVault::hosted();
    let other = ServedVault::hosted();
    let vault = &served.vault;
    let claim = vault.new_entity_id().expect("unknown claim id");
    let presence = scripted_gate(vault, [Err(PresenceError::Declined)]);
    let rows = served.authority_rows();
    for refused in [
        vault
            .revert_model_pack_change_as_owner(&other.owner, &missing_change())
            .map(drop),
        vault.confirm_proactivity_policy_proposal(&other.owner, claim, [0; 32]),
        vault
            .revert_dreamer_maintenance(&other.owner, MaintenanceTarget::Finding(claim), NOW)
            .map(drop),
        vault
            .resolve_gate_consent_bundle(
                &other.owner,
                [0; 32],
                POLICY_RUN,
                GateConsentBundleAction::Approve,
                NOW,
            )
            .map(drop),
    ] {
        assert!(
            matches!(
                refused,
                Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "owner proof belongs to another vault"
                )))
            ),
            "another vault's proof is refused: {refused:?}"
        );
    }
    assert_eq!(presence.prompts(), 0);
    assert_eq!(served.authority_rows(), rows);
}

/// An unknown, changed, or already confirmed policy proposal never prompts.
#[test]
fn a_policy_proposal_that_is_not_the_one_shown_never_raises_the_prompt() {
    let served = ServedVault::hosted();
    let vault = &served.vault;
    let confirmed = propose_policy(&served);
    let confirmed_revision = vault
        .proactivity_policy_proposal(&served.owner, confirmed)
        .expect("the policy proposal")
        .revision;
    vault
        .confirm_proactivity_policy_proposal(&served.owner, confirmed, confirmed_revision)
        .expect("confirm a policy proposal without a configured gate");
    let pending = propose_policy(&served);
    let mut wrong_revision = vault
        .proactivity_policy_proposal(&served.owner, pending)
        .expect("the pending policy proposal")
        .revision;
    wrong_revision[0] ^= 1;
    let missing = vault.new_entity_id().expect("unknown proposal id");
    let presence = scripted_gate(vault, [Err(PresenceError::Declined)]);
    for (claim, revision) in [
        (missing, [0; 32]),
        (pending, wrong_revision),
        (confirmed, confirmed_revision),
    ] {
        let refused = vault.confirm_proactivity_policy_proposal(&served.owner, claim, revision);
        assert!(
            matches!(refused, Err(Error::InvalidConfig(ref message))
            if message == "invalid Dreamer maintenance row"),
            "the proposal is refused: {refused:?}"
        );
    }
    assert_eq!(presence.prompts(), 0);
}

/// Reverting an unknown maintenance target returns not found without asking.
#[test]
fn a_maintenance_revert_of_an_unknown_target_never_raises_the_prompt() {
    let served = ServedVault::hosted();
    let target = MaintenanceTarget::Finding(served.vault.new_entity_id().expect("unknown target"));
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    assert!(matches!(
        served
            .vault
            .revert_dreamer_maintenance(&served.owner, target, NOW),
        Err(Error::EntityNotFound)
    ));
    assert_eq!(presence.prompts(), 0);
}

/// An empty, absent, or stale approval is refused without a bundle prompt.
#[test]
fn a_bundle_approval_refused_on_its_read_never_raises_the_prompt() {
    let served = ServedVault::rooted();
    let (claim, mut wrong_id) = park_policy_request(&served);
    wrong_id[0] ^= 1;
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let approve = |id, run: &str| {
        served.vault.resolve_gate_consent_bundle(
            &served.owner,
            id,
            run,
            GateConsentBundleAction::Approve,
            NOW,
        )
    };
    assert!(matches!(
        approve([0; 32], ""),
        Err(Error::InvalidClaimBody(
            "gate consent bundle requires a dreamer run id"
        ))
    ));
    assert!(matches!(
        approve([0; 32], "no-such-run"),
        Err(Error::EntityNotFound)
    ));
    assert!(
        matches!(approve(wrong_id, POLICY_RUN), Err(Error::Gate(GateError::GateConsentStale { claim_id })) if claim_id == claim)
    );
    assert_eq!(presence.prompts(), 0);
}

/// Declining device presence for a valid write leaves the setting rows unchanged.
#[test]
fn a_declined_confirm_refuses_each_setting_row_writer_and_stores_nothing() {
    let served = ServedVault::rooted();
    let vault = &served.vault;
    install_model_pack(&served, OLDER_PACK, 20_700);
    install_model_pack(&served, NEWER_PACK, 20_710);
    let pack = served.model_pack_setting();
    assert_eq!(
        pack.previous
            .as_ref()
            .expect("installed previous pack")
            .pack,
        OLDER_PACK
    );
    let change = ModelPackRevertRequest {
        change_ref: pack.change_ref.clone().expect("live pack change"),
    };
    let proposal = propose_policy(&served);
    let expected = vault
        .proactivity_policy_proposal(&served.owner, proposal)
        .expect("pending proposal");
    let (member, bundle_id) = park_policy_request(&served);
    let member_before = vault
        .proactivity_policy_proposal(&served.owner, member)
        .expect("pending member");
    let basis = vault
        .proactivity_policy_basis()
        .expect("policy setting rows");
    let rows = served.authority_rows();
    let decisions = vault
        .gate_decisions(128)
        .expect("gate ledger")
        .into_iter()
        .map(|row| row.decision_id)
        .collect::<Vec<_>>();
    let presence = scripted_gate(
        vault,
        [
            Err(PresenceError::Declined),
            Err(PresenceError::Declined),
            Err(PresenceError::Declined),
        ],
    );

    assert_declined(vault.revert_model_pack_change_as_owner(&served.owner, &change));
    assert_eq!(presence.reasons(), [MODEL_PACK_REVERT_REASON]);
    assert_eq!(served.model_pack_setting(), pack);
    assert_declined(vault.confirm_proactivity_policy_proposal(
        &served.owner,
        proposal,
        expected.revision,
    ));
    assert_eq!(
        presence.reasons(),
        [MODEL_PACK_REVERT_REASON, PROACTIVITY_POLICY_REASON]
    );
    assert_eq!(
        vault
            .proactivity_policy_basis()
            .expect("policy setting rows"),
        basis
    );
    assert_eq!(
        vault
            .proactivity_policy_proposal(&served.owner, proposal)
            .expect("still pending"),
        expected
    );
    assert_declined(vault.resolve_gate_consent_bundle(
        &served.owner,
        bundle_id,
        POLICY_RUN,
        GateConsentBundleAction::Approve,
        NOW,
    ));
    assert_eq!(
        presence.reasons(),
        [
            MODEL_PACK_REVERT_REASON,
            PROACTIVITY_POLICY_REASON,
            PROACTIVITY_POLICY_REASON
        ]
    );
    assert_eq!(presence.prompts(), 3);
    assert_eq!(
        served
            .review_bundle()
            .expect("the same live bundle")
            .bundle_id,
        bundle_id
    );
    assert_eq!(
        vault
            .proactivity_policy_proposal(&served.owner, member)
            .expect("member still pending"),
        member_before
    );
    assert_eq!(
        vault
            .proactivity_policy_basis()
            .expect("policy setting rows"),
        basis
    );
    assert_eq!(served.authority_rows(), rows);
    assert_eq!(
        vault
            .gate_decisions(128)
            .expect("gate ledger")
            .into_iter()
            .map(|row| row.decision_id)
            .collect::<Vec<_>>(),
        decisions
    );
}

/// A policy-bundle decline and a non-policy maintenance revert land without asking.
#[test]
fn a_bundle_decline_and_a_revert_of_another_kind_ask_nothing() {
    let served = ServedVault::rooted();
    let target = apply_non_policy_maintenance(&served);
    let (member, bundle_id) = park_policy_request(&served);
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let receipt = served
        .vault
        .resolve_gate_consent_bundle(
            &served.owner,
            bundle_id,
            POLICY_RUN,
            GateConsentBundleAction::Decline,
            NOW + 120,
        )
        .expect("decline lands");
    assert_eq!(receipt.action, GateConsentBundleAction::Decline);
    assert_eq!(receipt.member_claim_ids, [member]);
    assert!(matches!(served.review_bundle(), Err(Error::EntityNotFound)));
    let reverted = served
        .vault
        .revert_dreamer_maintenance(&served.owner, target, NOW + 120)
        .expect("non-policy revert lands");
    assert!(
        served
            .vault
            .applied_dreamer_maintenance(&served.owner, 10)
            .expect("applied maintenance")
            .iter()
            .any(|row| row.target == target && row.reverted.as_ref() == Some(&reverted))
    );
    assert_eq!(presence.prompts(), 0);
}
