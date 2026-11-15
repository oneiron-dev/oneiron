//! Restriction wave 20: four request caps become owner Setting keys, default = today.
//!
//! `snapshot_read.open.max_kinds` (16), `snapshot_read.preflight.max_refs` (100),
//! `snapshot_read.evidence.max_ranges` (64) and `engine_executor.checkpoint_read.max_limit`
//! (128). Each key's default is today's const, so nothing moves until the owner sets it.
//!
//! The raise tests fail before Part 2 (the doors do not read the keys yet) and pass after it;
//! the no-row tests pass on both.
//!
//! Public paths only: the generated engine fns in `oneiron::verbs`, `Vault::set_setting` for
//! the owner's rows, and `Vault::put_code_run_replay_record` for the checkpoint runs.

use oneiron::code_run::{
    CODE_RUN_REPLAY_HASH_LEN, CodeRunDeterminism, CodeRunReplayRecord, CodeRunStepCheckpoint,
};
use oneiron::engine_executor::checkpoint_read::CheckpointReadRequest;
use oneiron::memory::{Memory, WitnessAssertions};
use oneiron::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_EVENT,
    ENTITY_TYPE_FACET, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE,
    ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_SESSION, ENTITY_TYPE_SKILL, ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_WORLD,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::snapshot_read::{
    EvidenceRange, EvidenceSpansRequest, PolicyPreflightAct, PolicyPreflightRequest, SnapshotKind,
    SnapshotOpenRequest,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    EdgeActorClass, EntityId, Vault, VaultConfig, WitnessAuthor, WitnessMessage, WitnessTurn,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

fn owner_memory(vault: &Vault) -> Result<Memory<'_>, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(vault.memory(owner, EdgeActorClass::Human))
}

/// The owner sets `key` to `value` at the vault scope.
fn set_vault_u32(vault: &Vault, key: &str, value: u32) -> TestResult {
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let outcome = vault.set_setting(
        SettingCaller::Owner(&proof),
        SetSetting {
            key: key.to_owned(),
            item: None,
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(serde_json::json!(value)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the owner's change did not apply: {outcome:?}"
    );
    Ok(())
}

/// 17 distinct kinds: the four named kinds and 13 other type codes.
fn seventeen_kinds() -> Vec<SnapshotKind> {
    let mut kinds = vec![
        SnapshotKind::Claim,
        SnapshotKind::Turn,
        SnapshotKind::Message,
        SnapshotKind::Note,
    ];
    for entity_type in [
        ENTITY_TYPE_SESSION,
        ENTITY_TYPE_CONVERSATION,
        ENTITY_TYPE_SUMMARY,
        ENTITY_TYPE_PERSON,
        ENTITY_TYPE_RELATIONSHIP,
        ENTITY_TYPE_ORG,
        ENTITY_TYPE_FACET,
        ENTITY_TYPE_EVENT,
        ENTITY_TYPE_PLACE,
        ENTITY_TYPE_WORLD,
        ENTITY_TYPE_ASSET,
        ENTITY_TYPE_ASSET_TEXT,
        ENTITY_TYPE_SKILL,
    ] {
        kinds.push(SnapshotKind::Entity { entity_type });
    }
    kinds
}

#[test]
fn snapshot_open_names_seventeen_kinds_once_max_kinds_is_seventeen() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let memory = owner_memory(&vault)?;
    set_vault_u32(&vault, "snapshot_read.open.max_kinds", 17)?;
    let handle = oneiron::verbs::vault_snapshot_open(
        &memory,
        SnapshotOpenRequest {
            kinds: seventeen_kinds(),
            filter: None,
            lifetime_secs: None,
        },
    )?;
    assert_eq!(handle.kinds.len(), 17);
    Ok(())
}

#[test]
fn snapshot_open_refuses_seventeen_kinds_with_no_setting_row() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let memory = owner_memory(&vault)?;
    let refused = match oneiron::verbs::vault_snapshot_open(
        &memory,
        SnapshotOpenRequest {
            kinds: seventeen_kinds(),
            filter: None,
            lifetime_secs: None,
        },
    ) {
        Ok(handle) => panic!("the open was not refused: {handle:?}"),
        Err(refused) => refused,
    };
    assert_eq!(refused.message, "a snapshot pages 1 to 16 kinds");
    Ok(())
}

#[test]
fn policy_preflight_takes_101_refs_once_max_refs_is_101() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let memory = owner_memory(&vault)?;
    set_vault_u32(&vault, "snapshot_read.preflight.max_refs", 101)?;
    let refs: Vec<EntityId> = (0..101).map(|_| EntityId::now()).collect();
    let answer = oneiron::verbs::vault_policy_preflight(
        &memory,
        PolicyPreflightRequest {
            refs,
            act: PolicyPreflightAct::Read,
        },
    )?;
    assert_eq!(answer.value.refs.len(), 101);
    Ok(())
}

#[test]
fn policy_preflight_refuses_101_refs_with_no_setting_row() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let memory = owner_memory(&vault)?;
    let refs: Vec<EntityId> = (0..101).map(|_| EntityId::now()).collect();
    let refused = match oneiron::verbs::vault_policy_preflight(
        &memory,
        PolicyPreflightRequest {
            refs,
            act: PolicyPreflightAct::Read,
        },
    ) {
        Ok(answer) => panic!("the preflight was not refused: {answer:?}"),
        Err(refused) => refused,
    };
    assert_eq!(refused.message, "at most 100 refs per preflight");
    Ok(())
}

/// The owner witnesses one TURN of one MESSAGE row holding 200 `a`s.
fn long_turn(memory: &Memory<'_>) -> Result<EntityId, Box<dyn std::error::Error>> {
    Ok(memory
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "a".repeat(200),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 900,
            assertions: WitnessAssertions::default(),
        })?
        .turn_id)
}

fn sixty_five_ranges() -> Vec<EvidenceRange> {
    (0..65)
        .map(|start| EvidenceRange {
            start,
            end: start + 1,
        })
        .collect()
}

#[test]
fn evidence_spans_takes_65_ranges_once_max_ranges_is_65() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let memory = owner_memory(&vault)?;
    let turn = long_turn(&memory)?;
    set_vault_u32(&vault, "snapshot_read.evidence.max_ranges", 65)?;
    let answer = oneiron::verbs::vault_evidence_spans(
        &memory,
        EvidenceSpansRequest {
            source: turn,
            version: None,
            ranges: sixty_five_ranges(),
        },
    )?;
    assert_eq!(answer.value.spans.len(), 65);
    Ok(())
}

#[test]
fn evidence_spans_refuses_65_ranges_with_no_setting_row() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let memory = owner_memory(&vault)?;
    let turn = long_turn(&memory)?;
    let refused = match oneiron::verbs::vault_evidence_spans(
        &memory,
        EvidenceSpansRequest {
            source: turn,
            version: None,
            ranges: sixty_five_ranges(),
        },
    ) {
        Ok(answer) => panic!("the spans read was not refused: {answer:?}"),
        Err(refused) => refused,
    };
    assert_eq!(refused.message, "at most 64 evidence ranges per request");
    Ok(())
}

/// A code run with `steps` committed step checkpoints, public paths only.
fn run_with_steps(vault: &Vault, steps: u64) -> Result<EntityId, Box<dyn std::error::Error>> {
    let run = EntityId::now();
    let mut record = CodeRunReplayRecord::new(run, CodeRunDeterminism::new(0, [0u8; 32]));
    for seq in 0..steps {
        let checkpoint = CodeRunStepCheckpoint::new(
            seq,
            format!("step-{seq}"),
            [0u8; CODE_RUN_REPLAY_HASH_LEN],
            0,
        )?;
        record.step_checkpoints.push(checkpoint);
    }
    vault.put_code_run_replay_record(&record)?;
    Ok(run)
}

#[test]
fn checkpoint_page_serves_129_steps_once_max_limit_is_129() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let memory = owner_memory(&vault)?;
    let run = run_with_steps(&vault, 130)?;
    set_vault_u32(&vault, "engine_executor.checkpoint_read.max_limit", 129)?;
    let view = oneiron::verbs::vault_runs_checkpoint(
        &memory,
        CheckpointReadRequest {
            run_ref: run.to_hex(),
            from_step: 0,
            limit: Some(129),
        },
    )?
    .expect("the run reads");
    assert_eq!(view.steps.len(), 129);
    Ok(())
}

#[test]
fn checkpoint_page_serves_128_steps_with_no_setting_row() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let memory = owner_memory(&vault)?;
    let run = run_with_steps(&vault, 130)?;
    let view = oneiron::verbs::vault_runs_checkpoint(
        &memory,
        CheckpointReadRequest {
            run_ref: run.to_hex(),
            from_step: 0,
            limit: Some(129),
        },
    )?
    .expect("the run reads");
    assert_eq!(view.steps.len(), 128);
    Ok(())
}
