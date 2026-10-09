//! Census cases for who reads or witnesses what.
use super::Case;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use crate::test_util::entity;
use crate::voice_identity::{
    VoiceAttributionEvidence, VoiceResolvedSegment, VoiceSessionRosterV1, put_voice_roster_for_test,
};
use crate::workspace_roster::{LEADER_CHAT_RULE_PREDICATE, ProjectRecord};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};
use rmpv::Value;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn put_person(vault: &Vault, id: EntityId) -> Result<()> {
    vault.put_entity(&id, ENTITY_TYPE_PERSON, at(1), 1, b"person")
}

/// A person the backup does not hold, whom no decision reads anything about.
fn new_person(vault: &Vault) -> Result<()> {
    put_person(vault, entity(0xBF))
}

/// A relationship whose body lists no participants: only its edges name any.
fn put_relationship(vault: &Vault, id: EntityId) -> Result<()> {
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "participant_ids": [] }))
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    vault.put_entity(&id, ENTITY_TYPE_RELATIONSHIP, at(1), 1, &body)
}

/// A claim scoped to a relationship is read only by its participants. One
/// whose `participates_in` edge was taken off since the backup, the
/// relationship's body unchanged, is a participant a restore would put back.
pub(super) fn record_audiences() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (sora, rin) = (entity(0xB1), entity(0xB2));
    let relationship = entity(0xB3);
    put_person(&vault, sora)?;
    put_person(&vault, rin)?;
    put_relationship(&vault, relationship)?;
    for person in [sora, rin] {
        vault.put_edge(&person, EdgeKind::ParticipatesIn, &relationship, 1.0)?;
    }
    put_scoped_fact(&vault, entity(0xB4), sora, relationship)?;
    Case::after_backup("record audiences", (dir, vault), new_person, move |vault| {
        vault
            .delete_edge(&rin, EdgeKind::ParticipatesIn, &relationship)
            .map(drop)
    })
}

/// Puts claim `id` about `subject`, read only by `relationship`'s
/// participants.
fn put_scoped_fact(
    vault: &Vault,
    id: EntityId,
    subject: EntityId,
    relationship: EntityId,
) -> Result<()> {
    let mut fact = ClaimBody::new(
        "event.headcount",
        ClaimSubject::Entity(subject),
        Value::from("12"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    fact.rel = Some(relationship);
    vault.put_claim(&id, &fact, at(1), 1)
}

/// The record-audience row refuses only a loosening. Records deleted since
/// the backup, one kept as a shell and one purged, come back with the
/// restore; no record's audience reads them, so no answer changes and the
/// restore goes ahead.
#[test]
fn a_restore_over_records_deleted_since_the_backup_goes_ahead() -> Result<()> {
    let (dir, vault) = open_vault();
    let (sora, rin) = (entity(0xB1), entity(0xB2));
    let relationship = entity(0xB3);
    put_person(&vault, sora)?;
    put_person(&vault, rin)?;
    put_relationship(&vault, relationship)?;
    for person in [sora, rin] {
        vault.put_edge(&person, EdgeKind::ParticipatesIn, &relationship, 1.0)?;
    }
    let (kept, shell, purged) = (entity(0xB4), entity(0xB7), entity(0xB8));
    for id in [kept, shell, purged] {
        put_scoped_fact(&vault, id, sora, relationship)?;
    }
    let backups = tempfile::tempdir()?;
    let image = backups.path().join("backup");
    // Reopened so it holds the policy a restored copy's open seeds.
    let vault = crate::test_util::reopen_test_vault(&dir, vault);
    vault.snapshot_checkpoint(&image, 100)?;
    assert!(vault.delete_entity(&shell)?);
    vault.delete_entity_with_options(
        &purged,
        crate::deletion::DeleteEntityOptions { purge: true },
    )?;
    if let Err(error) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("restored"),
        vault.config.clone(),
        &vault,
        1_000,
    ) {
        panic!(
            "{error}{}",
            super::unread(&vault, &image, &backups.path().join("unguarded"))
        );
    }
    Ok(())
}

/// A voice session's roster as resolved from `segments`.
fn roster(segments: Vec<VoiceResolvedSegment>) -> VoiceSessionRosterV1 {
    VoiceSessionRosterV1 {
        voice_session_ref: "voice-session-1".to_owned(),
        recording_id: "recording-1".to_owned(),
        embedding_space_id: "space-1".to_owned(),
        known_threshold: 0.65,
        segments,
        created_at: 100,
    }
}

/// A roster that names no one leaves the owner alone in the session. One
/// resolved again since the backup with a stranger in it supervises the
/// owner's session, which a restore would leave unsupervised.
pub(super) fn disclosure_clamps() -> Result<Case> {
    let (dir, vault) = open_vault();
    put_voice_roster_for_test(&vault, &roster(Vec::new()))?;
    Case::after_backup("disclosure clamps", (dir, vault), new_person, |vault| {
        put_voice_roster_for_test(
            vault,
            &roster(vec![VoiceResolvedSegment {
                segment_id: "segment-1".to_owned(),
                start_ms: 0,
                end_ms: 1_000,
                speaker_label: "speaker 1".to_owned(),
                subject_ref: None,
                contact_ref: None,
                evidence: VoiceAttributionEvidence::ResidualCluster {
                    cluster_ref: "cluster-1".to_owned(),
                },
            }]),
        )
    })
}

/// A public claim of `predicate` about `subject`.
fn headcount(subject: EntityId, predicate: &str) -> Result<ClaimBody> {
    let mut fact = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from("12"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    fact.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    Ok(fact)
}

/// A public claim reaches a party the owner supervises; one whose predicate
/// is an affect reading is held to tier A. One restated as an affect
/// reading since the backup, its read scope unchanged, is one a restore
/// would disclose again.
pub(super) fn disclosure_tiers() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (subject, fact) = (entity(0xB7), entity(0xB8));
    put_person(&vault, subject)?;
    vault.put_claim(&fact, &headcount(subject, "event.headcount")?, at(1), 1)?;
    Case::after_backup("disclosure tiers", (dir, vault), new_person, move |vault| {
        vault.put_claim(&fact, &headcount(subject, "affect.headcount")?, at(1), 2)
    })
}

/// Installs `policy` as a policy manifest the vault folds in.
fn put_policy(vault: &Vault, id: EntityId, policy: &serde_json::Value) -> Result<()> {
    let bytes =
        rmp_serde::to_vec_named(policy).map_err(|error| Error::InvalidConfig(error.to_string()))?;
    crate::test_util::put_policy_manifest_bytes(vault, id, &bytes)
}

/// A false leader-chat rule on a shared ancestor stops its descendants'
/// leaders from opening a chat or speaking in one. A rule that reaches the
/// ancestor through its `claim_of` edge since the backup, its body
/// unchanged, is one a restore would lift.
pub(super) fn leader_chats() -> Result<Case> {
    let (dir, vault) = open_vault();
    let version = env!("CARGO_PKG_VERSION");
    put_policy(
        &vault,
        entity(0xC0),
        &serde_json::json!({
            "schema_version": "1.2", "pack_id": "leader-chat-fixture",
            "pack_version": "1", "min_engine_version": version,
            "defaults": {"criticality": "normal", "sensitivity": "normal"},
            "rules": [],
            "actor_ceilings": [{"actor_class": "first_party", "ceiling": "auto"}],
            "project_collaboration": {
                "leader_chat": {"default": "allow", "precedence": "nested_narrowing",
                                "holder_override_cap": "vault"},
                "cross_project_ask": {"fallback": "hold"}
            }
        }),
    )?;
    let root = vault.root_project()?;
    let (alice, bob) = (entity(0xC1), entity(0xC2));
    for person in [alice, bob] {
        put_person(&vault, person)?;
        crate::conversation_dag::fixtures::grant(
            &vault,
            WriteActor::new(person, EdgeActorClass::Human),
            true,
        );
    }
    let (first, second) = (entity(0xC3), entity(0xC4));
    vault.put_project(
        first,
        &ProjectRecord::new(first, Some(root), first, alice)?,
        2,
    )?;
    vault.put_project(
        second,
        &ProjectRecord::new(second, Some(root), second, bob)?,
        2,
    )?;
    vault.open_leader_chat(
        entity(0xC5),
        [first, second],
        WriteActor::new(alice, EdgeActorClass::Human),
        3,
    )?;
    let rule = entity(0xC6);
    let mut against = ClaimBody::new(
        LEADER_CHAT_RULE_PREDICATE,
        ClaimSubject::Entity(root),
        Value::Boolean(false),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    against.scope_project = root;
    vault.put_claim(&rule, &against, at(4), 4)?;
    vault.delete_edge(&rule, EdgeKind::ClaimOf, &root)?;
    Case::after_backup(
        "leader chat admissions",
        (dir, vault),
        new_person,
        move |vault| vault.put_edge(&rule, EdgeKind::ClaimOf, &root, 1.0),
    )
}

/// The read fold hides a signed project that replay replaced with an
/// unsigned row. One replaced since the backup, its authority fields
/// unchanged, is one a restore would show again.
pub(super) fn project_verdicts() -> Result<Case> {
    let (dir, vault) = open_vault();
    let root = vault.root_project()?;
    let parent = vault.project(root)?.ok_or(Error::EntityNotFound)?;
    let child = entity(0xC7);
    crate::workspace_roster::spawn_signed_project_for_test(
        &vault,
        root,
        child,
        EntityId::from_hex(&parent.leader)?,
        entity(0xC8),
        parent.slice,
        1,
    )?;
    Case::after_backup("project verdicts", (dir, vault), new_person, move |vault| {
        let mut unsigned = vault.project(child)?.ok_or(Error::EntityNotFound)?;
        unsigned.write_proof = None;
        let bytes = rmp_serde::to_vec_named(&unsigned)
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        vault
            .batch()
            .put_replicated(&child, vault.project_type_byte()?, at(2), 2, &bytes)
            .commit()
    })
}
