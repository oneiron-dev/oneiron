//! Census cases for who a read admits.
use super::Case;
use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::memory::MemoryError;
use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SUMMARY};
use crate::test_util::entity;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

fn memory(error: MemoryError) -> Error {
    Error::InvalidConfig(format!("{error:?}"))
}

fn put_person(vault: &Vault, seed: u8) -> Result<EntityId> {
    let person = entity(seed);
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    Ok(person)
}

/// A diary `author` writes, private to them, at the vault's default facet.
fn diary(vault: &Vault, author: EntityId) -> Result<EntityId> {
    let receipt = vault
        .memory(author, EdgeActorClass::Human)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: author },
            markdown: "a private entry".into(),
            source_revision_ref: [0x7a; 16],
            mask: None,
        })
        .map_err(memory)?;
    EntityId::from_hex(&receipt.id_hex)
}

/// Puts `summary` with the body `fields` describe.
fn put_summary(vault: &Vault, summary: EntityId, fields: serde_json::Value) -> Result<()> {
    let body = rmp_serde::to_vec_named(&fields).expect("summary body encodes");
    vault.put_entity(
        &summary,
        ENTITY_TYPE_SUMMARY,
        TimeRange { start: 1, end: 1 },
        1,
        &body,
    )
}

/// A summary its principal's grant on the summary's relationship lets them
/// read. Made private since the backup, its relationship unchanged, it is
/// one a restore would open to them again.
pub(super) fn relationship_reads() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (principal, space, summary) = (entity(0xC1), entity(0xC2), entity(0xC3));
    vault.create_access_grant(
        &entity(0xC4),
        &AccessGrant {
            principal_ref: principal,
            scope: AccessGrantScope::Summaries { space_ref: space },
            capability: AccessGrantCapability::SummariesRead,
            status: AccessGrantStatus::Active,
            created_at: 1,
            revoked_at: None,
            expires_at: None,
            authority_scope: crate::federation::scope_codec::read_preset(),
        },
    )?;
    let rel = space.to_hex();
    put_summary(
        &vault,
        summary,
        serde_json::json!({"rel": rel, "text": "first"}),
    )?;
    Case::after_backup(
        "relationship reads",
        (dir, vault),
        {
            let rel = rel.clone();
            move |vault: &Vault| {
                put_summary(
                    vault,
                    summary,
                    serde_json::json!({"rel": rel, "text": "restated"}),
                )
            }
        },
        move |vault| {
            put_summary(
                vault,
                summary,
                serde_json::json!({"rel": rel, "text": "restated", "scope": "private"}),
            )
        },
    )
}

/// Puts `claim`, saying `value` about `subject`, bound to `reader` as the
/// reader of a typed question when there is one.
fn put_fact(
    vault: &Vault,
    (claim, subject): (EntityId, EntityId),
    value: &str,
    reader: Option<&str>,
    at: u64,
) -> Result<()> {
    let mut body = ClaimBody::new(
        "test.read_grant",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.scope = reader.map(|reader| {
        rmpv::Value::Map(vec![(
            rmpv::Value::from("typed_question_principal"),
            rmpv::Value::from(reader),
        )])
    });
    vault.put_claim(&claim, &body, TimeRange { start: at, end: at }, at)
}

/// A claim the policy lets two readers read. Bound since the backup to one
/// of them as a typed question's reader, its read scope unchanged, it is one
/// a restore would hand back to the other.
pub(super) fn claim_grants() -> Result<Case> {
    let (dir, vault) = open_vault();
    let fact = (entity(0xC6), put_person(&vault, 0xC5)?);
    put_fact(&vault, fact, "first", None, 10)?;
    crate::test_util::authorize_readers(&vault, &["sora", "rin"]);
    Case::after_backup(
        "claim read grants",
        (dir, vault),
        move |vault| put_fact(vault, fact, "restated", None, 20),
        move |vault| put_fact(vault, fact, "restated", Some("rin"), 30),
    )
}

/// Two diaries their authors linked and both granted, so each author reads
/// the other's. The link taken away since the backup, both grants unchanged,
/// is one a restore would put back.
pub(super) fn note_reads() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (sora, rin) = (put_person(&vault, 0xC7)?, put_person(&vault, 0xC8)?);
    let (own, other) = (diary(&vault, sora)?, diary(&vault, rin)?);
    {
        let (author, reader) = (
            vault.memory(sora, EdgeActorClass::Human),
            vault.memory(rin, EdgeActorClass::Human),
        );
        author.link_diary_coreference(own, other).map_err(memory)?;
        author.grant_diary_coreference(own, other).map_err(memory)?;
        reader.grant_diary_coreference(other, own).map_err(memory)?;
    }
    let (sora_ref, rin_ref) = (sora.to_hex(), rin.to_hex());
    crate::test_util::authorize_readers(&vault, &[sora_ref.as_str(), rin_ref.as_str()]);
    let (left, right) = if own < other {
        (own, other)
    } else {
        (other, own)
    };
    Case::after_backup(
        "private note reads",
        (dir, vault),
        move |vault| diary(vault, sora).map(drop),
        move |vault| vault.delete_edge(&left, EdgeKind::SameAs, &right).map(drop),
    )
}

/// A note is read and selected at the facet its `FacetOf` edge names. That
/// edge taken off it since the backup, its body unchanged, is one a restore
/// would put back.
pub(super) fn record_positions() -> Result<Case> {
    let (dir, vault) = open_vault();
    let author = put_person(&vault, 0xC9)?;
    let note = diary(&vault, author)?;
    let facet = vault
        .edges_out(&note)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::FacetOf)
        .map(|edge| edge.target)
        .ok_or(Error::EntityNotFound)?;
    Case::after_backup(
        "record positions",
        (dir, vault),
        move |vault| diary(vault, author).map(drop),
        move |vault| {
            vault
                .delete_edge(&note, EdgeKind::FacetOf, &facet)
                .map(drop)
        },
    )
}
