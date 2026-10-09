//! Census cases for who a read admits.
use super::Case;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::memory::MemoryError;
use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
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
    diary_entry(vault, author, 0x7a)
}

/// Entry `revision` of `author`'s diary, private to them.
fn diary_entry(vault: &Vault, author: EntityId, revision: u8) -> Result<EntityId> {
    let receipt = vault
        .memory(author, EdgeActorClass::Human)
        .author_note(&NoteWriteEnvelope {
            kind: NoteKind::Diary,
            scope: NoteScope::ActorPrivate { owner_ref: author },
            markdown: format!("a private entry {revision}"),
            source_revision_ref: [revision; 16],
            mask: None,
        })
        .map_err(memory)?;
    EntityId::from_hex(&receipt.id_hex)
}

/// A member binding lets its principal read the claims of the relationship
/// it is about, while that relationship is there. One purged since the
/// backup, its binding and its claims unchanged, is a relationship whose
/// claims a restore would open to the member again.
pub(super) fn relationship_reads() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (member, relationship) = (put_person(&vault, 0xC1)?, entity(0xC2));
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "participant_ids": [] }))
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    vault.put_entity(
        &relationship,
        ENTITY_TYPE_RELATIONSHIP,
        TimeRange { start: 1, end: 1 },
        1,
        &body,
    )?;
    crate::federation::bind_member_person(
        &vault,
        relationship,
        member,
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let mut fact = ClaimBody::new(
        "event.headcount",
        ClaimSubject::Entity(member),
        rmpv::Value::from("12"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    fact.rel = Some(relationship);
    vault.put_claim(&entity(0xC3), &fact, TimeRange { start: 1, end: 1 }, 1)?;
    Case::after_backup(
        "relationship reads",
        (dir, vault),
        |vault| put_person(vault, 0xC4).map(drop),
        move |vault| {
            vault
                .delete_entity_with_options(
                    &relationship,
                    crate::deletion::DeleteEntityOptions { purge: true },
                )
                .map(drop)
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
    // The policy the case installs holds a public write of a predicate it
    // does not class for the owner; the engine's own door writes it.
    let mut txn = vault.store.env.write_txn()?;
    vault.put_reserved_claim_in_txn(
        &mut txn,
        &claim,
        &body,
        TimeRange { start: at, end: at },
        at,
    )?;
    txn.commit()?;
    Ok(())
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

/// A graph read shows a diary link only where both authors granted that very
/// pair. Of three granted links between two authors' diaries, one taken away
/// since the backup leaves every diary readable through the other two, and
/// is one a restore would put back.
pub(super) fn diary_links() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (sora, rin) = (put_person(&vault, 0xC9)?, put_person(&vault, 0xCA)?);
    let (first, second) = (diary_entry(&vault, sora, 1)?, diary_entry(&vault, sora, 2)?);
    let (third, fourth) = (diary_entry(&vault, rin, 3)?, diary_entry(&vault, rin, 4)?);
    {
        let (author, reader) = (
            vault.memory(sora, EdgeActorClass::Human),
            vault.memory(rin, EdgeActorClass::Human),
        );
        for (own, other) in [(first, third), (first, fourth), (second, third)] {
            author.link_diary_coreference(own, other).map_err(memory)?;
            author.grant_diary_coreference(own, other).map_err(memory)?;
            reader.grant_diary_coreference(other, own).map_err(memory)?;
        }
    }
    let (sora_ref, rin_ref) = (sora.to_hex(), rin.to_hex());
    crate::test_util::authorize_readers(&vault, &[sora_ref.as_str(), rin_ref.as_str()]);
    let (left, right) = (first.min(third), first.max(third));
    Case::after_backup(
        "diary link reads",
        (dir, vault),
        move |vault| diary_entry(vault, sora, 5).map(drop),
        move |vault| vault.delete_edge(&left, EdgeKind::SameAs, &right).map(drop),
    )
}

/// A facet-scoped connector covers a turn by the facet its `FacetOf` stamp
/// names. That stamp taken off it since the backup, its body unchanged, is
/// one a restore would put back. (A live NOTE or ASSET keeps the stamp it was
/// born with: no door takes it off, #1322.)
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
    let turn = entity(0xCA);
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "role": "user" }))
        .map_err(|error| Error::InvalidConfig(error.to_string()))?;
    vault.put_entity(
        &turn,
        crate::registry::ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        &body,
    )?;
    vault.put_edge(&turn, EdgeKind::FacetOf, &facet, 1.0)?;
    Case::after_backup(
        "record positions",
        (dir, vault),
        move |vault| diary(vault, author).map(drop),
        move |vault| {
            vault
                .delete_edge(&turn, EdgeKind::FacetOf, &facet)
                .map(drop)
        },
    )
}
