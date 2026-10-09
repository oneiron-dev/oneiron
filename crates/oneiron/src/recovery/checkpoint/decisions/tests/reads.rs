//! Census cases for who a read admits.
use super::Case;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, PointRead,
    ScopedReadActorKey, decode_claim_body,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::federation::{ScopeAxis, ScopeId};
use crate::memory::MemoryError;
use crate::note::{NoteKind, NoteScope, NoteWriteEnvelope};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use crate::test_util::entity;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};
use std::collections::BTreeSet;

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

/// A claim a reader no policy grant names reads through the credential the
/// host minted it. Bound since the backup to another reader as a typed
/// question's reader, its read scope and the credential unchanged, it is one
/// a restore would hand back to the credential's holder.
pub(super) fn credential_backed_claim_reads() -> Result<Case> {
    let (dir, vault) = open_vault();
    let fact = (entity(0xC6), put_person(&vault, 0xC5)?);
    crate::test_util::authorize_readers(&vault, &[]);
    let holder = vault
        .ensure_host_root_slip(&crate::test_util::test_host_issuer())?
        .claims
        .holder_ref;
    put_fact(&vault, fact, "first", Some(holder.as_str()), 10)?;
    Case::after_backup(
        "verified slip claim reads",
        (dir, vault),
        move |vault| put_fact(vault, fact, "restated", Some(holder.as_str()), 20),
        move |vault| put_fact(vault, fact, "restated", Some("rin"), 30),
    )
}

/// The value of claim `id` `key` reads in `vault`; `None` where it reads
/// nothing.
fn read_value(vault: &Vault, key: ScopedReadActorKey, id: EntityId) -> Result<Option<String>> {
    let Some(row) = vault
        .scoped_read(key)
        .read(&[PointRead::id(id)], None)?
        .value
        .into_iter()
        .flatten()
        .next()
    else {
        return Ok(None);
    };
    let body = row.body.ok_or(Error::EntityNotFound)?;
    Ok(decode_claim_body(&body, true)?
        .value
        .as_str()
        .map(str::to_owned))
}

/// Astra R4-9. A reader no policy grant names reads a claim through its
/// verified slip alone; a plain key for the same reader reads nothing.
/// Restated since the backup, the claim reads through that slip in the
/// restored vault. Bound since to another typed question's reader, it no
/// longer reads, and the restore that would hand it back is refused. A
/// claim rebound between two readers whose only credential is held to
/// another world changes no reader's admission, so its restore goes ahead.
#[test]
fn a_restore_never_hands_a_rebound_claim_back_to_a_verified_slip() -> Result<()> {
    let (_dir, vault) = open_vault();
    let subject = put_person(&vault, 0xD1)?;
    let (fact, other) = ((entity(0xD2), subject), (entity(0xD3), subject));
    crate::test_util::authorize_readers(&vault, &[]);
    let issuer = crate::test_util::test_host_issuer();
    let root = vault.ensure_host_root_slip(&issuer)?;
    let proof = vault.verified_host_root_slip(&issuer)?;
    let holder = proof.claims().holder_ref.clone();
    let mut elsewhere = root.claims;
    elsewhere.slip_id = [0xD4; 32];
    elsewhere.holder_ref = "sora".to_owned();
    elsewhere.scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(entity(0xD5))]));
    let elsewhere = vault.mint_capability_slip(&issuer, elsewhere)?;
    let elsewhere = vault.verify_capability_slip(
        &issuer.public_key(),
        &elsewhere,
        b"elsewhere",
        &issuer.binding_proof(&elsewhere, b"elsewhere")?,
    )?;
    put_fact(&vault, fact, "first", Some(holder.as_str()), 10)?;
    put_fact(&vault, other, "first", Some("sora"), 10)?;
    let slip = ScopedReadActorKey::from_verified_slip(&proof).expect("read proof");
    let plain = ScopedReadActorKey::new(holder.clone()).expect("nonblank");
    let sora = ScopedReadActorKey::from_verified_slip(&elsewhere).expect("read proof");
    assert_eq!(read_value(&vault, plain, fact.0)?, None);
    assert_eq!(
        read_value(&vault, slip.clone(), fact.0)?.as_deref(),
        Some("first")
    );
    assert_eq!(read_value(&vault, sora, other.0)?, None);

    let backups = tempfile::tempdir()?;
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100)?;
    let restore = |name: &str| {
        Vault::restore_checkpoint_keeping_authority(
            &image,
            &backups.path().join(name),
            vault.config.clone(),
            &vault,
            1_000,
        )
    };
    put_fact(&vault, fact, "restated", Some(holder.as_str()), 20)?;
    put_fact(&vault, other, "restated", Some("rin"), 20)?;
    let restored = match restore("routine") {
        Ok((restored, _)) => restored,
        Err(error) => panic!(
            "{error}{}",
            super::unread(&vault, &image, &backups.path().join("unguarded"))
        ),
    };
    assert_eq!(
        read_value(&restored, slip.clone(), fact.0)?.as_deref(),
        Some("first")
    );
    drop(restored);

    put_fact(&vault, fact, "rebound", Some("rin"), 30)?;
    assert_eq!(read_value(&vault, slip, fact.0)?, None);
    let error = restore("rebound")
        .err()
        .expect("the restore must be refused");
    assert!(
        error.to_string().contains("verified slip claim reads"),
        "{error}"
    );
    Ok(())
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
