use super::*;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::{EntityId, Vault};

/// Exact immutable bytes to feed through either normal sync materializer.
pub(crate) fn contributions_for_test(
    vault: &Vault,
    project: EntityId,
) -> Result<Vec<(EntityId, Vec<u8>)>> {
    let txn = vault.store.env.read_txn()?;
    let mut result = Vec::new();
    for row in vault
        .store
        .type_index
        .prefix_iter(&txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = row?;
        let id = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("test project policy index"))?,
        )?;
        if !is_project_depth_id(&id) {
            continue;
        }
        let raw = vault
            .store
            .entities
            .get(&txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("test project policy body"))?;
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("test project policy header"))?;
        let decoded = decode_contribution(body)?;
        let target = match decoded {
            codec::ProjectDepthContribution::Default(_) => continue,
            codec::ProjectDepthContribution::DefaultEdit(ref edit)
                if project == codec::seeded_default_carrier()?.0 =>
            {
                &edit.project_ref
            }
            codec::ProjectDepthContribution::DefaultEdit(_) => continue,
            codec::ProjectDepthContribution::Birth(ref birth) => &birth.project_ref,
            codec::ProjectDepthContribution::Edit(ref edit) => &edit.project_ref,
        };
        if target == &project.to_hex() {
            result.push((id, body.to_vec()));
        }
    }
    Ok(result)
}

fn put_manifest_for_test(vault: &Vault, id: EntityId, body: &[u8], at: u64) -> Result<()> {
    vault.with_write_txn(|txn| {
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id,
                entity_type: ENTITY_TYPE_POLICY_MANIFEST,
                occurred: crate::TimeRange { start: at, end: at },
                learned_at: at,
                data: body.to_vec(),
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    })
}

fn owner(vault: &Vault, seed: u8) -> Result<crate::write_envelope::WriteActor> {
    let person = EntityId::now();
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let writer = crate::write_envelope::WriteActor::new(person, crate::edge::EdgeActorClass::Human);
    crate::subject_model::tests::authorization::root_owner(vault, writer, seed)?;
    Ok(writer)
}

fn project(vault: &Vault, parent: EntityId, project: EntityId) -> Result<()> {
    let leader = EntityId::from_hex(&vault.project(parent)?.ok_or(Error::EntityNotFound)?.leader)?;
    vault.put_project(
        project,
        &crate::workspace_roster::ProjectRecord::new(project, Some(parent), parent, leader),
        1,
    )
}

fn project_with_owner(
    vault: &Vault,
    parent: EntityId,
    id: EntityId,
    writer: &crate::write_envelope::WriteActor,
    seed: u8,
    at: u64,
) -> Result<()> {
    use ed25519_dalek::Signer;
    let leader = EntityId::from_hex(&vault.project(parent)?.ok_or(Error::EntityNotFound)?.leader)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    vault.create_project_with_owner(
        id,
        &crate::workspace_roster::ProjectRecord::new(id, Some(parent), parent, leader),
        writer,
        at,
        crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
        |message| Ok(signing.sign(message).to_bytes().to_vec()),
    )
}

#[test]
fn immutable_edits_merge_restrictively_and_causal_raise_supersedes_seen_heads() -> Result<()> {
    let _dir_a = tempfile::tempdir()?;
    let a = Vault::open(_dir_a.path(), crate::VaultConfig::default())?;
    let _dir_b = tempfile::tempdir()?;
    let b = Vault::open(_dir_b.path(), crate::VaultConfig::default())?;
    let root_a = a.root_project()?;
    let root_b = b.root_project()?;
    project(&a, root_a, EntityId::now())?; // control birth cannot poison the target
    project(&b, root_b, root_a)?;
    let id = EntityId::now();
    project(&a, root_a, id)?;
    project(&b, root_a, id)?;
    let author = owner(&a, 0xB8)?;
    b.put_entity(
        &author.entity_ref(),
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    b.import_signed_authority_history(&a.export_signed_authority_history()?)?;
    crate::workspace_roster::set_project_depth_signed_for_test(&a, id, 2, &author, 2, 0xB8)?;
    let a_fact = contributions_for_test(&a, id)?
        .into_iter()
        .find(|(_, body)| {
            matches!(
                decode_contribution(body).ok(),
                Some(codec::ProjectDepthContribution::Edit(_))
            )
        })
        .ok_or(Error::EntityNotFound)?;
    crate::workspace_roster::set_project_depth_signed_for_test(&b, id, 0, &author, 2, 0xB8)?;
    let b_fact = contributions_for_test(&b, id)?
        .into_iter()
        .find(|(_, body)| {
            matches!(
                decode_contribution(body).ok(),
                Some(codec::ProjectDepthContribution::Edit(_))
            )
        })
        .ok_or(Error::EntityNotFound)?;
    // Replaying the old stop or the same fact twice never removes any head.
    put_manifest_for_test(&a, b_fact.0, &b_fact.1, 3)?;
    put_manifest_for_test(&a, b_fact.0, &b_fact.1, 4)?;
    assert_eq!(a.project(id)?.unwrap().depth, 0);
    put_manifest_for_test(&a, a_fact.0, &a_fact.1, 4)?;
    assert_eq!(a.project(id)?.unwrap().depth, 0);
    crate::workspace_roster::set_project_depth_signed_for_test(&a, id, 12, &author, 5, 0xB8)?;
    assert_eq!(a.project(id)?.unwrap().depth, 12);
    put_manifest_for_test(&a, b_fact.0, &b_fact.1, 6)?;
    assert_eq!(a.project(id)?.unwrap().depth, 12);
    let saved = a.project(id)?.unwrap();
    let mut stale_member = saved.clone();
    stale_member.depth = 10;
    stale_member.roster.push(EntityId::now().to_hex());
    a.put_project(id, &stale_member, 7)?;
    assert_eq!(a.project(id)?.unwrap().depth, 12);
    assert_eq!(a.project(id)?.unwrap().roster, stale_member.roster);
    // A restriction B authored offline AFTER our raise, but without seeing
    // it, stays an unsuperseded concurrent head and narrows again.
    crate::workspace_roster::set_project_depth_signed_for_test(&b, id, 1, &author, 8, 0xB8)?;
    let new_stop = contributions_for_test(&b, id)?
        .into_iter()
        .find(|(fact, body)| {
            *fact != b_fact.0
                && matches!(
                    decode_contribution(body).ok(),
                    Some(codec::ProjectDepthContribution::Edit(_))
                )
        })
        .ok_or(Error::EntityNotFound)?;
    put_manifest_for_test(&a, new_stop.0, &new_stop.1, 9)?;
    assert_eq!(a.project(id)?.unwrap().depth, 1);
    Ok(())
}

#[test]
fn project_depth_creation_default_resolves_manifest_and_preserves_existing_births() -> Result<()> {
    use ed25519_dalek::Signer;
    let _dir = tempfile::tempdir()?;
    let vault = Vault::open(_dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let writer = owner(&vault, 0xBE)?;
    let old = EntityId::now();
    project_with_owner(&vault, root, old, &writer, 0xBE, 1)?;
    assert_eq!(vault.project(old)?.unwrap().depth, 10);
    let signer = ed25519_dalek::SigningKey::from_bytes(&[0xBE; 32]);
    let key = crate::authority::AuthorityKey::Ed25519(signer.verifying_key().to_bytes());
    vault.set_project_creation_depth_default(8, &writer, 2, key.clone(), |message| {
        Ok(signer.sign(message).to_bytes().to_vec())
    })?;
    let middle = EntityId::now();
    project_with_owner(&vault, root, middle, &writer, 0xBE, 4)?;
    assert_eq!(vault.project(middle)?.unwrap().depth, 8);
    vault.set_project_creation_depth_default(6, &writer, 3, key, |message| {
        Ok(signer.sign(message).to_bytes().to_vec())
    })?;
    let next = EntityId::now();
    project_with_owner(&vault, root, next, &writer, 0xBE, 5)?;
    assert_eq!(vault.project(next)?.unwrap().depth, 6);
    assert_eq!(vault.project(middle)?.unwrap().depth, 8);
    assert_eq!(vault.project(old)?.unwrap().depth, 10);
    assert_eq!(vault.project(root)?.unwrap().depth, 10);
    drop(vault);
    let reopened = Vault::open(_dir.path(), crate::VaultConfig::default())?;
    assert_eq!(reopened.project(old)?.unwrap().depth, 10);
    assert_eq!(reopened.project(middle)?.unwrap().depth, 8);
    assert_eq!(reopened.project(next)?.unwrap().depth, 6);
    Ok(())
}

#[test]
fn predecessor_and_owner_history_can_arrive_after_edits_without_widening() -> Result<()> {
    let _src_dir = tempfile::tempdir()?;
    let source = Vault::open(_src_dir.path(), crate::VaultConfig::default())?;
    let parent = source.root_project()?;
    let id = EntityId::now();
    let writer = owner(&source, 0xB9)?;
    project_with_owner(&source, parent, id, &writer, 0xB9, 1)?;
    let history = source.export_signed_authority_history()?;
    crate::workspace_roster::set_project_depth_signed_for_test(&source, id, 2, &writer, 2, 0xB9)?;
    crate::workspace_roster::set_project_depth_signed_for_test(&source, id, 12, &writer, 3, 0xB9)?;
    let entries = contributions_for_test(&source, id)?;
    let (birth, first, second) = {
        let mut birth = None;
        let mut first = None;
        let mut second = None;
        for (key, body) in &entries {
            match decode_contribution(body)? {
                codec::ProjectDepthContribution::Default(_)
                | codec::ProjectDepthContribution::DefaultEdit(_) => continue,
                codec::ProjectDepthContribution::Birth(_) => birth = Some((*key, body.clone())),
                codec::ProjectDepthContribution::Edit(edit) if edit.depth == 2 => {
                    first = Some((*key, body.clone()))
                }
                codec::ProjectDepthContribution::Edit(edit) if edit.depth == 12 => {
                    second = Some((*key, body.clone()))
                }
                _ => {
                    return Err(Error::InvalidConfig(
                        "unrecognized test contribution".into(),
                    ));
                }
            }
        }
        (
            birth.ok_or(Error::EntityNotFound)?,
            first.ok_or(Error::EntityNotFound)?,
            second.ok_or(Error::EntityNotFound)?,
        )
    };
    let _dst_dir = tempfile::tempdir()?;
    let target = Vault::open(_dst_dir.path(), crate::VaultConfig::default())?;
    let root_b = target.root_project()?;
    project(&target, root_b, parent)?;
    target.put_entity(
        &writer.entity_ref(),
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    target.import_signed_authority_history(&history[..1])?; // genesis, not BindActor
    put_manifest_for_test(&target, birth.0, &birth.1, 3)?;
    let leader = EntityId::from_hex(&target.project(parent)?.unwrap().leader)?;
    target.put_project(
        id,
        &crate::workspace_roster::ProjectRecord::new(id, Some(parent), parent, leader),
        3,
    )?;
    put_manifest_for_test(&target, second.0, &second.1, 4)?;
    assert_eq!(target.project(id)?.unwrap().depth, 0);
    put_manifest_for_test(&target, second.0, &second.1, 5)?; // retry drain, no loss
    assert_eq!(target.project(id)?.unwrap().depth, 0);
    target.import_signed_authority_history(&history[1..])?;
    assert_eq!(
        target.project(id)?.unwrap().depth,
        0,
        "missing predecessor still holds"
    );
    put_manifest_for_test(&target, first.0, &first.1, 6)?;
    assert_eq!(target.project(id)?.unwrap().depth, 12);
    let mut tampered = second.1.clone();
    tampered.push(0x01);
    assert_eq!(
        put_manifest_for_test(&target, second.0, &tampered, 7)
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert!(target.batch().delete(&second.0).commit().is_err());
    assert_eq!(target.project(id)?.unwrap().depth, 12);
    // First materialization can see edit rows before the birth, but nothing
    // becomes a permissive project without its immutable birth identity.
    let _fresh_dir = tempfile::tempdir()?;
    let fresh = Vault::open(_fresh_dir.path(), crate::VaultConfig::default())?;
    let fresh_root = fresh.root_project()?;
    project(&fresh, fresh_root, parent)?;
    fresh.put_entity(
        &writer.entity_ref(),
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    fresh.import_signed_authority_history(&history)?;
    put_manifest_for_test(&fresh, second.0, &second.1, 8)?;
    assert!(fresh.project(id)?.is_none());
    put_manifest_for_test(&fresh, first.0, &first.1, 9)?;
    put_manifest_for_test(&fresh, birth.0, &birth.1, 10)?;
    let lead = EntityId::from_hex(&fresh.project(parent)?.unwrap().leader)?;
    fresh.put_project(
        id,
        &crate::workspace_roster::ProjectRecord::new(id, Some(parent), parent, lead),
        11,
    )?;
    assert_eq!(fresh.project(id)?.unwrap().depth, 12);
    Ok(())
}

#[test]
fn revoked_edit_stays_non_authorizing_after_regrant_until_post_regrant_edit() -> Result<()> {
    use ed25519_dalek::Signer;
    let _dir = tempfile::tempdir()?;
    let vault = Vault::open(_dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let id = EntityId::now();
    let writer = owner(&vault, 0xBD)?;
    project_with_owner(&vault, root, id, &writer, 0xBD, 1)?;
    // `owner` created a live signed genesis and binding. Obtain the matching
    // signed revocation from the shared authority test fixture on a separate
    // first-party vault would create a second genesis, so reconstruct it from
    // this vault's current binding head with the same authority key.
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0xBD; 32]);
    let authority = vault.export_signed_authority_history()?;
    let bind: crate::authority::AuthorityLogEntry =
        crate::authority::decode_authority_log_entry_body(&authority[1])?;
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, id, 2, &writer, 2, 0xBD)?;
    assert_eq!(vault.project(id)?.unwrap().depth, 2);
    let mut revoke = crate::authority::AuthorityLogEntry {
        schema_version: bind.schema_version,
        vault_id: bind.vault_id,
        seq: 2,
        parent_hashes: vec![crate::authority::authority_entry_hash(&bind)?],
        op: crate::authority::AuthorityOp::RevokeActor {
            authority_key: bind.signer.public_key.clone(),
            epoch: 1,
        },
        signer: bind.signer.clone(),
        cosigns: Vec::new(),
        ts: 102,
    };
    revoke.signer.signature = signing
        .sign(&crate::authority::authority_transcript(&revoke)?)
        .to_bytes()
        .to_vec();
    vault.put_authority_log_entry(
        &revoke,
        crate::TimeRange {
            start: 102,
            end: 102,
        },
        102,
    )?;
    assert_eq!(vault.project(id)?.unwrap().depth, 0);
    let mut regrant = crate::authority::AuthorityLogEntry {
        schema_version: bind.schema_version,
        vault_id: bind.vault_id,
        seq: 3,
        parent_hashes: vec![crate::authority::authority_entry_hash(&revoke)?],
        op: crate::authority::AuthorityOp::BindActor {
            authority_key: bind.signer.public_key.clone(),
            actor_ref: writer.entity_ref(),
            actor_class: "human".into(),
            epoch: 2,
        },
        signer: bind.signer.clone(),
        cosigns: Vec::new(),
        ts: 103,
    };
    regrant.signer.signature = signing
        .sign(&crate::authority::authority_transcript(&regrant)?)
        .to_bytes()
        .to_vec();
    vault.put_authority_log_entry(
        &regrant,
        crate::TimeRange {
            start: 103,
            end: 103,
        },
        103,
    )?;
    assert_eq!(
        vault.project(id)?.unwrap().depth,
        0,
        "regrant cannot retroactively bless a pre-regrant edit"
    );
    assert!(
        crate::workspace_roster::set_project_depth_signed_for_test(
            &vault, id, 12, &writer, 4, 0xBD,
        )
        .is_err(),
        "stale writer frontier cannot borrow a regrant"
    );
    let current = vault.observed_write_actor(writer)?;
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, id, 12, &current, 5, 0xBD)?;
    assert_eq!(vault.project(id)?.unwrap().depth, 12);
    Ok(())
}

#[test]
fn unsigned_seed_birth_cannot_reset_an_owner_changed_creation_default() -> Result<()> {
    let _dir = tempfile::tempdir()?;
    let vault = Vault::open(_dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    let writer = owner(&vault, 0xBF)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0xBF; 32]);
    let key = crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    use ed25519_dalek::Signer;
    vault.set_project_creation_depth_default(8, &writer, 2, key, |message| {
        Ok(signing.sign(message).to_bytes().to_vec())
    })?;
    let project = EntityId::now();
    let (seed, seed_bytes) = codec::seeded_default_carrier()?;
    let forged = codec::ProjectDepthBirth {
        version: 1,
        project_ref: project.to_hex(),
        depth: 10,
        source_manifest: seed.to_hex(),
        source_hash: *blake3::hash(&seed_bytes).as_bytes(),
        owner: None,
    };
    let id = codec::birth_id(&forged)?;
    let body = codec::encode_contribution(&codec::ProjectDepthContribution::Birth(forged))?;
    // A hostile replicated birth cannot mint its own locally-trusted marker.
    #[cfg(feature = "sync")]
    assert_eq!(
        vault
            .with_write_txn(|txn| vault
                .batch_in()
                .put_replicated(
                    &id,
                    ENTITY_TYPE_POLICY_MANIFEST,
                    crate::TimeRange { start: 3, end: 3 },
                    3,
                    &body,
                )
                .apply(txn))
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    // Even an internal raw row that has the right content address cannot
    // turn this unsigned birth into a human-authorized project creation.
    put_manifest_for_test(&vault, id, &body, 3)?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    let record = crate::workspace_roster::ProjectRecord::new(project, Some(root), root, leader);
    assert_eq!(
        vault.put_project(project, &record, 4).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    assert!(vault.project(project)?.is_none());
    let signed_project = EntityId::now();
    project_with_owner(&vault, root, signed_project, &writer, 0xBF, 5)?;
    assert_eq!(vault.project(signed_project)?.unwrap().depth, 8);
    Ok(())
}

#[test]
fn signed_birth_cannot_use_an_orphan_default_edit_as_its_source() -> Result<()> {
    use ed25519_dalek::Signer;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = owner(&vault, 0xC4)?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0xC4; 32]);
    let key = crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let fold = vault.authority_fold()?;
    let frontier = *fold
        .actor_write_frontiers
        .get(&key)
        .and_then(|heads| heads.iter().next_back())
        .ok_or(Error::EntityNotFound)?;
    let default_id = codec::seeded_default_carrier()?.0;
    let mut orphan = codec::ProjectDepthEdit {
        version: 1,
        project_ref: default_id.to_hex(),
        depth: 8,
        vault_id: fold.vault_id.ok_or(Error::EntityNotFound)?,
        actor_ref: owner.entity_ref().to_hex(),
        frontier,
        predecessors: vec![EntityId::now().to_hex()], // valid shape, missing causal parent
        suite: "ed25519".into(),
        public_key: signing.verifying_key().to_bytes().to_vec(),
        signature: Vec::new(),
    };
    orphan.signature = signing
        .sign(&codec::edit_transcript(&orphan)?)
        .to_bytes()
        .to_vec();
    let orphan_id = codec::default_edit_id(&orphan)?;
    let orphan_body =
        codec::encode_contribution(&codec::ProjectDepthContribution::DefaultEdit(orphan))?;
    put_manifest_for_test(&vault, orphan_id, &orphan_body, 2)?;
    assert_eq!(
        super::fold::resolve_creation_default(
            &vault.store,
            &vault.store.env.read_txn()?,
            vault.privacy_posture(),
        )?
        .disposition,
        super::fold::ProjectDepthDisposition::Pending
    );

    let project = EntityId::now();
    let mut birth = codec::ProjectDepthBirth {
        version: 1,
        project_ref: project.to_hex(),
        depth: 8,
        source_manifest: orphan_id.to_hex(),
        source_hash: *blake3::hash(&orphan_body).as_bytes(),
        owner: Some(codec::ProjectBirthOwnerProof {
            vault_id: fold.vault_id.ok_or(Error::EntityNotFound)?,
            actor_ref: owner.entity_ref().to_hex(),
            frontier,
            suite: "ed25519".into(),
            public_key: signing.verifying_key().to_bytes().to_vec(),
            signature: Vec::new(),
        }),
    };
    let signature = signing
        .sign(&codec::birth_transcript(&birth)?)
        .to_bytes()
        .to_vec();
    birth.owner.as_mut().ok_or(Error::EntityNotFound)?.signature = signature;
    let birth_id = codec::birth_id(&birth)?;
    let body = codec::encode_contribution(&codec::ProjectDepthContribution::Birth(birth))?;
    put_manifest_for_test(&vault, birth_id, &body, 3)?;
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.unwrap().leader)?;
    vault.put_project(
        project,
        &crate::workspace_roster::ProjectRecord::new(project, Some(root), root, leader),
        4,
    )?;
    assert_eq!(
        vault.project(project)?.unwrap().depth,
        0,
        "cryptographic signatures do not turn an orphan default into authority"
    );
    let other = EntityId::now();
    assert!(
        vault
            .create_project_with_owner(
                other,
                &crate::workspace_roster::ProjectRecord::new(other, Some(root), root, leader,),
                &owner,
                5,
                key,
                |message| Ok(signing.sign(message).to_bytes().to_vec()),
            )
            .is_err()
    );
    Ok(())
}

/// A vault written before depth rows existed has project bodies without a
/// `depth` key and no birth rows. Those bodies still decode and pass the write
/// door, every project resolves the seeded default, and the projects stay
/// editable after the vault is owner-rooted. No backfill write is needed: the
/// implicit birth is the same on every replica.
#[test]
fn vault_written_before_depth_rows_upgrades_without_stored_births() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let child = EntityId::now();
    let root = {
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let root = vault.root_project()?;
        project(&vault, root, child)?;
        let kind = vault.project_type_byte()?;
        for id in [root, child] {
            let current = rmp_serde::to_vec_named(&vault.project(id)?.unwrap())
                .map_err(|_| Error::CorruptedIndex("test project body"))?;
            let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut current.as_slice())
                .map_err(|_| Error::CorruptedIndex("test project body"))?
            else {
                return Err(Error::CorruptedIndex("test project body"));
            };
            let mut legacy = Vec::new();
            rmpv::encode::write_value(
                &mut legacy,
                &rmpv::Value::Map(
                    entries
                        .into_iter()
                        .filter(|(key, _)| key.as_str() != Some("depth"))
                        .collect(),
                ),
            )
            .map_err(|_| Error::CorruptedIndex("test project body"))?;
            let decoded: crate::workspace_roster::ProjectRecord = rmp_serde::from_slice(&legacy)
                .map_err(|_| Error::CorruptedIndex("test project body"))?;
            assert_eq!(decoded.depth, 10);
            vault
                .batch()
                .put(&id, kind, crate::TimeRange { start: 2, end: 2 }, 2, &legacy)
                .commit()?;
        }
        root
    };
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.project(root)?.unwrap().depth, 10);
    assert_eq!(vault.project(child)?.unwrap().depth, 10);
    assert!(contributions_for_test(&vault, root)?.is_empty());
    assert!(contributions_for_test(&vault, child)?.is_empty());
    let writer = owner(&vault, 0xC8)?;
    let mut members = vault.project(child)?.unwrap();
    members.roster.push(EntityId::now().to_hex());
    vault.put_project(child, &members, 3)?;
    assert_eq!(vault.project(child)?.unwrap().roster, members.roster);
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, child, 2, &writer, 4, 0xC8)?;
    crate::workspace_roster::set_project_depth_signed_for_test(&vault, root, 3, &writer, 5, 0xC8)?;
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(reopened.project(child)?.unwrap().depth, 2);
    assert_eq!(reopened.project(root)?.unwrap().depth, 3);
    // A new project in the owner-rooted vault still needs a signed birth.
    let fresh = EntityId::now();
    let leader = EntityId::from_hex(&reopened.project(root)?.unwrap().leader)?;
    assert_eq!(
        reopened
            .put_project(
                fresh,
                &crate::workspace_roster::ProjectRecord::new(fresh, Some(root), root, leader),
                6,
            )
            .unwrap_err()
            .kind(),
        crate::error::ErrorKind::InvalidProjectBody
    );
    Ok(())
}

/// A malformed loaded policy manifest fails the project ceiling closed to 0;
/// it does not stop the vault from opening or seeding its root project.
#[test]
fn malformed_policy_fails_the_depth_ceiling_closed_without_bricking_open() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let id = crate::gate::default_policy_manifest_id()?;
    {
        let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::default())?;
        vault.with_write_txn(|txn| {
            vault
                .store
                .entities
                .put(txn, id.as_bytes(), &[ENTITY_TYPE_POLICY_MANIFEST])?;
            vault.store.type_index.put(
                txn,
                &crate::store::Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id),
                &[],
            )?;
            Ok(())
        })?;
    }
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root = vault.root_project()?;
    assert_eq!(vault.project(root)?.unwrap().depth, 0);
    let txn = vault.store.env.read_txn()?;
    assert_eq!(
        crate::gate::resolve_project_depth_max(&vault.store, &txn)?,
        0
    );
    Ok(())
}
