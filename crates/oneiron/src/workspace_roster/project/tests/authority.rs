//! Leader and board authority over PROJECT rows: live doors refuse a bad
//! proof, replay stores it, and the read fold hides it with a reason.
use super::super::*;
use crate::authority::{CapabilitySlip, HostSlipIssuer, SlipCaveat};
use crate::error::ErrorKind;
#[cfg(feature = "sync")]
use crate::ports::EntityStoreRead;
use ed25519_dalek::Signer;

const FIXTURE_HOST: &[u8] = b"project fixture authority";

fn holder_key(actor: EntityId) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(blake3::hash(actor.as_bytes()).as_bytes())
}

/// Signs `body` as `holder` (the fixture host when `None`) over `anchor`.
/// A holder's slip narrows to `project.write` for `audience`.
pub(crate) fn sign_with(
    vault: &Vault,
    id: EntityId,
    body: &mut ProjectRecord,
    holder: Option<EntityId>,
    anchor: Option<ProjectAnchor>,
    expires_at: Option<u64>,
) -> Result<ProjectWriteProof> {
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = "host".into();
    if let Some(expires_at) = expires_at {
        claims.expires_at = expires_at;
        claims.ttl_secs = claims.ttl_secs.min(expires_at - claims.issued_at);
    }
    if let Some(actor) = holder {
        claims.holder_ref = actor.to_hex();
        claims.binding_key = holder_key(actor).verifying_key().to_bytes();
    }
    let mut slip = vault.mint_capability_slip(&issuer, claims)?;
    if let Some(actor) = holder {
        let audience = if anchor.is_some() {
            id
        } else {
            EntityId::from_hex(body.parents.first().ok_or_else(invalid)?)?
        };
        let mut scope = crate::federation::Scope::top();
        scope.audience = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
            crate::federation::ScopeId(audience),
        ]));
        scope.verbs = crate::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
            "project.write".into(),
        ]));
        slip.attenuate(
            SlipCaveat {
                scope: Some(scope),
                ..Default::default()
            },
            &holder_key(actor),
        )?;
    }
    let signed_at = slip.claims.issued_at;
    let anchor = anchor.map(Box::new);
    let challenge = body
        .authority()
        .write_challenge(id, signed_at, anchor.as_deref())?;
    let holder_signature = match holder {
        Some(actor) => holder_key(actor)
            .sign(&slip.binding_transcript(&challenge)?)
            .to_bytes()
            .to_vec(),
        None => issuer.binding_proof(&slip, &challenge)?,
    };
    let proof = ProjectWriteProof {
        slip_wire: slip.to_token()?,
        holder_signature,
        signed_at,
        anchor,
    };
    body.write_proof = Some(proof.clone());
    Ok(proof)
}

/// Signs the next revision of `id` over its visible current authority. The
/// owner (the fixture host) signs over an unsigned owner-door row and any
/// root widening; `actor` signs everything else.
pub(crate) fn sign_project(
    vault: &Vault,
    id: EntityId,
    body: &mut ProjectRecord,
    actor: EntityId,
) -> Result<ProjectWriteProof> {
    let prior = vault.project(id)?;
    let root = vault.root_project()?;
    let host = prior.as_ref().is_some_and(|prior| {
        (prior.write_proof.is_none() && id != root)
            || (id == root && prior.authority().board_action(&body.authority()))
    });
    let anchor = prior.as_ref().map(ProjectRecord::anchor);
    sign_with(vault, id, body, (!host).then_some(actor), anchor, None)
}

pub(crate) fn put_signed_project(
    vault: &Vault,
    id: EntityId,
    body: &mut ProjectRecord,
    actor: EntityId,
    now: u64,
) -> Result<()> {
    if !body.parents.is_empty()
        && vault.project(id)?.is_none()
        && !body.board.contains(&actor.to_hex())
    {
        body.board.push(actor.to_hex());
    }
    sign_project(vault, id, body, actor)?;
    vault.put_project(id, body, now)
}

/// The child body a spawn by `actor` under `parent_id` writes.
fn child_body(
    vault: &Vault,
    parent_id: EntityId,
    child_id: EntityId,
    actor: EntityId,
    leader: EntityId,
    slice: crate::llm::Scope,
) -> Result<ProjectRecord> {
    let parent = vault.project(parent_id)?.ok_or(Error::EntityNotFound)?;
    let mut body = ProjectRecord::new(
        child_id,
        Some(parent_id),
        EntityId::from_hex(&parent.claims_scope_ref)?,
        leader,
    )?;
    body.slice = slice;
    body.depth_limit = parent.depth_limit;
    body.depth_remaining = parent
        .depth_remaining
        .min(parent.depth_limit)
        .saturating_sub(1);
    body.board.push(actor.to_hex());
    Ok(body)
}

fn spawn_signed(
    vault: &Vault,
    parent_id: EntityId,
    child_id: EntityId,
    actor: EntityId,
    leader: EntityId,
    slice: crate::llm::Scope,
    now: u64,
) -> Result<ProjectRecord> {
    let mut body = child_body(vault, parent_id, child_id, actor, leader, slice.clone())?;
    let proof = sign_with(vault, child_id, &mut body, Some(actor), None, None)?;
    vault.spawn_subproject(parent_id, child_id, leader, slice, proof, now)
}

fn root_leader(vault: &Vault) -> Result<(EntityId, ProjectRecord, EntityId)> {
    let root_id = vault.root_project()?;
    let root = vault.project(root_id)?.ok_or(Error::EntityNotFound)?;
    let leader = EntityId::from_hex(&root.leader)?;
    Ok((root_id, root, leader))
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else if entry.file_type()?.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

#[cfg(feature = "sync")]
fn replay_project(vault: &Vault, id: EntityId, body: &ProjectRecord, at: u64) -> Result<()> {
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .put_replicated(
                &id,
                vault.project_type_byte()?,
                TimeRange { start: at, end: at },
                at,
                &encode(body)?,
            )
            .apply(txn)
    })
}

/// Replays stored rows of `from` into `to`, as the sync entity pass would.
#[cfg(feature = "sync")]
fn replay_rows(from: &Vault, to: &Vault, ids: &[EntityId]) -> Result<()> {
    for id in ids {
        let raw = {
            let txn = from.store.env.read_txn()?;
            from.store
                .port_entity_raw(&txn, id)?
                .ok_or(Error::EntityNotFound)?
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("replayed header"))?;
        to.with_write_txn(|txn| {
            to.batch_in()
                .put_replicated(
                    id,
                    header.entity_type,
                    TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                )
                .apply(txn)
        })?;
    }
    Ok(())
}

/// Replays every authority-log entry `to` lacks.
#[cfg(feature = "sync")]
fn replay_authority(from: &Vault, to: &Vault) -> Result<()> {
    let kind = crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
    let ids: Vec<EntityId> = {
        let txn = from.store.env.read_txn()?;
        from.store
            .port_entity_ids_by_type(&txn, kind, None)?
            .collect::<Result<_>>()?
    };
    let missing: Vec<EntityId> = {
        let txn = to.store.env.read_txn()?;
        let mut missing = Vec::new();
        for id in ids {
            if to.store.entities.get(&txn, id.as_bytes())?.is_none() {
                missing.push(id);
            }
        }
        missing
    };
    replay_rows(from, to, &missing)
}

#[cfg(feature = "sync")]
fn verdict_of(vault: &Vault, id: EntityId) -> Result<Option<ProjectVerdict>> {
    Ok(vault
        .quarantined_projects()?
        .into_iter()
        .find(|row| row.id == id)
        .map(|row| row.verdict))
}

#[test]
fn only_leader_spawns_with_narrower_slice_and_decremented_depth() -> Result<()> {
    use crate::llm::{Scope, ScopeResource};
    use std::collections::BTreeSet;

    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let (root_id, mut root, actor) = root_leader(&vault)?;
    let bucket = ScopeResource::Bucket {
        key: "allowed".into(),
    };
    let denied = ScopeResource::Bucket {
        key: "outside".into(),
    };
    root.slice.readable = BTreeSet::from([bucket.clone()]);
    put_signed_project(&vault, root_id, &mut root, actor, 1)?;

    let narrow = Scope {
        project: Some(EntityId::now()),
        readable: BTreeSet::from([bucket.clone()]),
        ..Scope::default()
    };
    let child_id = EntityId::now();
    let other_leader = EntityId::now();
    let child = spawn_signed(
        &vault,
        root_id,
        child_id,
        actor,
        other_leader,
        narrow.clone(),
        2,
    )?;
    assert_eq!(child.parents, vec![root_id.to_hex()]);
    assert_eq!(child.leader, other_leader.to_hex());
    assert_eq!(child.board, vec![actor.to_hex()]);
    assert_eq!(child.depth_remaining, root.depth_remaining - 1);
    let stored = vault.project(child_id)?.expect("visible child");
    assert_eq!(stored.authority(), child.authority());
    assert_eq!(
        vault
            .project_room(EntityId::from_hex(&child.home_room)?)?
            .unwrap()
            .member_ids,
        child.roster
    );

    // An occupied id is not an upsert: a second leader cannot replace this one.
    let error = vault
        .spawn_subproject(
            root_id,
            child_id,
            EntityId::now(),
            narrow.clone(),
            child.write_proof.clone().unwrap(),
            3,
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidProjectBody);
    assert_eq!(vault.project(child_id)?, Some(stored));
    // A non-leader holds a valid slip but is not the parent's leader.
    let error = spawn_signed(
        &vault,
        root_id,
        EntityId::now(),
        other_leader,
        other_leader,
        narrow.clone(),
        3,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidProjectBody);

    let mut wider = narrow;
    wider.readable.insert(denied);
    let rejected_id = EntityId::now();
    let error = vault
        .spawn_subproject(
            root_id,
            rejected_id,
            other_leader,
            wider.clone(),
            child.write_proof.unwrap(),
            3,
        )
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidProjectBody);
    assert!(vault.project(rejected_id)?.is_none());
    assert!(vault.project_room(home_room_id(rejected_id)?)?.is_none());

    // A signed spawn wider than its parent is refused at the direct and batch doors.
    let mut forged = child_body(&vault, root_id, rejected_id, actor, other_leader, wider)?;
    sign_with(&vault, rejected_id, &mut forged, Some(actor), None, None)?;
    assert_eq!(
        vault
            .put_project(rejected_id, &forged, 4)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidProjectBody
    );
    assert_eq!(
        vault
            .batch()
            .put(
                &rejected_id,
                vault.project_type_byte()?,
                TimeRange { start: 4, end: 4 },
                4,
                &encode(&forged)?
            )
            .commit()
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidProjectBody
    );
    assert!(vault.project(rejected_id)?.is_none());

    // Moving a parent inward cannot leave its live child wider.
    root = vault.project(root_id)?.unwrap();
    root.slice.readable.clear();
    sign_project(&vault, root_id, &mut root, actor)?;
    assert_eq!(
        vault.put_project(root_id, &root, 5).unwrap_err().kind(),
        ErrorKind::InvalidProjectBody
    );
    assert_eq!(
        vault.project(root_id)?.unwrap().slice.readable,
        BTreeSet::from([bucket])
    );
    Ok(())
}

#[test]
fn project_depth_is_bounded_by_its_row_and_zero_refuses_spawn() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let (root_id, mut root, actor) = root_leader(&vault)?;
    assert_eq!((root.depth_limit, root.depth_remaining), (10, 10));
    root.depth_limit = 1;
    root.depth_remaining = 1;
    put_signed_project(&vault, root_id, &mut root, actor, 1)?;
    let child_id = EntityId::now();
    let child = spawn_signed(
        &vault,
        root_id,
        child_id,
        actor,
        actor,
        root.slice.clone(),
        2,
    )?;
    assert_eq!(child.depth_remaining, 0);
    let grandchild_id = EntityId::now();
    let mut grandchild = child_body(
        &vault,
        child_id,
        grandchild_id,
        actor,
        actor,
        root.slice.clone(),
    )?;
    let proof = sign_with(
        &vault,
        grandchild_id,
        &mut grandchild,
        Some(actor),
        None,
        None,
    )?;
    let error = vault
        .spawn_subproject(child_id, grandchild_id, actor, root.slice.clone(), proof, 3)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidProjectBody);
    assert!(vault.project(grandchild_id)?.is_none());
    // Editing a signed field without a new signature breaks the proof.
    let mut too_deep = vault.project(child_id)?.unwrap();
    too_deep.depth_remaining = 1;
    assert_eq!(
        vault
            .put_project(child_id, &too_deep, 4)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidProjectBody
    );
    let mut too_deep = vault.project(root_id)?.unwrap();
    too_deep.depth_remaining = 2;
    assert_eq!(
        vault.put_project(root_id, &too_deep, 5).unwrap_err().kind(),
        ErrorKind::InvalidProjectBody
    );
    Ok(())
}

#[test]
fn a_forged_spawn_or_depth_restore_is_refused_live_and_hidden_after_replay() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let (root_id, root, leader) = root_leader(&vault)?;
    let child_id = EntityId::now();
    let outsider = EntityId::now();
    // The outsider holds a valid project.write slip, but leads no parent.
    let mut forged = child_body(
        &vault,
        root_id,
        child_id,
        outsider,
        leader,
        root.slice.clone(),
    )?;
    forged.depth_remaining = 9;
    sign_with(&vault, child_id, &mut forged, Some(outsider), None, None)?;
    assert_eq!(
        vault.put_project(child_id, &forged, 1).unwrap_err().kind(),
        ErrorKind::InvalidProjectBody
    );
    assert_eq!(
        vault
            .batch()
            .put(
                &child_id,
                vault.project_type_byte()?,
                TimeRange { start: 1, end: 1 },
                1,
                &encode(&forged)?,
            )
            .commit()
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidProjectBody
    );
    assert!(vault.project(child_id)?.is_none());

    let child = spawn_signed(&vault, root_id, child_id, leader, leader, root.slice, 2)?;
    let room = vault.project_room(home_room_id(child_id)?)?;
    assert!(room.is_some());
    let mut narrowed = vault.project(child_id)?.unwrap();
    narrowed.depth_remaining = 0;
    sign_project(&vault, child_id, &mut narrowed, leader)?;
    vault.put_project(child_id, &narrowed, 3)?;
    // The outsider signs a depth restore over the current authority.
    let mut restored = vault.project(child_id)?.unwrap();
    restored.depth_remaining = 9;
    let anchor = restored.anchor();
    sign_with(
        &vault,
        child_id,
        &mut restored,
        Some(outsider),
        Some(anchor),
        None,
    )?;
    for door in 0..2 {
        let result = if door == 0 {
            vault.put_project(child_id, &restored, 4)
        } else {
            vault
                .batch()
                .put(
                    &child_id,
                    vault.project_type_byte()?,
                    TimeRange { start: 4, end: 4 },
                    4,
                    &encode(&restored)?,
                )
                .commit()
        };
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidProjectBody);
        assert_eq!(vault.project(child_id)?.unwrap().depth_remaining, 0);
        assert_eq!(vault.project_room(home_room_id(child_id)?)?, room);
    }
    // The parent leader sits on the child's board: its proof may restore depth.
    let mut restored = vault.project(child_id)?.unwrap();
    restored.depth_remaining = 9;
    sign_project(&vault, child_id, &mut restored, leader)?;
    vault.put_project(child_id, &restored, 5)?;
    assert_eq!(vault.project(child_id)?.unwrap().depth_remaining, 9);
    assert_eq!(child.board, vec![leader.to_hex()]);
    // A signed body cannot be detached into a second root.
    let mut detached = vault.project(child_id)?.unwrap();
    detached.parents.clear();
    detached.depth_remaining = 10;
    sign_project(&vault, child_id, &mut detached, leader)?;
    assert_eq!(
        vault
            .put_project(child_id, &detached, 6)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidProjectBody
    );
    assert_eq!(vault.project(child_id)?.unwrap().depth_remaining, 9);

    #[cfg(feature = "sync")]
    {
        // Replay stores the forged rows (ARCH-0040 ONE-AUTHLOG-F2); the read fold hides them.
        let forged_id = EntityId::now();
        let mut forged = child_body(
            &vault,
            root_id,
            forged_id,
            outsider,
            leader,
            root_slice(&vault)?,
        )?;
        sign_with(&vault, forged_id, &mut forged, Some(outsider), None, None)?;
        replay_project(&vault, forged_id, &forged, 7)?;
        assert!(vault.project(forged_id)?.is_none());
        assert!(vault.project_room(home_room_id(forged_id)?)?.is_none());
        assert_eq!(
            verdict_of(&vault, forged_id)?,
            Some(ProjectVerdict::Quarantined(
                "project spawn needs parent leader slip"
            ))
        );
    }
    Ok(())
}

#[cfg(feature = "sync")]
fn root_slice(vault: &Vault) -> Result<crate::llm::Scope> {
    Ok(root_leader(vault)?.1.slice)
}

#[test]
fn leader_signed_spawn_verifies_from_a_copied_vault_without_the_issuer() -> Result<()> {
    let origin = tempfile::tempdir()?;
    let copy = tempfile::tempdir()?;
    let vault = Vault::open(origin.path(), crate::VaultConfig::default())?;
    let (root_id, root, actor) = root_leader(&vault)?;
    let child_id = EntityId::now();
    let mut child = child_body(&vault, root_id, child_id, actor, actor, root.slice)?;
    sign_with(&vault, child_id, &mut child, Some(actor), None, None)?;
    drop(vault);
    copy_tree(origin.path(), copy.path())?;
    let replica = Vault::open(copy.path(), crate::VaultConfig::default())?;
    assert_eq!(replica.root_project()?, root_id);
    replica.put_project(child_id, &child, 1)?;
    assert_eq!(
        replica.project(child_id)?.map(|row| row.authority()),
        Some(child.authority())
    );
    assert!(replica.project_room(home_room_id(child_id)?)?.is_some());
    let mut tampered = replica.project(child_id)?.unwrap();
    tampered.depth_remaining = 0;
    let error = replica.put_project(child_id, &tampered, 2).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidProjectBody);
    assert_eq!(replica.project(child_id)?.unwrap().depth_remaining, 9);
    Ok(())
}

#[test]
fn project_slice_entity_refs_cannot_publish_live_off_record_ids() -> Result<()> {
    use crate::llm::ScopeResource;
    use crate::off_record::OffRecordBackendClass;
    use crate::session_overlay::OverlayKeyspace;

    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let root_id = vault.root_project()?;
    let original = vault.project(root_id)?.unwrap();
    let room_id = EntityId::from_hex(&original.home_room)?;
    let original_room = vault.project_room(room_id)?;
    let tainted = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("project-slice-taint", OffRecordBackendClass::Local)?;
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(OverlayKeyspace::Entities, tainted.as_bytes(), b"overlay")?;
    segment.commit()?;
    for field in 0..6 {
        let mut body = original.clone();
        match field {
            0 => body.slice.world = Some(tainted),
            1 => body.slice.facet = Some(tainted),
            2 => body.slice.relationship = Some(tainted),
            3 => body.slice.project = Some(tainted),
            4 => {
                body.slice.readable.insert(ScopeResource::DocumentVersion {
                    document: tainted,
                    version: "rev".into(),
                });
            }
            _ => {
                body.slice.writable.insert(ScopeResource::DocumentVersion {
                    document: tainted,
                    version: "rev".into(),
                });
            }
        }
        let bytes = encode(&body)?;
        for door in 0..2 {
            let err = if door == 0 {
                vault.put_project(root_id, &body, 1).unwrap_err()
            } else {
                vault
                    .batch()
                    .put(
                        &root_id,
                        vault.project_type_byte()?,
                        TimeRange { start: 1, end: 1 },
                        1,
                        &bytes,
                    )
                    .commit()
                    .unwrap_err()
            };
            assert_eq!(
                err.kind(),
                ErrorKind::OffRecordTaintedBaseWrite,
                "field {field}, door {door}"
            );
            assert_eq!(vault.project(root_id)?, Some(original.clone()));
            assert_eq!(vault.project_room(room_id)?, original_room);
        }
    }
    session.close()?;
    Ok(())
}

/// Every entity-bearing position a signed proof carries meets the off-record
/// guard: slip scope, pact grant and pact bound worlds and facets, at the
/// typed, batch and replay doors.
#[test]
fn signed_proof_positions_cannot_hide_an_off_record_reference() -> Result<()> {
    use crate::federation::{FederationDirectionScope, ScopeAxis, ScopeId};
    use crate::off_record::OffRecordBackendClass;
    use crate::session_overlay::OverlayKeyspace;
    use std::collections::BTreeSet;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let id = vault.root_project()?;
    let before = vault.project(id)?.unwrap();
    let room = EntityId::from_hex(&before.home_room)?;
    let prior_room = vault.project_room(room)?;
    let overlay_id = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("project-slip-taint", OffRecordBackendClass::Local)?;
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(OverlayKeyspace::Entities, overlay_id.as_bytes(), b"overlay")?;
    segment.commit()?;
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let actor = EntityId::from_hex(&before.leader)?;
    let tainted = ScopeAxis::Some(BTreeSet::from([ScopeId(overlay_id)]));
    for position in 0..3 {
        let mut claims = root.claims.clone();
        claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
        claims.holder_ref = actor.to_hex();
        claims.binding_key = holder_key(actor).verifying_key().to_bytes();
        if position == 0 {
            claims.scope.worlds = tainted.clone();
        }
        let mut slip: CapabilitySlip = vault.mint_capability_slip(&issuer, claims)?;
        if position > 0 {
            let bound = FederationDirectionScope {
                worlds: if position == 1 {
                    tainted.clone()
                } else {
                    ScopeAxis::All
                },
                facets: if position == 2 {
                    tainted.clone()
                } else {
                    ScopeAxis::All
                },
                bands: ScopeAxis::All,
            };
            slip.attenuate(
                SlipCaveat {
                    pact: Some((EntityId::now(), bound)),
                    ..Default::default()
                },
                &holder_key(actor),
            )?;
        }
        let mut changed = before.clone();
        changed.write_proof = Some(ProjectWriteProof {
            slip_wire: slip.to_token()?,
            holder_signature: vec![0; 64],
            signed_at: slip.claims.issued_at,
            anchor: Some(Box::new(before.anchor())),
        });
        let bytes = encode(&changed)?;
        let mut doors: Vec<Result<()>> = vec![
            vault.put_project(id, &changed, 1),
            vault
                .batch()
                .put(
                    &id,
                    vault.project_type_byte()?,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &bytes,
                )
                .commit(),
        ];
        #[cfg(feature = "sync")]
        doors.push(vault.with_write_txn(|txn| {
            vault
                .batch_in()
                .put_replicated(
                    &id,
                    vault.project_type_byte()?,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &bytes,
                )
                .apply(txn)
        }));
        for (door, result) in doors.into_iter().enumerate() {
            assert_eq!(
                result.unwrap_err().kind(),
                ErrorKind::OffRecordTaintedBaseWrite,
                "position {position}, door {door}"
            );
        }
        assert_eq!(vault.project(id)?, Some(before.clone()));
        assert_eq!(vault.project_room(room)?, prior_room);
    }
    session.close()?;
    Ok(())
}

/// Acceptance: the fold judges slip expiry at the signed time, so a change
/// that syncs after its slip expired is accepted and visible. The live door
/// still judges a new signature at its own clock.
#[cfg(feature = "sync")]
#[test]
fn a_change_whose_slip_expired_before_it_synced_is_accepted_and_visible() -> Result<()> {
    let origin = tempfile::tempdir()?;
    let copy = tempfile::tempdir()?;
    let vault = Vault::open(origin.path(), crate::VaultConfig::default())?;
    let (root_id, root, leader) = root_leader(&vault)?;
    let issued = vault
        .ensure_host_root_slip(&HostSlipIssuer::from_secret(FIXTURE_HOST)?)?
        .claims
        .issued_at;
    let child_id = EntityId::now();
    let mut child = child_body(&vault, root_id, child_id, leader, leader, root.slice)?;
    sign_with(
        &vault,
        child_id,
        &mut child,
        Some(leader),
        None,
        Some(issued + 2),
    )?;
    drop(vault);
    copy_tree(origin.path(), copy.path())?;
    let replica = Vault::open(copy.path(), crate::VaultConfig::default())?;
    // Anchor the replica's monotonic authority clock, then let the slip age.
    replica.ensure_host_root_slip(&HostSlipIssuer::from_secret(FIXTURE_HOST)?)?;
    std::thread::sleep(std::time::Duration::from_secs(3));
    // The approval has expired: a live write with it is refused.
    assert_eq!(
        replica.put_project(child_id, &child, 3).unwrap_err().kind(),
        ErrorKind::InvalidProjectBody
    );
    // The same change arriving by sync was made while it was valid.
    replay_project(&replica, child_id, &child, 1)?;
    assert_eq!(
        replica.project(child_id)?.map(|row| row.authority()),
        Some(child.authority())
    );
    assert!(replica.quarantined_projects()?.is_empty());
    Ok(())
}

/// Acceptance: a leader's update that syncs before the project's birth is
/// stored, never refused for authority, and waits hidden until the birth's
/// authority arrives; then it is visible. The update carries its lineage, so
/// the birth revision itself never has to replay.
#[cfg(feature = "sync")]
#[test]
fn an_update_that_arrives_before_the_project_birth_becomes_visible_once_it_arrives() -> Result<()> {
    let origin = tempfile::tempdir()?;
    let copy = tempfile::tempdir()?;
    let vault = Vault::open(origin.path(), crate::VaultConfig::default())?;
    let (root_id, root, parent_leader) = root_leader(&vault)?;
    vault.ensure_host_root_slip(&HostSlipIssuer::from_secret(FIXTURE_HOST)?)?;
    drop(vault);
    copy_tree(origin.path(), copy.path())?;
    let vault = Vault::open(origin.path(), crate::VaultConfig::default())?;
    let replica = Vault::open(copy.path(), crate::VaultConfig::default())?;
    // A distinct child leader updates the child the parent leader spawned.
    let child_id = EntityId::now();
    let child_leader = EntityId::now();
    spawn_signed(
        &vault,
        root_id,
        child_id,
        parent_leader,
        child_leader,
        root.slice,
        1,
    )?;
    let mut update = vault.project(child_id)?.unwrap();
    update.depth_remaining = 3;
    update.roster.push(parent_leader.to_hex());
    sign_project(&vault, child_id, &mut update, child_leader)?;
    vault.put_project(child_id, &update, 2)?;
    let update = vault.project(child_id)?.unwrap();

    replay_project(&replica, child_id, &update, 2)?;
    assert!(replica.project(child_id)?.is_none());
    assert!(replica.project_room(home_room_id(child_id)?)?.is_none());
    assert!(matches!(
        verdict_of(&replica, child_id)?,
        Some(ProjectVerdict::Pending(_))
    ));
    // The birth and the update's slips arrive with the authority log.
    replay_authority(&vault, &replica)?;
    let visible = replica.project(child_id)?.expect("visible after the birth");
    assert_eq!(visible.authority(), update.authority());
    assert_eq!(visible.leader, child_leader.to_hex());
    assert!(replica.quarantined_projects()?.is_empty());
    Ok(())
}

/// Acceptance: an edit and a concurrent revoke of its slip reach the same
/// verdict on two devices that see them in opposite orders: revocations order
/// before concurrent events (federation:F-MERGE), and the row stays stored.
#[cfg(feature = "sync")]
#[test]
fn a_revoke_concurrent_with_an_edit_reaches_one_verdict_in_either_order() -> Result<()> {
    let origin = tempfile::tempdir()?;
    let (left_dir, right_dir) = (tempfile::tempdir()?, tempfile::tempdir()?);
    let vault = Vault::open(origin.path(), crate::VaultConfig::default())?;
    let (root_id, root, leader) = root_leader(&vault)?;
    let child_id = EntityId::now();
    spawn_signed(&vault, root_id, child_id, leader, leader, root.slice, 1)?;
    let mut edit = vault.project(child_id)?.unwrap();
    edit.depth_remaining = 2;
    let proof = sign_project(&vault, child_id, &mut edit, leader)?;
    let slip_id = CapabilitySlip::from_token(&proof.slip_wire)?.claims.slip_id;
    drop(vault);
    copy_tree(origin.path(), left_dir.path())?;
    copy_tree(origin.path(), right_dir.path())?;
    let left = Vault::open(left_dir.path(), crate::VaultConfig::default())?;
    let right = Vault::open(right_dir.path(), crate::VaultConfig::default())?;

    // Left edits first, then learns of the revoke.
    left.put_project(child_id, &edit, 2)?;
    assert!(left.project(child_id)?.is_some());
    // Right revokes first, then receives the edit.
    right.revoke_capability_slip(&HostSlipIssuer::from_secret(FIXTURE_HOST)?, slip_id)?;
    replay_authority(&right, &left)?;
    replay_project(&right, child_id, &edit, 2)?;

    for device in [&left, &right] {
        assert!(device.project(child_id)?.is_none());
        let hidden = device
            .quarantined_projects()?
            .into_iter()
            .find(|row| row.id == child_id)
            .expect("the edit stays in storage");
        assert_eq!(hidden.record.authority(), edit.authority());
        assert_eq!(
            hidden.verdict,
            ProjectVerdict::Quarantined("authorizing slip revoked")
        );
    }
    Ok(())
}

/// Acceptance: a non-leader's change arriving by sync is stored, hidden from
/// ordinary reads, and listed for the owner with its reason.
#[cfg(feature = "sync")]
#[test]
fn a_non_leader_change_by_sync_is_quarantined_not_dropped() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let (root_id, root, leader) = root_leader(&vault)?;
    let child_id = EntityId::now();
    let child_leader = EntityId::now();
    spawn_signed(
        &vault,
        root_id,
        child_id,
        leader,
        child_leader,
        root.slice,
        1,
    )?;
    let before = vault.project(child_id)?.unwrap();
    let outsider = EntityId::now();
    let mut takeover = before.clone();
    takeover.leader = outsider.to_hex();
    takeover.roster.push(outsider.to_hex());
    sign_with(
        &vault,
        child_id,
        &mut takeover,
        Some(outsider),
        Some(before.anchor()),
        None,
    )?;
    assert_eq!(
        vault
            .put_project(child_id, &takeover, 2)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidProjectBody
    );
    assert_eq!(vault.project(child_id)?, Some(before.clone()));

    replay_project(&vault, child_id, &takeover, 2)?;
    assert!(vault.project(child_id)?.is_none());
    let hidden = vault.quarantined_projects()?;
    assert_eq!(hidden.len(), 1);
    assert_eq!(hidden[0].id, child_id);
    assert_eq!(hidden[0].record.leader, outsider.to_hex());
    assert_eq!(
        hidden[0].verdict,
        ProjectVerdict::Quarantined("project widening needs board holder proof")
    );
    // The last authorized revision repairs the hidden row at the live door.
    vault.put_project(child_id, &before, 3)?;
    assert_eq!(vault.project(child_id)?, Some(before));
    assert!(vault.quarantined_projects()?.is_empty());
    Ok(())
}

/// Acceptance: every project read path goes through the read fold. Only the
/// write doors and the fold itself decode a stored PROJECT row.
#[test]
fn every_project_read_path_goes_through_the_read_fold() {
    use crate::test_util::source_scan::{SourceTree, mask_cfg_test_modules};
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let tree = SourceTree::read(&src);
    // Write doors judge a body before it lands; they read the stored row.
    let write_doors = [
        "workspace_roster/project/read.rs",
        "workspace_roster/project/proof.rs",
        "workspace_roster/project/projection.rs",
        "workspace_roster/project/deletion.rs",
        "workspace_roster/project/edges.rs",
        "workspace_roster/project/origin.rs",
        "workspace_roster/project/conversion.rs",
        "workspace_roster/project/mint.rs",
        "workspace_roster/project/goal/admission.rs",
        "workspace_roster/project/mod.rs",
        "batch/export/document_import.rs",
    ];
    let mut raw_reads = Vec::new();
    let mut fold_reads = 0;
    for (path, source) in tree.production_sources() {
        let rel = tree.relative(path);
        let source = mask_cfg_test_modules(source);
        for statement in source.split(';') {
            let decodes = statement.contains("record::<ProjectRecord>")
                || statement.contains("record::<super::super::ProjectRecord>")
                || (statement.contains("ProjectRecord")
                    && (statement.contains("from_slice") || statement.contains("record(")))
                || (statement.contains("project_type_byte()") && statement.contains("record("));
            if decodes && !write_doors.contains(&rel.as_str()) {
                raw_reads.push(rel.clone());
            }
            if statement.contains("visible_project_in_txn")
                || statement.contains("ProjectReader::new")
            {
                fold_reads += 1;
            }
        }
    }
    assert!(raw_reads.is_empty(), "raw PROJECT reads: {raw_reads:?}");
    // Rooms, leader chat, goals, weave report, docs corpus, spawn and the
    // public accessors all resolve projects through the fold.
    assert!(fold_reads >= 12, "fold reads: {fold_reads}");
}
