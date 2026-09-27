//! Transaction-bound project-policy birth and owner edit doors.
use crate::Vault;
use crate::authority::{ActorBindingStatus, AuthorityKey};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

use super::codec::{
    ProjectBirthOwnerProof, ProjectDepthBirth, ProjectDepthContribution, ProjectDepthEdit,
    birth_id, birth_transcript, edit_id, edit_transcript, encode_contribution,
};
use super::fold::{ProjectDepthDisposition, resolve_project_depth};

fn invalid() -> Error {
    Error::InvalidConfig("project depth requires an authenticated policy contribution".into())
}

fn put_contribution(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    value: &ProjectDepthContribution,
    now: u64,
) -> Result<()> {
    crate::batch::apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![crate::batch::BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_POLICY_MANIFEST,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: encode_contribution(value)?,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(())
}

/// Snapshot the governing immutable creation-default fact in a birth.
fn birth_from_policy(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
) -> Result<ProjectDepthBirth> {
    let (depth, _) =
        crate::gate::resolve_project_depth_config(&vault.store, txn, vault.privacy_posture())?;
    let default =
        super::fold::resolve_creation_default(&vault.store, txn, vault.privacy_posture())?;
    if default.disposition != ProjectDepthDisposition::Authorized {
        return Err(invalid());
    }
    let mut source = None;
    for id in default.frontier {
        let raw = vault
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or_else(invalid)?;
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?;
        let selected = match super::codec::decode_contribution(body)? {
            ProjectDepthContribution::Default(row) => row.depth,
            ProjectDepthContribution::DefaultEdit(row) => row.depth,
            _ => return Err(invalid()),
        };
        if selected == depth {
            source = Some((id, *blake3::hash(body).as_bytes()));
            break;
        }
    }
    let (source, source_hash) = source.ok_or_else(invalid)?;
    Ok(ProjectDepthBirth {
        version: 1,
        project_ref: project.to_hex(),
        depth,
        source_manifest: source.to_hex(),
        source_hash,
        owner: None,
    })
}

/// Root/bootstrap birth only. An owner-rooted vault creates new projects
/// through the signed `create_project_with_owner` door instead.
pub(crate) fn put_birth_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    now: u64,
) -> Result<(EntityId, u8)> {
    if vault
        .authority_fold_readonly_in_txn(txn)?
        .vault_id
        .is_some()
    {
        return Err(invalid());
    }
    let birth = birth_from_policy(vault, txn, project)?;
    let depth = birth.depth;
    let id = birth_id(&birth)?;
    put_contribution(vault, txn, id, &ProjectDepthContribution::Birth(birth), now)?;
    let body = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or_else(invalid)?;
    vault.store.sync_state.put(
        txn,
        &format!("project:birth:local:{}", id.to_hex()),
        blake3::hash(&body[ENTITY_METADATA_HEADER_LEN..]).as_bytes(),
    )?;
    Ok((id, depth))
}

pub(crate) fn put_signed_birth_in_txn<S>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    writer: &WriteActor,
    now: u64,
    signer_key: AuthorityKey,
    signer: S,
) -> Result<(EntityId, u8)>
where
    S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    vault.verify_owner_write_actor_in_txn(txn, writer)?;
    let mut birth = birth_from_policy(vault, txn, project)?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    let binding = fold.actor_bindings.get(&signer_key).ok_or_else(invalid)?;
    if binding.actor_ref != writer.entity_ref()
        || binding.actor_class != "human"
        || binding.status != ActorBindingStatus::Active
    {
        return Err(invalid());
    }
    let frontier = if let Some(frontier) = writer.authority_frontier() {
        frontier
    } else {
        *fold
            .actor_write_frontiers
            .get(&signer_key)
            .and_then(|set| set.iter().next_back())
            .ok_or_else(invalid)?
    };
    if !fold
        .actor_write_frontiers
        .get(&signer_key)
        .is_some_and(|set| set.contains(&frontier))
    {
        return Err(invalid());
    }
    let (suite, public_key) = match signer_key {
        AuthorityKey::Ed25519(key) => ("ed25519", key.to_vec()),
        AuthorityKey::P256(key) => ("p256", key),
    };
    birth.owner = Some(ProjectBirthOwnerProof {
        vault_id: fold.vault_id.ok_or_else(invalid)?,
        actor_ref: writer.entity_ref().to_hex(),
        frontier,
        suite: suite.into(),
        public_key,
        signature: Vec::new(),
    });
    let signature = signer(&birth_transcript(&birth)?)?;
    birth.owner.as_mut().ok_or_else(invalid)?.signature = signature;
    let depth = birth.depth;
    let id = birth_id(&birth)?;
    put_contribution(vault, txn, id, &ProjectDepthContribution::Birth(birth), now)?;
    Ok((id, depth))
}

pub(crate) fn put_edit_in_txn<S>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    depth: u8,
    writer: &WriteActor,
    now: u64,
    signer_key: AuthorityKey,
    signer: S,
) -> Result<()>
where
    S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    vault.verify_owner_write_actor_in_txn(txn, writer)?;
    let maximum = crate::gate::resolve_project_depth_max(&vault.store, txn)?;
    if depth > maximum {
        return Err(invalid());
    }
    let resolved = resolve_project_depth(&vault.store, txn, vault.privacy_posture(), project)?;
    if resolved.disposition == ProjectDepthDisposition::Pending || resolved.frontier.is_empty() {
        return Err(invalid());
    }
    let edit = signed_edit(
        vault,
        txn,
        project,
        depth,
        &resolved.frontier,
        writer,
        signer_key,
        signer,
    )?;
    let id = edit_id(&edit)?;
    put_contribution(vault, txn, id, &ProjectDepthContribution::Edit(edit), now)?;
    Ok(())
}

fn signed_edit<S>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
    depth: u8,
    heads: &[EntityId],
    writer: &WriteActor,
    signer_key: AuthorityKey,
    signer: S,
) -> Result<ProjectDepthEdit>
where
    S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    let authority = vault.authority_fold_readonly_in_txn(txn)?;
    let binding = authority
        .actor_bindings
        .get(&signer_key)
        .ok_or_else(invalid)?;
    if binding.actor_ref != writer.entity_ref()
        || binding.actor_class != "human"
        || binding.status != ActorBindingStatus::Active
    {
        return Err(invalid());
    }
    // The chosen signing key, not another binding of the same human, supplies
    // the causal frontier. A post-regrant edit must observe the regrant.
    let frontier = if let Some(frontier) = writer.authority_frontier() {
        frontier
    } else {
        *authority
            .actor_write_frontiers
            .get(&signer_key)
            .and_then(|frontiers| frontiers.iter().next_back())
            .ok_or_else(invalid)?
    };
    if !authority
        .actor_write_frontiers
        .get(&signer_key)
        .is_some_and(|set| set.contains(&frontier))
    {
        return Err(invalid());
    }
    let (suite, public_key) = match &signer_key {
        AuthorityKey::Ed25519(key) => ("ed25519", key.to_vec()),
        AuthorityKey::P256(key) => ("p256", key.clone()),
    };
    let mut predecessors: Vec<_> = heads.iter().map(EntityId::to_hex).collect();
    predecessors.sort();
    predecessors.dedup();
    let mut edit = ProjectDepthEdit {
        version: 1,
        project_ref: subject.to_hex(),
        depth,
        vault_id: authority.vault_id.ok_or_else(invalid)?,
        actor_ref: writer.entity_ref().to_hex(),
        frontier,
        predecessors,
        suite: suite.into(),
        public_key,
        signature: Vec::new(),
    };
    edit.signature = signer(&edit_transcript(&edit)?)?;
    Ok(edit)
}

pub(crate) fn put_default_edit_in_txn<S>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    depth: u8,
    writer: &WriteActor,
    now: u64,
    signer_key: AuthorityKey,
    signer: S,
) -> Result<()>
where
    S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
    vault.verify_owner_write_actor_in_txn(txn, writer)?;
    let maximum = crate::gate::resolve_project_depth_max(&vault.store, txn)?;
    if depth > maximum {
        return Err(invalid());
    }
    let resolved =
        super::fold::resolve_creation_default(&vault.store, txn, vault.privacy_posture())?;
    if resolved.disposition == ProjectDepthDisposition::Pending || resolved.frontier.is_empty() {
        return Err(invalid());
    }
    let subject = super::codec::seeded_default_carrier()?.0;
    let edit = signed_edit(
        vault,
        txn,
        subject,
        depth,
        &resolved.frontier,
        writer,
        signer_key,
        signer,
    )?;
    let id = super::codec::default_edit_id(&edit)?;
    put_contribution(
        vault,
        txn,
        id,
        &ProjectDepthContribution::DefaultEdit(edit),
        now,
    )
}

impl Vault {
    /// Owner-authored immutable creation-default policy contribution. Existing
    /// project births retain their original, separately keyed source fact.
    pub fn set_project_creation_depth_default<S>(
        &self,
        depth: u8,
        authenticated_owner: &WriteActor,
        now: u64,
        signer_key: AuthorityKey,
        signer: S,
    ) -> Result<()>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        self.with_write_txn(|txn| {
            put_default_edit_in_txn(
                self,
                txn,
                depth,
                authenticated_owner,
                now,
                signer_key,
                signer,
            )
        })
    }
}
