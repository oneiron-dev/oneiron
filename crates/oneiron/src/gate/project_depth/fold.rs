//! Read-snapshot causal head fold for independently keyed project-depth policy facts.
use std::collections::{BTreeMap, BTreeSet};

use crate::HostingPrivacyPosture;
use crate::authority::{ActorBindingStatus, AuthorityKey, CausalWriteDisposition};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;

use super::codec::{
    ProjectDepthBirth, ProjectDepthContribution, ProjectDepthEdit, decode_contribution,
    is_project_depth_id,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectDepthDisposition {
    Authorized,
    Pending,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectDepthResolution {
    pub(crate) depth: u8,
    pub(crate) frontier: Vec<EntityId>,
    pub(crate) disposition: ProjectDepthDisposition,
}

fn unresolved(disposition: ProjectDepthDisposition) -> ProjectDepthResolution {
    ProjectDepthResolution {
        depth: 0,
        frontier: Vec::new(),
        disposition,
    }
}

/// An immutable default source must itself be a causally anchored policy
/// chain. Verifying only its signature would let a forged orphan default fact
/// act as the birth source while the real default fold is still pending.
fn default_source_disposition(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    source: EntityId,
) -> Result<ProjectDepthDisposition> {
    let seed_id = super::codec::seeded_default_carrier()?.0;
    let authority =
        crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    let mut stack = vec![source];
    let mut visited = BTreeSet::new();
    let mut anchored = false;
    let mut pending = false;
    let mut quarantined = false;
    while let Some(next) = stack.pop() {
        if !visited.insert(next) {
            continue;
        }
        if visited.len() > 4096 {
            return Ok(ProjectDepthDisposition::Quarantined);
        }
        if next == seed_id {
            anchored = true;
            continue;
        }
        let Some(raw) = store.entities.get(txn, next.as_bytes())? else {
            pending = true;
            continue;
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_POLICY_MANIFEST)
        {
            quarantined = true;
            continue;
        }
        let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
            quarantined = true;
            continue;
        };
        let ProjectDepthContribution::DefaultEdit(edit) = decode_contribution(body)? else {
            quarantined = true;
            continue;
        };
        for predecessor in &edit.predecessors {
            let parent = EntityId::from_hex(predecessor)?;
            if parent == next {
                quarantined = true;
            } else {
                stack.push(parent);
            }
        }
        match edit_disposition(&edit, &authority)? {
            ProjectDepthDisposition::Authorized => {}
            ProjectDepthDisposition::Pending => pending = true,
            ProjectDepthDisposition::Quarantined => quarantined = true,
        }
    }
    if pending {
        Ok(ProjectDepthDisposition::Pending)
    } else if quarantined || !anchored {
        Ok(ProjectDepthDisposition::Quarantined)
    } else {
        Ok(ProjectDepthDisposition::Authorized)
    }
}

fn birth_disposition(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    birth: &ProjectDepthBirth,
) -> Result<ProjectDepthDisposition> {
    let source = EntityId::from_hex(&birth.source_manifest)?;
    let (seed_id, seed_body) = super::codec::seeded_default_carrier()?;
    let source_status = if source == seed_id {
        if *blake3::hash(&seed_body).as_bytes() == birth.source_hash
            && birth.depth == super::codec::seeded_default().depth
        {
            ProjectDepthDisposition::Authorized
        } else {
            ProjectDepthDisposition::Quarantined
        }
    } else {
        let Some(raw) = store.entities.get(txn, source.as_bytes())? else {
            return Ok(ProjectDepthDisposition::Pending);
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != ENTITY_TYPE_POLICY_MANIFEST)
        {
            return Ok(ProjectDepthDisposition::Quarantined);
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if *blake3::hash(body).as_bytes() != birth.source_hash {
            return Ok(ProjectDepthDisposition::Quarantined);
        }
        match decode_contribution(body)? {
            ProjectDepthContribution::DefaultEdit(row) if row.depth == birth.depth => {
                default_source_disposition(store, txn, posture, source)?
            }
            _ => ProjectDepthDisposition::Quarantined,
        }
    };
    if source_status != ProjectDepthDisposition::Authorized {
        return Ok(source_status);
    }
    if let Some(proof) = &birth.owner {
        // The birth transcript's signature was verified at its immutable put
        // door. Its signer/frontier use the very same live causal classifier
        // as an owner's subsequent depth edit, not receiver-local timestamps.
        let signer = ProjectDepthEdit {
            version: birth.version,
            project_ref: birth.project_ref.clone(),
            depth: birth.depth,
            vault_id: proof.vault_id,
            actor_ref: proof.actor_ref.clone(),
            frontier: proof.frontier,
            predecessors: vec![birth.source_manifest.clone()],
            suite: proof.suite.clone(),
            public_key: proof.public_key.clone(),
            signature: proof.signature.clone(),
        };
        let fold = crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
        return edit_disposition(&signer, &fold);
    }
    Ok(if unsigned_birth_trusted(store, txn, posture, birth)? {
        ProjectDepthDisposition::Authorized
    } else {
        ProjectDepthDisposition::Quarantined
    })
}

/// How the creation of a project with no signed write proof is authorized:
/// its stored owner birth, or the implicit seeded birth where that applies.
pub(crate) fn birth_authorization(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    project: EntityId,
) -> Result<ProjectDepthDisposition> {
    match birth_for_project(store, txn, project)? {
        Some((_, birth)) => birth_disposition(store, txn, posture, &birth),
        None if implicit_birth_applies(store, txn, posture, project)? => {
            Ok(ProjectDepthDisposition::Authorized)
        }
        None => Ok(ProjectDepthDisposition::Pending),
    }
}

/// A vault with no authority root has no signer to require.
fn vault_is_unrooted(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
) -> Result<bool> {
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    Ok(fold.vault_id.is_none() && !fold.vault_root_is_conflicted())
}

/// This replica knew the project before births were signed: its row is
/// stored here, or an authorized owner edit already builds on its implicit
/// birth (so delete and recreate keep the owner's row).
fn predates_signed_birth(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    project: EntityId,
) -> Result<bool> {
    if crate::workspace_roster::is_project_entity(store, txn, project)? {
        return Ok(true);
    }
    let implicit = super::codec::birth_id(&super::codec::canonical_birth(project)?)?.to_hex();
    let project_ref = project.to_hex();
    let mut anchored = Vec::new();
    for row in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = row?;
        let id = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("project-depth type index"))?,
        )?;
        if !is_project_depth_id(&id) {
            continue;
        }
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("project-depth manifest missing"))?;
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("project-depth header"))?;
        if let ProjectDepthContribution::Edit(edit) = decode_contribution(body)?
            && edit.project_ref == project_ref
            && edit.predecessors.contains(&implicit)
        {
            anchored.push(edit);
        }
    }
    if anchored.is_empty() {
        return Ok(false);
    }
    let authority =
        crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    for edit in &anchored {
        if edit_disposition(edit, &authority)? == ProjectDepthDisposition::Authorized {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A project with no stored birth is born from the seeded default when it is
/// the vault root, when the vault has no authority root, or when this replica
/// knew it before births were signed. Anything else waits for its stored
/// birth.
pub(crate) fn implicit_birth_applies(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    project: EntityId,
) -> Result<bool> {
    Ok(store.vault_meta.get(txn, b"project.root.v1")?.as_deref()
        == Some(project.as_bytes().as_slice())
        || vault_is_unrooted(store, txn, posture)?
        || predates_signed_birth(store, txn, posture, project)?)
}

/// The same rule for a stored UNSIGNED birth, plus a birth this replica wrote
/// itself. A peer cannot mint a trusted unsigned birth for a new project in
/// an owner-rooted vault.
pub(crate) fn unsigned_birth_trusted(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    birth: &ProjectDepthBirth,
) -> Result<bool> {
    let exact = super::codec::encode_contribution(&ProjectDepthContribution::Birth(birth.clone()))?;
    let local_key = format!(
        "project:birth:local:{}",
        super::codec::birth_id(birth)?.to_hex()
    );
    if store
        .sync_state
        .get(txn, &local_key)?
        .is_some_and(|hash| hash.as_ref() == blake3::hash(&exact).as_bytes())
    {
        return Ok(true);
    }
    let project = EntityId::from_hex(&birth.project_ref)?;
    if store.vault_meta.get(txn, b"project.root.v1")?.as_deref()
        == Some(project.as_bytes().as_slice())
        || vault_is_unrooted(store, txn, posture)?
    {
        return Ok(true);
    }
    Ok(*birth == super::codec::canonical_birth(project)?
        && predates_signed_birth(store, txn, posture, project)?)
}

fn edit_disposition(
    edit: &ProjectDepthEdit,
    fold: &crate::authority::AuthorityFold,
) -> Result<ProjectDepthDisposition> {
    if fold.vault_root_is_conflicted() || fold.vault_id.is_some_and(|id| id != edit.vault_id) {
        return Ok(ProjectDepthDisposition::Quarantined);
    }
    let key = match edit.suite.as_str() {
        "ed25519" => AuthorityKey::Ed25519(
            edit.public_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        ),
        "p256" => AuthorityKey::P256(edit.public_key.clone()),
        _ => return Ok(ProjectDepthDisposition::Quarantined),
    };
    let Some(binding) = fold.actor_bindings.get(&key) else {
        return Ok(ProjectDepthDisposition::Pending);
    };
    let actor = EntityId::from_hex(&edit.actor_ref)?;
    if binding.actor_ref != actor
        || binding.actor_class != "human"
        || binding.status != ActorBindingStatus::Active
    {
        return Ok(ProjectDepthDisposition::Quarantined);
    }
    if !fold.valid_entries.contains(&edit.frontier) {
        return Ok(ProjectDepthDisposition::Pending);
    }
    if !fold
        .actor_write_frontiers
        .get(&key)
        .is_some_and(|frontiers| frontiers.contains(&edit.frontier))
        || fold.actor_write_disposition(&actor, "human", Some(edit.frontier))
            != CausalWriteDisposition::Admitted
    {
        return Ok(ProjectDepthDisposition::Quarantined);
    }
    Ok(ProjectDepthDisposition::Authorized)
}

/// Restrictive fold over the seeded creation row and signed vault-default
/// overrides. A birth pins the selected immutable head, so later default
/// changes cannot rewrite an already-created project's provenance.
pub(crate) fn resolve_creation_default(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
) -> Result<ProjectDepthResolution> {
    let seed_id = super::codec::seeded_default_carrier()?.0;
    let mut rows = BTreeMap::new();
    rows.insert(seed_id, super::codec::seeded_default().depth);
    let mut edits = BTreeMap::new();
    for row in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = row?;
        let id = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("default depth index"))?,
        )?;
        if !is_project_depth_id(&id) || id == seed_id {
            continue;
        }
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("default depth row"))?;
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("default depth body"))?;
        if let ProjectDepthContribution::DefaultEdit(edit) = decode_contribution(body)? {
            if edits.len() >= 4096 {
                return Ok(unresolved(ProjectDepthDisposition::Quarantined));
            }
            rows.insert(id, edit.depth);
            edits.insert(id, edit);
        }
    }
    let mut shadowed = BTreeSet::new();
    for edit in edits.values() {
        for predecessor in &edit.predecessors {
            let parent = EntityId::from_hex(predecessor)?;
            if rows.contains_key(&parent) {
                shadowed.insert(parent);
            }
        }
    }
    let frontier: Vec<_> = rows
        .keys()
        .filter(|id| !shadowed.contains(id))
        .copied()
        .collect();
    if frontier.is_empty() {
        return Ok(unresolved(ProjectDepthDisposition::Quarantined));
    }
    let authority =
        crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    let mut pending = false;
    let mut quarantined = false;
    for id in &frontier {
        let mut stack = vec![*id];
        let mut seen = BTreeSet::new();
        let mut anchored = false;
        while let Some(next) = stack.pop() {
            if !seen.insert(next) {
                continue;
            }
            if next == seed_id {
                anchored = true;
                continue;
            }
            match edits.get(&next) {
                Some(edit) => {
                    for predecessor in &edit.predecessors {
                        let parent = EntityId::from_hex(predecessor)?;
                        if parent == next {
                            quarantined = true;
                        } else if rows.contains_key(&parent) {
                            stack.push(parent);
                        } else {
                            pending = true;
                        }
                    }
                }
                None => pending = true,
            }
        }
        if !anchored && !pending {
            quarantined = true;
        }
        if let Some(edit) = edits.get(id) {
            match edit_disposition(edit, &authority)? {
                ProjectDepthDisposition::Authorized => {}
                ProjectDepthDisposition::Pending => pending = true,
                ProjectDepthDisposition::Quarantined => quarantined = true,
            }
        }
    }
    if pending {
        return Ok(ProjectDepthResolution {
            depth: 0,
            frontier,
            disposition: ProjectDepthDisposition::Pending,
        });
    }
    if quarantined {
        return Ok(ProjectDepthResolution {
            depth: 0,
            frontier,
            disposition: ProjectDepthDisposition::Quarantined,
        });
    }
    let depth = frontier
        .iter()
        .filter_map(|id| rows.get(id))
        .copied()
        .min()
        .unwrap_or(0);
    Ok(ProjectDepthResolution {
        depth,
        frontier,
        disposition: ProjectDepthDisposition::Authorized,
    })
}

/// The unique immutable birth for a project identity. Used by project-body
/// writes so a member update cannot rewrite the depth or mint a second birth.
pub(crate) fn birth_for_project(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
) -> Result<Option<(EntityId, ProjectDepthBirth)>> {
    let mut found = None;
    for row in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = row?;
        let id = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("project birth index"))?,
        )?;
        if !is_project_depth_id(&id) {
            continue;
        }
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("project birth row"))?;
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("project birth body"))?;
        if let ProjectDepthContribution::Birth(birth) = decode_contribution(body)?
            && birth.project_ref == project.to_hex()
        {
            if found.is_some() {
                return Err(Error::InvalidConfig(
                    "project has conflicting birth policy".into(),
                ));
            }
            found = Some((id, birth));
        }
    }
    Ok(found)
}

/// Derive one replica-independent depth from the immutable manifest set.
/// Unresolved/revoked controlling facts refuse new depth rather than restore
/// an older or more permissive birth value.
pub(crate) fn resolve_project_depth(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    posture: HostingPrivacyPosture,
    project: EntityId,
) -> Result<ProjectDepthResolution> {
    let maximum = crate::gate::resolve_project_depth_max(store, txn)?;
    let mut rows = BTreeMap::new();
    for row in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = row?;
        let id = EntityId::from_bytes(
            key[1..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("project-depth type index"))?,
        )?;
        if !is_project_depth_id(&id) {
            continue;
        }
        let raw = store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("project-depth manifest missing"))?;
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("project-depth header"))?;
        let contribution = decode_contribution(body)?;
        let named = match &contribution {
            ProjectDepthContribution::Default(_) | ProjectDepthContribution::DefaultEdit(_) => {
                continue;
            }
            ProjectDepthContribution::Birth(b) => &b.project_ref,
            ProjectDepthContribution::Edit(e) => &e.project_ref,
        };
        if named == &project.to_hex() {
            if rows.len() >= 4096 {
                return Ok(unresolved(ProjectDepthDisposition::Quarantined));
            }
            rows.insert(id, contribution);
        }
    }
    if !rows
        .values()
        .any(|row| matches!(row, ProjectDepthContribution::Birth(_)))
        && implicit_birth_applies(store, txn, posture, project)?
    {
        let birth = super::codec::canonical_birth(project)?;
        rows.insert(
            super::codec::birth_id(&birth)?,
            ProjectDepthContribution::Birth(birth),
        );
    }
    let births: Vec<_> = rows
        .iter()
        .filter_map(|(id, row)| {
            if let ProjectDepthContribution::Birth(b) = row {
                Some((*id, b))
            } else {
                None
            }
        })
        .collect();
    if births.is_empty() {
        return Ok(unresolved(ProjectDepthDisposition::Pending));
    }
    if births.len() != 1 {
        return Ok(unresolved(ProjectDepthDisposition::Quarantined));
    }
    let (birth_id, birth) = births[0];
    let birth_status = birth_disposition(store, txn, posture, birth)?;
    let authority =
        crate::authority::authority_fold_readonly_for_store_in_txn(store, posture, txn)?;
    let mut shadowed = BTreeSet::new();
    for (id, row) in &rows {
        let ProjectDepthContribution::Edit(edit) = row else {
            continue;
        };
        for predecessor in &edit.predecessors {
            let parent = EntityId::from_hex(predecessor)?;
            if parent != *id && rows.contains_key(&parent) {
                shadowed.insert(parent);
            }
        }
    }
    let frontier: Vec<_> = rows
        .keys()
        .filter(|id| !shadowed.contains(id))
        .copied()
        .collect();
    if frontier.is_empty() {
        return Ok(unresolved(ProjectDepthDisposition::Quarantined));
    }
    let mut pending = birth_status == ProjectDepthDisposition::Pending;
    let mut quarantined =
        birth_status == ProjectDepthDisposition::Quarantined && frontier.contains(&birth_id);
    // Only unsuperseded heads control the live row. A later authorized edit
    // can explicitly supersede old quarantined facts; an unseen concurrent
    // restriction remains a separate head and still narrows.
    for id in &frontier {
        let mut stack = vec![*id];
        let mut seen = BTreeSet::new();
        let mut anchored = false;
        while let Some(next) = stack.pop() {
            if !seen.insert(next) {
                continue;
            }
            if next == birth_id {
                anchored = true;
                continue;
            }
            match rows.get(&next) {
                Some(ProjectDepthContribution::Edit(edit)) => {
                    for predecessor in &edit.predecessors {
                        let parent = EntityId::from_hex(predecessor)?;
                        if parent == next {
                            quarantined = true;
                        } else if rows.contains_key(&parent) {
                            stack.push(parent);
                        } else {
                            pending = true;
                        }
                    }
                }
                Some(_) => quarantined = true,
                None => pending = true,
            }
        }
        if !anchored && !pending {
            quarantined = true;
        }
        if let Some(ProjectDepthContribution::Edit(edit)) = rows.get(id) {
            match edit_disposition(edit, &authority)? {
                ProjectDepthDisposition::Authorized => {}
                ProjectDepthDisposition::Pending => pending = true,
                ProjectDepthDisposition::Quarantined => quarantined = true,
            }
        }
    }
    if pending {
        return Ok(ProjectDepthResolution {
            depth: 0,
            frontier,
            disposition: ProjectDepthDisposition::Pending,
        });
    }
    if quarantined {
        return Ok(ProjectDepthResolution {
            depth: 0,
            frontier,
            disposition: ProjectDepthDisposition::Quarantined,
        });
    }
    if !rows.contains_key(&birth_id) {
        return Ok(unresolved(ProjectDepthDisposition::Quarantined));
    }
    let depth = frontier
        .iter()
        .map(|id| match rows.get(id) {
            Some(
                ProjectDepthContribution::Default(_) | ProjectDepthContribution::DefaultEdit(_),
            ) => 0, // not in this project's row set
            Some(ProjectDepthContribution::Birth(b)) => b.depth,
            Some(ProjectDepthContribution::Edit(e)) => e.depth,
            None => 0,
        })
        .min()
        .unwrap_or(0)
        .min(maximum);
    Ok(ProjectDepthResolution {
        depth,
        frontier,
        disposition: ProjectDepthDisposition::Authorized,
    })
}
