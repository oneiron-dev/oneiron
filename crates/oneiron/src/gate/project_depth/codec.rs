//! Exact, content-addressed POLICY_MANIFEST carrier and signature grammar.
use serde::{Deserialize, Serialize};

use crate::authority::{AuthorityKey, AuthoritySignature, verify_authority_signature};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;

const DOMAIN: &[u8] = b"oneiron.project.depth.policy.v1\0";
const MAX_BODY: usize = 16 * 1024;
const PREFIX: &[u8; 4] = &[0xD5, 0x9A, 0x3C, 0x7E];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ProjectDepthContribution {
    Default(ProjectDepthDefault),
    DefaultEdit(ProjectDepthEdit),
    Birth(ProjectDepthBirth),
    Edit(ProjectDepthEdit),
}

/// The seeded creation-default row. It is derived from the shipped default
/// alone, never stored, and never bound to the whole default manifest's bytes,
/// so an engine upgrade that adds unrelated manifest rows keeps every birth
/// sourced from it anchored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectDepthDefault {
    pub(crate) version: u8,
    pub(crate) depth: u8,
}

pub(crate) fn seeded_default() -> ProjectDepthDefault {
    ProjectDepthDefault {
        version: 1,
        depth: crate::gate::default_manifest::SEEDED_PROJECT_DEPTH_DEFAULT,
    }
}

pub(crate) fn seeded_default_carrier() -> Result<(EntityId, Vec<u8>)> {
    let bytes = encode_contribution(&ProjectDepthContribution::Default(seeded_default()))?;
    Ok((content_id(&bytes)?, bytes))
}

/// The one birth every replica derives for a project that has no stored
/// birth: the seeded default, unsigned. Its content address is the same on
/// every replica, so owner edits can name it as their predecessor.
pub(crate) fn canonical_birth(project: EntityId) -> Result<ProjectDepthBirth> {
    let (seed, seed_body) = seeded_default_carrier()?;
    Ok(ProjectDepthBirth {
        version: 1,
        project_ref: project.to_hex(),
        depth: seeded_default().depth,
        source_manifest: seed.to_hex(),
        source_hash: *blake3::hash(&seed_body).as_bytes(),
        owner: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectDepthBirth {
    pub(crate) version: u8,
    pub(crate) project_ref: String,
    pub(crate) depth: u8,
    pub(crate) source_manifest: String,
    pub(crate) source_hash: [u8; 32],
    pub(crate) owner: Option<ProjectBirthOwnerProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectBirthOwnerProof {
    pub(crate) vault_id: [u8; 32],
    pub(crate) actor_ref: String,
    pub(crate) frontier: [u8; 32],
    pub(crate) suite: String,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

pub(crate) fn birth_transcript(birth: &ProjectDepthBirth) -> Result<Vec<u8>> {
    let proof = birth.owner.as_ref().ok_or_else(invalid)?;
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(b"project_birth\0");
    bytes.extend_from_slice(
        &rmp_serde::to_vec_named(&(
            birth.version,
            &birth.project_ref,
            birth.depth,
            &birth.source_manifest,
            birth.source_hash,
            proof.vault_id,
            &proof.actor_ref,
            proof.frontier,
            &proof.suite,
            &proof.public_key,
        ))
        .map_err(|_| invalid())?,
    );
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectDepthEdit {
    pub(crate) version: u8,
    pub(crate) project_ref: String,
    pub(crate) depth: u8,
    pub(crate) vault_id: [u8; 32],
    pub(crate) actor_ref: String,
    pub(crate) frontier: [u8; 32],
    pub(crate) predecessors: Vec<String>,
    pub(crate) suite: String,
    pub(crate) public_key: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

pub(crate) fn edit_transcript(edit: &ProjectDepthEdit) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(
        if edit.project_ref == seeded_default_carrier()?.0.to_hex() {
            b"default_edit\0"
        } else {
            b"project_edit\0"
        },
    );
    bytes.extend_from_slice(
        &rmp_serde::to_vec_named(&(
            edit.version,
            &edit.project_ref,
            edit.depth,
            edit.vault_id,
            &edit.actor_ref,
            edit.frontier,
            &edit.predecessors,
            &edit.suite,
            &edit.public_key,
        ))
        .map_err(|_| invalid())?,
    );
    Ok(bytes)
}

fn invalid() -> Error {
    RecordError::InvalidProjectBody("invalid project-depth policy contribution").into()
}

pub(crate) fn encode_contribution(value: &ProjectDepthContribution) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid())
}

pub(crate) fn is_project_depth_id(id: &EntityId) -> bool {
    id.as_bytes().starts_with(PREFIX)
}

pub(crate) fn is_project_depth_contribution(bytes: &[u8]) -> bool {
    // Distinct tagged envelope. A malformed candidate must never downgrade
    // to an ordinary locally trusted policy pack.
    rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
        .ok()
        .and_then(|value| value.as_map().cloned())
        .is_some_and(|entries| {
            entries.iter().any(|(key, value)| {
                key.as_str() == Some("kind")
                    && matches!(
                        value.as_str(),
                        Some("default" | "default_edit" | "birth" | "edit")
                    )
            })
        })
}

pub(crate) fn decode_contribution(bytes: &[u8]) -> Result<ProjectDepthContribution> {
    if bytes.len() > MAX_BODY || bytes.is_empty() {
        return Err(invalid());
    }
    let value: ProjectDepthContribution = rmp_serde::from_slice(bytes).map_err(|_| invalid())?;
    if encode_contribution(&value)? != bytes {
        return Err(invalid());
    }
    if let ProjectDepthContribution::Default(default) = &value {
        if *default != seeded_default() {
            return Err(invalid());
        }
        return Ok(value);
    }
    let (project_ref, depth, version) = match &value {
        ProjectDepthContribution::Default(_) => unreachable!("handled above"),
        ProjectDepthContribution::Birth(b) => (&b.project_ref, b.depth, b.version),
        ProjectDepthContribution::Edit(e) | ProjectDepthContribution::DefaultEdit(e) => {
            (&e.project_ref, e.depth, e.version)
        }
    };
    if version != 1
        || usize::from(depth) > crate::context_projection::CONTEXT_PROJECTION_MAX_ANCESTORS
        || !EntityId::from_hex(project_ref).is_ok_and(|id| id.to_hex() == *project_ref)
    {
        return Err(invalid());
    }
    match &value {
        ProjectDepthContribution::Default(_) => unreachable!("handled above"),
        ProjectDepthContribution::Birth(b) => {
            if EntityId::from_hex(&b.source_manifest).is_err() || b.source_hash == [0; 32] {
                return Err(invalid());
            }
            if let Some(proof) = &b.owner {
                if !EntityId::from_hex(&proof.actor_ref)
                    .is_ok_and(|id| id.to_hex() == proof.actor_ref)
                {
                    return Err(invalid());
                }
                let key = match proof.suite.as_str() {
                    "ed25519" => AuthorityKey::Ed25519(
                        proof
                            .public_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| invalid())?,
                    ),
                    "p256" => AuthorityKey::P256(proof.public_key.clone()),
                    _ => return Err(invalid()),
                };
                if !verify_authority_signature(
                    &AuthoritySignature {
                        suite: key.suite(),
                        public_key: key,
                        signature: proof.signature.clone(),
                    },
                    &birth_transcript(b)?,
                ) {
                    return Err(invalid());
                }
            }
        }
        ProjectDepthContribution::DefaultEdit(e) => {
            if e.project_ref != seeded_default_carrier()?.0.to_hex() {
                return Err(invalid());
            }
            validate_signed_edit(e)?;
        }
        ProjectDepthContribution::Edit(e) => {
            if e.project_ref == seeded_default_carrier()?.0.to_hex() {
                return Err(invalid());
            }
            validate_signed_edit(e)?;
        }
    }
    Ok(value)
}

fn validate_signed_edit(e: &ProjectDepthEdit) -> Result<()> {
    let actor = EntityId::from_hex(&e.actor_ref).map_err(|_| invalid())?;
    if actor.to_hex() != e.actor_ref
        || e.predecessors.is_empty()
        || e.predecessors.len() > 256
        || e.predecessors.windows(2).any(|pair| pair[0] >= pair[1])
        || e.predecessors
            .iter()
            .any(|id| !EntityId::from_hex(id).is_ok_and(|parsed| parsed.to_hex() == *id))
    {
        return Err(invalid());
    }
    let key = match e.suite.as_str() {
        "ed25519" => {
            AuthorityKey::Ed25519(e.public_key.as_slice().try_into().map_err(|_| invalid())?)
        }
        "p256" => AuthorityKey::P256(e.public_key.clone()),
        _ => return Err(invalid()),
    };
    if !verify_authority_signature(
        &AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: e.signature.clone(),
        },
        &edit_transcript(e)?,
    ) {
        return Err(invalid());
    }
    Ok(())
}

fn content_id(body: &[u8]) -> Result<EntityId> {
    let digest = blake3::hash(&[DOMAIN, body].concat());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[..PREFIX.len()].copy_from_slice(PREFIX);
    EntityId::from_bytes(bytes).map_err(|_| invalid())
}

pub(crate) fn birth_id(birth: &ProjectDepthBirth) -> Result<EntityId> {
    content_id(&encode_contribution(&ProjectDepthContribution::Birth(
        birth.clone(),
    ))?)
}
pub(crate) fn default_edit_id(edit: &ProjectDepthEdit) -> Result<EntityId> {
    content_id(&encode_contribution(
        &ProjectDepthContribution::DefaultEdit(edit.clone()),
    )?)
}

pub(crate) fn edit_id(edit: &ProjectDepthEdit) -> Result<EntityId> {
    content_id(&encode_contribution(&ProjectDepthContribution::Edit(
        edit.clone(),
    ))?)
}

/// Shared local/replicated put door. An id cannot change its contribution.
pub(crate) fn validate_contribution_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &[u8],
    replicated: bool,
    posture: crate::HostingPrivacyPosture,
) -> Result<()> {
    let value = decode_contribution(body)?;
    // The seeded row is derived by every replica and is never a stored fact.
    if content_id(body)? != id || matches!(value, ProjectDepthContribution::Default(_)) {
        return Err(invalid());
    }
    if let Some(old) = store.entities.get(txn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&old)
            .ok_or(Error::CorruptedIndex("depth contribution header"))?;
        if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST
            || old.get(ENTITY_METADATA_HEADER_LEN..) != Some(body)
        {
            return Err(invalid());
        }
    }
    if let ProjectDepthContribution::Birth(b) = value {
        let source = EntityId::from_hex(&b.source_manifest).map_err(|_| invalid())?;
        if source == id {
            return Err(invalid());
        }
        if replicated
            && b.owner.is_none()
            && !super::fold::unsigned_birth_trusted(store, txn, posture, &b)?
        {
            return Err(invalid());
        }
    }
    Ok(())
}
