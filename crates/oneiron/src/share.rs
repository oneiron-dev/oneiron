//! Revocable brief read grants. Documents and rendered content stay outside the vault.

use std::collections::BTreeSet;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    decode_access_grant_body, decode_entity_ref, encode_access_grant_body, invalid_grant,
    required_value, validate_keys,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ScopedReadActorKey, claim_surfaceable, decode_claim_body};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::{GateOutcome, resolve_policy_manifest, scoped_read_claim_allowed};
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_CLAIM};
use crate::store::{GateDecisionId, Store};
use crate::write_envelope::WriteActor;

/// A typed AccessGrant. Only the opaque brief handle and redaction maximum are stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Authenticated recipient identity required at every resolution.
    pub recipient_ref: EntityId,
    /// Opaque rendering-layer document handle.
    pub brief_ref: String,
    /// Maximum permitted WORLD refs.
    pub world_refs: BTreeSet<EntityId>,
    /// Maximum permitted FACET refs.
    pub facet_refs: BTreeSet<EntityId>,
    /// Whether an unscoped dimension may pass.
    pub include_unscoped: bool,
    /// Active or revoked; creation accepts active only.
    pub status: AccessGrantStatus,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Revocation time in Unix seconds.
    pub revoked_at: Option<u64>,
}

/// Optional request narrowing, never evidence of the recipient's current authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareViewerScope {
    /// Requested WORLD maximum.
    pub world_refs: BTreeSet<EntityId>,
    /// Requested FACET maximum.
    pub facet_refs: BTreeSet<EntityId>,
    /// Whether unscoped dimensions remain requested.
    pub include_unscoped: bool,
}

/// A fresh render input, containing references only. Do not cache it as authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedShare {
    /// AccessGrant entity id.
    pub share_id: EntityId,
    /// Opaque rendering-layer document handle.
    pub brief_ref: String,
    /// Current, surfaceable claims permitted by the maximum and live read policy.
    pub visible_claim_refs: Vec<EntityId>,
}

impl Share {
    pub(crate) fn grant(&self) -> AccessGrant {
        AccessGrant {
            principal_ref: self.recipient_ref,
            scope: AccessGrantScope::SharedBrief {
                brief_ref: self.brief_ref.clone(),
                world_refs: self.world_refs.clone(),
                facet_refs: self.facet_refs.clone(),
                include_unscoped: self.include_unscoped,
            },
            capability: AccessGrantCapability::SharedBriefRead,
            status: self.status,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
        }
    }

    pub(crate) fn from_grant(grant: &AccessGrant) -> Option<Self> {
        let AccessGrantScope::SharedBrief {
            brief_ref,
            world_refs,
            facet_refs,
            include_unscoped,
        } = &grant.scope
        else {
            return None;
        };
        Some(Self {
            recipient_ref: grant.principal_ref,
            brief_ref: brief_ref.clone(),
            world_refs: world_refs.clone(),
            facet_refs: facet_refs.clone(),
            include_unscoped: *include_unscoped,
            status: grant.status,
            created_at: grant.created_at,
            revoked_at: grant.revoked_at,
        })
    }

    /// SHA-256 of a domain-separated, length-framed, canonically ordered typed scope.
    #[must_use]
    pub fn redaction_scope_hash(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"oneiron.share.redaction_scope.v1\0");
        for refs in [&self.world_refs, &self.facet_refs] {
            hash.update((refs.len() as u64).to_be_bytes());
            for id in refs {
                hash.update(id.as_bytes());
            }
        }
        hash.update([u8::from(self.include_unscoped)]);
        crate::entity_id::bytes_to_hex_lower(&hash.finalize())
    }
}

const SCOPE_KEYS: [&str; 5] = [
    "kind",
    "brief_ref",
    "world_refs",
    "facet_refs",
    "include_unscoped",
];

pub(crate) fn validate_shared_brief_grant(grant: &AccessGrant) -> Result<()> {
    let AccessGrantScope::SharedBrief {
        brief_ref,
        world_refs,
        facet_refs,
        ..
    } = &grant.scope
    else {
        return Err(invalid_grant());
    };
    if brief_ref.trim().is_empty() {
        return Err(invalid_grant());
    }
    EntityId::from_bytes(*grant.principal_ref.as_bytes()).map_err(|_| invalid_grant())?;
    for id in world_refs.iter().chain(facet_refs) {
        EntityId::from_bytes(*id.as_bytes()).map_err(|_| invalid_grant())?;
    }
    Ok(())
}

pub(crate) fn encode_shared_brief_scope(scope: &AccessGrantScope) -> Value {
    let AccessGrantScope::SharedBrief {
        brief_ref,
        world_refs,
        facet_refs,
        include_unscoped,
    } = scope
    else {
        unreachable!("shared brief codec receives only its own scope")
    };
    Value::Map(vec![
        (Value::from("kind"), Value::from("shared_brief")),
        (Value::from("brief_ref"), Value::from(brief_ref.as_str())),
        (Value::from("world_refs"), encode_refs(world_refs)),
        (Value::from("facet_refs"), encode_refs(facet_refs)),
        (
            Value::from("include_unscoped"),
            Value::Boolean(*include_unscoped),
        ),
    ])
}

fn encode_refs(refs: &BTreeSet<EntityId>) -> Value {
    Value::Array(refs.iter().map(|id| Value::from(id.to_hex())).collect())
}

pub(crate) fn decode_shared_brief_scope(entries: &[(Value, Value)]) -> Result<AccessGrantScope> {
    validate_keys(entries, &SCOPE_KEYS)?;
    Ok(AccessGrantScope::SharedBrief {
        brief_ref: required_value(entries, "brief_ref")?
            .as_str()
            .ok_or_else(invalid_grant)?
            .to_owned(),
        world_refs: decode_refs(required_value(entries, "world_refs")?)?,
        facet_refs: decode_refs(required_value(entries, "facet_refs")?)?,
        include_unscoped: required_value(entries, "include_unscoped")?
            .as_bool()
            .ok_or_else(invalid_grant)?,
    })
}

fn decode_refs(value: &Value) -> Result<BTreeSet<EntityId>> {
    let Value::Array(values) = value else {
        return Err(invalid_grant());
    };
    let mut refs = BTreeSet::new();
    for value in values {
        if !refs.insert(decode_entity_ref(value)?) {
            return Err(invalid_grant());
        }
    }
    Ok(refs)
}

// Local, engine-written provenance. Generic grant writes cannot touch a reserved id,
// even after deletion or a foreign overwrite. A replayed row with no local admission
// never becomes a usable share. No rendered bytes or claim values live here.
fn admission_key(id: &EntityId) -> Vec<u8> {
    [b"share:brief:admission:v1:".as_slice(), id.as_bytes()].concat()
}

pub(crate) fn check_generic_grant_write(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    grant: &AccessGrant,
) -> Result<()> {
    if matches!(grant.scope, AccessGrantScope::SharedBrief { .. })
        || vault
            .store
            .vault_meta
            .get(txn, &admission_key(id))?
            .is_some()
    {
        return Err(Error::InvalidAccessGrantBody(
            "shared briefs require the share door",
        ));
    }
    if let Some(raw) = vault.store.entities.get(txn, id.as_bytes())?
        && EntityMetadataHeader::parse(&raw)
            .is_some_and(|header| header.entity_type == ENTITY_TYPE_ACCESS_GRANT)
    {
        let old = decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if matches!(old.scope, AccessGrantScope::SharedBrief { .. }) {
            return Err(Error::InvalidAccessGrantBody(
                "shared briefs require the share door",
            ));
        }
    }
    Ok(())
}

/// Immutable creation provenance plus a monotonic local revocation latch.
pub(crate) struct ShareAdmission {
    pub(crate) issuer: WriteActor,
    pub(crate) gate_id: GateDecisionId,
    digest: [u8; 32],
    revoked_at: Option<u64>,
    pub(crate) revoker: Option<WriteActor>,
}

impl ShareAdmission {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![1, self.issuer.actor_class() as u8];
        bytes.extend_from_slice(self.issuer.entity_ref().as_bytes());
        bytes.extend_from_slice(&self.gate_id.as_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes.push(u8::from(self.revoked_at.is_some()));
        bytes.extend_from_slice(&self.revoked_at.unwrap_or(0).to_be_bytes());
        bytes.push(self.revoker.map_or(0, |actor| actor.actor_class() as u8));
        bytes.extend_from_slice(
            &self
                .revoker
                .map_or([0; 16], |actor| *actor.entity_ref().as_bytes()),
        );
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 92 || bytes[0] != 1 {
            return None;
        }
        let class = EdgeActorClass::try_from_u8(bytes[1])?;
        let timestamp = u64::from_be_bytes(bytes[67..75].try_into().ok()?);
        let revoked_at = match bytes[66] {
            0 if timestamp == 0 => None,
            1 => Some(timestamp),
            _ => return None,
        };
        Some(Self {
            issuer: WriteActor::new(
                EntityId::from_bytes(bytes[2..18].try_into().ok()?).ok()?,
                class,
            ),
            gate_id: GateDecisionId::from_bytes(bytes[18..34].try_into().ok()?),
            digest: bytes[34..66].try_into().ok()?,
            revoked_at,
            revoker: if revoked_at.is_some() {
                Some(WriteActor::new(
                    EntityId::from_bytes(bytes[76..92].try_into().ok()?).ok()?,
                    EdgeActorClass::try_from_u8(bytes[75])?,
                ))
            } else {
                if bytes[75..92] != [0; 17] {
                    return None;
                }
                None
            },
        })
    }
}

pub(crate) fn share_effect_target(
    id: &EntityId,
    issuer: &WriteActor,
    share: &Share,
) -> Result<String> {
    let mut grant = share.grant();
    grant.status = AccessGrantStatus::Active;
    grant.revoked_at = None;
    let mut hash = Sha256::new();
    hash.update(b"oneiron.share.effect.v1\0");
    hash.update(id.as_bytes());
    hash.update(issuer.entity_ref().as_bytes());
    hash.update([issuer.actor_class() as u8]);
    hash.update(encode_access_grant_body(&grant)?);
    Ok(format!(
        "share:brief:{}",
        crate::entity_id::bytes_to_hex_lower(&hash.finalize())
    ))
}

fn read_admitted_share_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(Share, ShareAdmission)>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    if EntityMetadataHeader::parse(&raw)
        .is_none_or(|header| header.entity_type != ENTITY_TYPE_ACCESS_GRANT)
    {
        return Ok(None);
    }
    let Ok(grant) = decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]) else {
        return Ok(None);
    };
    let Some(share) = Share::from_grant(&grant) else {
        return Ok(None);
    };
    let Some(bytes) = store.vault_meta.get(txn, &admission_key(id))? else {
        return Ok(None);
    };
    let Some(admission) = ShareAdmission::decode(&bytes) else {
        return Ok(None);
    };
    let target = share_effect_target(id, &admission.issuer, &share)?;
    let digest: [u8; 32] = Sha256::digest(target.as_bytes()).into();
    if admission.digest != digest || admission.revoked_at != share.revoked_at {
        return Ok(None);
    }
    Ok(Some((share, admission)))
}

pub(crate) fn read_share_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(Share, ShareAdmission)>> {
    let Some((share, admission)) = read_admitted_share_in_txn(store, txn, id)? else {
        return Ok(None);
    };
    let Some(gate) = store.gate_decision_in_txn(txn, admission.gate_id)? else {
        return Ok(None);
    };
    if gate.outcome != "allow"
        || gate.redacted_at.is_some()
        || gate.content_kind != "external_effect"
        || gate.actor_ref.as_deref() != Some(admission.issuer.entity_ref().to_hex().as_str())
        || gate.actor_class != admission.issuer.actor_class().gate_actor_class()
    {
        return Ok(None);
    }
    Ok(Some((share, admission)))
}

fn verify_share_actor(store: &Store, txn: &heed::RoTxn<'_>, actor: &WriteActor) -> Result<()> {
    let raw = store
        .entities
        .get(txn, actor.entity_ref().as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("share actor"))?;
    crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())
}

impl Vault {
    /// Creates an active share only after recording an allowing external-effect decision.
    /// The transport must derive `issuer` from the authenticated principal, not request data.
    /// Pending and denied decisions are durable but never create a grant.
    pub fn create_share(
        &self,
        share_id: &EntityId,
        issuer: &WriteActor,
        share: &Share,
    ) -> Result<()> {
        let grant = share.grant();
        let data = encode_access_grant_body(&grant)?;
        if share.status != AccessGrantStatus::Active {
            return Err(invalid_grant());
        }
        let mut txn = self.store.env.write_txn()?;
        if self
            .store
            .entities
            .get(&txn, share_id.as_bytes())?
            .is_some()
            || self
                .store
                .vault_meta
                .get(&txn, &admission_key(share_id))?
                .is_some()
        {
            return Err(Error::AccessGrantAlreadyExists);
        }
        verify_share_actor(&self.store, &txn, issuer)?;
        let (gate_id, decision) =
            crate::gate::check_share_create_policy(&self.store, &mut txn, share_id, issuer, share)?;
        if decision.outcome() != GateOutcome::Allow {
            let error = Error::GateWriteRejected {
                outcome: decision.outcome().as_str(),
                reason_codes: decision
                    .reason_codes()
                    .iter()
                    .map(|code| code.as_str())
                    .collect(),
            };
            txn.commit()?;
            return Err(error);
        }
        let target = share_effect_target(share_id, issuer, share)?;
        let admission = ShareAdmission {
            issuer: *issuer,
            gate_id,
            digest: Sha256::digest(target.as_bytes()).into(),
            revoked_at: None,
            revoker: None,
        };
        self.apply_access_grant_body(&mut txn, share_id, share.created_at, data)?;
        self.store
            .vault_meta
            .put(&mut txn, &admission_key(share_id), &admission.encode())?;
        txn.commit()?;
        Ok(())
    }

    /// Revokes the same grant immediately. Only the authenticated original issuer
    /// or a live authority-log owner may stop it. No new consent is requested.
    pub fn revoke_share(
        &self,
        share_id: &EntityId,
        actor: &WriteActor,
        revoked_at: u64,
    ) -> Result<Share> {
        let mut txn = self.store.env.write_txn()?;
        let (mut share, mut admission) = read_admitted_share_in_txn(&self.store, &txn, share_id)?
            .ok_or(Error::EntityNotFound)?;
        verify_share_actor(&self.store, &txn, actor)?;
        if *actor != admission.issuer {
            let fold = self.authority_fold_readonly_in_txn(&txn)?;
            if actor.actor_class() != EdgeActorClass::Human
                || fold.vault_root_is_conflicted()
                || !crate::authority::actor_binding_is_active(&fold, &actor.entity_ref(), "human")
            {
                return Err(Error::InvalidAccessGrantBody(
                    "share revocation requires issuer or owner",
                ));
            }
        }
        if share.status == AccessGrantStatus::Revoked {
            return Ok(share);
        }
        let revoked = share.grant().revoked(revoked_at)?;
        self.apply_access_grant_body(
            &mut txn,
            share_id,
            revoked_at,
            encode_access_grant_body(&revoked)?,
        )?;
        admission.revoked_at = Some(revoked_at);
        admission.revoker = Some(*actor);
        self.store
            .vault_meta
            .put(&mut txn, &admission_key(share_id), &admission.encode())?;
        txn.commit()?;
        share.status = AccessGrantStatus::Revoked;
        share.revoked_at = Some(revoked_at);
        Ok(share)
    }

    /// Resolves on one fresh read transaction. `viewer` MUST come from the authenticated
    /// transport principal. Candidate refs must be freshly loaded by the rendering layer
    /// for this opaque brief. Neither candidates nor request narrowing grant authority.
    /// The stored maximum intersects live `core:read` policy, never a cached view.
    pub fn resolve_share_for_view(
        &self,
        share_id: &EntityId,
        viewer: &EntityId,
        requested_scope_narrowing: Option<&ShareViewerScope>,
        brief_claim_refs: &[EntityId],
    ) -> Result<Option<ResolvedShare>> {
        let txn = self.store.env.read_txn()?;
        let Some((share, _)) = read_share_in_txn(&self.store, &txn, share_id)? else {
            return Ok(None);
        };
        if share.status != AccessGrantStatus::Active || share.recipient_ref != *viewer {
            return Ok(None);
        }
        let policy = resolve_policy_manifest(&self.store, &txn)?;
        let actor = ScopedReadActorKey::new(viewer.to_hex()).ok_or_else(invalid_grant)?;
        let mut scope = ShareViewerScope {
            world_refs: share.world_refs,
            facet_refs: share.facet_refs,
            include_unscoped: share.include_unscoped,
        };
        if let Some(request) = requested_scope_narrowing {
            scope
                .world_refs
                .retain(|id| request.world_refs.contains(id));
            scope
                .facet_refs
                .retain(|id| request.facet_refs.contains(id));
            scope.include_unscoped &= request.include_unscoped;
        }
        let mut visible_claim_refs = Vec::new();
        let mut seen = BTreeSet::new();
        for id in brief_claim_refs {
            if !seen.insert(*id) {
                continue;
            }
            let Some(raw) = self.store.entities.get(&txn, id.as_bytes())? else {
                continue;
            };
            if EntityMetadataHeader::parse(&raw)
                .is_none_or(|header| header.entity_type != ENTITY_TYPE_CLAIM)
            {
                continue;
            }
            let Ok(body) = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
                continue;
            };
            if !claim_surfaceable(&body) {
                continue;
            }
            let facets = share_claim_facets(&self.store, &txn, id, &body)?;
            let Some(facets) = facets else { continue };
            let Some(permitted_facets) = scope.permitted_facets(&body, &facets) else {
                continue;
            };
            // Evaluate LIVE authority on only the facets that survived the maximum.
            // Passing all facets here would let grant A and current authority B
            // combine to leak a multiply-faceted claim despite an empty intersection.
            if scoped_read_claim_allowed(&policy, &actor, &body, &permitted_facets) {
                visible_claim_refs.push(*id);
            }
        }
        Ok(Some(ResolvedShare {
            share_id: *share_id,
            brief_ref: share.brief_ref,
            visible_claim_refs,
        }))
    }
}

impl ShareViewerScope {
    fn permitted_facets(&self, body: &ClaimBody, facets: &[EntityId]) -> Option<Vec<EntityId>> {
        if !body
            .world
            .map_or(self.include_unscoped, |id| self.world_refs.contains(&id))
        {
            return None;
        }
        if facets.is_empty() {
            return self.include_unscoped.then(Vec::new);
        }
        let permitted: Vec<_> = facets
            .iter()
            .copied()
            .filter(|id| self.facet_refs.contains(id))
            .collect();
        (!permitted.is_empty()).then_some(permitted)
    }
}

fn share_claim_facets(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<Option<Vec<EntityId>>> {
    let prefix = [id.as_bytes().as_slice(), &[EdgeKind::FacetOf as u8]].concat();
    let mut facets = Vec::new();
    for entry in store.edges_out.prefix_iter(txn, &prefix)? {
        if facets.len() >= crate::vault::MAX_EDGE_QUERY_RESULTS {
            return Err(Error::IndexOverflow("share claim facets"));
        }
        let (key, value) = entry?;
        facets.push(crate::vault::parse_edge_record(&key, &value)?.target);
    }
    // Match the existing read lane's edge-first, scope-map fallback convention.
    if facets.is_empty()
        && let Some(Value::Map(entries)) = body.scope.as_ref()
    {
        for (key, value) in entries {
            if key
                .as_str()
                .is_some_and(|key| ["facet", "facet_ref", "facetRef"].contains(&key))
            {
                if !facets.is_empty() {
                    return Ok(None);
                }
                let facet = match value {
                    Value::Binary(bytes) => bytes
                        .as_slice()
                        .try_into()
                        .ok()
                        .and_then(|bytes| EntityId::from_bytes(bytes).ok()),
                    _ => value
                        .as_str()
                        .and_then(|text| EntityId::from_hex(text).ok()),
                };
                let Some(facet) = facet else { return Ok(None) };
                facets.push(facet);
            }
        }
    }
    Ok(Some(facets))
}

#[cfg(test)]
pub(crate) mod tests;
