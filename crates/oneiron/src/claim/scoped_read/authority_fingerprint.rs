//! A canonical fingerprint of the live read authority behind one actor key
//! (FIX 9661), the second half of a campaign enrollment's cause baseline.
//!
//! Explanation and baseline only, never authorization: no read door, gate or
//! admission consults it, every row is still judged by the read lanes alone,
//! and a fingerprint that cannot be read refuses nothing (its caller keeps
//! the path it had). It folds, in ONE snapshot, what those lanes resolve live
//! for the key: its own ceilings (credential Scope, world ceiling, locality,
//! room bounds, owner exemption), the reader's standing for `read` and each
//! agent Grant that stands for it, and the principal's live access grants and
//! relationship memberships. A change in any of them changes the digest; a
//! raw key, a grant id alone or a vault-wide counter never stands in for it.
//!
//! The grant and relationship scans repeat `agent_grants`' and
//! `AccessContext`'s own rather than share them, because those answers are
//! private to the lanes that authorize, and this one only describes.
//!
//! A live vault Owner reads clearance-free: the Owner's key folds the owner
//! and its world ceiling, and no clearance.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::{RoomTurnCeiling, ScopedReadActorKey};
use crate::authority::{HostActionGuard, PeerMachine, VerifiedSlip};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimSubject, claim_surfaceable, decode_claim_body};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::federation::Scope;
use crate::pipeline::WorldAuthoritySet;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_RELATIONSHIP,
};
use crate::settings::ReadDestination;
use crate::{EntityId, Vault};

impl ScopedReadActorKey {
    /// The canonical fingerprint of the live read authority behind this key,
    /// read in one snapshot. Explanation and baseline only: it is never an
    /// authorization input (module docs).
    ///
    /// # Errors
    ///
    /// Storage and decode errors propagate; the caller keeps its own path.
    pub(crate) fn read_authority_fingerprint(&self, vault: &Vault) -> Result<[u8; 32]> {
        let txn = vault.store.env.read_txn()?;
        let mut hasher = Sha256::new();
        hasher.update(b"oneiron.scoped_read.authority_fingerprint.v1");
        fold_scope(&mut hasher, &self.world_ceiling())?;
        if let Some(owner) = self.vault_owner_ref() {
            hasher.update([0u8]);
            hasher.update(owner.as_bytes());
            return Ok(hasher.finalize().into());
        }
        hasher.update([1u8]);
        fold_str(&mut hasher, self.actor_ref());
        fold_str(&mut hasher, self.actor_class().unwrap_or_default());
        hasher.update([
            u8::from(self.enforce_access_grants),
            u8::from(self.unscoped_rows_open),
            u8::from(self.off_device()),
            u8::from(self.proof.is_some()),
            u8::from(self.facets_owner_exempt_in(vault, &txn)?),
        ]);
        fold_id(&mut hasher, self.principal_ref);
        fold_id(&mut hasher, self.room_turn().map(|turn| turn.room));
        fold_id(&mut hasher, self.room_facets);
        match self.authority_scope() {
            Some(scope) => {
                hasher.update([1u8]);
                fold_scope(&mut hasher, scope)?;
            }
            None => hasher.update([0u8]),
        }
        // A reader's own Grants read for a key with no proof and no Scope.
        match EntityId::from_hex(self.actor_ref()) {
            Ok(reader) if self.proof.is_none() && self.authority_scope().is_none() => {
                fold_reader_grants(&mut hasher, vault, &txn, reader)?;
            }
            _ => hasher.update([0u8]),
        }
        match self.principal_ref {
            Some(principal) if self.enforce_access_grants => {
                fold_principal_reach(&mut hasher, vault, &txn, principal)?;
            }
            _ => hasher.update([0u8]),
        }
        Ok(hasher.finalize().into())
    }
}

/// The reader's standing for `read` and every agent Grant that alone stands
/// for it, each id with its Scope, as `agent_grants` resolves them.
fn fold_reader_grants(
    hasher: &mut Sha256,
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: EntityId,
) -> Result<()> {
    let class = match crate::vault::live_entity_row_in_txn(&vault.store, txn, &reader)?.live_type()
    {
        Some(ENTITY_TYPE_AGENT_DEF) => EdgeActorClass::Agent,
        Some(ENTITY_TYPE_MACHINE) => EdgeActorClass::System,
        _ => {
            hasher.update([1u8]);
            return Ok(());
        }
    };
    if crate::authority::principal_standing_in_txn(vault, txn, reader, class, "read")?.is_none() {
        hasher.update([2u8]);
        return Ok(());
    }
    hasher.update([3u8]);
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let (grants, mut undecoded) = vault.agent_grants_reporting_in_txn(txn)?;
    let mut standing: Vec<(EntityId, &Scope)> = grants
        .iter()
        .filter(|grant| grant.stands_in_txn(vault, txn, reader, "read", now, &owners))
        .map(|grant| (grant.id, &grant.grant.authority_scope))
        .collect();
    standing.sort_by_key(|(id, _)| *id);
    fold_len(hasher, standing.len());
    for (id, scope) in standing {
        hasher.update(id.as_bytes());
        fold_scope(hasher, scope)?;
    }
    // A Grant row that does not decode stands for no one; it still marks a
    // change in what the reader's Grants are.
    undecoded.sort_unstable();
    fold_len(hasher, undecoded.len());
    for id in &undecoded {
        hasher.update(id.as_bytes());
    }
    Ok(())
}

/// The principal's live access grants and relationship memberships, as
/// `AccessContext` resolves them at the authorization floor.
fn fold_principal_reach(
    hasher: &mut Sha256,
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
) -> Result<()> {
    let now = crate::ports::authorization_floor_in_txn(&vault.store, txn)?;
    let live = |id: &EntityId| -> Result<bool> {
        Ok(crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live())
    };
    let mut grants = Vec::new();
    let mut relationships = BTreeSet::new();
    for kind in [ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_CLAIM] {
        for row in
            crate::ports::EntityStoreRead::port_entity_ids_by_type(&vault.store, txn, kind, None)?
        {
            let id = row?;
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
                .ok_or(Error::CorruptedIndex("authority fingerprint row"))?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("authority fingerprint header"))?;
            if header.entity_type != kind {
                return Err(Error::CorruptedIndex("authority fingerprint type"));
            }
            if raw.len() <= ENTITY_METADATA_HEADER_LEN {
                continue;
            }
            if kind == ENTITY_TYPE_ACCESS_GRANT {
                let Some(grant) = crate::access_grant::decode_live_access_grant_body(
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                )?
                else {
                    continue;
                };
                if grant.principal_ref == principal
                    && grant.effective_status_at(now)
                        == crate::access_grant::AccessGrantStatus::Active
                    && live(&id)?
                {
                    grants.push((id, crate::access_grant::encode_access_grant_body(&grant)?));
                }
                continue;
            }
            let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if body.predicate == crate::federation::PREDICATE_RELATIONSHIP_PERSON_REF
                && claim_surfaceable(&body)
                && body
                    .value
                    .as_str()
                    .and_then(|value| EntityId::from_hex(value).ok())
                    == Some(principal)
                && crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &id)?
                && let ClaimSubject::Entity(space) = body.subject
                && live(&id)?
                && crate::vault::live_entity_row_in_txn(&vault.store, txn, &space)?.live_type()
                    == Some(ENTITY_TYPE_RELATIONSHIP)
            {
                relationships.insert(space);
            }
        }
    }
    hasher.update([1u8]);
    grants.sort_by_key(|(id, _)| *id);
    fold_len(hasher, grants.len());
    for (id, body) in &grants {
        hasher.update(id.as_bytes());
        fold_len(hasher, body.len());
        hasher.update(body);
    }
    fold_len(hasher, relationships.len());
    for space in &relationships {
        hasher.update(space.as_bytes());
    }
    Ok(())
}

/// A Scope's canonical bytes: its serde form, whose set axes are ordered.
fn fold_scope(hasher: &mut Sha256, scope: &Scope) -> Result<()> {
    let bytes =
        serde_json::to_vec(scope).map_err(|error| Error::InvalidConfig(error.to_string()))?;
    fold_len(hasher, bytes.len());
    hasher.update(&bytes);
    Ok(())
}

fn fold_str(hasher: &mut Sha256, value: &str) {
    fold_len(hasher, value.len());
    hasher.update(value.as_bytes());
}

fn fold_id(hasher: &mut Sha256, id: Option<EntityId>) {
    match id {
        Some(id) => {
            hasher.update([1u8]);
            hasher.update(id.as_bytes());
        }
        None => hasher.update([0u8]),
    }
}

fn fold_len(hasher: &mut Sha256, len: usize) {
    hasher.update((len as u64).to_be_bytes());
}

impl ScopedReadActorKey {
    /// A stable fingerprint of this key's own material, for session keying:
    /// BLAKE3-256 over every field in declaration order under
    /// `oneiron.scoped_read.actor_key_fingerprint.v1`. Key material only: it
    /// reads no vault state, unlike [`Self::read_authority_fingerprint`], so
    /// a key that cannot reach its vault still fingerprints. Two keys
    /// fingerprint alike only when their material matches field for field;
    /// the owner-proof fold below renders Debug only because that proof
    /// exposes no vault-free typed accessor, and a rendering change there
    /// only costs a cold turn.
    #[must_use]
    pub fn key_fingerprint(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(KEY_FINGERPRINT_DOMAIN);
        key_fold_str(&mut hasher, self.actor_ref());
        key_fold_opt_str(&mut hasher, self.actor_class());
        key_fold_id(&mut hasher, self.principal_ref);
        hasher.update([
            u8::from(self.enforce_access_grants),
            u8::from(self.unscoped_rows_open),
        ]);
        key_fold_proof(&mut hasher, self.proof.as_ref());
        key_fold_json_opt(&mut hasher, self.authority_scope());
        key_fold_opt_str(&mut hasher, self.channel.as_deref());
        key_fold_id(&mut hasher, self.vault_owner_ref());
        key_fold_id(&mut hasher, self.owner_exemption);
        key_fold_room_turn(&mut hasher, self.room_turn());
        key_fold_id(&mut hasher, self.room_facets);
        key_fold_worlds(&mut hasher, self.worlds.as_ref());
        key_fold_destination(&mut hasher, self.destination());
        key_fold_host_action(&mut hasher, self.host_action_guard());
        key_fold_owner_proof(&mut hasher, self.owner_proof_guard());
        hasher.update([u8::from(self.owner_by_census())]);
        *hasher.finalize().as_bytes()
    }
}

/// Domain tag for [`ScopedReadActorKey::key_fingerprint`].
const KEY_FINGERPRINT_DOMAIN: &[u8] = b"oneiron.scoped_read.actor_key_fingerprint.v1";

fn key_fold_len(hasher: &mut blake3::Hasher, len: usize) {
    hasher.update(&(len as u64).to_be_bytes());
}

fn key_fold_str(hasher: &mut blake3::Hasher, value: &str) {
    key_fold_len(hasher, value.len());
    hasher.update(value.as_bytes());
}

fn key_fold_opt_str(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1u8]);
            key_fold_str(hasher, value);
        }
        None => hasher.update([0u8]),
    }
}

fn key_fold_id(hasher: &mut blake3::Hasher, id: Option<EntityId>) {
    match id {
        Some(id) => {
            hasher.update([1u8]);
            hasher.update(id.as_bytes());
        }
        None => hasher.update([0u8]),
    }
}

/// A typed value's canonical bytes: its serde form, whose set axes are
/// ordered (as [`fold_scope`]); the Debug rendering only when that cannot
/// encode, so the fold stays total.
fn key_fold_json(hasher: &mut blake3::Hasher, value: &(impl serde::Serialize + std::fmt::Debug)) {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| format!("{value:?}").into_bytes());
    key_fold_len(hasher, bytes.len());
    hasher.update(&bytes);
}

/// [`key_fold_json`], presence-tagged, for an optional typed value.
fn key_fold_json_opt(
    hasher: &mut blake3::Hasher,
    value: Option<&(impl serde::Serialize + std::fmt::Debug)>,
) {
    match value {
        Some(value) => {
            hasher.update([1u8]);
            key_fold_json(hasher, value);
        }
        None => hasher.update([0u8]),
    }
}

/// A verified proof's key material: its claims, its pact bound, and whether
/// it is unattenuated or transferred.
fn key_fold_proof(hasher: &mut blake3::Hasher, proof: Option<&VerifiedSlip>) {
    let Some(proof) = proof else {
        hasher.update([0u8]);
        return;
    };
    hasher.update([1u8]);
    key_fold_json(hasher, proof.claims());
    match proof.pact() {
        Some((grant, scope)) => {
            hasher.update([1u8]);
            hasher.update(grant.as_bytes());
            key_fold_json(hasher, scope);
        }
        None => hasher.update([0u8]),
    }
    hasher.update([
        u8::from(proof.is_unattenuated()),
        u8::from(proof.is_transferred()),
    ]);
}

/// A bound room turn's ceiling: the room, the caller, the terms the turn
/// holds now, its roster and peer keys (each fingerprinted, sorted, so
/// order never moves the digest), its thread and whether it is personal.
fn key_fold_room_turn(hasher: &mut blake3::Hasher, ceiling: Option<&RoomTurnCeiling>) {
    let Some(ceiling) = ceiling else {
        hasher.update([0u8]);
        return;
    };
    hasher.update([1u8]);
    hasher.update(ceiling.room.as_bytes());
    hasher.update(ceiling.caller.as_bytes());
    let terms = ceiling.terms.get();
    key_fold_json(hasher, &terms.worlds);
    key_fold_json(hasher, &terms.facets);
    key_fold_json_opt(hasher, terms.clearance.as_ref());
    hasher.update([u8::from(terms.p7)]);
    let mut roster = ceiling.roster.clone();
    roster.sort_unstable();
    key_fold_len(hasher, roster.len());
    for member in &roster {
        hasher.update(member.as_bytes());
    }
    let mut peers: Vec<[u8; 32]> = ceiling
        .peers
        .iter()
        .map(ScopedReadActorKey::key_fingerprint)
        .collect();
    peers.sort_unstable();
    key_fold_len(hasher, peers.len());
    for peer in &peers {
        hasher.update(peer);
    }
    key_fold_id(hasher, ceiling.branch);
    hasher.update([u8::from(ceiling.personal)]);
}

/// The asked-worlds ceiling: whether base reality reads, and each world in
/// sorted order.
fn key_fold_worlds(hasher: &mut blake3::Hasher, worlds: Option<&WorldAuthoritySet>) {
    let Some(worlds) = worlds else {
        hasher.update([0u8]);
        return;
    };
    hasher.update([1u8, u8::from(worlds.include_base())]);
    key_fold_len(hasher, worlds.worlds().len());
    for world in worlds.worlds() {
        hasher.update(world.as_bytes());
    }
}

/// Where the key's rows go: off this device or not, and each machine a
/// connection proved beside that, sorted, so order never moves the digest.
/// The effective destination the reads judge, not latent proof state.
fn key_fold_destination(hasher: &mut blake3::Hasher, destination: &ReadDestination) {
    hasher.update([u8::from(destination.is_off_device())]);
    let mut peers: Vec<Vec<u8>> = destination
        .peers()
        .iter()
        .map(|peer| match peer {
            PeerMachine::Proven { machine, key } => {
                let mut bytes = vec![1u8];
                bytes.extend_from_slice(machine.as_bytes());
                bytes.extend_from_slice(key);
                bytes
            }
            PeerMachine::Unknown => vec![0u8],
        })
        .collect();
    peers.sort_unstable();
    key_fold_len(hasher, peers.len());
    for peer in &peers {
        key_fold_len(hasher, peer.len());
        hasher.update(peer);
    }
}

/// A host action's guard: that one is bound, the owner it acts as, and the
/// root it acts under by slip id (`None` for the dev mode).
fn key_fold_host_action(hasher: &mut blake3::Hasher, guard: Option<&HostActionGuard>) {
    let Some(guard) = guard else {
        hasher.update([0u8]);
        return;
    };
    hasher.update([1u8]);
    hasher.update(guard.owner().as_bytes());
    match guard.root_slip_id() {
        Some(id) => {
            hasher.update([1u8]);
            hasher.update(id);
        }
        None => hasher.update([0u8]),
    }
}

/// An owner proof's binding: that one is held, and its Debug rendering over
/// key material. The proof exposes no vault-free typed accessor, so this
/// field alone renders; the rendering is deterministic for identical
/// material, and a rendering change only costs a cold turn.
fn key_fold_owner_proof(hasher: &mut blake3::Hasher, proof: Option<&AuthenticatedOwner>) {
    match proof {
        Some(proof) => {
            hasher.update([1u8]);
            key_fold_str(hasher, &format!("{proof:?}"));
        }
        None => hasher.update([0u8]),
    }
}
