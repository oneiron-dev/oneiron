//! Recovery preflight through the existing replay doors, in an aborted transaction.

use super::Materializer;
use crate::batch::EdgeValueFields;
use crate::edge::EdgeKind;
use crate::error::{ArtifactError, Result};
use crate::recovery::{CanonicalBaseEdge, CanonicalSnapshot};
use crate::sync::ingest::{
    EntityStep, IngestCtx, authority_parent_order, ingest_entity_in_txn, is_authority_row,
};
use crate::sync::loro_support::TombstoneIndex;
use crate::{EntityId, Vault};
use heed::RwTxn;
use loro::LoroDoc;
use std::collections::{HashMap, HashSet};

/// All writes here are speculative LMDB pages. The transaction is ALWAYS
/// aborted: a bad later entity/edge cannot publish an earlier valid record.
/// The real forward pass repeats the same admission before committing.
///
/// The writer it takes stays the parent of that transaction, for the
/// preflight's legal-hold refusals alone: once the speculative transaction
/// and the materializer lock ended, they are logged in it and committed
/// before this returns, and nothing else of the attempt is (FIX 2433). With
/// none, the parent aborts too.
pub(crate) fn preflight_canonical_recovery(
    vault: &Vault,
    materializer: &Materializer,
    snapshot: &CanonicalSnapshot,
    doc: &LoroDoc,
) -> Result<()> {
    snapshot.validate()?;
    let analyzer = vault
        .analyzer
        .manifest()
        .canonical_json()
        .map_err(|_| ArtifactError::InvalidRecoveryArtifact("analyzer manifest"))?;
    if *blake3::hash(analyzer.as_bytes()).as_bytes()
        != snapshot.schema_manifest.analyzer_manifest_blake3
    {
        return Err(ArtifactError::InvalidRecoveryArtifact("analyzer manifest mismatch").into());
    }
    let guard = materializer.lock();
    let mut parent = vault.store.env.write_txn()?;
    let refusals = vault.store.begin_refusal_attempt();
    let preflight = match vault.store.env.nested_write_txn(&mut parent) {
        Ok(mut txn) => preflight_in_txn(vault, materializer, snapshot, doc, &mut txn),
        Err(err) => Err(err.into()),
    };
    drop(guard);
    refusals.finish().settle_in(parent);
    preflight
}

/// The preflight's speculative work in `txn`, which its caller drops.
fn preflight_in_txn(
    vault: &Vault,
    materializer: &Materializer,
    snapshot: &CanonicalSnapshot,
    doc: &LoroDoc,
    txn: &mut RwTxn<'_>,
) -> Result<()> {
    crate::recovery::validate_window_documents(doc)?;
    snapshot.preflight_note_recovery(vault, txn)?;
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    let ingest = IngestCtx::new(
        vault,
        &snapshot.window,
        materializer.lease_vault_id(),
        &tombstones,
    );
    // AUTHORITY_LOG rows first, parents first, as the forward pass lands
    // them (H72): the door holds a row whose signer's enrollment is not
    // staged yet, and the preflight refuses on any held row.
    let keys: Vec<String> = snapshot
        .entity_blobs
        .iter()
        .map(|entity| EntityId::from_bytes(entity.id).map(|id| id.to_hex()))
        .collect::<std::result::Result<_, _>>()?;
    let (authority, rest): (Vec<usize>, Vec<usize>) = (0..snapshot.entity_blobs.len())
        .partition(|at| is_authority_row(&snapshot.entity_blobs[*at].blob));
    let rows: Vec<(&str, &[u8])> = authority
        .iter()
        .map(|at| (keys[*at].as_str(), &snapshot.entity_blobs[*at].blob[..]))
        .collect();
    let order = authority_parent_order(&rows)
        .into_iter()
        .map(|at| authority[at])
        .chain(rest);
    for at in order {
        let entity = &snapshot.entity_blobs[at];
        let id = EntityId::from_bytes(entity.id)?;
        if let Some((blob, tombstone)) = crate::recovery::retained_soft_shell(doc, &tombstones, &id)
        {
            crate::batch::restore_recovery_shell_in_txn(vault, txn, &id, &blob, &tombstone)?;
        } else if let EntityStep::Quarantine(refusal) =
            ingest_entity_in_txn(&ingest, txn, &id.to_hex(), Some(&entity.blob))?
        {
            return Err(refusal.err);
        }
        // A file-plane ASSET the ingest skipped as the same body keeps its row, inline or by
        // reference (FIX 5393, FIX 5489), and a pad row rests as its reference (KS-5).
        let stored = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?;
        let landed = match stored {
            Some(stored) if stored == entity.blob => true,
            Some(stored) => {
                crate::sync::asset_body::doc_echo_equal(
                    &vault.store,
                    txn,
                    doc,
                    &id,
                    &stored,
                    &entity.blob,
                )? || crate::world_keys::pad_echo_equal(&vault.store, &stored, &entity.blob)
            }
            None => false,
        };
        if !landed {
            return Err(ArtifactError::InvalidRecoveryArtifact(
                "entity refused recovery preflight",
            )
            .into());
        }
    }
    // FIX 5972: a `regenerates` link is proven on its MESSAGEs' axes, so it
    // lands after every other base edge. FIX 8857: the conversation DAG's
    // own links go through its shared replay doors after the edges they
    // read: ChildOf membership with the ordinary edges, then SpawnedBy and
    // RepliesTo, then Parent, each chain from its root.
    let rank = |kind: u8| match EdgeKind::try_from_u8(kind) {
        Some(EdgeKind::SpawnedBy | EdgeKind::RepliesTo) => 1,
        Some(EdgeKind::Parent) => 2,
        Some(EdgeKind::Regenerates) => 3,
        _ => 0,
    };
    let mut edges: Vec<&CanonicalBaseEdge> = snapshot.base_edges.iter().collect();
    edges.sort_by_key(|edge| rank(edge.kind));
    let (parents, rest): (Vec<_>, Vec<_>) =
        edges.into_iter().partition(|edge| rank(edge.kind) == 2);
    let (regenerates, ordinary): (Vec<_>, Vec<_>) =
        rest.into_iter().partition(|edge| rank(edge.kind) == 3);
    for edge in ordinary {
        land_edge(vault, snapshot, txn, edge)?;
    }
    land_parents(vault, txn, &snapshot.window, &tombstones, &parents)?;
    for edge in regenerates {
        land_edge(vault, snapshot, txn, edge)?;
    }
    for tombstone in &snapshot.tombstones {
        let entity = EntityId::from_bytes(tombstone.id)?;
        vault.apply_replayed_tombstone_in_txn(txn, &entity, &tombstone.value)?;
    }
    crate::recovery::materialize_recovery_notes_in_txn(vault, txn, doc, snapshot)?;
    // The caller drops `txn`, aborting it even on success; in particular
    // lease/quota debits and all quarantine rows remain speculative and are
    // never committed here.
    Ok(())
}

/// Lands one base edge that is not a conversation Parent: the identity-shell
/// mandate judges only the reserved kinds it owns (FIX 8857), and the DAG's
/// SpawnedBy and RepliesTo go through their shared received-edge door.
fn land_edge(
    vault: &Vault,
    snapshot: &CanonicalSnapshot,
    txn: &mut RwTxn<'_>,
    edge: &CanonicalBaseEdge,
) -> Result<()> {
    let source = EntityId::from_bytes(edge.source)?;
    let target = EntityId::from_bytes(edge.target)?;
    let kind = crate::edge::EdgeKind::try_from_u8(edge.kind).ok_or(crate::Error::InvalidKey)?;
    let fields = crate::edge::decode_edge_value_for_kind(kind, &edge.value)?;
    if kind == crate::edge::EdgeKind::AddressedTo {
        let trusted_soft =
            crate::recovery::trusted_soft_addressing_edge(snapshot, &source, &target, &edge.value)?;
        if trusted_soft
            && !matches!(
                crate::batch::stored_entity_type(&vault.store, txn, &target)?,
                Some(crate::registry::ENTITY_TYPE_PERSON | crate::registry::ENTITY_TYPE_AGENT_DEF)
            )
        {
            return Err(ArtifactError::InvalidRecoveryArtifact(
                "retained addressing recipient missing or not a PERSON or AGENT_DEF",
            )
            .into());
        }
        if !trusted_soft
            && !crate::conversation_dag::addressed_to_echo_in_txn(
                &vault.store,
                txn,
                &source,
                &target,
                fields,
            )?
        {
            return Err(crate::error::RegistryError::ReservedEdgeKind("conversation_dag").into());
        }
    } else if !matches!(kind, EdgeKind::SpawnedBy | EdgeKind::RepliesTo)
        && let Err(reserved) = crate::edge::validate_public_edge_kind(kind)
    {
        let mandated_at =
            vault.identity_topology_mandated_shell_edge_in_txn(txn, &source, kind, &target)?;
        if !mandated_at.is_some_and(|at| {
            fields.created_at == at && kind.default_weight() == Some(fields.weight)
        }) {
            return Err(reserved);
        }
    }
    if !crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &source)?
        || !crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &target)?
    {
        return Err(
            ArtifactError::InvalidRecoveryArtifact("edge endpoint missing at recovery").into(),
        );
    }
    if matches!(kind, EdgeKind::SpawnedBy | EdgeKind::RepliesTo) {
        crate::conversation_dag::validate_received_edge(
            &vault.store,
            txn,
            source,
            kind,
            target,
            fields,
        )?;
    }
    crate::batch::validate_replayed_facet_of_edge(&vault.store, txn, source, kind, target)?;
    // A stored pair, or the canonical artifact's own link onto an erased
    // shell, is restored as it is held; a new pair its MESSAGEs refute
    // is left out, as the forward pass quarantines it, and one still
    // missing an axis waits for the forward pass.
    if kind == crate::edge::EdgeKind::Regenerates
        && !crate::edge::regeneration_stored(&vault.store, txn, &source, &target)?
        && crate::edge::regeneration_pair(&vault.store, txn, &source, &target)?
            == crate::edge::Regeneration::Refuses
    {
        return Ok(());
    }
    vault
        .batch_in()
        .edge_with_value_fields(
            &source,
            kind,
            &target,
            EdgeValueFields::from_decoded(fields),
        )
        .apply(txn)?;
    Ok(())
}

/// Lands the snapshot's conversation Parent links through the one Parent
/// door forward rematerialization uses (FIX 8857), each after the link that
/// places its target. A link the door refuses refuses the recovery; one
/// still waiting once no other link lands is left to the forward pass,
/// which holds it the same way.
fn land_parents(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    window: &str,
    tombstones: &TombstoneIndex,
    parents: &[&CanonicalBaseEdge],
) -> Result<()> {
    let mut pending = parents_in_dependency_order(parents)?;
    loop {
        let before = pending.len();
        let mut waiting = Vec::new();
        for (source, target, value) in pending {
            if !endpoints_present(vault, txn, &source, &target)? {
                return Err(ArtifactError::InvalidRecoveryArtifact(
                    "edge endpoint missing at recovery",
                )
                .into());
            }
            let tombstoned = tombstones.contains(&source) || tombstones.contains(&target);
            let outcome =
                super::submit_parent_in_txn(vault, txn, window, source, target, value, tombstoned)?;
            match outcome {
                super::ParentOutcome::Waiting => waiting.push((source, target, value)),
                super::ParentOutcome::Rejected => {
                    return Err(ArtifactError::InvalidRecoveryArtifact(
                        "conversation Parent refused recovery preflight",
                    )
                    .into());
                }
                super::ParentOutcome::Written
                | super::ParentOutcome::Unchanged
                | super::ParentOutcome::Ignored => {}
            }
        }
        if waiting.is_empty() || waiting.len() == before {
            return Ok(());
        }
        pending = waiting;
    }
}

/// The Parent links, ordered by the depth of their source in the snapshot's
/// own Parent chains, so a link lands after the one whose source is its
/// target.
fn parents_in_dependency_order<'a>(
    parents: &[&'a CanonicalBaseEdge],
) -> Result<Vec<(EntityId, EntityId, &'a [u8])>> {
    let mut links = Vec::with_capacity(parents.len());
    let mut parent_of = HashMap::new();
    for edge in parents {
        let source = EntityId::from_bytes(edge.source)?;
        let target = EntityId::from_bytes(edge.target)?;
        parent_of.entry(source).or_insert(target);
        links.push((source, target, edge.value.as_slice()));
    }
    let mut depth = HashMap::<EntityId, usize>::new();
    for &(source, _, _) in &links {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut cursor = source;
        // A cycle stops the walk; the Parent door refuses it.
        let reached = loop {
            if let Some(&known) = depth.get(&cursor) {
                break Some(known);
            }
            if !seen.insert(cursor) {
                break Some(0);
            }
            chain.push(cursor);
            match parent_of.get(&cursor) {
                Some(&next) => cursor = next,
                None => break None,
            }
        };
        let mut at = reached.map_or(0, |known| known + 1);
        for id in chain.into_iter().rev() {
            depth.insert(id, at);
            at += 1;
        }
    }
    links.sort_by_key(|(source, _, _)| depth.get(source).copied().unwrap_or(0));
    Ok(links)
}

/// Whether both endpoints of a link have a row here.
fn endpoints_present(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &EntityId,
    target: &EntityId,
) -> Result<bool> {
    Ok(
        crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, source)?
            && crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, target)?,
    )
}
