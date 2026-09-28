//! Recovery preflight through the existing replay doors, in an aborted transaction.

use super::Materializer;
use crate::batch::EdgeValueFields;
use crate::error::{ArtifactError, Result};
use crate::recovery::CanonicalSnapshot;
use crate::sync::ingest::{EntityStep, IngestCtx, ingest_entity_in_txn};
use crate::{EntityId, Vault};
use loro::LoroDoc;

/// All writes here are speculative LMDB pages. The transaction is ALWAYS
/// aborted: a bad later entity/edge cannot publish an earlier valid record.
/// The real forward pass repeats the same admission before committing.
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
    let _guard = materializer.lock();
    let mut txn = vault.store.env.write_txn()?;
    crate::recovery::validate_window_documents(doc)?;
    snapshot.preflight_note_recovery(vault, &txn)?;
    let tombstones_map = doc.get_map("tombstones");
    let ingest = IngestCtx::new(
        vault,
        &snapshot.window,
        materializer.lease_vault_id(),
        &tombstones_map,
    );
    for entity in &snapshot.entity_blobs {
        let id = EntityId::from_bytes(entity.id)?;
        if let Some((blob, tombstone)) = crate::recovery::retained_soft_shell(doc, &id) {
            crate::batch::restore_recovery_shell_in_txn(vault, &mut txn, &id, &blob, &tombstone)?;
        } else if let EntityStep::Quarantine(refusal) =
            ingest_entity_in_txn(&ingest, &mut txn, &id.to_hex(), Some(&entity.blob))?
        {
            return Err(refusal.err);
        }
        if crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &id)?.as_deref()
            != Some(entity.blob.as_slice())
        {
            return Err(ArtifactError::InvalidRecoveryArtifact(
                "entity refused recovery preflight",
            )
            .into());
        }
    }
    for edge in &snapshot.base_edges {
        let source = EntityId::from_bytes(edge.source)?;
        let target = EntityId::from_bytes(edge.target)?;
        let kind = crate::edge::EdgeKind::try_from_u8(edge.kind).ok_or(crate::Error::InvalidKey)?;
        let fields = crate::edge::decode_edge_value_for_kind(kind, &edge.value)?;
        if kind == crate::edge::EdgeKind::AddressedTo {
            let trusted_soft = crate::recovery::trusted_soft_addressing_edge(
                snapshot,
                &source,
                &target,
                &edge.value,
            )?;
            if trusted_soft
                && crate::batch::stored_entity_type(&vault.store, &txn, &target)?
                    != Some(crate::registry::ENTITY_TYPE_PERSON)
            {
                return Err(ArtifactError::InvalidRecoveryArtifact(
                    "retained addressing recipient missing or not a PERSON",
                )
                .into());
            }
            if !trusted_soft
                && !crate::conversation_dag::addressed_to_echo_in_txn(
                    &vault.store,
                    &txn,
                    &source,
                    &target,
                    fields,
                )?
            {
                return Err(
                    crate::error::RegistryError::ReservedEdgeKind("conversation_dag").into(),
                );
            }
        } else if let Err(reserved) = crate::edge::validate_public_edge_kind(kind) {
            let mandated_at =
                vault.identity_topology_mandated_shell_edge_in_txn(&txn, &source, kind, &target)?;
            if !mandated_at.is_some_and(|at| {
                fields.created_at == at && kind.default_weight() == Some(fields.weight)
            }) {
                return Err(reserved);
            }
        }
        if crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &source)?.is_none()
            || crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &target)?
                .is_none()
        {
            return Err(ArtifactError::InvalidRecoveryArtifact(
                "edge endpoint missing at recovery",
            )
            .into());
        }
        crate::batch::validate_facet_of_edge(&vault.store, &txn, source, kind, target)?;
        vault
            .batch_in()
            .edge_with_value_fields(
                &source,
                kind,
                &target,
                EdgeValueFields::from_decoded(fields),
            )
            .apply(&mut txn)?;
    }
    for tombstone in &snapshot.tombstones {
        let entity = EntityId::from_bytes(tombstone.id)?;
        vault.apply_replayed_tombstone_in_txn(&mut txn, &entity, &tombstone.value)?;
    }
    crate::recovery::materialize_recovery_notes_in_txn(vault, &mut txn, doc, snapshot)?;
    // Drop aborts even on success; in particular lease/quota debits and all
    // quarantine rows remain speculative and are never committed here.
    drop(txn);
    Ok(())
}
