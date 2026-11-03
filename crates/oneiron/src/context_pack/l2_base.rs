//! Content-addressed persona/user evidence prefix. Retrieval remains the read-time delta.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::Vault;
use crate::claim::ScopedRead;
use crate::disclosure::DisclosureContext;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::PipelineBuilder;
use crate::ppr::PprNodeVisibility;

#[cfg(test)]
mod tests;

pub(crate) use crate::store::l2_evidence::L2BaseCache;
pub use crate::store::l2_evidence::L2BaseSummary;

/// Select the vault-owned user identity. A generic PERSON row is not proof
/// that it is this context's user. Its evidence still passes every retrieval,
/// disclosure, and scoped-read gate.
pub(super) fn default_l2_subjects(
    vault: &Vault,
    reader: Option<&ScopedRead<'_>>,
) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let owner = crate::vault::embedded_owner_actor_id()?;
    let person_id = match reader {
        Some(read) => read.actor_key().authenticated_person(),
        None => Some(owner),
    };
    let principal = if let Some(id) = person_id {
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &id)?
            .as_deref()
            .and_then(crate::batch::EntityMetadataHeader::parse)
            .filter(|header| header.entity_type == crate::registry::ENTITY_TYPE_PERSON)
            .map(|_| id)
    } else {
        None
    };
    let mut subjects = BTreeSet::new();
    if crate::ports::EntityStoreRead::port_entity_present(&vault.store, &txn, &owner)? {
        subjects.insert(owner);
    }
    if let Some(person) = principal {
        subjects.insert(person);
    }
    drop(txn);
    if subjects.len() > 8 {
        // An automatically discovered optional prefix must not turn an
        // otherwise valid context pack into a failed read. Explicit selections
        // read every deduplicated subject.
        return Ok(Vec::new());
    }
    Ok(subjects.into_iter().collect())
}

pub(super) fn produce_l2_base(
    vault: &Vault,
    pipeline: &PipelineBuilder<'_>,
    subjects: &[EntityId],
    clamp: Option<&DisclosureContext>,
    reader: Option<&ScopedRead<'_>>,
    cache_enabled: bool,
) -> Result<Option<L2BaseSummary>> {
    if subjects.is_empty() {
        return Ok(None);
    }
    if reader.is_some_and(|reader| reader.vault().vault_id() != vault.vault_id()) {
        return Err(Error::InvalidConfig(
            "L2 reader belongs to another vault".into(),
        ));
    }
    if let Some(reader) = reader {
        reader.persist_grant_clock()?;
    }
    // Capture before opening the snapshot. A later erasure invalidates any
    // producer with this revision, even if it finishes after that write.
    let revision = vault.store.env.info().last_txn_id;
    let txn = vault.store.env.read_txn()?;
    let admitted = admitted_l2_evidence(vault, pipeline, &txn, subjects, clamp, reader)?;
    if admitted.is_empty() {
        return Ok(None);
    }
    let subjects: BTreeSet<_> = subjects.iter().copied().collect();
    let rendered = render_l2_rows_with_handles(pipeline, &txn, &admitted)?;
    let content_hash = evidence_hash(
        subjects.iter().copied(),
        &admitted,
        &rendered.handle_spellings,
        pipeline,
    )?;
    if cache_enabled {
        let cache = vault
            .store
            .l2_base_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(summary) = cache.entries.get(&content_hash) {
            return Ok(Some(summary.clone()));
        }
    }
    let max_field_chars = rendered
        .rows
        .iter()
        .map(max_string_chars)
        .max()
        .unwrap_or(0);
    let body = serde_json::to_string(&rendered.rows)
        .map_err(|_| Error::InvariantViolation("L2 JSON render"))?;
    let summary = L2BaseSummary {
        content_hash,
        body: Arc::from(body),
        evidence_ids: admitted.into_iter().map(|(id, _)| id).collect(),
        subjects: subjects.into_iter().collect(),
        max_field_chars,
    };
    if cache_enabled {
        let mut cache = vault
            .store
            .l2_base_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache
            .erased_at_revision
            .is_none_or(|erased| revision > erased)
        {
            // A concurrent producer may already have rendered this content.
            if let Some(existing) = cache.entries.get(&content_hash) {
                return Ok(Some(existing.clone()));
            }
            cache.insert(summary.clone());
        }
    }
    Ok(Some(summary))
}

/// Re-admit through the producer's retrieval gates on the hydration snapshot.
/// A changed evidence set, body, handle, authority, world or temporal admission
/// drops the entire optional prefix.
pub(super) fn revalidate_l2_base(
    vault: &Vault,
    pipeline: &PipelineBuilder<'_>,
    txn: &heed::RoTxn<'_>,
    summary: &L2BaseSummary,
    clamp: Option<&DisclosureContext>,
    reader: Option<&ScopedRead<'_>>,
) -> Result<bool> {
    let admitted = admitted_l2_evidence(vault, pipeline, txn, &summary.subjects, clamp, reader)?;
    let rendered = render_l2_rows_with_handles(pipeline, txn, &admitted)?;
    Ok(evidence_hash(
        summary.subjects.iter().copied(),
        &admitted,
        &rendered.handle_spellings,
        pipeline,
    )? == summary.content_hash)
}

fn admitted_l2_evidence(
    vault: &Vault,
    pipeline: &PipelineBuilder<'_>,
    txn: &heed::RoTxn<'_>,
    subjects: &[EntityId],
    clamp: Option<&DisclosureContext>,
    reader: Option<&ScopedRead<'_>>,
) -> Result<Vec<(EntityId, crate::claim::ClaimBody)>> {
    let visibility = reader
        .map(|reader| reader.retrieval_visibility_in(txn, None))
        .transpose()?;
    let evidence = pipeline.l2_evidence_in(txn, subjects)?;
    let quarantine = super::quarantine::load_pack_quarantine_index(&vault.store, txn)?;
    let mut bodies = std::collections::HashMap::new();
    let mut admitted = Vec::new();
    for (id, body) in evidence {
        pipeline.answer_checkpoint(Error::IndexOverflow("L2 evidence claims"))?;
        if let Some(visibility) = &visibility
            && !visibility.ppr_node_visible(txn, &id)?
        {
            continue;
        }
        if let Some(clamp) = clamp
            && !super::retained_copies::clamp_admits(
                clamp,
                &vault.store,
                txn,
                &id,
                crate::registry::ENTITY_TYPE_CLAIM,
                Some(&body),
            )?
        {
            continue;
        }
        bodies.insert(id, body.clone());
        super::validation::validate_pack_entity_reference(
            &pipeline.store_read(),
            txn,
            &id,
            &mut bodies,
            &quarantine,
        )?;
        admitted.push((id, body));
    }
    admitted.sort_unstable_by_key(|(id, _)| *id);
    Ok(admitted)
}

struct RenderedL2Rows {
    rows: Vec<serde_json::Value>,
    handle_spellings: Vec<String>,
}

fn render_l2_rows_with_handles(
    pipeline: &PipelineBuilder<'_>,
    txn: &heed::RoTxn<'_>,
    admitted: &[(EntityId, crate::claim::ClaimBody)],
) -> Result<RenderedL2Rows> {
    let content = &pipeline.store_read();
    let mut rows = Vec::with_capacity(admitted.len());
    let mut handle_spellings = Vec::new();
    let mut unresolved_short_handles = 0usize;
    for (id, body) in admitted {
        pipeline.answer_checkpoint(Error::IndexOverflow("L2 evidence claims"))?;
        let crate::claim::ClaimSubject::Entity(subject) = body.subject else {
            return Err(Error::InvariantViolation("L2 non-entity subject"));
        };
        let (id_handle, unresolved) = read_l2_handle(content, txn, id)?;
        unresolved_short_handles += unresolved as usize;
        handle_spellings.push(id_handle.clone());
        let (subject_handle, unresolved) = read_l2_handle(content, txn, &subject)?;
        unresolved_short_handles += unresolved as usize;
        handle_spellings.push(subject_handle.clone());
        let world_handle = match body.world {
            Some(world) => {
                let (handle, unresolved) = read_l2_handle(content, txn, &world)?;
                unresolved_short_handles += unresolved as usize;
                handle_spellings.push(handle.clone());
                Some(handle)
            }
            None => None,
        };
        // Parts that read as a secret together, before the projection drops a
        // float's width, render as null.
        let secret = crate::batch::export::claim_reads_as_secret(body);
        let mut value = if secret {
            serde_json::Value::Null
        } else {
            crate::serialize::null_credentials("val", &super::hydration::rmpv_to_json(&body.value))
        };
        // Every L2 format shares the same cached, credential-safe projection.
        crate::serialize::scrub_provider_credential("val", &mut value);
        rows.push(serde_json::json!({
            "id": id_handle, "subj": subject_handle,
            "pred": (!secret).then_some(&body.predicate), "val": value,
            "world": world_handle,
        }));
    }
    if unresolved_short_handles > 0 {
        tracing::debug!(
            unresolved_short_handles,
            "L2 prefix kept full ids for unresolved short handles"
        );
    }
    Ok(RenderedL2Rows {
        rows,
        handle_spellings,
    })
}

fn read_l2_handle(
    content: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<(String, bool)> {
    match crate::ports::ShortIdStoreRead::port_short_id_reference(content, txn, id) {
        Ok(Some((handle, _))) => Ok((handle, false)),
        Ok(None) | Err(Error::CorruptedIndex(_)) => Ok((id.to_hex(), true)),
        Err(error) => Err(error),
    }
}

fn evidence_hash(
    subjects: impl ExactSizeIterator<Item = EntityId>,
    admitted: &[(EntityId, crate::claim::ClaimBody)],
    handle_spellings: &[String],
    pipeline: &PipelineBuilder<'_>,
) -> Result<[u8; 32]> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:l2-base:v1");
    digest.update(&(subjects.len() as u64).to_be_bytes());
    for subject in subjects {
        pipeline.answer_checkpoint(Error::IndexOverflow("L2 subject adjacency"))?;
        digest.update(subject.as_bytes());
    }
    for (id, body) in admitted {
        pipeline.answer_checkpoint(Error::IndexOverflow("L2 evidence bytes"))?;
        let raw = crate::claim::encode_claim_body(body)?;
        digest.update(id.as_bytes());
        digest.update(&(raw.len() as u64).to_be_bytes());
        digest.update(&raw);
    }
    digest.update(b"oneiron:l2-handles:v1");
    digest.update(&(handle_spellings.len() as u64).to_be_bytes());
    for handle in handle_spellings {
        pipeline.answer_checkpoint(Error::IndexOverflow("L2 evidence bytes"))?;
        digest.update(&(handle.len() as u64).to_be_bytes());
        digest.update(handle.as_bytes());
    }
    Ok(*digest.finalize().as_bytes())
}

fn max_string_chars(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::String(text) => text.chars().count(),
        serde_json::Value::Array(values) => values.iter().map(max_string_chars).max().unwrap_or(0),
        serde_json::Value::Object(values) => {
            values.values().map(max_string_chars).max().unwrap_or(0)
        }
        _ => 0,
    }
}
