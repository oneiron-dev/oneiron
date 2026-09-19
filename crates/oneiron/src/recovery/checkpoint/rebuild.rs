//! Rebuild mechanical projections and reset leased attempt ownership.
use super::codec_error;
use crate::{
    EntityId, Error, Result, Vault,
    attempt_queue::AttemptState,
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    temporal::TimeRange,
};
pub(super) fn unlease_attempt(key: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    let (&version, _) = bytes.split_first().ok_or_else(codec_error)?;
    let mut record = crate::attempt_queue::decode_record(
        bytes,
        crate::attempt_queue::AttemptId::from_bytes(key)?,
    )?;
    if record.state == AttemptState::Landing {
        // A landing needs its executor to finish its audited cancellation.
        // Do not invent a completed/cancelled receipt during backup.
        return Err(Error::InvalidConfig(
            "checkpoint requires landing attempts to settle".into(),
        ));
    }
    if record.state == AttemptState::Leased {
        record.state = AttemptState::Queued;
        record.lease_owner = None;
        record.claimed_at = None;
    }
    let mut out = vec![version];
    out.extend(rmp_serde::to_vec_named(&record).map_err(|_| codec_error())?);
    Ok(out)
}
pub(super) fn rebuild(vault: &Vault) -> Result<(usize, usize, usize)> {
    vault.with_write_txn(|txn| {
        let rows: Vec<_> = vault
            .store
            .entities
            .iter(txn)?
            .map(|r| r.map(|(k, v)| (k.to_vec(), v.to_vec())))
            .collect::<std::result::Result<_, _>>()?;
        let mut embeddings = 0;
        for (key, raw) in &rows {
            let id = EntityId::from_bytes(key.as_slice().try_into().map_err(|_| codec_error())?)?;
            let header = EntityMetadataHeader::parse(raw).ok_or_else(codec_error)?;
            crate::batch::stage_entity_index_rows(
                &vault.store,
                txn,
                &id,
                header.entity_type,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
            )?;
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let mut embeddable = !body.is_empty();
            match header.entity_type {
                crate::registry::ENTITY_TYPE_CLAIM => {
                    let claim = crate::claim::decode_claim_body(body, true)?;
                    embeddable &= claim.predicate != crate::claim::PREDICATE_LEXICAL_QUERY_HINT;
                    crate::dreamer_runner::index_dreamer_milestone_claim_for_put(
                        &vault.store,
                        txn,
                        &id,
                        &claim,
                        header.learned_at,
                    )?;
                    crate::llm::index_dreamer_step_claim_for_put(
                        &vault.store,
                        txn,
                        &id,
                        &claim,
                        header.learned_at,
                    )?;
                }
                crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT => {
                    crate::counterparty_contact::rebuild_checkpoint_contact_index(
                        &vault.store,
                        txn,
                        id,
                        body,
                    )?;
                }
                crate::registry::ENTITY_TYPE_CONNECTOR_KEY => {
                    crate::connector_key::rebuild_checkpoint_connector_index(
                        &vault.store,
                        txn,
                        id,
                        body,
                    )?;
                }
                crate::registry::ENTITY_TYPE_OUTBOUND_GRANT => {
                    crate::outbound_grant::rebuild_checkpoint_grant_index(
                        &vault.store,
                        txn,
                        id,
                        body,
                    )?;
                }
                _ => {}
            }
            if embeddable
                && matches!(
                    header.entity_type,
                    crate::registry::ENTITY_TYPE_CLAIM | crate::registry::ENTITY_TYPE_SUMMARY
                )
            {
                vault
                    .store
                    .mark_pending_embedding(txn, &id, &raw[ENTITY_METADATA_HEADER_LEN..])?;
                embeddings += 1;
            }
        }
        let sources: Vec<_> = vault
            .store
            .vault_meta
            .prefix_iter(txn, b"index_source:text:v1:")?
            .map(|r| r.map(|(k, v)| (k.to_vec(), v.to_vec())))
            .collect::<std::result::Result<_, _>>()?;
        let mut texts = 0;
        for (key, source) in sources {
            let id = EntityId::from_bytes(
                key[b"index_source:text:v1:".len()..]
                    .try_into()
                    .map_err(|_| codec_error())?,
            )?;
            if vault.store.entities.get(txn, id.as_bytes())?.is_none() {
                continue;
            }
            let fields: Vec<(String, String)> =
                rmp_serde::from_slice(&source).map_err(|_| codec_error())?;
            crate::bm25::index_text(&vault.store, txn, &vault.analyzer, &id, &fields)?;
            texts += 1;
        }
        let phonetic: Vec<_> = vault
            .store
            .vault_meta
            .prefix_iter(txn, b"index_source:phonetic:v1:")?
            .map(|row| row.map(|(key, value)| (key.to_vec(), value.to_vec())))
            .collect::<std::result::Result<_, _>>()?;
        for (key, raw) in phonetic {
            let id = EntityId::from_bytes(
                key[b"index_source:phonetic:v1:".len()..]
                    .try_into()
                    .map_err(|_| codec_error())?,
            )?;
            if vault.store.entities.get(txn, id.as_bytes())?.is_none() {
                continue;
            }
            let codes: Vec<String> = rmp_serde::from_slice(&raw).map_err(|_| codec_error())?;
            crate::batch::apply_phonetic(&vault.store, txn, id, &codes)?;
        }
        let windows: Vec<_> = vault
            .store
            .sync_state
            .prefix_iter(txn, "d:w:")?
            .map(|r| r.map(|(k, _)| k.into_owned()))
            .collect::<std::result::Result<_, _>>()?;
        for key in windows {
            vault
                .store
                .sync_state
                .put(txn, &format!("fr:w:{}", &key[4..]), &[1])?;
        }
        crate::attempt_queue::rebuild_checkpoint_indexes(&vault.store, txn)?;
        vault.store.rebuild_commitment_due_sidecars(txn)?;
        vault.store.rebuild_pending_gate_consent_sidecars(txn)?;
        // Runtime budget rows were excluded from the image, not refunded in the billing ledger.
        Ok((rows.len(), texts, embeddings))
    })
}

/// Backfills that own their transactions run after the base index transaction.
pub(super) fn rebuild_auxiliary(vault: &Vault, checkpoint_time: u64) -> Result<()> {
    crate::skill_hub::backfill_content_hash_index_if_needed(vault)?;
    crate::skill_convert::rebuild_skill_source_index(vault)?;
    crate::edit_distance::routing::rebuild_routing_projection(vault)?;
    crate::edit_distance::reservoir::rebuild_reservoir_index(vault)?;
    vault.rebuild_ramp_stats_from_receipts()?;
    crate::human_task::HumanTaskFollowupDriver::new(vault).rebuild_cursors(checkpoint_time)?;
    Ok(())
}
