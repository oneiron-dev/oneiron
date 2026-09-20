//! Atomic native NOTE core/document admission and monotone workflow replay.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::temporal::TimeRange;

pub(crate) fn apply(
    vault: &Vault,
    doc: &LoroDoc,
    mut state: State,
    window: &str,
) -> Result<Vec<EntityId>> {
    vault.with_write_txn(|txn| {
        let mut admitted = BTreeSet::new();
        for note in state.cores.keys() {
            if !blocked(vault, txn, doc, note)?
                && !crate::sync::quarantine::unproven_remat_marker_exists_in_txn(
                    vault, txn, window, note,
                )?
            {
                admitted.insert(*note);
            }
        }
        let dropped = state
            .cores
            .keys()
            .filter(|note| !admitted.contains(note))
            .copied()
            .collect();
        state.drop_deleted(&dropped);
        state.validate()?;
        for note in state.cores.keys() {
            let Some(old) = vault
                .store
                .vault_meta
                .get(txn, &crate::note::documents::head_key(*note))?
            else {
                continue;
            };
            let previous = EntityId::from_bytes(
                old.as_ref()
                    .try_into()
                    .map_err(|_| invalid("NOTE stored head"))?,
            )?;
            let head = state
                .heads
                .get(note)
                .copied()
                .ok_or(invalid("NOTE stale inline core"))?;
            if !super::merge::reaches(&state, *note, previous, head) {
                return Err(invalid("NOTE head move lacks forward receipt"));
            }
        }
        // An old carrier must not undo a verdict or overwrite an immutable
        // receipt, even when it arrives from an already-known window frontier.
        for row in state.receipts.values() {
            if let Some(old) = vault
                .store
                .vault_meta
                .get(txn, &metadata_key(b"note_receipt:v1:", row.id))?
                && unpack::<NoteLandingReceipt>(&old)? != *row
            {
                return Err(invalid("NOTE receipt divergence"));
            }
        }
        for fork in state.forks.values() {
            if let Some(old) = vault
                .store
                .vault_meta
                .get(txn, &metadata_key(b"note_fork:v1:", fork.fork))?
            {
                let old: NoteFork = unpack(&old)?;
                if old.note != fork.note
                    || old.parent != fork.parent
                    || old.actor != fork.actor
                    || old.rewrite != fork.rewrite
                    || old.frontier != fork.frontier
                    || (!fork.decided && old.recovery_merge != fork.recovery_merge)
                    || (old.decided && !fork.decided)
                    || (old.proposal.is_some() && old.proposal != fork.proposal)
                {
                    return Err(invalid("NOTE fork divergence or stale verdict"));
                }
            }
        }
        for bundle in state.bundles.values() {
            if let Some(old) = vault
                .store
                .vault_meta
                .get(txn, &metadata_key(b"note_proposal:v1:", bundle.id))?
            {
                let old: NoteReviewBundle = unpack(&old)?;
                if old
                    .landed
                    .iter()
                    .any(|receipt| !bundle.landed.contains(receipt))
                {
                    return Err(invalid("NOTE stale proposal verdict"));
                }
            }
        }
        // Core, native snapshots, current head, text index and workflows commit
        // together. Neither the entity pass nor Observer B writes these cores.
        for (note, raw) in &state.cores {
            let header = EntityMetadataHeader::parse(raw).ok_or(invalid("NOTE header"))?;
            vault
                .batch_in()
                .put_replicated(
                    note,
                    header.entity_type,
                    TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                )
                .apply(txn)?;
            let core = crate::note::decode_note_body_using(
                &raw[ENTITY_METADATA_HEADER_LEN..],
                crate::note::NoteKind::wire,
            )?;
            if core.document_head.is_none() {
                vault
                    .batch_in()
                    .text(note, &[("markdown", &core.markdown)])
                    .apply(txn)?;
            }
        }
        for ((note, head), incoming) in &state.docs {
            let key = doc_key(*note, *head);
            let bytes = if let Some(old) = vault.store.sync_state.get(txn, &key)? {
                merge_document(&old, incoming)?
            } else {
                incoming.clone()
            };
            vault.store.sync_state.put(txn, &key, &bytes)?;
        }
        for receipt in state.receipts.values() {
            if receipt.verdict == crate::note::NoteVerdict::Reject {
                vault
                    .store
                    .sync_state
                    .delete(txn, &doc_key(receipt.note, receipt.fork))?;
            }
            vault.store.vault_meta.put(
                txn,
                &metadata_key(b"note_receipt:v1:", receipt.id),
                &pack(receipt)?,
            )?;
        }
        for (note, head) in &state.heads {
            vault.store.vault_meta.put(
                txn,
                &crate::note::documents::head_key(*note),
                head.as_bytes(),
            )?;
            let current = crate::note::documents::load_head(vault, txn, *note, *head)?;
            vault
                .batch_in()
                .text(note, &[("markdown", &current.text())])
                .apply(txn)?;
        }
        for fork in state.forks.values() {
            vault.store.vault_meta.put(
                txn,
                &metadata_key(b"note_fork:v1:", fork.fork),
                &pack(fork)?,
            )?;
        }
        for bundle in state.bundles.values() {
            vault.store.vault_meta.put(
                txn,
                &metadata_key(b"note_proposal:v1:", bundle.id),
                &pack(bundle)?,
            )?;
        }
        Ok(admitted.into_iter().collect())
    })
}
