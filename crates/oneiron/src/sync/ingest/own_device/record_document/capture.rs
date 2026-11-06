//! An import's closed, uncommitted capture and its durable transport writer.

use std::collections::BTreeMap;
use std::path::PathBuf;

use heed::RwTxn;
use loro::LoroDoc;

use super::{ImportSpan, PairDigest};
use crate::error::Result;
use crate::store::Store;
use crate::store::window_record_sources::RecordDocumentSource;
use crate::sync::loro_support::map_get_bytes;
use crate::sync::skill_docs::selected_record_document;
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

/// Created only from the actual authenticated import after its materializer
/// returned without an error. It is neither admission nor a commit receipt.
pub(crate) struct CapturedRecordDocuments {
    vault: PathBuf,
    window: String,
    machine: EntityId,
    pairs: BTreeMap<EntityId, PairDigest>,
}

/// Only a genuine capture's same-writer reconstruction can construct this.
/// Holding the original mutable transaction prevents a different sink writer.
pub(crate) struct RecordDocumentSources<'write, 'env> {
    store: &'write Store,
    txn: &'write mut RwTxn<'env>,
    window: &'write str,
    machine: EntityId,
    sources: Vec<RecordDocumentSource>,
}

impl<'write, 'env> RecordDocumentSources<'write, 'env> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        &'write Store,
        &'write mut RwTxn<'env>,
        &'write str,
        EntityId,
        Vec<RecordDocumentSource>,
    ) {
        (
            self.store,
            self.txn,
            self.window,
            self.machine,
            self.sources,
        )
    }
}

impl CapturedRecordDocuments {
    pub(super) fn take(span: &mut ImportSpan) -> Self {
        Self {
            vault: span.vault.clone(),
            window: span.window.clone(),
            machine: span.machine,
            pairs: std::mem::take(&mut span.pairs),
        }
    }

    fn matches(&self, vault: &Vault, window: &WindowKey) -> bool {
        self.vault == vault.store.env.path() && self.window == window.as_str()
    }

    fn matching_sources(
        &self,
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        durable: &LoroDoc,
        window: &WindowKey,
    ) -> Result<Vec<RecordDocumentSource>> {
        if !self.matches(vault, window)
            || crate::ports::removed_in_txn(&vault.store, txn, &self.machine)?
        {
            return Ok(Vec::new());
        }
        let entities = durable.get_map("entities");
        let mut matched = Vec::new();
        for (entity, expected) in &self.pairs {
            let Some(raw) = map_get_bytes(&entities, &entity.to_hex()) else {
                continue;
            };
            let Ok(Some((head, snapshot, refinement))) =
                selected_record_document(durable, entity, &raw)
            else {
                continue;
            };
            if PairDigest::of(&raw, &head, &snapshot, refinement.as_ref())? != *expected {
                continue;
            }
            crate::sync::ingest::carried_origin_in_txn(
                vault,
                txn,
                durable,
                window.as_str(),
                entity,
                &raw,
            )?;
            if crate::ports::removed_in_txn(&vault.store, txn, entity)?
                || crate::sync::ingest::peer_row_in_txn(vault, txn, window.as_str(), entity, &raw)?
            {
                continue;
            }
            matched.push(RecordDocumentSource {
                entity: *entity,
                pair: *expected,
                head: head.encode()?,
            });
        }
        Ok(matched)
    }

    fn durable_sources<'write, 'env>(
        &self,
        vault: &'write Vault,
        txn: &'write mut RwTxn<'env>,
        window: &'write WindowKey,
    ) -> Result<RecordDocumentSources<'write, 'env>> {
        let durable = super::retained::durable_window_in_txn(vault, txn, window)?;
        let sources = self.matching_sources(vault, txn, &durable, window)?;
        Ok(RecordDocumentSources {
            store: &vault.store,
            txn,
            window: window.as_str(),
            machine: self.machine,
            sources,
        })
    }
}

/// Keep the original update and its matched source facts in one commit.
/// Without a capture, retain the original persistence path exactly.
pub(in crate::sync) fn persist_record_document_update(
    vault: &Vault,
    key: &WindowKey,
    update: Option<&[u8]>,
    captured: Option<&CapturedRecordDocuments>,
) -> Result<()> {
    let Some(captured) = captured else {
        return match update {
            Some(update) => crate::sync::bridge::persist_window_update(vault, key.as_str(), update),
            None => Ok(()),
        };
    };
    vault.with_write_txn_grouped(|txn| {
        if let Some(update) = update {
            crate::sync::bridge::persist_window_update_in_txn(vault, txn, key.as_str(), update)?;
        }
        let source = captured.durable_sources(vault, txn, key)?;
        crate::store::window_record_sources::persist_captured(source)
    })
}
