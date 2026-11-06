//! A selected SKILL record/document pair in one live own-device import.
//!
//! Separate from the MESSAGE witness: this span vouches for transport of
//! the selected pair only, never the author, hub standing or native write
//! permission. Ordinary batch admission must still judge the logical body.

mod capture;
mod retained;
pub(in crate::sync) use capture::persist_record_document_update;
pub(crate) use capture::{CapturedRecordDocuments, RecordDocumentSources};

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::rc::{Rc, Weak};

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue};

use super::super::entity::{IngestCtx, Residence};
use crate::entity_doc::{CarriedRecordDocument, RefinementOriginSource};
use crate::error::{Error, Result};
use crate::sync::client::OwnDeviceImport;
use crate::sync::loro_support::{map_for_each_value_bytes, map_get_bytes};
use crate::sync::skill_docs::{SKILL_DOCS_MAP, affected_rows, selected_record_document};
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

use crate::store::window_record_sources::RecordDocumentPair as PairDigest;

struct ImportSpan {
    vault: PathBuf,
    window: String,
    machine: EntityId,
    scope: Rc<()>,
    pairs: BTreeMap<EntityId, PairDigest>,
    materializer_error: Option<Error>,
}

thread_local! {
    static RECORD_DOCUMENT_SPAN: RefCell<Option<ImportSpan>> = const { RefCell::new(None) };
}

struct Restore(Option<ImportSpan>);

impl Drop for Restore {
    fn drop(&mut self) {
        let outer = self.0.take();
        RECORD_DOCUMENT_SPAN.with(|slot| *slot.borrow_mut() = outer);
    }
}

/// Run beside, not instead of, the original MESSAGE import span. A nested
/// import with no proof clears this span until that import returns too.
/// The outer result reports only an actual materializer error in this span;
/// success pairs the unchanged land value with an uncommitted capture. Its
/// persistence owner rechecks the durable carrier in the original writer.
/// An error does not
/// undo Loro's import: its owner must discard the live window before ACK or
/// persistence, as on its existing persist-failure path.
/// The client inlet handles the outer error before either durability path;
/// the land closure still owns and returns its original transport result.
pub(in crate::sync) fn with_import<T>(
    vault: &Vault,
    import: Option<&OwnDeviceImport>,
    (key, doc): (&WindowKey, &LoroDoc),
    update: &[u8],
    land: impl FnOnce() -> T,
) -> Result<(T, Option<CapturedRecordDocuments>)> {
    let span = import
        .filter(|_| key.world().is_none())
        .map(|import| ImportSpan {
            vault: vault.store.env.path().to_path_buf(),
            window: key.as_str().to_owned(),
            machine: import.machine(),
            scope: Rc::new(()),
            pairs: selected_pairs(doc, update),
            materializer_error: None,
        });
    let _restore =
        Restore(RECORD_DOCUMENT_SPAN.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), span)));
    let landed = land();
    let (error, captured) = RECORD_DOCUMENT_SPAN.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(span) = slot.as_mut() else {
            return (None, None);
        };
        let error = span.materializer_error.take();
        let captured = (error.is_none() && !span.pairs.is_empty())
            .then(|| CapturedRecordDocuments::take(span));
        (error, captured)
    });
    match error {
        Some(error) => Err(error),
        None => Ok((landed, captured)),
    }
}

/// Retain the original failed entity transaction's error for this live import.
/// Matching carrier data identifies the affected import; it grants no admission.
/// The caller has already logged the error and keeps its original retry markers.
pub(in crate::sync) fn record_document_materializer_failed(
    vault: &Vault,
    window: &str,
    delta: &loro::event::MapDelta<'_>,
    error: Error,
) {
    RECORD_DOCUMENT_SPAN.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(span) = slot.as_mut() else {
            return;
        };
        if span.vault != vault.store.env.path()
            || span.window != window
            || span.materializer_error.is_some()
        {
            return;
        }
        let affected = delta.updated.iter().any(|(key, value)| {
            let Some(loro::ValueOrContainer::Value(LoroValue::Binary(raw))) = value else {
                return false;
            };
            let Ok(entity) = EntityId::from_hex(key) else {
                return false;
            };
            span.pairs
                .get(&entity)
                .is_some_and(|pair| pair.row == *blake3::hash(raw.as_ref()).as_bytes())
        });
        if affected {
            span.materializer_error = Some(error);
        }
    });
}

enum RecordDocumentTransport {
    Live(Weak<()>),
    Retained(crate::store::window_record_sources::RetainedRecordDocumentSource),
}

/// Facts of the selected transport, from the current import or its retained
/// Store source and exact durable carrier. Neither is native admission and
/// neither can mint SkillStateWrite.
pub(crate) struct SelectedRecordDocument<'a> {
    vault: &'a Vault,
    carrier: &'a LoroDoc,
    transport: RecordDocumentTransport,
    machine: EntityId,
    window: String,
    raw: Vec<u8>,
    head: CarriedRecordDocument,
    snapshot: Vec<u8>,
    refinement: Option<RefinementOriginSource>,
}

impl SelectedRecordDocument<'_> {
    /// Recheck at actual batch consumption. A live scope cannot outlive its
    /// import; a retained source must still match its Store row and the
    /// actual durable carrier in this same transaction.
    pub(crate) fn recheck_transport_in_txn(
        &self,
        store: &crate::store::Store,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<bool> {
        if store.env.path() != self.vault.store.env.path() {
            return Ok(false);
        }
        let entity = self.head.entity()?;
        let expected = PairDigest::of(
            &self.raw,
            &self.head,
            &self.snapshot,
            self.refinement.as_ref(),
        )?;
        let current = match &self.transport {
            RecordDocumentTransport::Live(scope) => RECORD_DOCUMENT_SPAN.with(|slot| {
                slot.borrow().as_ref().is_some_and(|span| {
                    Weak::ptr_eq(scope, &Rc::downgrade(&span.scope))
                        && span.vault == store.env.path()
                        && span.window == self.window
                        && span.machine == self.machine
                        && span.pairs.get(&entity) == Some(&expected)
                })
            }),
            RecordDocumentTransport::Retained(source) => {
                retained::recheck_in_txn(self, source, txn, &entity, &expected)?
            }
        };
        if !current {
            return Ok(false);
        }
        if map_get_bytes(&self.carrier.get_map("entities"), &entity.to_hex()).as_deref()
            != Some(self.raw.as_slice())
        {
            return Ok(false);
        }
        let Some((head, snapshot, refinement)) =
            selected_record_document(self.carrier, &entity, &self.raw)?
        else {
            return Ok(false);
        };
        if PairDigest::of(&self.raw, &head, &snapshot, refinement.as_ref())? != expected {
            return Ok(false);
        }
        Ok(!crate::sync::ingest::peer_row_in_txn(
            self.vault,
            txn,
            &self.window,
            &entity,
            &self.raw,
        )?)
    }

    pub(crate) fn vault(&self) -> &Vault {
        self.vault
    }

    pub(crate) fn machine(&self) -> EntityId {
        self.machine
    }

    pub(crate) fn window(&self) -> &str {
        &self.window
    }

    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub(crate) fn head(&self) -> &CarriedRecordDocument {
        &self.head
    }

    pub(crate) fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }

    /// Exact transported FIRST bytes, not a local origin or admission proof.
    pub(crate) fn refinement_source(&self) -> Option<&RefinementOriginSource> {
        self.refinement.as_ref()
    }
}

/// Bind the actual current carrier in the same writer that recorded its
/// peer origin. A relay of peer-origin bytes never gains an own-device pair.
pub(in crate::sync) fn selected_in_txn<'a>(
    ctx: &IngestCtx<'a>,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
    raw: &[u8],
) -> Result<Option<SelectedRecordDocument<'a>>> {
    let doc = match ctx.residence {
        Some(
            Residence::Quarantine(doc)
            | Residence::Forward {
                doc,
                trusted: false,
            },
        ) => doc,
        _ => return Ok(None),
    };
    let transport = RECORD_DOCUMENT_SPAN.with(|slot| {
        slot.borrow().as_ref().and_then(|span| {
            if span.vault != ctx.vault.store.env.path() || span.window != ctx.window_key {
                return None;
            }
            let digest = *span.pairs.get(entity)?;
            Some((span.machine, Rc::downgrade(&span.scope), digest))
        })
    });
    let Some((head, snapshot, refinement)) = selected_record_document(doc, entity, raw)? else {
        return Ok(None);
    };
    let expected = PairDigest::of(raw, &head, &snapshot, refinement.as_ref())?;
    let (machine, transport) = match transport {
        Some((machine, scope, imported)) => {
            if imported != expected {
                return Ok(None);
            }
            (machine, RecordDocumentTransport::Live(scope))
        }
        None => {
            let Some(source) = retained::select_in_txn(ctx, txn, entity, raw, &expected)? else {
                return Ok(None);
            };
            (source.machine(), RecordDocumentTransport::Retained(source))
        }
    };
    if crate::sync::ingest::peer_row_in_txn(ctx.vault, txn, ctx.window_key, entity, raw)? {
        return Ok(None);
    }
    Ok(Some(SelectedRecordDocument {
        vault: ctx.vault,
        carrier: doc,
        transport,
        machine,
        window: ctx.window_key.to_owned(),
        raw: raw.to_vec(),
        head,
        snapshot,
        refinement,
    }))
}

/// A head or part update can complete a row received earlier. Its selected
/// pair is bound to the new import, but the old row is re-presented to every
/// ordinary gate; the current machine is not taken to be its author.
fn selected_pairs(doc: &LoroDoc, update: &[u8]) -> BTreeMap<EntityId, PairDigest> {
    let Ok(meta) = LoroDoc::decode_import_blob_meta(update, true) else {
        return BTreeMap::new();
    };
    let candidate = if meta.mode.is_snapshot() {
        match LoroDoc::from_snapshot(update) {
            Ok(candidate) => candidate,
            Err(_) => return BTreeMap::new(),
        }
    } else {
        let candidate = doc.fork();
        if !candidate
            .import(update)
            .is_ok_and(|status| status.pending.is_none())
        {
            return BTreeMap::new();
        }
        candidate
    };
    let mut rows = BTreeSet::new();
    let mut heads = BTreeSet::new();
    if meta.mode.is_snapshot() {
        map_for_each_value_bytes(&candidate.get_map("entities"), |key, raw| {
            if raw.is_some()
                && let Ok(entity) = EntityId::from_hex(key)
            {
                rows.insert(entity);
            }
        });
    } else {
        let entities = ContainerID::new_root("entities", ContainerType::Map);
        let sidecars = ContainerID::new_root(SKILL_DOCS_MAP, ContainerType::Map);
        let sent = candidate.export_json_updates(&meta.partial_start_vv, &meta.partial_end_vv);
        for op in sent.changes.into_iter().flat_map(|change| change.ops) {
            if let JsonOpContent::Map(MapOp::Insert {
                key,
                value: LoroValue::Binary(_),
            }) = op.content
            {
                if op.container == entities {
                    if let Ok(entity) = EntityId::from_hex(&key) {
                        rows.insert(entity);
                    }
                } else if op.container == sidecars {
                    heads.insert(key);
                }
            }
        }
        rows.extend(affected_rows(&candidate, &heads));
    }
    let entities = candidate.get_map("entities");
    rows.into_iter()
        .filter_map(|entity| {
            let raw = map_get_bytes(&entities, &entity.to_hex())?;
            let (head, snapshot, refinement) =
                selected_record_document(&candidate, &entity, &raw).ok()??;
            let digest = PairDigest::of(&raw, &head, &snapshot, refinement.as_ref()).ok()?;
            Some((entity, digest))
        })
        .collect()
}
