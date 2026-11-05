//! A selected SKILL record/document pair in one live own-device import.
//!
//! Separate from the MESSAGE witness: this span vouches for transport of
//! the selected pair only, never the author, hub standing or native write
//! permission. Ordinary batch admission must still judge the logical body.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::rc::{Rc, Weak};

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue};

use super::super::entity::{IngestCtx, Residence};
use crate::entity_doc::CarriedRecordDocument;
use crate::error::Result;
use crate::sync::client::OwnDeviceImport;
use crate::sync::loro_support::{map_for_each_value_bytes, map_get_bytes};
use crate::sync::skill_docs::{SKILL_DOCS_MAP, affected_rows, selected_record_document};
use crate::sync::types::WindowKey;
use crate::{EntityId, Vault};

#[derive(Clone, Copy, PartialEq, Eq)]
struct PairDigest {
    row: [u8; 32],
    head: [u8; 32],
    snapshot: [u8; 32],
}

impl PairDigest {
    fn of(raw: &[u8], head: &CarriedRecordDocument, snapshot: &[u8]) -> Result<Self> {
        Ok(Self {
            row: *blake3::hash(raw).as_bytes(),
            head: *blake3::hash(&head.encode()?).as_bytes(),
            snapshot: *blake3::hash(snapshot).as_bytes(),
        })
    }
}

struct ImportSpan {
    vault: PathBuf,
    window: String,
    machine: EntityId,
    scope: Rc<()>,
    pairs: BTreeMap<EntityId, PairDigest>,
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
/// This helper has no call sites until the cohesive pair door is complete.
pub(in crate::sync) fn with_import<T>(
    vault: &Vault,
    import: Option<&OwnDeviceImport>,
    (key, doc): (&WindowKey, &LoroDoc),
    update: &[u8],
    land: impl FnOnce() -> T,
) -> T {
    let span = import
        .filter(|_| key.world().is_none())
        .map(|import| ImportSpan {
            vault: vault.store.env.path().to_path_buf(),
            window: key.as_str().to_owned(),
            machine: import.machine(),
            scope: Rc::new(()),
            pairs: selected_pairs(doc, update),
        });
    let _restore =
        Restore(RECORD_DOCUMENT_SPAN.with(|slot| std::mem::replace(&mut *slot.borrow_mut(), span)));
    land()
}

/// Facts of the actual selected transport. Private construction binds the
/// exact row, document and snapshot to this import and its selected window.
/// This is not a native admission proof and cannot mint SkillStateWrite.
pub(crate) struct SelectedRecordDocument<'a> {
    vault: &'a Vault,
    carrier: &'a LoroDoc,
    scope: Weak<()>,
    machine: EntityId,
    window: String,
    raw: Vec<u8>,
    head: CarriedRecordDocument,
    snapshot: Vec<u8>,
}

impl SelectedRecordDocument<'_> {
    /// Recheck at actual batch consumption. Retained data from an import
    /// that returned, or from an enclosing rather than current import,
    /// cannot authorize this transport in another write.
    pub(crate) fn recheck_transport_in_txn(
        &self,
        store: &crate::store::Store,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<bool> {
        if store.env.path() != self.vault.store.env.path() {
            return Ok(false);
        }
        let entity = self.head.entity()?;
        let expected = PairDigest::of(&self.raw, &self.head, &self.snapshot)?;
        let current = RECORD_DOCUMENT_SPAN.with(|slot| {
            slot.borrow().as_ref().is_some_and(|span| {
                Weak::ptr_eq(&self.scope, &Rc::downgrade(&span.scope))
                    && span.vault == store.env.path()
                    && span.window == self.window
                    && span.machine == self.machine
                    && span.pairs.get(&entity) == Some(&expected)
            })
        });
        if !current {
            return Ok(false);
        }
        if map_get_bytes(&self.carrier.get_map("entities"), &entity.to_hex()).as_deref()
            != Some(self.raw.as_slice())
        {
            return Ok(false);
        }
        let Some((head, snapshot)) = selected_record_document(self.carrier, &entity, &self.raw)?
        else {
            return Ok(false);
        };
        if PairDigest::of(&self.raw, &head, &snapshot)? != expected {
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
    let Some((head, snapshot)) = selected_record_document(doc, entity, raw)? else {
        return Ok(None);
    };
    let digest = PairDigest::of(raw, &head, &snapshot)?;
    let machine = RECORD_DOCUMENT_SPAN.with(|slot| {
        slot.borrow().as_ref().and_then(|span| {
            (span.vault == ctx.vault.store.env.path()
                && span.window == ctx.window_key
                && span.pairs.get(entity) == Some(&digest))
            .then(|| (span.machine, Rc::downgrade(&span.scope)))
        })
    });
    let Some((machine, scope)) = machine else {
        return Ok(None);
    };
    if crate::sync::ingest::peer_row_in_txn(ctx.vault, txn, ctx.window_key, entity, raw)? {
        return Ok(None);
    }
    Ok(Some(SelectedRecordDocument {
        vault: ctx.vault,
        carrier: doc,
        scope,
        machine,
        window: ctx.window_key.to_owned(),
        raw: raw.to_vec(),
        head,
        snapshot,
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
            let (head, snapshot) = selected_record_document(&candidate, &entity, &raw).ok()??;
            let digest = PairDigest::of(&raw, &head, &snapshot).ok()?;
            Some((entity, digest))
        })
        .collect()
}
