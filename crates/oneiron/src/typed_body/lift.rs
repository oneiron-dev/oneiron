//! Typed bodies the historical lift sweep reads again (OF-067, Engine ruling
//! G2 = b). A typed body's operation log is its receipt ledger: a new call
//! that brings a key into a clean body is refused, and a body that held one
//! before keeps it. The sweep marks the keys of each text in a body's state
//! (owner ruling C2), under that text's hash: an office body's runs and
//! cells, a deck's slide text and each stamped operation of its fork log.
//! One door serves every typed body and each of its forks. The snapshot, the
//! operations, the receipts and every frontier stay as they are. A reader
//! other than the owner reads each lifted key as its handle, a writer that
//! carries a handle back writes its value again, and a commit on a body that
//! still reads as secret marks the texts it leaves.

use heed::{RoTxn, RwTxn};
use loro::LoroDoc;

use super::{DOCS, FORK_DOCS, HEADS, load};
use crate::Vault;
use crate::batch::secret_scan::{
    CarrierText, LiftedKeys, carrier_text_placeable, carrier_texts_hit_in_txn,
    mark_carrier_texts_in_txn, propose_typed_body_at_in_txn, typed_body_at_proposal_due_in_txn,
    write_payload_hit,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::masked_file_in_txn;
use crate::side_table::{self, SideTableDecl};
use crate::store::Store;

/// One family of a typed body's stored documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypedBodyRows {
    /// The live body.
    Doc,
    /// One fork's body.
    ForkDoc,
}

impl TypedBodyRows {
    const fn decl(self) -> &'static SideTableDecl {
        match self {
            Self::Doc => &side_table::TYPED_BODY_DOC,
            Self::ForkDoc => &side_table::TYPED_BODY_FORK_DOC,
        }
    }
}

/// The body one stored row of `rows` holds, by its key after the table's
/// prefix: `None` for a row that is gone or a key no row of it has.
fn body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    rows: TypedBodyRows,
    key: &[u8],
) -> Result<Option<LoroDoc>> {
    let id = |bytes: Option<&[u8]>| {
        bytes
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .and_then(|id| EntityId::from_bytes(id).ok())
    };
    match rows {
        TypedBodyRows::Doc => {
            let Some(entity) = id(Some(key)) else {
                return Ok(None);
            };
            let Some(bytes) = DOCS.get(store, txn, &entity)? else {
                return Ok(None);
            };
            let frontier = HEADS.get(store, txn, &entity)?.map(|head| head.frontier);
            load(Some(bytes), frontier.as_deref()).map(Some)
        }
        TypedBodyRows::ForkDoc => {
            let (Some(entity), Some(fork)) = (id(key.get(..16)), id(key.get(16..))) else {
                return Ok(None);
            };
            FORK_DOCS
                .get(store, txn, &(entity, fork))?
                .map(|bytes| load(Some(bytes), None))
                .transpose()
        }
    }
}

/// `doc`'s state as the write door reads it whole, and each text in it. A
/// deck's log keeps each operation as its JSON spelling, and its tree and
/// charts each node's and chart's fields, and a view shows the values they
/// decode to, so the decoded operations and values stand beside the stored
/// state and each of their strings is a text marked under its own hash
/// (FIX 2940, FIX 8995); the stored spelling stays a text too.
fn state_of(doc: &LoroDoc) -> Result<(serde_json::Value, Vec<String>)> {
    let mut state = serde_json::to_value(doc.get_deep_value())
        .map_err(|_| Error::InvariantViolation("typed body state did not encode"))?;
    let mut decoded = crate::office_body::deck_log_ops(&state);
    decoded.extend(crate::office_body::deck_json_values(&state));
    if !decoded.is_empty() {
        state = serde_json::Value::Array(vec![state, serde_json::Value::Array(decoded)]);
    }
    let mut texts = Vec::new();
    collect_texts(&state, &mut texts);
    Ok((state, texts))
}

fn collect_texts(value: &serde_json::Value, texts: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => texts.push(text.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_texts(item, texts);
            }
        }
        serde_json::Value::Object(fields) => {
            for item in fields.values() {
                collect_texts(item, texts);
            }
        }
        _ => {}
    }
}

/// The hit the write door finds in `state` with each key `texts`' marks
/// name read as its handle: a key split over two texts, which no text's
/// mark places.
fn residual_hit_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    mut state: serde_json::Value,
    texts: &[String],
) -> Result<Option<&'static str>> {
    LiftedKeys::of_in_txn(store, txn, texts)?.mask_json(&mut state);
    let read = serde_json::to_vec(&state)
        .map_err(|_| Error::InvariantViolation("typed body state did not encode"))?;
    Ok(write_payload_hit(&read))
}

/// The write door's first hit in the body one stored row of `rows` holds
/// that no mark covers.
pub(crate) fn typed_body_lift_hit_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    rows: TypedBodyRows,
    key: &[u8],
) -> Result<Option<&'static str>> {
    let Some(doc) = body_in_txn(store, txn, rows, key)? else {
        return Ok(None);
    };
    let (state, texts) = state_of(&doc)?;
    if let Some(hit) = carrier_texts_hit_in_txn(store, txn, &texts)? {
        return Ok(Some(hit));
    }
    residual_hit_in_txn(store, txn, state, &texts)
}

/// Marks the keys of each text in the body one stored row of `rows` holds,
/// in the caller's transaction. A hit no text's mark places is left
/// unplaced.
pub(crate) fn lift_typed_body_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    rows: TypedBodyRows,
    key: &[u8],
) -> Result<CarrierText> {
    let Some(doc) = body_in_txn(&vault.store, txn, rows, key)? else {
        return Ok(CarrierText::Clean);
    };
    mark_state_in_txn(vault, txn, rows.decl(), key, &doc)
}

/// [`lift_typed_body_in_txn`] for `doc`, the body `table`'s row `key` holds.
fn mark_state_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    table: &SideTableDecl,
    key: &[u8],
    doc: &LoroDoc,
) -> Result<CarrierText> {
    let (state, texts) = state_of(doc)?;
    let hits: Vec<String> = texts
        .iter()
        .filter(|text| write_payload_hit(text.as_bytes()).is_some())
        .cloned()
        .collect();
    let marked = mark_carrier_texts_in_txn(vault, txn, table, key, &hits)?;
    if matches!(marked, CarrierText::Unplaceable(_)) {
        return Ok(marked);
    }
    Ok(
        match residual_hit_in_txn(&vault.store, txn, state, &texts)? {
            Some(left) => CarrierText::Unplaceable(left),
            None => marked,
        },
    )
}

/// After a commit on `entity`'s body that the write door let stand because
/// the body read as secret before it: each text it leaves that holds a key
/// is marked, a lifted value keeping its record.
pub(super) fn remark_typed_body_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    doc: &LoroDoc,
) -> Result<()> {
    mark_state_in_txn(
        vault,
        txn,
        &side_table::TYPED_BODY_DOC,
        entity.as_bytes(),
        doc,
    )?;
    Ok(())
}

/// Each text of `entity`'s typed body, read in `txn`: its live body's and
/// each open fork's.
fn body_texts_in_txn(store: &Store, txn: &RoTxn<'_>, entity: &EntityId) -> Result<Vec<String>> {
    let mut texts = Vec::new();
    if let Some(doc) = body_in_txn(store, txn, TypedBodyRows::Doc, entity.as_bytes())? {
        texts.extend(state_of(&doc)?.1);
    }
    for row in FORK_DOCS.iter_from(store, txn, entity.as_bytes())? {
        let (_, bytes) = row?;
        texts.extend(state_of(&load(Some(bytes), None)?)?.1);
    }
    Ok(texts)
}

/// The custody records the marks of a typed body's lifted texts name: each
/// key once, in custody-id order. Only
/// [`Vault::typed_body_lifted_sources_in_txn`] and
/// [`Vault::typed_body_read_lifted_in_txn`] make one, so a read's sight
/// ([`Vault::typed_body_sight`]) is judged over the keys the body holds,
/// never over keys a caller names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiftedSources(Vec<EntityId>);

impl LiftedSources {
    /// Whether the body's texts name no key: every reader reads it alike.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The keys, each once, in custody-id order.
    pub(crate) fn keys(&self) -> &[EntityId] {
        &self.0
    }

    /// These keys and `keys`, the custody records the marks of what a read
    /// shows name, each once, in custody-id order: the keys of the parts a
    /// deck preview's asked slides draw (FIX 10453).
    pub(crate) fn with_keys(mut self, keys: impl IntoIterator<Item = EntityId>) -> Self {
        self.0.extend(keys);
        self.0.sort_unstable();
        self.0.dedup();
        self
    }
}

/// The custody records the marks of `texts` name, a key in a marked member
/// included: each key once, in custody-id order.
fn sources_in_txn(store: &Store, txn: &RoTxn<'_>, texts: &[String]) -> Result<LiftedSources> {
    let mut keys = Vec::new();
    for text in texts {
        let hash = blake3::hash(text.as_bytes());
        let Some(mark) = masked_file_in_txn(store, txn, hash.as_bytes())? else {
            continue;
        };
        let marked = mark
            .keys
            .iter()
            .chain(mark.members.iter().flat_map(|member| member.keys.iter()));
        keys.extend(marked.map(|key| key.custody));
    }
    keys.sort_unstable();
    keys.dedup();
    Ok(LiftedSources(keys))
}

impl Vault {
    /// `sources` and the custody records the stored-file marks of `files`
    /// name, each file by the BLAKE3 of its bytes and a key in a marked
    /// member included, read in `txn`: each key once, in custody-id order. A
    /// deck preview judges its texts' keys with those of the retained
    /// package it draws over, that package's parts and the pictures it
    /// resolves, all read in one snapshot (FIX 9994).
    pub(crate) fn lifted_sources_with_files_in_txn(
        &self,
        txn: &RoTxn<'_>,
        sources: LiftedSources,
        files: &[[u8; 32]],
    ) -> Result<LiftedSources> {
        let mut keys = sources.0;
        for hash in files {
            let Some(mark) = masked_file_in_txn(&self.store, txn, hash)? else {
                continue;
            };
            let marked = mark
                .keys
                .iter()
                .chain(mark.members.iter().flat_map(|member| member.keys.iter()));
            keys.extend(marked.map(|key| key.custody));
        }
        keys.sort_unstable();
        keys.dedup();
        Ok(LiftedSources(keys))
    }

    /// The keys the lifted texts of `entity`'s typed body hold, its live
    /// body's and each open fork's.
    pub(crate) fn typed_body_lifted_keys(&self, entity: &EntityId) -> Result<LiftedKeys> {
        let txn = self.store.env.read_txn()?;
        let texts = body_texts_in_txn(&self.store, &txn, entity)?;
        LiftedKeys::of_in_txn(&self.store, &txn, texts)
    }

    /// The custody records the marks of `entity`'s typed body texts name,
    /// its live body's and each open fork's, as [`Self::typed_body_lifted_keys`]
    /// reads them (a key in a marked member included), read in `txn`: the
    /// snapshot the caller reads the projection it shows in, so the keys a
    /// read's sight judges ([`Vault::typed_body_sight`]) are the keys it
    /// shows.
    pub(crate) fn typed_body_lifted_sources_in_txn(
        &self,
        txn: &RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<LiftedSources> {
        sources_in_txn(
            &self.store,
            txn,
            &body_texts_in_txn(&self.store, txn, entity)?,
        )
    }

    /// The custody records of `entity`'s typed body texts that the strings
    /// `drawn` hold: a key whose value no drawn string holds withholds
    /// nothing (FIX 12234). A span that does not read, and a key in a marked
    /// member, count as [`Self::typed_body_lifted_sources_in_txn`] counts
    /// them. Each key once, in custody-id order.
    pub(crate) fn typed_body_lifted_sources_drawn_in_txn(
        &self,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        drawn: &[String],
    ) -> Result<LiftedSources> {
        let mut keys = Vec::new();
        for text in body_texts_in_txn(&self.store, txn, entity)? {
            let hash = blake3::hash(text.as_bytes());
            let Some(mark) = masked_file_in_txn(&self.store, txn, hash.as_bytes())? else {
                continue;
            };
            for key in &mark.keys {
                let value = usize::try_from(key.start)
                    .ok()
                    .zip(usize::try_from(key.end).ok())
                    .and_then(|(start, end)| text.get(start..end));
                match value {
                    Some(value) if !drawn.iter().any(|held| held.contains(value)) => {}
                    _ => keys.push(key.custody),
                }
            }
            for member in &mark.members {
                keys.extend(member.keys.iter().map(|key| key.custody));
            }
        }
        keys.sort_unstable();
        keys.dedup();
        Ok(LiftedSources(keys))
    }

    /// The keys the lifted texts a read of `entity`'s typed body may show
    /// hold, and their custody records, from one list of texts read in
    /// `txn`, the snapshot the read projects its view in: the live body's
    /// and each open fork's, and with `at`, the document a read at an
    /// earlier frontier projects (FIX 2939). A value only that version held
    /// reads as its handle, and a read's sight judges each key it masks.
    pub(crate) fn typed_body_read_lifted_in_txn(
        &self,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        at: Option<&LoroDoc>,
    ) -> Result<(LiftedKeys, LiftedSources)> {
        let mut texts = body_texts_in_txn(&self.store, txn, entity)?;
        if let Some(doc) = at {
            texts.extend(state_of(doc)?.1);
        }
        self.lifted_projection_texts_in_txn(txn, texts)
    }

    /// The keys `texts` hold and their custody records, read in `txn`: the
    /// exact carrier texts engine code decoded for a projection it releases,
    /// a typed body's or another's (a deck outline NOTE's, FIX 9605), never
    /// texts or custody ids a caller names. A read's sight
    /// ([`Vault::typed_body_sight`]) judges the keys its view masks.
    pub(crate) fn lifted_projection_texts_in_txn(
        &self,
        txn: &RoTxn<'_>,
        texts: Vec<String>,
    ) -> Result<(LiftedKeys, LiftedSources)> {
        let sources = sources_in_txn(&self.store, txn, &texts)?;
        Ok((LiftedKeys::of_in_txn(&self.store, txn, texts)?, sources))
    }

    /// Whether `doc`, `entity`'s typed body at an earlier frontier, holds a
    /// text with a hit the write door finds that no mark covers yet and that
    /// a write would act on: one the door's rules place, or one they cannot
    /// while the owner's proposal for it is due (FIX 8996). A text whose key
    /// no rule places, once its proposal stands, opens no writer: a masked
    /// reader reads it as the door's placeholder. Each text is judged alone,
    /// so a key split over two texts, which no text alone shows, opens no
    /// writer and files no proposal: an earlier frontier's text is history,
    /// and a masked reader reads each text the key touches as the
    /// placeholder (FIX 12232).
    pub(crate) fn typed_body_unmarked_in_txn(
        &self,
        txn: &RoTxn<'_>,
        entity: &EntityId,
        doc: &LoroDoc,
    ) -> Result<bool> {
        let mut unplaced = false;
        for text in state_of(doc)?.1 {
            let hash = blake3::hash(text.as_bytes());
            if write_payload_hit(text.as_bytes()).is_none()
                || masked_file_in_txn(&self.store, txn, hash.as_bytes())?.is_some()
            {
                continue;
            }
            if carrier_text_placeable(text.as_bytes())? {
                return Ok(true);
            }
            unplaced = true;
        }
        Ok(unplaced && typed_body_at_proposal_due_in_txn(self, txn, entity)?)
    }

    /// Marks the keys of each text in `doc`, `entity`'s typed body at an
    /// earlier frontier, in the caller's transaction, as the lift sweep
    /// marks its live body's: under each text's hash, the live body's row
    /// named as where they were found (FIX 2939). Only custody and span rows
    /// are written; the stored document stays as it is. A hit no text's mark
    /// places files the sweep's `unplaceable` proposal on the body's row
    /// (FIX 8996).
    pub(crate) fn mark_typed_body_at_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        entity: &EntityId,
        doc: &LoroDoc,
    ) -> Result<()> {
        let marked = mark_state_in_txn(
            self,
            txn,
            &side_table::TYPED_BODY_DOC,
            entity.as_bytes(),
            doc,
        )?;
        propose_typed_body_at_in_txn(self, txn, entity, marked)
    }
}
