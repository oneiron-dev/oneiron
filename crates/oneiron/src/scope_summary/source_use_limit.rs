//! Whether the words of a stored row came from a record a use limit keeps
//! for storage only (FIX 1496 S8). The owner's scoped read and each door a
//! row leaves this vault by ask the same walk, so an owner archive or the
//! owner's devices never carry a row the owner's own read withholds (FIX
//! EGRESS-CARRIES-ROWS-DERIVED-FROM-USE-LIMITED-RECORDS).

use std::collections::BTreeSet;

use heed::RoTxn;

use super::WordSources;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::compaction::StoredEpoch;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityRecord, EntityStoreRead};
use crate::{EntityId, Vault};

/// The rows and `DerivedFrom` edges a use-limit walk reads: the vault's
/// base ([`BaseRows`]), or a scoped read's own view of them, a live
/// session's overlay included.
pub(crate) trait SourceRowRead {
    /// The vault whose use limits and word sources the walk asks.
    fn vault(&self) -> &Vault;
    /// The stored row `id` as this view holds it; `None` when it holds none.
    fn source_row_in(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityRecord>>;
    /// The targets of the `DerivedFrom` edges out of `id` in this view.
    fn derived_from_in(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>>;
    /// The epoch shape of `id`'s stored SUMMARY body `body` in this view.
    fn stored_epoch_in(&self, txn: &RoTxn<'_>, id: &EntityId, body: &[u8]) -> Result<StoredEpoch>;
}

/// The vault's base rows, as a door that sends a row off this vault reads
/// them.
struct BaseRows<'a>(&'a Vault);

impl SourceRowRead for BaseRows<'_> {
    fn vault(&self) -> &Vault {
        self.0
    }

    fn source_row_in(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityRecord>> {
        self.0.port_entity_record(txn, id)
    }

    fn derived_from_in(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
        self.0
            .port_edges(
                txn,
                id,
                EdgeDirection::Out,
                Some(EdgeKind::DerivedFrom),
                None,
            )?
            .map(|edge| edge.map(|edge| edge.target))
            .collect()
    }

    fn stored_epoch_in(&self, txn: &RoTxn<'_>, id: &EntityId, body: &[u8]) -> Result<StoredEpoch> {
        crate::compaction::stored_epoch_in(&self.0.store, txn, id, body)
    }
}

fn use_limited_in(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(crate::store::legal_hold::use_limit_in_txn(&vault.store, txn, id)?.is_some())
}

/// Whether `id` itself, or any record the words of its stored revision came
/// from, carries a standing record use limit
/// ([`crate::store::legal_hold::use_limit_in_txn`]): the question a door
/// asks before a row leaves this vault, for the owner's archive or devices
/// too. A SUMMARY or PSYCH_PROFILE of a use-limited CLAIM stays home with
/// the claim, as the owner's own scoped read withholds it
/// ([`word_sources_use_limited_in`]). A vault with no use limit answers from
/// two table probes; a row this vault stores no revision of answers by its
/// own limit alone.
///
/// # Errors
///
/// Storage failures, a stored row with no readable header, and a word
/// source the owner's read cannot judge either.
pub(crate) fn row_or_word_source_use_limited_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if !crate::store::legal_hold::any_record_use_limit_in_txn(&vault.store, txn)? {
        return Ok(false);
    }
    if use_limited_in(vault, txn, id)? {
        return Ok(true);
    }
    let Some(raw) = EntityStoreRead::port_entity_raw(&vault.store, txn, id)? else {
        return Ok(false);
    };
    word_sources_use_limited_in(&BaseRows(vault), txn, id, &raw)
}

/// Whether any source the derived row `id` (revision `raw`) was written
/// from carries a standing C6 use limit (FIX 1496 S8), read through `rows`.
/// Only the use limit binds; missing, withdrawn, unplaced or otherwise
/// unreadable sources do not (the owner shortcut's policy still skips every
/// other gate). `Ok(false)` for a row with no sources of its own.
///
/// # Errors
///
/// Storage failures, `raw` with no readable header, and a word source
/// [`super::word_sources_in`] cannot judge.
pub(crate) fn word_sources_use_limited_in(
    rows: &impl SourceRowRead,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let vault = rows.vault();
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_ASSET_TEXT {
        for source in rows.derived_from_in(txn, id)? {
            if use_limited_in(vault, txn, &source)? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if header.entity_type == crate::registry::ENTITY_TYPE_SUMMARY {
        let epoch = rows.stored_epoch_in(txn, id, &raw[ENTITY_METADATA_HEADER_LEN..])?;
        // Epoch keyframes traverse for Yes and Unresolved alike: an
        // unresolved head hides no source (review P1 on #4466).
        if epoch == StoredEpoch::Yes || epoch == StoredEpoch::Unresolved {
            return epoch_sources_use_limited_in(rows, txn, id);
        }
    }
    match super::word_sources_in(vault, txn, id, raw)? {
        WordSources::From(sources) => {
            for source in &sources {
                if use_limited_in(vault, txn, source)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        WordSources::Own => Ok(false),
        // Validation failure is not proof of no limited source (review
        // P1 on #4466): check the recorded IDs without admission
        // validation.
        WordSources::Unresolved => recorded_word_sources_use_limited_in(rows, txn, id, raw),
    }
}

/// Whether any RECORDED word source of `id` carries a standing C6 use
/// limit, without source-admission validation (FIX 1496 P1 review on
/// #4466): graph-recorded `DerivedFrom` targets + dependency sources,
/// plus a merge claim's named summary covers. A validation failure
/// (withheld NOTE pins, failed landing, conversation mismatch) leaves
/// the recorded IDs readable; the use limit is a table fact either way.
fn recorded_word_sources_use_limited_in(
    rows: &impl SourceRowRead,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let vault = rows.vault();
    let mut recorded: BTreeSet<EntityId> = rows.derived_from_in(txn, id)?.into_iter().collect();
    for source in crate::ports::dependency_sources_in(&vault.store, txn, id)? {
        recorded.insert(source);
    }
    // A merge claim's words are its named summary's recorded covers.
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if let Ok(claim) = crate::write_envelope::claim_body::decode_claim_body(body, true) {
            if let Ok(Some((_, summary))) = super::merge_summary_ref(&claim) {
                if let Some(row) = rows.source_row_in(txn, &summary)? {
                    if let Ok(logical) = crate::entity_doc::resolve_record_body(
                        &vault.store,
                        txn,
                        &summary,
                        &row.body,
                    ) {
                        if let Ok(summary_body) = super::decode_scope_summary_body(&logical) {
                            // The header's words came from these MESSAGEs
                            // too (review P1 on #4466): an edited pinned
                            // MESSAGE must not hide a limit on another.
                            recorded.extend(summary_body.covers);
                            recorded.extend(summary_body.messages.iter().map(|m| m.id));
                        }
                    }
                }
            }
        }
    }
    for source in &recorded {
        if use_limited_in(vault, txn, source)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether any record an epoch summary's words came from, through nested
/// epoch summaries, carries a standing C6 use limit (FIX 1496 S8). The
/// walk skips rows that no longer resolve instead of refusing (owner
/// policy), and expands through nested epoch summaries with Yes or
/// Unresolved keyframes, mirroring `epoch_sources_admitted_in`'s
/// expansion with a use-limit-only predicate.
fn epoch_sources_use_limited_in(
    rows: &impl SourceRowRead,
    txn: &RoTxn<'_>,
    summary: &EntityId,
) -> Result<bool> {
    let vault = rows.vault();
    let mut seen = BTreeSet::from([*summary]);
    let mut pending = vec![*summary];
    while let Some(next) = pending.pop() {
        for source in rows.derived_from_in(txn, &next)? {
            if !seen.insert(source) {
                continue;
            }
            if use_limited_in(vault, txn, &source)? {
                return Ok(true);
            }
            let Some(row) = rows.source_row_in(txn, &source)? else {
                continue;
            };
            if row.entity_type != crate::registry::ENTITY_TYPE_SUMMARY {
                continue;
            }
            let epoch = rows.stored_epoch_in(txn, &source, &row.body)?;
            // Yes and Unresolved alike: an unresolved head hides no
            // source (review P1 on #4466).
            if epoch == StoredEpoch::Yes || epoch == StoredEpoch::Unresolved {
                pending.push(source);
            }
        }
    }
    Ok(false)
}
