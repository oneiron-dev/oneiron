//! Byte-bound DOCX revision-author carriers over the existing export rows.
//!
//! A copy names its default revision authors by opaque token. These methods
//! gather the export records those tokens name, validate carried records
//! against the copy's actual XML, and merge them with local erasure winning.
//! They do not tokenize typed authors, transport a companion, or retain a row
//! past its origin artifact's erase: those are the full FIX 5470 follow-up.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use oneiron_docedit::ooxml::XmlTree;
use oneiron_docedit::retained_opc::Package;

use super::super::{
    EXPORT_AUTHORS, EXPORTS, OfficeBodyExportAuthor, OfficeBodyExportRecord, document_refused,
    document_resources, invalid, version_key,
};
use super::{DOCUMENT_PART, index, revision_token};
use crate::Vault;
use crate::deletion::carrier_actor_merged;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::typed_body::BodyActor;

impl Vault {
    /// Every export record whose exact token is a whole tracked-revision
    /// `w:author` in `bytes`, across origins and versions. The origin
    /// artifact need not be live. An unreadable package has no bindings;
    /// memory or a deadline that stops the read returns that refusal.
    pub(crate) fn docx_author_records_for_bytes_in_txn(
        &self,
        txn: &RoTxn<'_>,
        bytes: &[u8],
    ) -> Result<Vec<OfficeBodyExportRecord>> {
        let tokens = revision_tokens(self, txn, bytes)?;
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        // The token lookup (FIX 12403) reads the same rows a scan would, in
        // the same key order; the validators and mergers below are untouched.
        Ok(index::lookup_exports(&self.store, txn, &tokens)?
            .into_iter()
            .map(|(_, record)| record)
            .collect())
    }

    /// Validate carried records against the actual DOCX tokens and each
    /// other. A token in the bytes with no record is only a missing binding,
    /// never evidence of erasure and never a refusal.
    pub(crate) fn validate_docx_author_records_in_txn(
        &self,
        txn: &RoTxn<'_>,
        bytes: &[u8],
        records: &[OfficeBodyExportRecord],
    ) -> Result<()> {
        let tokens = revision_tokens(self, txn, bytes)?;
        let mut carried: BTreeMap<Vec<u8>, OfficeBodyExportRecord> = BTreeMap::new();
        let mut live_authors: BTreeMap<Vec<u8>, (BodyActor, String)> = BTreeMap::new();
        for record in records {
            let Some(token) = record.token.as_deref().filter(|token| !token.is_empty()) else {
                return Err(invalid("a DOCX author carrier has no token"));
            };
            if !tokens.contains(token.as_bytes()) {
                return Err(invalid(
                    "a DOCX author carrier's token is not in these bytes",
                ));
            }
            let key = token.as_bytes().to_vec();
            if record.actor != BodyActor::Erased {
                let live = (record.actor, record.author.clone());
                if let Some(previous) = live_authors.insert(key.clone(), live.clone())
                    && previous != live
                {
                    return Err(invalid(
                        "DOCX author carrier live actors or display authors disagree",
                    ));
                }
            }
            if let Some(held) = carried.get(&key) {
                let merged = merge_carrier_facts(held, record)?;
                carried.insert(key, merged);
            } else {
                carried.insert(key, record.clone());
            }
        }
        Ok(())
    }

    /// Validate and merge carried records into the existing export table in
    /// the caller's writer. Fixed facts must agree; actor identity merges
    /// erased-wins, including this vault's hard-delete markers. Missing
    /// bindings delete nothing and refuse nothing.
    pub(crate) fn merge_docx_author_records_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        bytes: &[u8],
        records: &[OfficeBodyExportRecord],
    ) -> Result<()> {
        self.validate_docx_author_records_in_txn(wtxn, bytes, records)?;
        for record in records {
            let carried = self.locally_erased_author_record_in_txn(wtxn, record.clone())?;
            let key = version_key(&carried.artifact, carried.version);
            let merged = match EXPORTS.get(&self.store, wtxn, &key)? {
                Some(held) => {
                    let held = self.locally_erased_author_record_in_txn(wtxn, held)?;
                    merge_carrier_facts(&held, &carried)?
                }
                None => carried,
            };
            EXPORTS.put(&self.store, wtxn, &key, &merged)?;
            // The token lookup names this row in the same writer (FIX 12403).
            if let Some(token) = merged.token.as_deref() {
                index::note_export_put(&self.store, wtxn, &key, token)?;
            }
        }
        Ok(())
    }

    /// Every per-group revision-author row whose token is bound by these
    /// bytes, with its (artifact, version, group index) storage key.
    pub(crate) fn docx_export_author_rows_for_bytes_in_txn(
        &self,
        txn: &RoTxn<'_>,
        bytes: &[u8],
    ) -> Result<Vec<((EntityId, u64, u64), OfficeBodyExportAuthor)>> {
        let tokens = revision_tokens(self, txn, bytes)?;
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        // The token lookup (FIX 12403) reads the same rows a scan would, in
        // the same key order; the validators and mergers below are untouched.
        index::lookup_authors(&self.store, txn, &tokens)
    }

    /// Validate per-group revision-author rows against the DOCX bytes and
    /// each other. A token with no row is a missing binding, never erasure.
    pub(crate) fn validate_docx_export_author_rows_in_txn(
        &self,
        txn: &RoTxn<'_>,
        bytes: &[u8],
        records: &[((EntityId, u64, u64), OfficeBodyExportAuthor)],
    ) -> Result<()> {
        let tokens = revision_tokens(self, txn, bytes)?;
        let mut carried: BTreeMap<(EntityId, u64, u64), OfficeBodyExportAuthor> = BTreeMap::new();
        let mut tokens_seen = BTreeMap::new();
        let mut live_actors: BTreeMap<Vec<u8>, EntityId> = BTreeMap::new();
        for (key, record) in records {
            if record.token.is_empty() || !tokens.contains(record.token.as_bytes()) {
                return Err(invalid(
                    "a DOCX revision-author carrier's token is not in these bytes",
                ));
            }
            if let Some(previous) = tokens_seen.insert(record.token.as_bytes().to_vec(), *key)
                && previous != *key
            {
                return Err(invalid(
                    "a DOCX revision-author token names two export groups",
                ));
            }
            if let Some(actor) = record.actor {
                if let Some(previous) = live_actors.insert(record.token.as_bytes().to_vec(), actor)
                    && previous != actor
                {
                    return Err(invalid("DOCX revision-author live actors disagree"));
                }
            }
            if let Some(held) = carried.get(key) {
                let merged = merge_export_author_facts(held, record)?;
                carried.insert(*key, merged);
            } else {
                carried.insert(*key, record.clone());
            }
        }
        Ok(())
    }

    /// Validate and merge per-group revision-author rows in the caller's
    /// writer. Tokens are fixed; optional actors merge erased-wins with the
    /// local hard-delete marker applied to both copies.
    pub(crate) fn merge_docx_export_author_rows_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        bytes: &[u8],
        records: &[((EntityId, u64, u64), OfficeBodyExportAuthor)],
    ) -> Result<()> {
        self.validate_docx_export_author_rows_in_txn(wtxn, bytes, records)?;
        for (key, record) in records {
            let carried = self.locally_erased_export_author_in_txn(wtxn, record.clone())?;
            let merged = match EXPORT_AUTHORS.get(&self.store, wtxn, key)? {
                Some(held) => {
                    let held = self.locally_erased_export_author_in_txn(wtxn, held)?;
                    merge_export_author_facts(&held, &carried)?
                }
                None => carried,
            };
            EXPORT_AUTHORS.put(&self.store, wtxn, key, &merged)?;
            // The token lookup names this row in the same writer (FIX 12403).
            index::note_author_put(&self.store, wtxn, key, &merged.token)?;
        }
        Ok(())
    }

    fn locally_erased_export_author_in_txn(
        &self,
        txn: &RoTxn<'_>,
        mut record: OfficeBodyExportAuthor,
    ) -> Result<OfficeBodyExportAuthor> {
        if let Some(actor) = record.actor
            && self.carrier_actor_erased_in_txn(txn, &actor)?
        {
            record.actor = None;
        }
        Ok(record)
    }

    fn locally_erased_author_record_in_txn(
        &self,
        txn: &RoTxn<'_>,
        mut record: OfficeBodyExportRecord,
    ) -> Result<OfficeBodyExportRecord> {
        if let Some(actor) = record.actor.id()
            && self.carrier_actor_erased_in_txn(txn, &actor)?
        {
            record.actor = BodyActor::Erased;
            record.author.clear();
        }
        Ok(record)
    }
}

/// Parse only whole tracked-revision `w:author` tokens. Malformed input and
/// a package this vault's limits do not read have no token set; an actual
/// memory floor or deadline remains a typed refusal.
fn revision_tokens(vault: &Vault, txn: &RoTxn<'_>, bytes: &[u8]) -> Result<BTreeSet<Vec<u8>>> {
    let empty = BTreeSet::new;
    if !bytes.starts_with(b"PK\x03\x04") {
        return Ok(empty());
    }
    let Ok(limits) = vault.docedit_package_limits_in_txn(txn) else {
        return Ok(empty());
    };
    let package = match Package::open(bytes, limits, &document_resources()) {
        Ok(package) => package,
        Err(error) => {
            if let Some(refusal) = error.resource() {
                return Err(document_refused(refusal));
            }
            return Ok(empty());
        }
    };
    let document = match package.part(DOCUMENT_PART) {
        Ok(Some(document)) => document,
        Ok(None) => return Ok(empty()),
        Err(error) => {
            if let Some(refusal) = error.resource() {
                return Err(document_refused(refusal));
            }
            return Ok(empty());
        }
    };
    let tree = match XmlTree::parse(&document, package.resources()) {
        Ok(tree) => tree,
        Err(error) => {
            if let Some(refusal) = error.resource() {
                return Err(document_refused(refusal));
            }
            return Ok(empty());
        }
    };
    Ok(tree
        .nodes
        .iter()
        .filter_map(revision_token)
        .map(|token| token.as_bytes().to_vec())
        .collect())
}

/// Two per-group author rows with the same key. The token is fixed; the
/// optional actor merges erased-wins, with `None` as the erased form.
fn merge_export_author_facts(
    held: &OfficeBodyExportAuthor,
    carried: &OfficeBodyExportAuthor,
) -> Result<OfficeBodyExportAuthor> {
    if held.token != carried.token {
        return Err(invalid("DOCX revision-author tokens disagree"));
    }
    let actor = carrier_actor_merged(held.actor, carried.actor, None)
        .ok_or_else(|| invalid("DOCX revision-author actors disagree"))?;
    Ok(OfficeBodyExportAuthor {
        actor,
        token: carried.token.clone(),
    })
}

/// Two copies with the same storage identity and token. Every field except
/// actor and its display author is fixed; actor identity merges erased-wins,
/// and one live actor may not carry two display authors.
fn merge_carrier_facts(
    held: &OfficeBodyExportRecord,
    carried: &OfficeBodyExportRecord,
) -> Result<OfficeBodyExportRecord> {
    let mut held_fixed = held.clone();
    held_fixed.actor = BodyActor::Erased;
    held_fixed.author.clear();
    let mut carried_fixed = carried.clone();
    carried_fixed.actor = BodyActor::Erased;
    carried_fixed.author.clear();
    if held_fixed != carried_fixed {
        return Err(invalid("DOCX author carrier facts disagree"));
    }
    let actor = carrier_actor_merged(held.actor, carried.actor, BodyActor::Erased)
        .ok_or_else(|| invalid("DOCX author carrier actors disagree"))?;
    if actor != BodyActor::Erased && held.author != carried.author {
        return Err(invalid("DOCX author carrier display authors disagree"));
    }
    let mut merged = carried.clone();
    merged.actor = actor;
    if actor == BodyActor::Erased {
        merged.author.clear();
    }
    Ok(merged)
}
