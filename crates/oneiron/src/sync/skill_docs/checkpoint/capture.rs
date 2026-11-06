//! Exact SKILL pairs from one closed window-history capture.
//!
//! This is a read-only intermediate, not a projected carrier or an admission
//! witness. Its temporary capture admits digest keys only in memory; neither
//! that skeleton nor the original heads/part keys may be sealed as structure.

use std::collections::BTreeMap;

use loro::checkpoint::{AtomId, Capture, Classify, Field, OwnerId, Payload, Site};
use loro::{LoroDoc, LoroValue};

use super::super::{SKILL_DOCS_MAP, decode};
use super::{SplitRecordDocument, split};
use crate::store::checkpoint_payload::rows::Unresolved;
use crate::sync::carrier_parts::{Parts, admit_part, is_part_key};

/// An actual value site from the vendored capture, not its encounter order.
/// `atom` belongs only to this temporary capture, never a projected carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CapturedSite {
    pub(crate) atom: AtomId,
    pub(crate) site: Site,
}

struct Value {
    key: String,
    bytes: Vec<u8>,
    at: CapturedSite,
}

/// One descriptor position and every captured write of its exact part.
/// Repeated positions and uses in other heads or the other leg stay separate.
pub(crate) struct CapturedPart {
    pub(crate) key: String,
    pub(crate) sites: Vec<CapturedSite>,
}

/// One historical head, its exact row's sites and its two independent legs.
/// Only `split` is suitable for subsequent owner/actor projection; the other
/// fields locate the original transport that projection must replace.
pub(crate) struct CapturedRecordDocument {
    pub(crate) key: String,
    pub(crate) head: Vec<u8>,
    pub(crate) at: CapturedSite,
    pub(crate) rows: Vec<CapturedSite>,
    pub(crate) snapshot: Vec<CapturedPart>,
    pub(crate) refinement: Option<Vec<CapturedPart>>,
    pub(crate) split: SplitRecordDocument,
}

/// A complete successful history read. No source is returned from an export
/// that stopped early, or when any historical head lacks its exact pair.
pub(crate) struct CapturedRecordDocuments {
    pub(crate) sources: Vec<CapturedRecordDocument>,
}

#[derive(Default)]
struct Reading {
    next_atom: AtomId,
    heads: Vec<Value>,
    rows: Vec<Value>,
    parts: BTreeMap<String, Vec<Value>>,
    // Verify callback/atom association against the completed capture, rather
    // than assuming that callback encounter order is an operation id.
    values: Vec<(AtomId, LoroValue)>,
}

impl Classify for Reading {
    fn plain_key(&mut self, _: &str, _: &str) -> bool {
        // This skeleton is discarded, not emitted under the outer seal.
        true
    }

    fn holders(&mut self, field: Field<'_>) -> Option<Vec<OwnerId>> {
        let Field::Value {
            root,
            key,
            value,
            site,
        } = field
        else {
            return None;
        };
        let LoroValue::Binary(bytes) = value else {
            return None;
        };
        let atom = self.next_atom;
        self.next_atom = atom.checked_add(1)?;
        self.values.push((atom, value.clone()));
        let relevant = root == SKILL_DOCS_MAP || root == "entities";
        if relevant {
            let value = Value {
                key: key.to_owned(),
                bytes: bytes.to_vec(),
                at: CapturedSite { atom, site },
            };
            if root == "entities" {
                self.rows.push(value);
            } else if is_part_key(key) {
                admit_part(key, &LoroValue::Binary(bytes.clone())).ok()?;
                self.parts.entry(key.to_owned()).or_default().push(value);
            } else {
                self.heads.push(value);
            }
        }
        // An index for this ephemeral read only, not a rightful owner.
        Some(vec![0])
    }
}

/// Reads shallow winners and every retained value through the real Loro
/// capture. `roots` is the window owner's existing allowlist; adding SKILL
/// here expands only this read, never the emitted window's admitted roots.
/// The caller supplies the same document opened over snapshot/pending/queue.
pub(crate) fn capture(
    doc: &LoroDoc,
    roots: &[&str],
) -> std::result::Result<CapturedRecordDocuments, Unresolved> {
    let mut roots = roots.to_vec();
    if !roots.contains(&SKILL_DOCS_MAP) {
        roots.push(SKILL_DOCS_MAP);
    }
    let mut reading = Reading::default();
    let Capture::Classified(captured) = doc.export_root_map_checkpoint(&roots, &mut reading) else {
        return Err(Unresolved::Undecodable);
    };
    if captured.atoms.len() != reading.values.len()
        || captured
            .atoms
            .iter()
            .zip(&reading.values)
            .any(|(atom, (id, value))| {
                atom.id != *id || atom.payload != Payload::Value(value.clone())
            })
    {
        return Err(Unresolved::Undecodable);
    }
    // The plain-key skeleton is deliberately never carried out of this read.
    drop(captured);
    reading.bind()
}

impl Reading {
    fn bind(self) -> std::result::Result<CapturedRecordDocuments, Unresolved> {
        let mut sources = Vec::with_capacity(self.heads.len());
        for head in &self.heads {
            let (carried, entity) = decode(&head.bytes).map_err(|_| Unresolved::Undecodable)?;
            if entity.to_hex() != head.key {
                return Err(Unresolved::Undecodable);
            }
            // The record's native row digest selects historical raw bytes,
            // not the current winner, callback order or a receiver's row.
            let rows: Vec<&Value> = self
                .rows
                .iter()
                .filter(|row| {
                    row.key == head.key
                        && blake3::hash(&row.bytes).as_bytes() == carried.record.row_digest()
                })
                .collect();
            let row = rows.first().ok_or(Unresolved::Undecodable)?;
            if rows.iter().any(|other| other.bytes != row.bytes) {
                return Err(Unresolved::Undecodable);
            }
            let snapshot = self.leg(&carried.snapshot)?;
            let refinement = carried
                .refinement
                .as_ref()
                .map(|source| self.leg(&source.row))
                .transpose()?;
            let split = split(&head.key, &head.bytes, &row.bytes, |key| {
                self.parts
                    .get(key)
                    .and_then(|values| values.first())
                    .map(|value| value.bytes.as_slice())
            })?;
            sources.push(CapturedRecordDocument {
                key: head.key.clone(),
                head: head.bytes.clone(),
                at: head.at,
                rows: rows.into_iter().map(|row| row.at).collect(),
                snapshot,
                refinement,
                split,
            });
        }
        Ok(CapturedRecordDocuments { sources })
    }

    fn leg(&self, parts: &Parts) -> std::result::Result<Vec<CapturedPart>, Unresolved> {
        parts
            .keys()
            .map(|key| {
                let values = self.parts.get(&key).ok_or(Unresolved::Undecodable)?;
                let first = values.first().ok_or(Unresolved::Undecodable)?;
                if values.iter().any(|value| value.bytes != first.bytes) {
                    return Err(Unresolved::Undecodable);
                }
                Ok(CapturedPart {
                    key,
                    sites: values.iter().map(|value| value.at).collect(),
                })
            })
            .collect()
    }
}
