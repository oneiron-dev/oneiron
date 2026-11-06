//! Native SKILL source copies for one closed window capture.
//!
//! Source content is sealed once per rightful holder, independently of the
//! original part writes shared with other heads. Opening re-parts each native
//! snapshot and FIRST without imposing the old descriptor count. This owns
//! source copies, not the outer map-write expansion or native admission.

mod bind;

use std::collections::BTreeSet;

use loro::LoroDoc;
use loro::checkpoint::{AtomId, Parts, Skeleton};
use serde::{Deserialize, Serialize};

use super::{
    AtomHome, AtomRef, Holder, OpenedAtom, OpenedSyncAtoms, Placement, SlotCopy, SyncAtom,
    SyncPayloadOwners, root_entry,
};
use crate::error::Result;
use crate::store::checkpoint_payload::loro::opened_atoms;
use crate::store::checkpoint_payload::rows::{ActorPart, RowLocator, Unresolved, bad_part};
use crate::sync::skill_docs::checkpoint::capture::{CapturedRecordDocument, capture};
use crate::sync::skill_docs::checkpoint::{RecordDocumentTransport, join};

/// One original value and its withheld key, in the FINAL outer capture.
/// The skeleton, not a temporary callback ordinal, retains its native site.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordDocumentSlot {
    pub(crate) value: AtomId,
    pub(crate) key: Option<AtomId>,
}

/// Original uses of one source. Every descriptor position keeps every write;
/// shared slots remain separate uses in each source and each leg.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordDocumentSlots {
    pub(crate) head: RecordDocumentSlot,
    pub(crate) rows: Vec<RecordDocumentSlot>,
    pub(crate) snapshot: Vec<Vec<RecordDocumentSlot>>,
    pub(crate) refinement: Option<Vec<Vec<RecordDocumentSlot>>>,
}

struct Source {
    captured: CapturedRecordDocument,
    holders: Vec<Holder>,
}

/// All historical native pairs read from the SAME opened window document.
/// Original heads and digest keys remain only in this ephemeral preparation.
pub(crate) struct PreparedRecordDocuments {
    sources: Vec<Source>,
}

struct BoundSource {
    source: Source,
    slots: RecordDocumentSlots,
}

/// Source ownership bound to actual slots after the final classifier has
/// withheld its keys. No temporary capture atom id crosses this boundary.
pub(crate) struct BoundRecordDocuments {
    sources: Vec<BoundSource>,
}

/// The actual final window capture and its paired sources, owned together.
/// Original payloads are ephemeral here: this is neither a carrier nor a
/// serializable product and cannot use the ordinary scalar-slot emitter.
pub(crate) struct ClassifiedRecordDocuments {
    parts: Parts,
    plans: Vec<super::classify::Plan>,
    homes: Vec<super::classify::Home>,
    turn: Option<super::joined_turns::TurnSource>,
    native_slots: BTreeSet<AtomId>,
    sources: BoundRecordDocuments,
}

impl PreparedRecordDocuments {
    /// Makes the FINAL native-aware capture over the same closed document,
    /// including ordinary families and all original snapshot/pending/queue
    /// writes. Returns the capture and ALL bound sources, never a bank that
    /// the caller could mistake for independent scalar values.
    pub(crate) fn classify(
        self,
        doc: &LoroDoc,
        roots: &[&str],
        owners: &dyn SyncPayloadOwners,
    ) -> std::result::Result<ClassifiedRecordDocuments, super::classify::Refusal> {
        let super::classify::RecordDocumentClassification {
            parts,
            ordinary,
            native_slots,
        } = super::classify::capture_record_documents(doc, roots, owners, &self)?;
        let sources = self
            .bind(&parts)
            .map_err(|_| (None, super::SyncUnclassified::Undecodable))?;
        // Every classified native slot must belong to the complete source
        // bank, and every use in that bank must be classified as native.
        let mut expected = BTreeSet::new();
        for source in &sources.sources {
            let slots = &source.slots;
            let parts = slots
                .snapshot
                .iter()
                .chain(slots.refinement.iter().flatten())
                .flatten();
            for slot in std::iter::once(&slots.head).chain(&slots.rows).chain(parts) {
                expected.insert(slot.value);
                expected.extend(slot.key);
            }
        }
        if expected != native_slots {
            return Err((None, super::SyncUnclassified::Undecodable));
        }
        Ok(ClassifiedRecordDocuments {
            parts,
            plans: ordinary.plans,
            homes: ordinary.homes,
            turn: ordinary.turn,
            native_slots,
            sources,
        })
    }
}

/// A source's independent sealed copies and its original operation uses.
/// No old head, part digest or actor id is kept in this outer metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JoinedRecordDocument {
    pub(crate) entity_key: String,
    pub(crate) slots: RecordDocumentSlots,
    pub(crate) copies: Vec<SlotCopy>,
    pub(crate) holes: Vec<String>,
}

/// A source rebuilt from one authenticated holder's copy. `transport` keeps
/// ALL new pieces; the original slots describe uses, not a capacity bound.
pub(crate) struct OpenedRecordDocument {
    pub(crate) transport: RecordDocumentTransport,
    pub(crate) lossless: bool,
}

/// Prepares the native sources from the actual document opened over the
/// group's snapshot/pending/queue. Uses the ordinary entities-row placement
/// for each exact historical row, never a guessed root-wide holder.
pub(crate) fn prepare(
    doc: &LoroDoc,
    roots: &[&str],
    owners: &dyn SyncPayloadOwners,
) -> std::result::Result<PreparedRecordDocuments, Unresolved> {
    let captured = capture(doc, roots)?;
    let mut sources = Vec::with_capacity(captured.sources.len());
    for captured in captured.sources {
        let holders = match root_entry("entities", &captured.key, &captured.split.row, owners) {
            Placement::Owned(holders) => holders,
            _ => return Err(Unresolved::NoOwner),
        };
        if holders.is_empty() {
            return Err(Unresolved::NoOwner);
        }
        let mut holes = BTreeSet::new();
        if captured
            .split
            .actors
            .iter()
            .any(|atom| !holes.insert(atom.field.as_str()))
        {
            return Err(Unresolved::Undecodable);
        }
        // The real native join must also accept the source's no-one form
        // before any holder's content or actor part is emitted.
        join(&captured.split.content, Vec::new()).map_err(|_| Unresolved::Undecodable)?;
        sources.push(Source { captured, holders });
    }
    Ok(PreparedRecordDocuments { sources })
}

impl PreparedRecordDocuments {
    /// Resolves EVERY original use against the actual final skeleton and
    /// payloads. A part key must be withheld, never left as structure.
    pub(crate) fn bind(
        self,
        final_parts: &Parts,
    ) -> std::result::Result<BoundRecordDocuments, Unresolved> {
        let mut sources = Vec::with_capacity(self.sources.len());
        for source in self.sources {
            let slots = bind::source(final_parts, &source.captured)?;
            sources.push(BoundSource { source, slots });
        }
        Ok(BoundRecordDocuments { sources })
    }
}

impl BoundRecordDocuments {
    /// Emits a copy per actual holder, with native history actors beside
    /// THAT copy. Every source has its own locator and lifetime even when
    /// its original head or part write was shared with another source.
    pub(crate) fn emit(
        self,
        first: &RowLocator,
        emit: &mut dyn FnMut(AtomHome, SyncAtom) -> Result<AtomRef>,
    ) -> Result<Vec<JoinedRecordDocument>> {
        let mut joined = Vec::with_capacity(self.sources.len());
        for (source_index, bound) in self.sources.into_iter().enumerate() {
            let BoundSource { source, slots } = bound;
            let Source { captured, holders } = source;
            let split = captured.split;
            let holes = split.actors.iter().map(|atom| atom.field.clone()).collect();
            let mut copies = Vec::with_capacity(holders.len());
            for (place, holder) in holders.into_iter().enumerate() {
                let at = first.fragment(format!("loro record {source_index} {place}"));
                let actors = split
                    .actors
                    .iter()
                    .map(|atom| ActorPart {
                        actor_entity: atom.actor,
                        content_locator: at.clone(),
                        field: atom.field.clone(),
                        bytes: atom.actor.as_bytes().to_vec(),
                    })
                    .collect();
                let home = AtomHome::Owner(holder.owner);
                let ordinal = emit(
                    home,
                    SyncAtom {
                        at: at.clone(),
                        value: split.content.clone(),
                        dependencies: holder.dependencies.clone(),
                        actors,
                    },
                )?;
                copies.push(SlotCopy {
                    at,
                    atom: ordinal,
                    home,
                    dependencies: holder.dependencies,
                });
            }
            joined.push(JoinedRecordDocument {
                entity_key: captured.key,
                slots,
                copies,
                holes,
            });
        }
        Ok(joined)
    }
}

impl PreparedRecordDocuments {
    /// Classifies one actual native value site. Every source using that write
    /// contributes its holders; an unrelated entities row uses its own codec.
    pub(super) fn value_holders(
        &self,
        root: &str,
        key: &str,
        value: &loro::LoroValue,
        site: loro::checkpoint::Site,
    ) -> std::result::Result<Option<Vec<Holder>>, Unresolved> {
        let loro::LoroValue::Binary(bytes) = value else {
            return Err(Unresolved::Undecodable);
        };
        let bytes = bytes.as_slice();
        let mut holders = Vec::new();
        let mut used = false;
        for source in &self.sources {
            let captured = &source.captured;
            let matches = if root == crate::sync::skill_docs::SKILL_DOCS_MAP {
                if key == captured.key && site == captured.at.site {
                    if bytes != captured.head.as_slice() {
                        return Err(Unresolved::Undecodable);
                    }
                    true
                } else {
                    let positions = captured
                        .snapshot
                        .iter()
                        .chain(captured.refinement.iter().flatten());
                    let matched = positions
                        .into_iter()
                        .any(|part| part.key == key && part.sites.iter().any(|at| at.site == site));
                    if matched {
                        crate::sync::carrier_parts::admit_part(key, value)
                            .map_err(|_| Unresolved::Undecodable)?;
                    }
                    matched
                }
            } else if root == "entities"
                && key == captured.key
                && captured.rows.iter().any(|at| at.site == site)
            {
                if bytes != captured.split.row.as_slice() {
                    return Err(Unresolved::Undecodable);
                }
                true
            } else {
                false
            };
            if matches {
                used = true;
                for holder in &source.holders {
                    if !holders.contains(holder) {
                        holders.push(holder.clone());
                    }
                }
            }
        }
        Ok(used.then_some(holders))
    }

    /// A digest key has the union of ALL sources using it, independently of
    /// their value-site aliases and repeated descriptor positions.
    pub(super) fn key_holders(&self, key: &str) -> Option<Vec<Holder>> {
        let mut holders = Vec::new();
        let mut used = false;
        for source in &self.sources {
            let captured = &source.captured;
            if captured
                .snapshot
                .iter()
                .chain(captured.refinement.iter().flatten())
                .any(|part| part.key == key)
            {
                used = true;
                for holder in &source.holders {
                    if !holders.contains(holder) {
                        holders.push(holder.clone());
                    }
                }
            }
        }
        used.then_some(holders)
    }
}

/// Opens each source independently. A missing source leaves exactly its
/// position empty; it never selects another source sharing an old slot.
/// The native join validates the actual row, history and immutable FIRST.
pub(crate) fn open(
    skeleton: &Skeleton,
    sources: &[JoinedRecordDocument],
    opened: &dyn OpenedSyncAtoms,
) -> Result<Vec<Option<OpenedRecordDocument>>> {
    super::frame::record_documents::validate(skeleton, sources)?;
    sources.iter().map(|source| source.open(opened)).collect()
}

impl JoinedRecordDocument {
    fn open(&self, opened: &dyn OpenedSyncAtoms) -> Result<Option<OpenedRecordDocument>> {
        let holes: BTreeSet<&str> = self.holes.iter().map(String::as_str).collect();
        if holes.len() != self.holes.len() {
            return Err(bad_part());
        }
        for copy in &self.copies {
            let OpenedAtom::Opened(content) = opened.atom(copy.atom) else {
                continue;
            };
            if !matches!(copy.home, AtomHome::Owner(_))
                || opened.opened_home(copy.atom) != Some(copy.home)
            {
                return Err(bad_part());
            }
            let parts = opened.actor_parts(copy.atom);
            let mut fields = BTreeSet::new();
            for part in &parts {
                if part.content_locator != copy.at
                    || !holes.contains(part.field.as_str())
                    || !fields.insert(part.field.as_str())
                {
                    return Err(bad_part());
                }
            }
            let lossless = fields.len() == holes.len();
            let transport = join(content, opened_atoms(&parts)?)?;
            if transport.entity()?.to_hex() != self.entity_key {
                return Err(bad_part());
            }
            return Ok(Some(OpenedRecordDocument {
                transport,
                lossless,
            }));
        }
        Ok(None)
    }
}
