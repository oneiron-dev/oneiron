//! Native SKILL source copies for one closed window capture.
//!
//! Source content is sealed once per rightful holder, independently of the
//! original part writes shared with other heads. Opening re-parts each native
//! snapshot and FIRST without imposing the old descriptor count. This owns
//! source copies, not the outer map-write expansion or native admission.

mod bind;

use std::collections::BTreeSet;

use loro::LoroDoc;
use loro::checkpoint::{AtomId, Parts};

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordDocumentSlot {
    pub(crate) value: AtomId,
    pub(crate) key: Option<AtomId>,
}

/// Original uses of one source. Every descriptor position keeps every write;
/// shared slots remain separate uses in each source and each leg.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Opens each source independently. A missing source leaves exactly its
/// position empty; it never selects another source sharing an old slot.
/// The native join validates the actual row, history and immutable FIRST.
pub(crate) fn open(
    sources: &[JoinedRecordDocument],
    opened: &dyn OpenedSyncAtoms,
) -> Result<Vec<Option<OpenedRecordDocument>>> {
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
