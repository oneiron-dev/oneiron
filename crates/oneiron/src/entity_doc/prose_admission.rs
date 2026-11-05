//! Core half of `entity_doc::prose_admission`: its store-layer items live in `oneiron_store::entity_doc::prose_admission` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::entity_doc::prose_admission::*;

use super::EntityDoc;
use super::verbs::Admitted;
use crate::EdgeActorClass;
use crate::Vault;
use crate::batch::secret_scan::LiftedKeys;
use crate::gate::record_references::validate_record_references;
use crate::memory::Memory;
use crate::receipt::receipt_reference_refusals;
use crate::store::record_links::{
    MAX_PROSE_LINKS, MAX_PROSE_SCAN_BYTES, PROSE_LINK_SCHEME, ProseLink, parse_record_links,
};
use crate::store::record_references::{NamedRecordRef, ReferenceRefusal};
use crate::store::reference_refusal::{ReferenceOutcome, ReferenceRefusalFacts};
use crate::write_envelope::WriteActor;
use std::ops::Range;

/// One prose slot a write landed: its writer, its pointer in the write and
/// the refs of the links it authored, as written.
pub(super) struct LandedProse {
    actor: WriteActor,
    slot: String,
    refs: Vec<String>,
}

impl LandedProse {
    /// A whole text its writer said (`said`), read as one Markdown carrier.
    pub(super) fn whole(actor: WriteActor, slot: String, said: &str) -> Self {
        let refs = if reads(actor) && said.contains(PROSE_LINK_SCHEME) {
            authored(said, 0..said.len())
        } else {
            Vec::new()
        };
        Self { actor, slot, refs }
    }

    /// An anchored edit's `text`, which landed in `doc` at Unicode position
    /// `place`, read in its place: the document's rest, each key `lifted`
    /// marks read as its handle, is its Markdown context, and a link only
    /// that rest holds is not this slot's.
    pub(super) fn anchored(
        actor: WriteActor,
        slot: String,
        doc: &EntityDoc,
        place: usize,
        text: &Admitted,
        lifted: &LiftedKeys,
    ) -> Self {
        let said = text.said.as_str();
        let linked = said.contains('[') || said.contains(PROSE_LINK_SCHEME);
        let refs = if reads(actor) && linked {
            in_place(&doc.text(), place, text, lifted)
        } else {
            Vec::new()
        };
        Self { actor, slot, refs }
    }
}

/// The refs `text` authored at `place` in `body`, the document's stored
/// text: read in the document's own Markdown while its parser reaches it,
/// else on its own.
fn in_place(body: &str, place: usize, text: &Admitted, lifted: &LiftedKeys) -> Vec<String> {
    let said = text.said.as_str();
    let start = body
        .char_indices()
        .nth(place)
        .map_or(body.len(), |(at, _)| at);
    let stored = text.stored.as_str();
    let Some(after) = body.get(start..).and_then(|rest| rest.strip_prefix(stored)) else {
        return authored(said, 0..said.len());
    };
    if !said.contains(PROSE_LINK_SCHEME) && !body.contains(PROSE_LINK_SCHEME) {
        return Vec::new();
    }
    let shown = |part: &str| lifted.masked(part).unwrap_or_else(|| part.to_owned());
    let before = shown(&body[..start]);
    let span = before.len()..before.len() + said.len();
    if span.end > MAX_PROSE_SCAN_BYTES {
        return authored(said, 0..said.len());
    }
    let links = parse_record_links(&format!("{before}{said}{}", shown(after)));
    if links.len() >= MAX_PROSE_LINKS {
        return authored(said, 0..said.len());
    }
    within(links, &span)
}

/// Receipts `landed`'s unresolved links under `row`, once its write has
/// landed. A raw door holds no caller handle: each writer reads under its
/// own local actor handle.
pub(super) fn admit_landed(vault: &Vault, row: &'static str, landed: &[LandedProse]) {
    for prose in landed.iter().filter(|prose| !prose.refs.is_empty()) {
        let memory = vault.memory(prose.actor.entity_ref(), prose.actor.actor_class());
        admit(&memory, row, prose);
    }
}

/// [`admit_landed`] for a write whose caller's own handle is in hand.
pub(super) fn admit_landed_as(memory: &Memory<'_>, row: &'static str, landed: &[LandedProse]) {
    for prose in landed {
        admit(memory, row, prose);
    }
}

/// One slot's links resolved under `memory`'s own scoped read: a link that
/// does not resolve earns the slot one `unlinked` receipt.
fn admit(memory: &Memory<'_>, row: &'static str, prose: &LandedProse) {
    if prose.refs.is_empty() || memory.actor_class() == EdgeActorClass::Human {
        return;
    }
    let refs: Vec<NamedRecordRef> = prose
        .refs
        .iter()
        .map(|reference| NamedRecordRef {
            pointer: prose.slot.clone(),
            reference: reference.clone(),
        })
        .collect();
    let field = match validate_record_references(memory, &refs) {
        Ok(()) => return,
        Err(ReferenceRefusal::Unresolved { pointer }) => pointer,
        Err(ReferenceRefusal::Read(error)) => {
            tracing::warn!(%error, "landed entity text's links could not be read");
            return;
        }
    };
    let facts = ReferenceRefusalFacts {
        actor: memory.actor(),
        actor_class: memory.actor_class(),
        row,
        field,
        outcome: ReferenceOutcome::Unlinked,
    };
    if let Err(error) = receipt_reference_refusals(memory, &[facts]) {
        tracing::warn!(%error, "landed entity text's unresolved links went unreceipted");
    }
}
