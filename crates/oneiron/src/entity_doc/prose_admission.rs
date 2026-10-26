//! OF-063 prose links for entity text (FIX 1227, 1351, 1672): the prose an
//! AI writer lands in an entity document (an anchored edit's text, a whole
//! update's text, a proposed fork's rewrite or edits) is read for
//! `oneiron://` links its writer cannot resolve, as a NOTE's markdown and a
//! KV value are. The text is read as its writer said it, each secret still
//! its handle (OF-067): a link inside a value a known handle writes again is
//! not this writer's speech. An anchored edit's text is read in its place in
//! the document, whose rest is its Markdown context (code fences, reference
//! definitions) and never read as new speech; a text that lands past the
//! parser's reach in its document is read on its own. Text equal to what it
//! replaced says nothing new.
//!
//! The links are taken from the text inside the writer, which reads no
//! record; they are resolved once the write has landed, so a refused or
//! rolled-back write and a partial diff it discarded earn nothing, and a
//! settlement that merges admitted operations is no new speech. A slot with
//! a link that does not resolve earns one receipt with the outcome
//! `unlinked`; the text is neither refused nor rewritten, and a read or
//! receipt that fails is logged while the write's answer stands.

use std::ops::Range;

use super::EntityDoc;
use super::verbs::Admitted;
use crate::EdgeActorClass;
use crate::Vault;
use crate::batch::secret_scan::LiftedKeys;
use crate::gate::record_references::{
    MAX_PROSE_LINKS, MAX_PROSE_SCAN_BYTES, NamedRecordRef, PROSE_LINK_SCHEME, ProseLink,
    ReferenceRefusal, parse_record_links, validate_record_references,
};
use crate::memory::Memory;
use crate::receipt::{ReferenceOutcome, ReferenceRefusalFacts, receipt_reference_refusals};
use crate::write_envelope::WriteActor;

/// The row an anchored edit lands through.
pub(super) const EDIT_ROW: &str = "vault.entity_text.edit";
/// The row a whole-text update lands through.
pub(super) const UPDATE_ROW: &str = "vault.entity_text.update";
/// The row a text proposal's forks land through.
pub(super) const PROPOSAL_ROW: &str = "vault.entity_text.propose";
/// The row a SUMMARY change's fork lands through.
pub(super) const SUMMARY_ROW: &str = "vault.summaries.propose";

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

/// Only an AI writer's prose is read (OF-063).
fn reads(actor: WriteActor) -> bool {
    actor.actor_class() != EdgeActorClass::Human
}

/// The refs `text` authored at `place` in `body`, the document's stored
/// text: read in the document's own Markdown while its parser reaches it,
/// else on its own.
fn in_place(body: &str, place: usize, text: &Admitted, lifted: &LiftedKeys) -> Vec<String> {
    let said = text.said.as_str();
    let start = body.char_indices().nth(place).map_or(body.len(), |(at, _)| at);
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

/// The refs of `carrier`'s links that overlap `span`.
fn authored(carrier: &str, span: Range<usize>) -> Vec<String> {
    within(parse_record_links(carrier), &span)
}

/// The refs of `links` that overlap `span`.
fn within(links: Vec<ProseLink>, span: &Range<usize>) -> Vec<String> {
    links
        .into_iter()
        .filter(|link| link.start < span.end && span.start < link.end)
        .map(|link| link.reference)
        .collect()
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
