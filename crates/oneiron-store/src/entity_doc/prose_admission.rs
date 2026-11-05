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

use crate::record_links::MAX_PROSE_LINKS;
use crate::record_links::MAX_PROSE_SCAN_BYTES;
use crate::record_links::PROSE_LINK_SCHEME;
use crate::record_links::ProseLink;
use crate::record_links::parse_record_links;
use crate::record_references::NamedRecordRef;
use crate::record_references::ReferenceRefusal;
use crate::reference_refusal::ReferenceOutcome;
use crate::reference_refusal::ReferenceRefusalFacts;
use crate::write_envelope::WriteActor;
use oneiron_base::edge::EdgeActorClass;

/// The row an anchored edit lands through.
pub const EDIT_ROW: &str = "vault.entity_text.edit";
/// The row a whole-text update lands through.
pub const UPDATE_ROW: &str = "vault.entity_text.update";
/// The row a text proposal's forks land through.
pub const PROPOSAL_ROW: &str = "vault.entity_text.propose";
/// The row a SUMMARY change's fork lands through.
pub const SUMMARY_ROW: &str = "vault.summaries.propose";

/// Only an AI writer's prose is read (OF-063).
pub fn reads(actor: WriteActor) -> bool {
    actor.actor_class() != EdgeActorClass::Human
}

/// The refs of `carrier`'s links that overlap `span`.
pub fn authored(carrier: &str, span: Range<usize>) -> Vec<String> {
    within(parse_record_links(carrier), &span)
}

/// The refs of `links` that overlap `span`.
pub fn within(links: Vec<ProseLink>, span: &Range<usize>) -> Vec<String> {
    links
        .into_iter()
        .filter(|link| link.start < span.end && span.start < link.end)
        .map(|link| link.reference)
        .collect()
}
