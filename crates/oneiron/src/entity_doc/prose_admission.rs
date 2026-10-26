//! OF-063 prose links for entity text (FIX 1227, 1351, 1672): the prose an
//! AI writer lands in an entity document (an anchored edit's text, a whole
//! update's text, a proposed fork's rewrite or edits) is read for
//! `oneiron://` links its writer cannot resolve, as a NOTE's markdown and a
//! KV value are. Each slot is read as one complete Markdown carrier, so its
//! code (fenced, indented or inline) and raw HTML are no prose. The read runs
//! once the write has landed, over the text as the document took it (masked
//! secrets keep their handles), so a refused or rolled-back write, a
//! partial diff it discarded and a link masking removed earn nothing, and a
//! settlement that merges admitted operations is no new speech. A slot with
//! a link that does not resolve earns one receipt with the outcome
//! `unlinked`; the text is neither refused nor rewritten, and a read or
//! receipt that fails is logged while the write's answer stands.

use crate::EdgeActorClass;
use crate::Vault;
use crate::gate::record_references::{PROSE_LINK_SCHEME, admit_prose_text};
use crate::memory::Memory;
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
/// its text as the document took it.
pub(super) struct LandedProse {
    actor: WriteActor,
    slot: String,
    text: String,
}

impl LandedProse {
    pub(super) fn new(actor: WriteActor, slot: String, text: String) -> Self {
        Self { actor, slot, text }
    }
}

/// Receipts `landed`'s unresolved links under `row`, once its write has
/// landed. A raw door holds no caller handle: each writer reads under its
/// own local actor handle.
pub(super) fn admit_landed(vault: &Vault, row: &'static str, landed: &[LandedProse]) {
    for prose in landed {
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

/// One slot read as its writer reads: only an AI writer's prose is read, and
/// text with no link is not read at all.
fn admit(memory: &Memory<'_>, row: &'static str, prose: &LandedProse) {
    if memory.actor_class() == EdgeActorClass::Human || !prose.text.contains(PROSE_LINK_SCHEME) {
        return;
    }
    admit_prose_text(memory, row, &prose.slot, &prose.text, 0);
}
