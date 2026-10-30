//! Born-with prompt text for a reader who is not the owner (FIX 6054): a
//! shared brief's recipient, and the caller of a non-owner artifact export,
//! get a prompt's text only from the prompt sources that reader can read
//! itself. The guest and federation sidecar does the same (FIX 5937). When
//! the reader cannot read a source, only that source's text is left out. The
//! body's other prompt sources keep their prose and order. Its why, keep
//! memo, intent prompt and carried text read as before. The owner's own brief
//! view and download never reach this module, and the stored birth is never
//! rewritten.

use std::collections::BTreeSet;

use super::{BornWith, BornWithField, TravelChoice};
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadReceipt};
use crate::context_board::{room_ceiling_in, thread_ceiling_in};
use crate::entity_id::EntityId;
use crate::lens::LensRenderFrame;
use crate::memory::{Memory, MemoryResult};
use crate::provenance::made_by::{MadeBy, MadeByInputRole};
use crate::share::ShareViewerScope;
use crate::vault::live_entity_row_in_txn;
use crate::{Result, Vault};

/// What a non-owner reader's prompt does with a prompt source that reader
/// cannot read, or one that is no longer live (CALLS: FIX 6054 reader-scoped
/// prompt sources).
enum DeniedPromptAction {
    /// Leave out that source's text. The body's other readable prompt
    /// sources and its other born-with fields still read.
    OmitSourceText,
}

const DENIED_PROMPT_ACTION: DeniedPromptAction = DeniedPromptAction::OmitSourceText;

/// What a non-owner reader's prompt does when the reader's own admission
/// cannot be built for this call: its credential is no longer live, its
/// room turn no longer reads its room or thread, or its share no longer
/// resolves for it (CALLS: FIX 6054 reader-scoped prompt sources).
enum DeniedAdmissionAction {
    /// Treat every prompt source of the call as denied. The view or export
    /// still goes, with its other born-with fields.
    OmitLocalPromptInputs,
}

const DENIED_ADMISSION_ACTION: DeniedAdmissionAction = DeniedAdmissionAction::OmitLocalPromptInputs;

/// What the prompt says at its end when a source's text was left out:
/// nothing, so it does not tell the reader that a source was left out
/// (CALLS: FIX 6054 reader-scoped prompt sources).
const WITHHELD_TEXT_MARKER: Option<&str> = None;

/// How a shared brief's recipient must read a prompt source (CALLS: FIX 6054
/// reader-scoped prompt sources).
enum SharedPromptAdmission {
    /// A CLAIM source must pass the share's own evaluator, as a citation
    /// does: the share's maximum, the viewer's narrowing and live
    /// `core:read`. Every source must also pass the viewer's own read and
    /// frame, as the brief and each pin's source document do.
    ShareClaimsAndViewerFrame,
}

const SHARED_PROMPT_ADMISSION: SharedPromptAdmission =
    SharedPromptAdmission::ShareClaimsAndViewerFrame;

/// One shared brief view's reader: the share it opens, the viewer and the
/// narrowing it asked for, and the frame and read the view renders under.
struct SharedViewer<'a, 'r> {
    share_id: &'a EntityId,
    viewer: &'a EntityId,
    narrowing: Option<&'a ShareViewerScope>,
    frame: &'a LensRenderFrame,
    read: &'a ScopedRead<'r>,
}

impl Vault {
    /// The born-with text that share `share_id`'s view of brief `brief`
    /// carries for `viewer`. It is the share's travel choice of
    /// [`Self::born_with_text_for_another`], with prompt text only from the
    /// prompt sources the viewer reads in this view
    /// ([`SHARED_PROMPT_ADMISSION`]). The receipt folds every source read;
    /// it is `None` when no source was read. A choice without the prompt
    /// reads no source. Also returns the readable sources whose text the
    /// prompt carries, in the order the brief's birth names them, for the
    /// view's producers (FIX 6310).
    pub(crate) fn shared_brief_born_with(
        &self,
        share_id: &EntityId,
        viewer: &EntityId,
        narrowing: Option<&ShareViewerScope>,
        brief: &EntityId,
        frame: &LensRenderFrame,
        read: &ScopedRead<'_>,
    ) -> Result<(BornWith, Option<ScopedReadReceipt>, Vec<EntityId>)> {
        let travel = self.share_travel(share_id)?;
        let birth = if travel.born_with.contains(&BornWithField::Prompt) {
            self.row_birth(brief)?
        } else {
            None
        };
        let Some(birth) = birth else {
            let text = self.born_with_text_for_another(brief, None)?;
            return Ok((travel.project(text), None, Vec::new()));
        };
        let reader = SharedViewer {
            share_id,
            viewer,
            narrowing,
            frame,
            read,
        };
        let mut receipt = None;
        let sources = prompt_sources(&birth.made_by);
        let readable = shared_sources_readable(self, &reader, &sources, &mut receipt)?;
        let read_sources: Vec<EntityId> = sources
            .into_iter()
            .filter(|source| readable.as_ref().is_some_and(|ids| ids.contains(source)))
            .collect();
        let (made_by, omitted) = readable_made_by(birth.made_by, readable.as_ref());
        let text = self.born_with_text_for_another(brief, Some(&made_by))?;
        Ok((
            travel.project(with_marker(text, omitted)),
            receipt,
            read_sources,
        ))
    }
}

impl Memory<'_> {
    /// The born-with text that a non-owner's export of one version of
    /// `artifact` (its `made_by`) carries. It is
    /// [`Vault::born_with_text_for_another`], with prompt text only from the
    /// prompt sources this handle's own read lane reads now: its grants, its
    /// credential's records, its room turn and where its rows go. A choice
    /// without the prompt reads no source. The caller projects `choice`.
    pub(crate) fn born_with_text_for_reader(
        &self,
        artifact: &EntityId,
        made_by: &MadeBy,
        choice: &TravelChoice,
    ) -> MemoryResult<BornWith> {
        let vault = self.vault();
        let sources = prompt_sources(made_by);
        if sources.is_empty() || !choice.born_with.contains(&BornWithField::Prompt) {
            return Ok(vault.born_with_text_for_another(artifact, Some(made_by))?);
        }
        let readable = self.lane_sources_readable(&sources)?;
        let (made_by, omitted) = readable_made_by(made_by.clone(), readable.as_ref());
        let text = vault.born_with_text_for_another(artifact, Some(&made_by))?;
        Ok(with_marker(text, omitted))
    }

    /// The `sources` this handle's read lane reads now, each one live, judged
    /// in one snapshot. `None` when that lane cannot be built for this call:
    /// its room turn no longer reads its room or thread, or its credential
    /// is no longer live. Any other error is the export's own.
    fn lane_sources_readable(
        &self,
        sources: &[EntityId],
    ) -> MemoryResult<Option<BTreeSet<EntityId>>> {
        if !self.room_turn_reads()? {
            return Ok(None);
        }
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        if !lane.proof_live_in(&txn)? {
            return Ok(None);
        }
        let admitted = lane.entities_readable_in_txn(&txn, sources)?;
        let mut readable = BTreeSet::new();
        for (source, admitted) in sources.iter().zip(admitted) {
            if admitted && live_entity_row_in_txn(&vault.store, &txn, source)?.is_live() {
                readable.insert(*source);
            }
        }
        Ok(Some(readable))
    }

    /// Whether the room turn this handle is bound to still reads its room
    /// or thread, where [`Memory::read_lane`] would build its ceiling. With
    /// no room turn, the answer is yes.
    fn room_turn_reads(&self) -> MemoryResult<bool> {
        let Some(turn) = self.room_turn() else {
            return Ok(true);
        };
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        Ok(match turn.branch {
            Some(thread) => {
                thread_ceiling_in(vault, &txn, turn.room, thread, self.actor())?.is_some()
            }
            None => room_ceiling_in(vault, &txn, turn.room, self.actor())?.is_some(),
        })
    }
}

/// The prompt sources `made_by` names, each once, in the order it first
/// names them.
fn prompt_sources(made_by: &MadeBy) -> Vec<EntityId> {
    let mut seen = BTreeSet::new();
    made_by
        .inputs
        .iter()
        .filter(|input| input.role == MadeByInputRole::Prompt && seen.insert(input.row))
        .map(|input| input.row)
        .collect()
}

/// The `sources` that `reader` reads in its shared view
/// ([`SHARED_PROMPT_ADMISSION`]), with each read's receipt folded into
/// `receipt`. `None` when the reader's admission cannot be built for this
/// call: its credential is no longer live, or the share no longer resolves
/// for it. Any other error is the view's own.
fn shared_sources_readable(
    vault: &Vault,
    reader: &SharedViewer<'_, '_>,
    sources: &[EntityId],
    receipt: &mut Option<ScopedReadReceipt>,
) -> Result<Option<BTreeSet<EntityId>>> {
    if sources.is_empty() {
        return Ok(Some(BTreeSet::new()));
    }
    let mut claims = Vec::new();
    let mut candidates = Vec::new();
    {
        let txn = vault.store.env.read_txn()?;
        if !reader.read.proof_live_in(&txn)? {
            return Ok(None);
        }
        for source in sources {
            // A row not stored here is no source this view reads.
            let Some(kind) = vault.get_entity_type_in_txn(&txn, source)? else {
                continue;
            };
            let share_judges = match SHARED_PROMPT_ADMISSION {
                SharedPromptAdmission::ShareClaimsAndViewerFrame => {
                    kind == crate::registry::ENTITY_TYPE_CLAIM
                }
            };
            if share_judges {
                claims.push(*source);
            } else {
                candidates.push(*source);
            }
        }
    }
    if !claims.is_empty() {
        let Some(resolved) = vault.resolve_share_for_view(
            reader.share_id,
            reader.viewer,
            reader.narrowing,
            &claims,
        )?
        else {
            return Ok(None);
        };
        candidates.extend(resolved.visible_claim_refs);
    }
    let mut readable = BTreeSet::new();
    for source in candidates {
        let body = reader.frame.scoped_body(reader.read, &source)?;
        if body.value.is_some() {
            readable.insert(source);
        }
        let folded = match receipt.take() {
            Some(mut folded) => {
                folded.restrict_with(&body.receipt);
                folded
            }
            None => body.receipt,
        };
        *receipt = Some(folded);
    }
    Ok(Some(readable))
}

/// `made_by`, keeping only the prompt inputs whose source is in `readable`.
/// Every other input stays as stamped, in its order. `None` means the
/// reader's admission could not be built for this call
/// ([`DENIED_ADMISSION_ACTION`]). Also returns whether any source's text
/// was left out.
fn readable_made_by(mut made_by: MadeBy, readable: Option<&BTreeSet<EntityId>>) -> (MadeBy, bool) {
    let denied = BTreeSet::new();
    let readable = match readable {
        Some(readable) => readable,
        None => match DENIED_ADMISSION_ACTION {
            DeniedAdmissionAction::OmitLocalPromptInputs => &denied,
        },
    };
    let mut omitted = false;
    made_by.inputs.retain(|input| {
        if input.role != MadeByInputRole::Prompt || readable.contains(&input.row) {
            return true;
        }
        match DENIED_PROMPT_ACTION {
            DeniedPromptAction::OmitSourceText => omitted = true,
        }
        false
    });
    (made_by, omitted)
}

/// `text`, with [`WITHHELD_TEXT_MARKER`] at the end of its prompt when a
/// source's text was left out (`omitted`).
fn with_marker(mut text: BornWith, omitted: bool) -> BornWith {
    if omitted && let Some(marker) = WITHHELD_TEXT_MARKER {
        let prompt = text.entry(BornWithField::Prompt).or_default();
        if !prompt.is_empty() {
            prompt.push_str("\n\n");
        }
        prompt.push_str(marker);
    }
    text
}
