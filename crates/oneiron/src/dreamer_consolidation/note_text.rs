//! The text of one NOTE as the Dreamer may read it (ARCH-0032 stage 2), in
//! the caller's transaction: one projection shared by the NOTE review and a
//! declared scope summary's evidence (FIX 907).
//!
//! A NOTE whose extraction default, its kind's or its own override, is
//! Allowed reads whole. An AfterSeal NOTE reads once it is sealed: a sealed
//! scratchpad through its line marks (ARCH-0032 #scratchpad-marks), its
//! `scratch` lines blanked, any other sealed NOTE whole. A diary stays
//! private strategy and a Disabled NOTE is never read. A NOTE with no text
//! left is not read either. The projection imposes no review cursor, review
//! record or project: those are the review's own.

use std::ops::Range;

use crate::note::ExtractionDefault;
use crate::{EntityId, Result, Vault};
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};
use oneiron_model::llm::ScopeResource;

/// One NOTE's admitted text, the stored version it was read at, and a
/// fingerprint of the projection that moves with the text and with the
/// policy that shaped it.
pub(super) struct NoteText {
    /// The stored markdown the text was projected from.
    pub(super) markdown: String,
    /// The text the Dreamer reads: the whole markdown, or a sealed pad's
    /// with its `scratch` lines blanked.
    pub(super) text: String,
    /// Whether the text is a sealed scratchpad's, read through its marks.
    pub(super) sealed_pad: bool,
    /// A sealed pad's `keep` lines, as byte ranges of `text`.
    pub(super) keep: Vec<Range<usize>>,
    /// The exact stored version the text was read from.
    pub(super) version: ScopeResource,
    /// BLAKE3 over the projection's mode and its text.
    pub(super) fingerprint: [u8; 32],
}

/// The admitted text of the NOTE `id` whose stored body is `body`, read in
/// `txn`; `None` when the Dreamer may not read it (an undecodable body, a
/// diary, a Disabled kind or override, an unsealed AfterSeal NOTE) or it
/// holds no text. The caller has checked the row is a NOTE.
pub(super) fn note_text_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<Option<NoteText>> {
    let Ok(decoded) = crate::note::decode_note_body_in_txn(&vault.store, txn, body) else {
        return Ok(None);
    };
    let extraction =
        crate::note::note_defaults_in_txn(&vault.store, txn, id, decoded.kind.as_str().as_ref())?
            .extraction;
    let (mode, text, sealed_pad, keep) = if extraction == ExtractionDefault::Allowed {
        ("allowed", decoded.markdown.clone(), false, Vec::new())
    } else if extraction == ExtractionDefault::AfterSeal
        && crate::note::note_sealed_in_txn(&vault.store, txn, *id)?
    {
        if vault.scratchpad_sealed_in_txn(txn, *id)? {
            let (text, keep) = crate::context_board::sealed_pad_review_text(&decoded.markdown);
            ("sealed_pad", text, true, keep)
        } else {
            ("sealed", decoded.markdown.clone(), false, Vec::new())
        }
    } else {
        return Ok(None);
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    let fingerprint = note_text_fingerprint(mode, &text);
    Ok(Some(NoteText {
        markdown: decoded.markdown,
        text,
        sealed_pad,
        keep,
        version: super::resources::document_version(*id, body),
        fingerprint,
    }))
}

/// A NOTE's text fingerprint (`purposes::dreamer_consolidation::NOTE_TEXT`):
/// the read mode, then the text, each after its u64-BE byte length.
fn note_text_fingerprint(mode: &str, text: &str) -> [u8; 32] {
    LegacyDigest::new(purposes::dreamer_consolidation::NOTE_TEXT)
        .len_u64_be(mode.len())
        .raw(mode.as_bytes())
        .len_u64_be(text.len())
        .raw(text.as_bytes())
        .finish()
}

/// [`note_text_fingerprint`] for the K door
/// (`test_doors::fingerprint_keep_dreamer_consolidation_digests`). Not API.
#[cfg(oneiron_test_support)]
pub(crate) fn note_text_fingerprint_for_test(mode: &str, text: &str) -> [u8; 32] {
    note_text_fingerprint(mode, text)
}
