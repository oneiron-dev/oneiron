//! The turns an Arc's reply names to open (FIX 7509 P8): when a line and
//! the claims disagree, the model names the cited turns by their labels and
//! the engine opens them through their handles before anything is written.
//! Each is read through the Dreamer's own scoped read (its point read of
//! the TURN, then every witnessed MESSAGE of it), in a snapshot of its own,
//! and must be the version the Arc's evidence pinned: one changed since is
//! the composition's to redo, never another version's words.

use super::super::call_labels::LabelKind;
use super::super::residency::waits_on_residency;
use super::super::turn_text::{collect_in, dreamer_read, snapshot};
use super::ScopeSummaryEvidence;
use super::arc_evidence::ArcView;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TURN;
use crate::{EntityId, Vault};

/// What opening a reply's turns came to.
pub(super) enum Opened {
    /// Each turn's words under its label, in the order named.
    Text(String),
    /// A turn that did not open, by its full id: the Arc stays owed.
    Unavailable(EntityId),
}

/// Opens `named`, each a TURN `view` labelled, as `evidence` pinned it. A
/// turn that changed since its pin refuses as a concurrent write, so the
/// Arc composes again; one partly away from this replica refuses as it
/// waits on residency.
pub(super) fn open_turns(
    vault: &Vault,
    evidence: &ScopeSummaryEvidence,
    view: &ArcView,
    named: &[EntityId],
) -> Result<Opened> {
    let read = dreamer_read(vault)?;
    let txn = snapshot(vault)?;
    let rows = read.get_entities_parts_in_txn(&txn, named)?;
    let mut text = String::new();
    for (turn, row) in named.iter().zip(rows) {
        let Some((ENTITY_TYPE_TURN, _, body)) = row else {
            return Ok(Opened::Unavailable(*turn));
        };
        let opened = match collect_in(&read, &txn, turn, &body, &mut 0) {
            Ok(opened) => opened,
            Err(error) if waits_on_residency(&error) => return Err(error),
            Err(_) => return Ok(Opened::Unavailable(*turn)),
        };
        let handle = turn.to_hex();
        let pinned = evidence
            .source_versions
            .iter()
            .find(|pin| pin.id == handle)
            .and_then(|pin| pin.projected_text);
        if pinned != Some(opened.summary_fingerprint()?) {
            return Err(Error::ConcurrentWrite(
                "an arc's turn changed during composition",
            ));
        }
        let Some(label) = view.labels.label(LabelKind::Turn, *turn) else {
            return Ok(Opened::Unavailable(*turn));
        };
        if let Some(words) = opened.text() {
            text.push_str(&format!("[{label}] {words}\n"));
        }
    }
    Ok(Opened::Text(text))
}
