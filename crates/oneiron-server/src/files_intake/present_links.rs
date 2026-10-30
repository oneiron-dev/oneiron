//! A rescan's present (already-landed) notes' links, resolved as their files
//! hold them now (FIX 1363). The rescan reconciles a superseded note's
//! `mentions` edges to them, landing new ones and deleting dropped ones.

use std::collections::{HashMap, HashSet};

use oneiron::note::{ImportedNoteLink, ImportedNoteStanding};

use super::reader::{Index, Note};

/// Resolves every present note's links as its file holds them now, by path.
/// Resolution is against the whole folder read, as the new-notes resolver;
/// the caller reads whole before this whenever any note changed, so a
/// skipped file's name still resolves and no live edge reads as dropped. A
/// link to a note that never landed, or to the note itself, stays out.
pub(crate) fn resolve_present_links(
    notes: &[Note],
    standings: &[ImportedNoteStanding],
) -> Vec<ImportedNoteLink> {
    let now = Index::new(notes, |_| true, |at| notes[at].title.as_deref());
    let first_parts = notes
        .iter()
        .enumerate()
        .filter(|(_, note)| note.part_of.is_none())
        .map(|(at, note)| (note.path.as_str(), at))
        .collect::<HashMap<_, _>>();
    let mut batch = Vec::new();
    let mut seen = HashSet::new();
    for (from, note) in notes.iter().enumerate() {
        if !matches!(
            standings[from],
            ImportedNoteStanding::Changed | ImportedNoteStanding::Unchanged
        ) {
            continue;
        }
        if let Some(&to) = note
            .part_of
            .as_deref()
            .and_then(|file| first_parts.get(file))
            && !matches!(
                standings[to],
                ImportedNoteStanding::Removed | ImportedNoteStanding::Refused
            )
            && seen.insert((from, to))
        {
            batch.push(ImportedNoteLink {
                from: note.path.clone(),
                to: notes[to].path.clone(),
            });
        }
        for link in &note.links {
            if link.target.is_empty() {
                continue;
            }
            let Some(to) = now.resolve(&link.target) else {
                continue;
            };
            if to == from
                || matches!(
                    standings[to],
                    ImportedNoteStanding::Removed | ImportedNoteStanding::Refused
                )
            {
                continue;
            }
            if seen.insert((from, to)) {
                batch.push(ImportedNoteLink {
                    from: note.path.clone(),
                    to: notes[to].path.clone(),
                });
            }
        }
    }
    batch
}
