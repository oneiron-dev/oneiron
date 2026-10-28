//! The recorded-ops lane's input (FIX 7820): the authored insert and delete
//! runs of a proposal's window, read change by change from its retained
//! document, with moves paired from those runs.
//!
//! Each recorded change is read as the document applied it: the text delta
//! between the versions on either side of it ([`OpSpan`]'s refs), so edits
//! scattered through one change stay separate runs. A Loro text has no move
//! operation; a move is a delete and an insert of the same content (ARCH-0056
//! §2), so a run of proposal text the window deleted pairs with a run the
//! window inserted and kept when their whitespace-collapsed contents match.

use loro::event::Diff;
use loro::{ContainerID, ContainerType, Frontiers, TextDelta};

use crate::edit_distance::myers::collapse_whitespace;
use crate::edit_distance::{FinalizedProposalText, LoroOpRef, OpSpan};
use crate::entity_doc::EntityDoc;
use crate::error::{ArtifactError, Error, Result};

use super::schema::u32_saturating;

/// The text container a proposal artifact's body is written into.
const BODY_TEXT: &str = "body";

/// What the window's authored runs did, in characters of the
/// whitespace-collapsed text.
pub(super) struct LoggedRuns {
    /// Characters inserted, every change summed, moved runs left out.
    pub(super) ins: u32,
    /// Characters deleted, every change summed, moved runs left out.
    pub(super) del: u32,
    /// Characters a paired delete and insert relocated.
    pub(super) moved: u32,
    /// Proposal characters still standing at finalize.
    pub(super) kept: u32,
    /// Length of the proposed text.
    pub(super) before_len: u32,
    /// Length of the final text.
    pub(super) after_len: u32,
}

/// Where one character of the replayed text came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Proposal text standing since the window opened.
    Proposed,
    /// Typed by the window's inserted run with this index.
    Typed(usize),
}

/// One run a change inserted.
struct InsertedRun {
    content: String,
    /// What the run was charged, in collapsed characters.
    mass: u32,
    /// No later change deleted any of its characters.
    survives: bool,
}

/// One run a change deleted.
struct DeletedRun {
    content: String,
    /// What the run was charged, in collapsed characters.
    mass: u32,
    /// Every character it took was proposal text: a move candidate.
    proposed_only: bool,
}

/// The runs one edit site laid down: consecutive inserts and deletes with no
/// retained text between them, so a replacement is one site.
struct Site {
    separators_before: u32,
    inserted: Vec<usize>,
    deleted: Vec<usize>,
}

/// Reads every recorded change of `record`'s window out of `document` and
/// counts its runs.
///
/// Runs count in the whitespace-collapsed frame: each run's non-whitespace
/// characters, plus the word separators its edit site adds or removes, which
/// go to the site's first inserted (or deleted) run with content. A site whose
/// runs are all whitespace (re-spacing, re-wrapping, a word split by a space)
/// counts nothing. Text typed and then deleted again by a later change counts
/// on both sides; that churn is what this lane sees and an endpoint diff
/// cannot. A move pairs the two runs' charges, so it leaves `ins` and `del`
/// in the unit they were charged in.
///
/// # Errors
///
/// [`ArtifactError::DeltaCaptureUnavailable`] when a recorded version no
/// longer reads in the document, or the replay does not land on the final
/// text.
pub(super) fn read_window(
    document: &EntityDoc,
    record: &FinalizedProposalText,
) -> Result<LoggedRuns> {
    let proposed = text_at(document, &record.proposed_ref)?;
    let mut chars: Vec<char> = proposed.chars().collect();
    let mut origins = vec![Origin::Proposed; chars.len()];
    let mut inserted: Vec<InsertedRun> = Vec::new();
    let mut deleted: Vec<DeletedRun> = Vec::new();
    let body = ContainerID::new_root(BODY_TEXT, ContainerType::Text);
    for (_, span) in &record.ops_by_actor {
        let mut cursor = 0_usize;
        let mut site: Option<Site> = None;
        for delta in change_deltas(document, span, &body)? {
            if let TextDelta::Retain { retain, .. } = delta {
                close_site(site.take(), &chars, &mut inserted, &mut deleted);
                cursor += retain;
                continue;
            }
            let open = site.get_or_insert_with(|| Site {
                separators_before: separators(&chars),
                inserted: Vec::new(),
                deleted: Vec::new(),
            });
            let at = cursor.min(chars.len());
            match delta {
                TextDelta::Insert { insert, .. } => {
                    let run: Vec<char> = insert.chars().collect();
                    let typed = std::iter::repeat_n(Origin::Typed(inserted.len()), run.len());
                    origins.splice(at..at, typed).for_each(drop);
                    cursor = at + run.len();
                    open.inserted.push(inserted.len());
                    inserted.push(InsertedRun {
                        mass: non_whitespace(&run),
                        content: insert,
                        survives: true,
                    });
                    chars.splice(at..at, run).for_each(drop);
                }
                TextDelta::Delete { delete } => {
                    let end = at.saturating_add(delete).min(chars.len());
                    let removed: Vec<char> = chars.drain(at..end).collect();
                    let mut proposed_only = true;
                    for origin in origins.drain(at..end) {
                        if let Origin::Typed(run) = origin {
                            proposed_only = false;
                            if let Some(run) = inserted.get_mut(run) {
                                run.survives = false;
                            }
                        }
                    }
                    open.deleted.push(deleted.len());
                    deleted.push(DeletedRun {
                        mass: non_whitespace(&removed),
                        content: removed.into_iter().collect(),
                        proposed_only,
                    });
                }
                TextDelta::Retain { .. } => {}
            }
        }
        close_site(site, &chars, &mut inserted, &mut deleted);
    }
    let final_text: String = chars.iter().collect();
    if final_text != text_at(document, &record.final_ref)? {
        return Err(unavailable(
            "recorded ops do not replay onto the final text",
        ));
    }
    let ins = inserted
        .iter()
        .fold(0_u32, |total, run| total.saturating_add(run.mass));
    let del = deleted
        .iter()
        .fold(0_u32, |total, run| total.saturating_add(run.mass));
    let moved = pair_moves(&deleted, &inserted);
    let kept: String = chars
        .iter()
        .zip(&origins)
        .filter(|(_, origin)| **origin == Origin::Proposed)
        .map(|(c, _)| *c)
        .collect();
    Ok(LoggedRuns {
        ins: ins.saturating_sub(moved),
        del: del.saturating_sub(moved),
        moved,
        kept: collapsed_len(&kept),
        before_len: collapsed_len(&proposed),
        after_len: collapsed_len(&final_text),
    })
}

/// Charges one closed edit site: a site of whitespace only costs nothing;
/// otherwise the separators it added go to its first inserted run with
/// content, the separators it removed to its first deleted run with content.
fn close_site(
    site: Option<Site>,
    chars: &[char],
    inserted: &mut [InsertedRun],
    deleted: &mut [DeletedRun],
) {
    let Some(site) = site else {
        return;
    };
    let has_content = |content: &str| content.chars().any(|c| !c.is_whitespace());
    let first_inserted = site
        .inserted
        .iter()
        .copied()
        .find(|index| has_content(&inserted[*index].content));
    let first_deleted = site
        .deleted
        .iter()
        .copied()
        .find(|index| has_content(&deleted[*index].content));
    if first_inserted.is_none() && first_deleted.is_none() {
        return;
    }
    let after = separators(chars);
    if let Some(index) = first_inserted.or(first_deleted)
        && after > site.separators_before
    {
        let added = after - site.separators_before;
        match first_inserted {
            Some(_) => inserted[index].mass = inserted[index].mass.saturating_add(added),
            None => deleted[index].mass = deleted[index].mass.saturating_add(added),
        }
    }
    if let Some(index) = first_deleted.or(first_inserted)
        && site.separators_before > after
    {
        let removed = site.separators_before - after;
        match first_deleted {
            Some(_) => deleted[index].mass = deleted[index].mass.saturating_add(removed),
            None => inserted[index].mass = inserted[index].mass.saturating_add(removed),
        }
    }
}

/// The text deltas one recorded change applied to the body, read between the
/// versions on either side of it.
fn change_deltas(
    document: &EntityDoc,
    span: &OpSpan,
    body: &ContainerID,
) -> Result<Vec<TextDelta>> {
    let batch = document
        .doc
        .diff(&frontiers(&span.before_ref)?, &frontiers(&span.after_ref)?)
        .map_err(|_| unavailable("a recorded change no longer reads in its document"))?;
    Ok(batch
        .iter()
        .find_map(|(container, diff)| match diff {
            Diff::Text(deltas) if container == body => Some(deltas.clone()),
            _ => None,
        })
        .unwrap_or_default())
}

/// Charges relocated: a deleted run of proposal text paired with a kept
/// inserted run of the same collapsed content, each run paired at most once,
/// moves the smaller of their two charges.
fn pair_moves(deleted: &[DeletedRun], inserted: &[InsertedRun]) -> u32 {
    let mut paired = vec![false; inserted.len()];
    let mut moved = 0_u32;
    for removed in deleted.iter().filter(|run| run.proposed_only) {
        let content = collapse_whitespace(&removed.content);
        if content.is_empty() {
            continue;
        }
        let candidate = inserted.iter().enumerate().position(|(index, run)| {
            run.survives && !paired[index] && collapse_whitespace(&run.content) == content
        });
        if let Some(index) = candidate {
            paired[index] = true;
            moved = moved.saturating_add(removed.mass.min(inserted[index].mass));
        }
    }
    moved
}

fn non_whitespace(run: &[char]) -> u32 {
    u32_saturating(run.iter().filter(|c| !c.is_whitespace()).count())
}

/// Word separators in the collapsed form of `chars`: one between each two
/// words.
fn separators(chars: &[char]) -> u32 {
    let mut words = 0_usize;
    let mut in_word = false;
    for c in chars {
        if c.is_whitespace() {
            in_word = false;
        } else if !in_word {
            in_word = true;
            words += 1;
        }
    }
    u32_saturating(words.saturating_sub(1))
}

fn collapsed_len(text: &str) -> u32 {
    u32_saturating(collapse_whitespace(text).chars().count())
}

fn text_at(document: &EntityDoc, frontier: &LoroOpRef) -> Result<String> {
    document
        .text_at(frontier.as_bytes())
        .map_err(|_| unavailable("a recorded version no longer reads in its document"))
}

fn frontiers(frontier: &LoroOpRef) -> Result<Frontiers> {
    Frontiers::decode(frontier.as_bytes())
        .map_err(|_| unavailable("a recorded version is not a frontier"))
}

fn unavailable(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::DeltaCaptureUnavailable(reason))
}
