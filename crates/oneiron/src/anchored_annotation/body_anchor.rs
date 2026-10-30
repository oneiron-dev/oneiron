//! The body-frontier anchor (FIX 2460; ARCH-0075 section 4, the body).
//!
//! An imported office file has a live body, and a person's edit there moves
//! no version. A thread on a version the body holds (the import, or an
//! export) also carries where its unit stands in the body, at a body
//! frontier. The housekeeping pass moves that anchor off every edit's and
//! export's answer ([`Vault::sweep_annotation_body_anchors`]): it stamps the
//! body anchor on a thread that has none, lands the thread on the newest
//! export, and follows the body's edits to its head, as the version sweep
//! moves a version anchor: a Word span with its paragraph's edit, a cell
//! range with the body's row, column and sheet edits, a deck's slide or
//! shape by its node id ([`super::deck_anchor`], FIX 12264). Deleting the
//! spot detaches the comment to the Unattached list. The body anchor is a hint:
//! a frontier that does not read leaves the thread on its version pin, with
//! a warning, for the next pass.

use std::collections::HashMap;

use oneiron_docedit::xlsx_body::{XlsxAxis, XlsxAxisEdit};

use super::anchor_text::{docx_blocks, remap_span};
use super::codec::ThreadHead;
use super::deck_anchor::{deck_body_locator, deck_file_locator, move_deck_locator};
use super::model::{
    Anchor, AnnotationThread, BodyAnchor, DriftMarker, Locator, ReanchorOp, ReanchorOutcome,
};
use super::reanchor::replay_locator;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::office_body::OfficeBodyUnits;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// Live bodies one sweep run settles at most; a run that reaches the cap
/// leaves a cursor, and the next pass goes on from it.
const BODY_ANCHOR_ARTIFACTS_PER_RUN: usize = 64;

/// Units by id and text: Word blocks, or worksheets by key and name.
type Units = [(String, String)];

/// A body's units by frontier, read once a pass; `None` where they did not read.
type UnitsAt = HashMap<Vec<u8>, Option<OfficeBodyUnits>>;

/// A Word version's blocks by version, read once a pass.
type FiledAt = HashMap<u64, Option<Vec<(String, String)>>>;

/// One thread's next head, planned in a read and written in a write.
struct Planned {
    thread: AnnotationThread,
    head: ThreadHead,
    effect: Effect,
}

#[derive(Clone, Copy)]
enum Effect {
    /// The body anchor alone moved or was stamped.
    Body,
    /// The thread landed on this export version.
    Landed(u64),
    /// The spot was deleted; the comment detached at this version.
    Detached(u64),
}

impl Vault {
    /// The housekeeping pass's body-anchor sweep: the live bodies'
    /// comments, from the artifact `after` an unfinished run stopped at, for
    /// at most [`BODY_ANCHOR_ARTIFACTS_PER_RUN`] bodies or until `stop`.
    /// Returns the heads written, the artifacts that failed (each keeps its
    /// heads and is tried again on the next pass) and where an unfinished run
    /// goes on.
    pub(crate) fn sweep_annotation_body_anchors(
        &self,
        after: Option<&[u8]>,
        stop: impl Fn() -> bool,
    ) -> Result<(u64, u64, Option<Vec<u8>>)> {
        let artifacts = {
            let rtxn = self.store.env.read_txn()?;
            self.office_bodies_in_txn(&rtxn)?
        };
        // The engine moves the comments as the vault's owner, as the
        // commitment-lapse sweep writes.
        let actor = WriteActor::new(
            crate::vault::embedded_owner_actor_id()?,
            EdgeActorClass::Human,
        );
        let (mut moved, mut failed) = (0_u64, 0_u64);
        for (settled, artifact) in artifacts
            .iter()
            .filter(|artifact| after.is_none_or(|after| artifact.as_bytes().as_slice() >= after))
            .enumerate()
        {
            if settled == BODY_ANCHOR_ARTIFACTS_PER_RUN || stop() {
                return Ok((moved, failed, Some(artifact.as_bytes().to_vec())));
            }
            match self.settle_body_anchors(artifact, actor) {
                Ok((written, unread)) => {
                    moved = moved.saturating_add(written);
                    // A body or version that did not read keeps its comments'
                    // heads for the next pass, as a failed body does.
                    if unread > 0 {
                        failed = failed.saturating_add(1);
                    }
                }
                Err(error) => {
                    failed = failed.saturating_add(1);
                    tracing::warn!(
                        artifact = %artifact.to_hex(),
                        error = ?error,
                        "comments could not follow the body; the next pass tries again",
                    );
                }
            }
        }
        Ok((moved, failed, None))
    }

    /// Plans one artifact's comments in a read, then writes the heads that
    /// changed in one write, each only while its head is the one planned on.
    /// Returns the heads written and how many reads failed in the plan.
    fn settle_body_anchors(&self, artifact: &EntityId, actor: WriteActor) -> Result<(u64, u64)> {
        let (plans, unread) = {
            let rtxn = self.store.env.read_txn()?;
            self.plan_body_anchors_in_txn(&rtxn, artifact)?
        };
        if plans.is_empty() {
            return Ok((0, unread));
        }
        let now = self.now_recorded_at();
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.with_write_txn_grouped(|wtxn| {
            let live: HashMap<EntityId, EntityId> = self
                .effect_annotation_threads_for_artifact_in_txn(wtxn, artifact)?
                .into_iter()
                .map(|thread| (thread.thread_id, thread.head_claim_id))
                .collect();
            let mut written = 0_u64;
            for plan in &plans {
                // A head written since the plan was read is the next pass's.
                if live.get(&plan.thread.thread_id) != Some(&plan.thread.head_claim_id) {
                    continue;
                }
                let op = match plan.effect {
                    Effect::Body => "follow_body",
                    Effect::Landed(version) => {
                        self.record_prior_anchor_in_txn(wtxn, artifact, &plan.thread, version)?;
                        "reanchor"
                    }
                    Effect::Detached(version) => {
                        self.record_detached_in_txn(wtxn, artifact, &plan.thread, version, now)?;
                        "reanchor"
                    }
                };
                let new_head = self.write_thread_head_in_txn(
                    wtxn,
                    artifact,
                    &plan.head,
                    actor,
                    op,
                    occurred,
                    now,
                )?;
                self.supersede_claim_in_txn(wtxn, &new_head, &plan.thread.head_claim_id, now)?;
                written = written.saturating_add(1);
            }
            Ok((written, unread))
        })
    }

    fn plan_body_anchors_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<(Vec<Planned>, u64)> {
        // A body with no attached comment reads no body.
        let threads: Vec<AnnotationThread> = self
            .effect_annotation_threads_for_artifact_in_txn(txn, artifact)?
            .into_iter()
            .filter(|thread| !thread.is_drifted())
            .collect();
        if threads.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let Some(head) = self.office_body_frontier_in_txn(txn, artifact)? else {
            return Ok((Vec::new(), 0));
        };
        let export = self.office_body_latest_export_in_txn(txn, artifact)?;
        let (mut units, mut filed) = (UnitsAt::new(), FiledAt::new());
        let mut unread = 0_u64;
        let mut plans = Vec::new();
        for thread in threads {
            let stamp = match &thread.anchor.body {
                Some(body) => Some((body.clone(), false)),
                None => self
                    .stamp_in_txn(
                        txn,
                        (artifact, head.as_slice()),
                        &thread.anchor,
                        (&mut units, &mut filed),
                        &mut unread,
                    )
                    .map(|body| (body, true)),
            };
            let Some((body, stamped)) = stamp else {
                continue;
            };
            let landing = export
                .as_ref()
                .filter(|(version, _)| thread.anchor.version < *version);
            // A comment already at the body's head with no export to land on
            // has nothing to follow: the pass reads no body for it.
            if !stamped && body.frontier == head && landing.is_none() {
                continue;
            }
            self.load_units(txn, artifact, &body.frontier, &mut units, &mut unread);
            self.load_units(txn, artifact, &head, &mut units, &mut unread);
            if let Some((version, frontier)) = landing {
                self.load_units(txn, artifact, frontier, &mut units, &mut unread);
                // Only a Word span lands through the file's own blocks.
                if matches!(thread.anchor.locator, Locator::Docx { .. }) {
                    self.load_filed(txn, artifact, *version, &mut filed, &mut unread);
                }
            }
            let plan = plan_thread(thread, body, stamped, &head, landing, &units, &filed);
            plans.extend(plan);
        }
        Ok((plans, unread))
    }

    /// The body anchor of a version anchor: the same unit in the live body,
    /// when the body held the anchor's version and, for Word, the body's
    /// paragraph of that block id reads as the version's; for a deck, the
    /// one node the version's ids name there.
    fn stamp_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        (artifact, head): (&EntityId, &[u8]),
        anchor: &Anchor,
        (units, filed): (&mut UnitsAt, &mut FiledAt),
        unread: &mut u64,
    ) -> Option<BodyAnchor> {
        let frontier = self
            .office_body_frontier_of_version_in_txn(txn, artifact, anchor.version)
            .unwrap_or_else(|error| {
                warn_unread(artifact, &error, unread);
                None
            })?;
        self.load_units(txn, artifact, &frontier, units, unread);
        // A deck's file ids are read from the deck bound to that version.
        if matches!(anchor.locator, Locator::Pptx { .. }) {
            self.load_units(txn, artifact, head, units, unread);
        }
        let held = match (units_at(units, &frontier), &anchor.locator) {
            (Some(OfficeBodyUnits::Docx(blocks)), Locator::Docx { para_path, .. }) => {
                self.load_filed(txn, artifact, anchor.version, filed, unread);
                let filed = filed
                    .get(&anchor.version)
                    .and_then(Option::as_deref)
                    .unwrap_or_default();
                text_of(blocks, para_path)
                    .is_some_and(|text| text_of(filed, para_path) == Some(text))
            }
            (Some(OfficeBodyUnits::Xlsx { sheets, .. }), Locator::Xlsx { sheet, .. }) => {
                sheets.iter().any(|(_, name)| name == sheet)
            }
            (Some(OfficeBodyUnits::Pptx(deck)), Locator::Pptx { .. }) => {
                let head = units_at(units, head);
                let locator = deck_body_locator(deck, head, anchor.version, &anchor.locator)?;
                return Some(BodyAnchor { frontier, locator });
            }
            _ => false,
        };
        held.then(|| BodyAnchor {
            frontier,
            locator: anchor.locator.clone(),
        })
    }

    fn load_units(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        frontier: &[u8],
        units: &mut UnitsAt,
        unread: &mut u64,
    ) {
        if units.contains_key(frontier) {
            return;
        }
        let read = self
            .office_body_units_in_txn(txn, artifact, frontier)
            .unwrap_or_else(|error| {
                warn_unread(artifact, &error, unread);
                None
            });
        units.insert(frontier.to_vec(), read);
    }

    fn load_filed(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        version: u64,
        filed: &mut FiledAt,
        unread: &mut u64,
    ) {
        if filed.contains_key(&version) {
            return;
        }
        let read = (|| -> Result<Option<Vec<(String, String)>>> {
            let Some(bytes) = self.read_blob_artifact_version_in_txn(txn, artifact, version)? else {
                return Ok(None);
            };
            docx_blocks(&bytes, &self.text_limits_in_txn(txn)?)
        })()
        .unwrap_or_else(|error| {
            warn_unread(artifact, &error, unread);
            None
        });
        filed.insert(version, read);
    }
}

fn warn_unread(artifact: &EntityId, error: &crate::error::Error, unread: &mut u64) {
    *unread = unread.saturating_add(1);
    tracing::warn!(
        artifact = %artifact.to_hex(),
        error = ?error,
        "a body or version did not read; its comments keep their version pin",
    );
}

/// One thread's next head: its body anchor at `body_head`, landed on
/// the newest export when it names an older version, or detached when the
/// body deleted its spot. `None` when nothing changes, or when the body's
/// edits since the anchor do not read in order: the thread keeps its head.
fn plan_thread(
    thread: AnnotationThread,
    body: BodyAnchor,
    stamped: bool,
    body_head: &[u8],
    landing: Option<&(u64, Vec<u8>)>,
    units: &UnitsAt,
    filed: &FiledAt,
) -> Option<Planned> {
    let Some(outcome) = units_at(units, &body.frontier)
        .zip(units_at(units, body_head))
        .and_then(|(from, to)| move_body_locator(from, to, &body.locator))
    else {
        tracing::warn!(
            thread = %thread.thread_id.to_hex(),
            "the body's edits since the comment's anchor do not read in order; it keeps its head",
        );
        return None;
    };
    let pinned = thread.anchor.version;
    let (head, effect) = match outcome {
        ReanchorOutcome::Drifted => {
            let at = landing.map_or(pinned, |(version, _)| *version);
            (
                ThreadHead {
                    thread_id: thread.thread_id,
                    origin_version: thread.origin_version,
                    anchor_version: pinned,
                    state: thread.state,
                    locator: thread.anchor.locator.clone(),
                    drift: Some(DriftMarker {
                        drifted_at_version: at,
                        pinned_version: pinned,
                    }),
                    body: None,
                },
                Effect::Detached(at),
            )
        }
        ReanchorOutcome::Mapped(at_head) => {
            let landed = landing.and_then(|(version, frontier)| {
                let target = units_at(units, frontier)?;
                let ReanchorOutcome::Mapped(at_export) =
                    move_body_locator(units_at(units, &body.frontier)?, target, &body.locator)?
                else {
                    return None;
                };
                let filed = filed.get(version).and_then(Option::as_deref);
                let located = match target {
                    OfficeBodyUnits::Pptx(deck) => {
                        let head = units_at(units, body_head);
                        deck_file_locator(deck, head, *version, &at_export)
                    }
                    _ => file_locator(filed, target, &at_export),
                };
                Some((*version, located?))
            });
            let moved = BodyAnchor {
                frontier: body_head.to_vec(),
                locator: at_head,
            };
            if !stamped && landed.is_none() && moved == body {
                return None;
            }
            let (version, locator, effect) = match landed {
                Some((version, locator)) => (version, locator, Effect::Landed(version)),
                None => (pinned, thread.anchor.locator.clone(), Effect::Body),
            };
            (
                ThreadHead {
                    thread_id: thread.thread_id,
                    origin_version: thread.origin_version,
                    anchor_version: version,
                    state: thread.state,
                    locator,
                    drift: None,
                    body: Some(moved),
                },
                effect,
            )
        }
    };
    Some(Planned {
        thread,
        head,
        effect,
    })
}

fn units_at<'a>(units: &'a UnitsAt, frontier: &[u8]) -> Option<&'a OfficeBodyUnits> {
    units.get(frontier).and_then(Option::as_ref)
}

fn text_of<'a>(units: &'a Units, id: &str) -> Option<&'a str> {
    units
        .iter()
        .find(|(unit, _)| unit.as_str() == id)
        .map(|(_, text)| text.as_str())
}

/// Where a body anchor's unit stands at another frontier, read from the
/// units at both. A deleted block, sheet, slide or shape, or a span or range
/// deleted whole, drifts. `None` when the edits between them cannot be read
/// in order.
fn move_body_locator(
    from: &OfficeBodyUnits,
    to: &OfficeBodyUnits,
    locator: &Locator,
) -> Option<ReanchorOutcome> {
    match (from, to, locator) {
        (
            OfficeBodyUnits::Docx(before),
            OfficeBodyUnits::Docx(after),
            Locator::Docx {
                para_path,
                char_start,
                char_end,
            },
        ) => {
            let was = text_of(before, para_path)?;
            let moved = text_of(after, para_path)
                .and_then(|now| remap_span(was, now, *char_start, *char_end))
                .and_then(|(start, end)| Locator::docx(para_path.clone(), start, end).ok());
            Some(moved.map_or(ReanchorOutcome::Drifted, ReanchorOutcome::Mapped))
        }
        (
            OfficeBodyUnits::Xlsx {
                sheets: before,
                axes: was,
            },
            OfficeBodyUnits::Xlsx {
                sheets: after,
                axes: now,
            },
            Locator::Xlsx { .. },
        ) => Some(replay_locator(locator, &sheet_ops(before, was, after, now)?)),
        (_, OfficeBodyUnits::Pptx(after), Locator::Pptx { .. }) => {
            move_deck_locator(after, locator)
        }
        _ => None,
    }
}

/// Where a body unit stands in the export that projected it. A cell range
/// stands at the same place: the body's addresses are the file's. A Word
/// span stands in the file's block of the same id when it reads the same,
/// else in the one block that reads the same; `None` when no block does.
fn file_locator(
    filed: Option<&Units>,
    target: &OfficeBodyUnits,
    locator: &Locator,
) -> Option<Locator> {
    let (
        OfficeBodyUnits::Docx(body),
        Locator::Docx {
            para_path,
            char_start,
            char_end,
        },
    ) = (target, locator)
    else {
        return Some(locator.clone());
    };
    let (filed, text) = (filed?, text_of(body, para_path)?);
    if text_of(filed, para_path) == Some(text) {
        return Some(locator.clone());
    }
    let mut same = filed.iter().filter(|(_, block)| block.as_str() == text);
    let (id, _) = same.next()?;
    if same.next().is_some() {
        return None;
    }
    Locator::docx(id.clone(), *char_start, *char_end).ok()
}

/// The version sweep's operations for a workbook body's edits between two
/// frontiers: the row and column edits the later one added, then each sheet
/// removed and each renamed, through a name no sheet holds so swapped names
/// stay apart. `None` when the later log does not begin with the earlier.
fn sheet_ops(
    before: &Units,
    was: &[(String, XlsxAxisEdit)],
    after: &Units,
    now: &[(String, XlsxAxisEdit)],
) -> Option<Vec<ReanchorOp>> {
    let added = now.strip_prefix(was)?;
    let mut ops: Vec<ReanchorOp> = added
        .iter()
        .filter_map(|(key, edit)| Some(axis_op(text_of(before, key)?.to_owned(), *edit)))
        .collect();
    let mut renamed = Vec::new();
    for (index, (key, name)) in before.iter().enumerate() {
        match text_of(after, key) {
            None => ops.push(ReanchorOp::RemoveSheet {
                sheet: name.clone(),
            }),
            Some(new) if new != name.as_str() => {
                let parked = format!("\u{0}{index}");
                ops.push(ReanchorOp::RenameSheet {
                    from: name.clone(),
                    to: parked.clone(),
                });
                renamed.push(ReanchorOp::RenameSheet {
                    from: parked,
                    to: new.to_owned(),
                });
            }
            Some(_) => {}
        }
    }
    ops.extend(renamed);
    Some(ops)
}

fn axis_op(sheet: String, edit: XlsxAxisEdit) -> ReanchorOp {
    let (at, count) = (edit.at, edit.count);
    match (edit.axis, edit.delete) {
        (XlsxAxis::Row, false) => ReanchorOp::InsertRows {
            sheet,
            at_row: at,
            count,
        },
        (XlsxAxis::Row, true) => ReanchorOp::DeleteRows {
            sheet,
            at_row: at,
            count,
        },
        (XlsxAxis::Column, false) => ReanchorOp::InsertCols {
            sheet,
            at_col: at,
            count,
        },
        (XlsxAxis::Column, true) => ReanchorOp::DeleteCols {
            sheet,
            at_col: at,
            count,
        },
    }
}
