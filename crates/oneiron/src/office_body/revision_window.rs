//! FIX 595 sequential per-actor DOCX projection, in memory (Engine 16:22).
//!
//! A default-author DOCX export projects one tracked revision per consecutive
//! actor group: the commits after the import through the head, oldest first
//! in deterministic `(lamport, peer)` order, grouped by consecutive honored
//! receipt actor (`None` actors form their own groups). Each non-empty group
//! applies onto one in-memory [`DocxProjection`] under a fresh opaque token;
//! the package serializes once, so block ids stay stable across groups.
//! (Chaining `project_docx` over bytes would re-parse between groups and
//! renumber every block: import mints positional ids. See
//! `lanes/l12/muse/BLOCKED-595-PROJECTION.md` for the evidence that forced
//! this shape.)
//!
//! Attribution rules: a new paragraph is inserted by its creating group with
//! its HEAD text (a later text edit leaves no incremental op, so inserting
//! creation-time text would project stale words); only ids surviving to the
//! head are ever inserted, and deletes of never-inserted ids are dropped (a
//! later delete cannot address what was never inserted). Every anchor names
//! an explicitly known id — an imported id translated past moves, or a
//! native id an earlier group reported back — never a guess. Each applied
//! group's order is verified against its body state before the next group
//! runs; any divergence refuses the export and nothing lands.
//!
//! DOCX allows one formatting revision per run, with no nested rPrChange.
//! Overlapping authors keep their exact in-engine commits; export uses the
//! whole-window default-author fallback. Disjoint spans stay native.

use super::author_token::DOCX_AUTHOR_TOKEN_MARKER;
use super::*;
use loro::{ChangeMeta, ExportMode, Frontiers, ID, IdSpan};
use oneiron_docedit::DoceditError;
use oneiron_docedit::docx_body::{DocxAnchor, DocxChange, DocxParagraph, DocxProjection};
use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

/// A default-author DOCX export projected in memory: the bytes, the total
/// change count, and one author binding per non-empty group in export order.
/// `authors[i]` persists at group index `i`.
pub(super) struct DocxSequentialProjection {
    pub(super) bytes: Vec<u8>,
    pub(super) changes: usize,
    pub(super) authors: Vec<OfficeBodyExportAuthor>,
}

/// One window change, flattened out of Loro's borrow-bound metadata.
struct WindowChange {
    peer: u64,
    counter: i32,
    len: u16,
    lamport: u32,
}

/// Every change between `from` and `to`, clipped to the window, oldest first
/// in deterministic `(lamport, peer)` order. Mirrors the proposal text window
/// walk: concurrent branches order by clock, never by schedule.
fn window_changes(doc: &LoroDoc, from: &Frontiers, to: &Frontiers) -> Result<Vec<WindowChange>> {
    let mut changes = Vec::new();
    for (peer, counters) in &doc.find_id_spans_between(from, to).forward {
        let mut counter = counters.start;
        while counter < counters.end {
            let meta = doc
                .get_change(ID::new(*peer, counter))
                .ok_or(Error::CorruptedIndex("office body window change"))?;
            let end = change_last_counter(&meta)? + 1;
            let clipped = end.min(counters.end);
            changes.push(WindowChange {
                peer: *peer,
                counter,
                len: u16::try_from(clipped - counter)
                    .map_err(|_| Error::CorruptedIndex("office body change length"))?,
                lamport: meta.lamport.saturating_add(change_offset(&meta, counter)?),
            });
            counter = end;
        }
    }
    changes.sort_by_key(|change| (change.lamport, change.peer));
    Ok(changes)
}

/// The counter of a change's last op.
fn change_last_counter(meta: &ChangeMeta) -> Result<i32> {
    let len =
        i32::try_from(meta.len).map_err(|_| Error::CorruptedIndex("office body change length"))?;
    if len < 1 {
        return Err(Error::CorruptedIndex("office body empty change"));
    }
    Ok(meta.id.counter + len - 1)
}

/// How far into its change `counter` sits: Lamport clocks advance one per
/// op, so this is the clipped span's Lamport offset.
fn change_offset(meta: &ChangeMeta, counter: i32) -> Result<u32> {
    u32::try_from(counter - meta.id.counter)
        .map_err(|_| Error::CorruptedIndex("office body change offset"))
}

/// Each history change's honored receipt actor by peer. The history walk and
/// the receipt rows are two reads of live state; a length or peer mismatch
/// means the body moved between them, so the export retries.
fn window_actors(
    vault: &Vault,
    artifact: &EntityId,
    doc: &LoroDoc,
) -> Result<HashMap<u64, Option<EntityId>>> {
    let mut metas = Vec::new();
    doc.travel_change_ancestors(&doc.oplog_frontiers().to_vec(), &mut |meta| {
        metas.push(meta);
        ControlFlow::Continue(())
    })
    .map_err(|_| Error::CorruptedIndex("office body change history"))?;
    metas.reverse();
    let receipts = vault.typed_body_receipts(artifact)?;
    if receipts.len() != metas.len() {
        return Err(invalid("the body moved during the export; export again"));
    }
    let mut actors = HashMap::with_capacity(metas.len());
    for (meta, receipt) in metas.iter().zip(receipts) {
        if receipt
            .as_ref()
            .is_some_and(|receipt| receipt.peer != meta.id.peer)
        {
            return Err(invalid("the body moved during the export; export again"));
        }
        let actor = receipt.map(|receipt| receipt.made_by.process.actor);
        if let Some(previous) = actors.insert(meta.id.peer, actor) {
            if previous != actor {
                return Err(Error::CorruptedIndex("office body peer named two actors"));
            }
        }
    }
    Ok(actors)
}

/// The honored actor of `window[at]`; every window peer walked the history.
/// Whether `error` failing this group's apply matches a cross-group shape
/// the sequential path cannot project (FIX 595 review P1-2/P1-3): formatting
/// over an earlier group's pending revision (the remark pass swallows the
/// native conflict into an invalid transaction), or a delete over earlier
/// groups' tracked segments or a moved copy (the native delete verb
/// refuses). The caller falls back to the single-revision projection for
/// the whole window instead of failing the export.
fn needs_default_author_fallback(built: &[DocxChange], error: &DoceditError) -> bool {
    match error {
        DoceditError::InvalidTransaction(_) => built
            .iter()
            .any(|change| matches!(change, DocxChange::SetRuns { .. })),
        DoceditError::Document(_) => built
            .iter()
            .any(|change| matches!(change, DocxChange::Delete { .. })),
    }
}

fn group_actor(
    window: &[WindowChange],
    actors: &HashMap<u64, Option<EntityId>>,
    at: usize,
) -> Result<Option<EntityId>> {
    actors
        .get(&window[at].peer)
        .copied()
        .ok_or(Error::CorruptedIndex(
            "office body window peer without history",
        ))
}

/// Import replayed window updates, failing closed on missing dependencies.
fn import_updates(doc: &LoroDoc, updates: &[u8]) -> Result<()> {
    let status = doc
        .import(updates)
        .map_err(|_| invalid("office body window import"))?;
    if status.pending.is_some() {
        return Err(Error::CorruptedIndex("office body window dependencies"));
    }
    Ok(())
}

/// Ids of blocks the body wrote rather than imported.
fn new_ids(state: &DocxBody) -> HashSet<&str> {
    state
        .blocks
        .iter()
        .filter(|block| !block.imported)
        .map(|block| block.id.as_str())
        .collect()
}

/// Whether `id` addresses an imported block of `state`.
fn is_imported(state: &DocxBody, id: &str) -> bool {
    state
        .blocks
        .iter()
        .any(|block| block.id == id && block.imported)
}

/// The current native id for a Loro id: translated past moves. Every id the
/// projection passes here was placed by the import or an earlier group.
fn native_id(native: &HashMap<String, String>, id: &str) -> Result<String> {
    native.get(id).cloned().ok_or(Error::InvariantViolation(
        "a change names a block the projection never placed",
    ))
}

/// An insert run's anchor from its body neighbors, skipping ids the package
/// never holds (gone before the head, or this group's own fresh ids): an
/// imported id translated past moves, or an earlier group's native id —
/// always an explicitly known id, never a guess. Beside a block this group
/// moves, the run anchors from its other side, since the grammar refuses
/// anchors on move sources; with no stable side, the export refuses.
#[allow(clippy::too_many_arguments)]
fn run_anchor(
    ids: &[&str],
    start: usize,
    len: usize,
    imported: &HashSet<&str>,
    fresh: &HashSet<&str>,
    surviving: &HashSet<&str>,
    moved: &HashSet<&str>,
    native: &HashMap<String, String>,
    base_last: Option<&str>,
) -> Result<DocxAnchor> {
    let placed =
        |id: &str| imported.contains(id) || (surviving.contains(id) && !fresh.contains(id));
    let prev = (0..start).rev().map(|at| ids[at]).find(|id| placed(*id));
    let next = (start + len..ids.len())
        .map(|at| ids[at])
        .find(|id| placed(*id));
    let prev_ok = prev.filter(|id| !moved.contains(id));
    let next_ok = next.filter(|id| !moved.contains(id));
    if (prev.is_some() || next.is_some()) && prev_ok.is_none() && next_ok.is_none() {
        return Err(invalid(
            "a new paragraph was inserted beside paragraphs moved in the same group",
        ));
    }
    match (prev_ok, next_ok) {
        (Some(id), _) => Ok(DocxAnchor::After(native_id(native, id)?)),
        (None, Some(id)) => Ok(DocxAnchor::Before(native_id(native, id)?)),
        (None, None) => match base_last {
            // No packaged neighbor either side: every neighbor is a ghost
            // this group skips. Anchor past the import's last block, whose
            // shadow stays in place even deleted.
            Some(id) => Ok(DocxAnchor::After(native_id(native, id)?)),
            None => Err(invalid("an empty import has no anchor")),
        },
    }
}

impl Vault {
    /// FIX 595: a default-author DOCX body as sequential per-actor tracked
    /// revisions, projected in one in-memory session. `None` when every
    /// group is empty, so a no-op keeps the original package. A group meeting
    /// a cross-group shape (FIX 595 review P1-2/P1-3) falls back to one
    /// default-author revision for the whole window, exactly the pre-PR
    /// export, attributed to `default_actor` under a fresh token.
    pub(super) fn project_sequential_docx(
        &self,
        artifact: &EntityId,
        head: &OfficeBodyHead,
        at: u64,
        default_actor: EntityId,
    ) -> Result<Option<DocxSequentialProjection>> {
        let doc = {
            let txn = self.store.env.read_txn()?;
            self.loro_body(&txn, artifact, OfficeBodyKind::Docx, Some(&head.frontier))?
                .1
        };
        let from = Frontiers::decode(&head.import_frontier)
            .map_err(|_| invalid("invalid body frontier"))?;
        let to = Frontiers::decode(&head.frontier).map_err(|_| invalid("invalid body frontier"))?;
        let window = window_changes(&doc, &from, &to)?;
        if window.is_empty() {
            return Ok(None);
        }
        let actors = window_actors(self, artifact, &doc)?;
        // Replay the window into a scratch fork of the import, one group at
        // a time in window order, reading each group boundary straight off
        // the scratch: the same updates the head holds, so the same state a
        // checkout would read, without a frontier round trip per group.
        let scratch = doc
            .fork_at(&from)
            .map_err(|_| invalid("unknown body frontier"))?;
        let live = docx::read(&doc)?;
        let surviving = new_ids(&live);
        let mut head_text = HashMap::with_capacity(live.blocks.len());
        for block in &live.blocks {
            head_text.insert(block.id.as_str(), block);
        }
        let source = self.body_source(artifact, head)?;
        let limits = self.office_docx_limits(None)?;
        let date = timestamp(at)?.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut session = crate::office_body::document_resources()
            .docx(|| DocxProjection::parse(&source, limits))
            .map_err(|error| {
                docx_error(&error, "the body could not be projected onto its package")
            })?;
        // Existing deletions and move sources stay locked in the body, but
        // are absent from accept-all order. Read that visibility without
        // resolving any source revisions in the exported package.
        let source_visible: HashSet<String> = session.accepted_id_order().into_iter().collect();
        // Native ids stay stable in memory: imported ids address themselves
        // until a move replaces one with its copy's id.
        let mut native: HashMap<String, String> = HashMap::new();
        let mut previous = docx::read(&scratch)?;
        for block in previous.blocks.iter().filter(|block| block.imported) {
            native.insert(block.id.clone(), block.id.clone());
        }
        let base_last = previous.blocks.last().map(|block| block.id.clone());
        let mut total = 0usize;
        let mut authors = Vec::new();
        let mut start = 0usize;
        while start < window.len() {
            let actor = group_actor(&window, &actors, start)?;
            let mut end = start + 1;
            while end < window.len() && group_actor(&window, &actors, end)? == actor {
                end += 1;
            }
            for change in &window[start..end] {
                let updates = doc
                    .export(ExportMode::updates_in_range(vec![IdSpan::new(
                        change.peer,
                        change.counter,
                        change.counter + i32::from(change.len),
                    )]))
                    .map_err(|_| Error::CorruptedIndex("office body window export"))?;
                import_updates(&scratch, &updates)?;
            }
            let state = docx::read(&scratch)?;
            let before = new_ids(&previous);
            let after = new_ids(&state);
            let fresh: HashSet<&str> = after.difference(&before).copied().collect();
            let insert: HashSet<&str> = fresh.intersection(&surviving).copied().collect();
            // A new paragraph an earlier group projected never moves under a
            // later group: the grammar cannot address it there, so refuse.
            // (A packaged id deleted mid-window is gone from the head too,
            // so it can never be packaged; the order check refuses that as
            // loudly as a reorder.)
            let settled: HashSet<&str> = surviving.intersection(&before).copied().collect();
            let order_before: Vec<&str> = previous
                .blocks
                .iter()
                .map(|block| block.id.as_str())
                .filter(|id| settled.contains(id))
                .collect();
            let order_after: Vec<&str> = state
                .blocks
                .iter()
                .map(|block| block.id.as_str())
                .filter(|id| settled.contains(id))
                .collect();
            if order_before != order_after {
                return Err(invalid(
                    "a new paragraph moved after its group projected it",
                ));
            }
            let raw = docx::changes(&previous, &state)?;
            // Blocks this group moves: an insert beside one anchors from its
            // other side.
            let moved: HashSet<&str> = raw
                .iter()
                .filter_map(|change| match change {
                    DocxChange::Move { block, .. } => Some(block.as_str()),
                    _ => None,
                })
                .collect();
            // The group's changes with translated ids, in the phase order
            // changes() uses: text and cell edits, moves, rebuilt inserts,
            // deletes. Loro ids per Insert/Move op stay alongside so the
            // reported native ids map back.
            let mut main = Vec::new();
            let mut deletes = Vec::new();
            let mut moved_loro = Vec::new();
            for change in &raw {
                match change {
                    DocxChange::SetText { block, text } => main.push(DocxChange::SetText {
                        block: native_id(&native, block)?,
                        text: text.clone(),
                    }),
                    DocxChange::SetRuns { block, runs } => main.push(DocxChange::SetRuns {
                        block: native_id(&native, block)?,
                        runs: runs.clone(),
                    }),
                    DocxChange::SetCell {
                        block,
                        row,
                        col,
                        text,
                    } => main.push(DocxChange::SetCell {
                        block: native_id(&native, block)?,
                        row: *row,
                        col: *col,
                        text: text.clone(),
                    }),
                    DocxChange::Move { block, anchor } => {
                        if !is_imported(&state, block) {
                            return Err(Error::InvariantViolation("a new paragraph moved"));
                        }
                        moved_loro.push(block.clone());
                        let anchor = match anchor {
                            DocxAnchor::After(id) => DocxAnchor::After(native_id(&native, id)?),
                            DocxAnchor::Before(id) => DocxAnchor::Before(native_id(&native, id)?),
                        };
                        main.push(DocxChange::Move {
                            block: native_id(&native, block)?,
                            anchor,
                        });
                    }
                    // Rebuilt below with head text and explicit anchors.
                    DocxChange::Insert { .. } => {}
                    DocxChange::Delete { block } => {
                        if is_imported(&previous, block) {
                            deletes.push(DocxChange::Delete {
                                block: native_id(&native, block)?,
                            });
                        }
                        // Else a new id: still live (spurious, since changes()
                        // emits Deletes for every prior new) or never inserted
                        // (a ghost): nothing to delete.
                    }
                }
            }
            let imported: HashSet<&str> = state
                .blocks
                .iter()
                .filter(|block| block.imported)
                .map(|block| block.id.as_str())
                .collect();
            let ids: Vec<&str> = state.blocks.iter().map(|block| block.id.as_str()).collect();
            // Insert runs: maximal runs of this group's surviving new ids in
            // body order, with head text (a later edit leaves no incremental
            // op, so creation-time text would project stale words).
            let mut runs: Vec<(usize, Vec<&str>)> = Vec::new();
            for (at, &id) in ids.iter().enumerate() {
                if insert.contains(id) {
                    match runs.last_mut() {
                        Some((start, run)) if at == *start + run.len() => run.push(id),
                        _ => runs.push((at, vec![id])),
                    }
                }
            }
            let mut inserts = Vec::new();
            let mut insert_loro: Vec<Vec<String>> = Vec::new();
            for (at, run) in &runs {
                let paragraphs =
                    run.iter()
                        .map(|id| {
                            let head = head_text.get(id).copied().ok_or(
                                Error::InvariantViolation("a new paragraph left the head"),
                            )?;
                            Ok(DocxParagraph {
                                role: head.role.clone(),
                                text: head.text.clone(),
                                runs: if head.runs.iter().any(|run| !run.marks.is_empty()) {
                                    head.runs.clone()
                                } else {
                                    Vec::new()
                                },
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                let anchor = run_anchor(
                    &ids,
                    *at,
                    run.len(),
                    &imported,
                    &fresh,
                    &surviving,
                    &moved,
                    &native,
                    base_last.as_deref(),
                )?;
                insert_loro.push(run.iter().map(|id| id.to_string()).collect());
                inserts.push(DocxChange::Insert { anchor, paragraphs });
            }
            let mut built = Vec::with_capacity(main.len() + inserts.len() + deletes.len());
            built.append(&mut main);
            built.append(&mut inserts);
            built.append(&mut deletes);
            if !built.is_empty() {
                let token = format!(
                    "{DOCX_AUTHOR_TOKEN_MARKER}{}",
                    self.new_entity_id()?.to_hex()
                );
                let mut group = blake3::Hasher::new();
                group.update(b"oneiron.office_body.docx_revision_group.v1\0");
                for part in [token.as_str(), date.as_str(), format!("{built:?}").as_str()] {
                    group.update(&(part.len() as u64).to_le_bytes());
                    group.update(part.as_bytes());
                }
                let revision = DocxRevision {
                    author: token.clone(),
                    date: date.clone(),
                    group: group.finalize().to_hex()[..16].to_owned(),
                };
                let gate = crate::office_body::document_resources()
                    .docx(|| session.apply_group(&built, &revision));
                let events = match gate {
                    Ok(events) => events,
                    Err(error) if needs_default_author_fallback(&built, &error) => {
                        // Cross-group shape (FIX 595 review P1-2/P1-3): an
                        // earlier group's pending revision blocks this group,
                        // so project the whole window as one default-author
                        // revision, exactly the pre-PR export, instead of
                        // failing the export. Later groups cannot continue on
                        // the session (order is verified per group against
                        // body state), so the window collapses into one group
                        // under a fresh token. A persistent single-shot
                        // failure is not a sequential regression; the
                        // single-shot error then replaces this one.
                        // The full window from the import frontier, exactly the
                        // pre-PR export: `scratch` already replayed earlier
                        // groups, so a tail diff would drop their edits from
                        // the original package (FIX 595 sol review).
                        let import_state = docx::read(
                            &doc.fork_at(&from)
                                .map_err(|_| invalid("unknown body frontier"))?,
                        )?;
                        let changes = docx::changes(&import_state, &live)?;
                        if changes.is_empty() {
                            return Ok(None);
                        }
                        let token = format!(
                            "{DOCX_AUTHOR_TOKEN_MARKER}{}",
                            self.new_entity_id()?.to_hex()
                        );
                        let mut group = blake3::Hasher::new();
                        group.update(b"oneiron.office_body.docx_revision_group.v1\0");
                        for part in [
                            token.as_str(),
                            date.as_str(),
                            format!("{changes:?}").as_str(),
                        ] {
                            group.update(&(part.len() as u64).to_le_bytes());
                            group.update(part.as_bytes());
                        }
                        let revision = DocxRevision {
                            author: token.clone(),
                            date: date.clone(),
                            group: group.finalize().to_hex()[..16].to_owned(),
                        };
                        let bytes = crate::office_body::document_resources()
                            .docx(|| project_docx(&source, &changes, &revision, limits))
                            .map_err(|error| {
                                docx_error(
                                    &error,
                                    "the body could not be projected onto its package",
                                )
                            })?;
                        return Ok(Some(DocxSequentialProjection {
                            bytes,
                            changes: changes.len(),
                            authors: vec![OfficeBodyExportAuthor {
                                actor: Some(default_actor),
                                token,
                            }],
                        }));
                    }
                    Err(error) => {
                        return Err(docx_error(
                            &error,
                            "the body could not be projected onto its package",
                        ));
                    }
                };
                if let Some(events) = events {
                    if insert_loro.len() != events.inserted.len()
                        || moved_loro.len() != events.moved.len()
                    {
                        return Err(Error::InvariantViolation(
                            "a group placement count diverged",
                        ));
                    }
                    for (loro_ids, native_ids) in insert_loro.iter().zip(events.inserted.iter()) {
                        if loro_ids.len() != native_ids.len() {
                            return Err(Error::InvariantViolation(
                                "a group placement count diverged",
                            ));
                        }
                        for (loro, id) in loro_ids.iter().zip(native_ids) {
                            native.insert(loro.clone(), id.clone());
                        }
                    }
                    for (loro, copy) in moved_loro.iter().zip(events.moved.iter()) {
                        native.insert(loro.clone(), copy.clone());
                    }
                    // Backstop: the package must now read exactly this
                    // group's body order through the id map; anything else
                    // refuses before the next group runs.
                    let mut expected = Vec::with_capacity(state.blocks.len());
                    for block in &state.blocks {
                        let id = block.id.as_str();
                        if (block.imported && !source_visible.contains(id))
                            || (!block.imported && !surviving.contains(id))
                        {
                            continue;
                        }
                        expected.push(native_id(&native, id)?);
                    }
                    if session.accepted_id_order() != expected {
                        return Err(invalid("the sequential projection diverged from the body"));
                    }
                    total += built.len();
                    authors.push(OfficeBodyExportAuthor { actor, token });
                }
            }
            if built.is_empty() {
                // A new-paragraph move leaves no ops but changes order. The
                // package must still match this group's body order.
                let mut expected = Vec::with_capacity(state.blocks.len());
                for block in &state.blocks {
                    let id = block.id.as_str();
                    if (block.imported && !source_visible.contains(id))
                        || (!block.imported && !surviving.contains(id))
                    {
                        continue;
                    }
                    expected.push(native_id(&native, id)?);
                }
                if session.accepted_id_order() != expected {
                    return Err(invalid("the sequential projection diverged from the body"));
                }
            }
            previous = state;
            start = end;
        }
        if authors.is_empty() {
            return Ok(None);
        }
        let bytes = crate::office_body::document_resources()
            .docx(|| session.finish())
            .map_err(|error| {
                docx_error(&error, "the body could not be projected onto its package")
            })?;
        Ok(Some(DocxSequentialProjection {
            bytes,
            changes: total,
            authors,
        }))
    }

    /// FIX 595: land a default-author DOCX export: the sequential bytes with
    /// an exporter-only export row plus one author binding per group. It
    /// lives here (not in doors) only for the doors line budget; the write
    /// checks the head moved exactly like the single-revision write.
    pub(super) fn export_docx_sequential(
        &self,
        artifact: &EntityId,
        request: &OfficeBodyExportRequest<'_>,
        head: &OfficeBodyHead,
        author: &author_token::ExportAuthor,
        at: u64,
    ) -> Result<OfficeBodyExport> {
        let Some(projection) =
            self.project_sequential_docx(artifact, head, at, request.actor.entity_ref())?
        else {
            return Ok(OfficeBodyExport {
                frontier: head.frontier.clone(),
                version: None,
                record: None,
            });
        };
        let provenance = if request.actor.actor_class() == EdgeActorClass::Human {
            BlobVersionProvenance::UserUpload
        } else {
            BlobVersionProvenance::AgentRun {
                run_ref: request.run_ref.to_owned(),
            }
        };
        self.with_write_txn_grouped(|wtxn| {
            if self.head_in_txn(wtxn, artifact)?.frontier != head.frontier {
                return Err(invalid("the body moved during the export; export again"));
            }
            // The version carries the export's envelope (ARCH-0078 made_by);
            // a DOCX projection recalculates nothing and adapts nothing.
            let version = self.append_blob_artifact_version_with_engine_and_parent_in_txn(
                wtxn,
                artifact,
                &projection.bytes,
                &provenance,
                None,
                request.actor,
                TimeRange { start: at, end: at },
                at,
                None,
                request.made_by,
            )?;
            let record = OfficeBodyExportRecord {
                artifact: *artifact,
                version: version.version,
                frontier: head.frontier.clone(),
                rebind_frontier: None,
                source_version: head.source_version,
                actor: BodyActor::Actor(request.actor.entity_ref()),
                author: author.shown.clone(),
                token: author.token.clone(),
                at,
                changes: projection.changes as u64,
                recalc: None,
                recalc_zone: Some(request.zone.clone()),
                effects: Vec::new(),
            };
            let export_key = version_key(artifact, version.version);
            EXPORTS.put(&self.store, wtxn, &export_key, &record)?;
            // The token lookup names this row in the same writer (FIX 12403).
            if let Some(token) = record.token.as_deref() {
                author_token::index::note_export_put(&self.store, wtxn, &export_key, token)?;
            }
            for (index, binding) in projection.authors.iter().enumerate() {
                let key = (*artifact, version.version, index as u64);
                // Erased-wins at commit time (FIX 595 review): a contributor
                // erased after the receipts were read must not be restored
                // here; store None for erased actors, like the merge path.
                let mut binding = binding.clone();
                if let Some(actor) = binding.actor
                    && self.carrier_actor_erased_in_txn(wtxn, &actor)?
                {
                    binding.actor = None;
                }
                EXPORT_AUTHORS.put(&self.store, wtxn, &key, &binding)?;
                author_token::index::note_author_put(&self.store, wtxn, &key, &binding.token)?;
            }
            Ok(OfficeBodyExport {
                frontier: head.frontier.clone(),
                version: Some(version),
                record: Some(record),
            })
        })
    }
}
