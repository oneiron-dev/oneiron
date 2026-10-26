//! Stable-cursor edit verbs and the lossless whole-text timeout path.

use super::document::{BODY, decode_frontier};
use super::prose_admission::{EDIT_ROW, LandedProse, UPDATE_ROW, admit_landed};
use super::{DocAuthorization, EntityDoc, ForkRequest, ForkStatus, SettleVerb, invalid, storage};
use crate::batch::secret_scan::{Lifted, LiftedKeys, Part, admit_parts_in_txn};
use crate::error::Result;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use loro::cursor::{Cursor, Side};
use loro::{ContainerTrait, UpdateOptions};
use serde::{Deserialize, Serialize};

/// An engine-created half-open Unicode span, bound to its origin document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TextAnchor {
    pub(super) entity: String,
    pub(super) frontier: Vec<u8>,
    pub(super) start: Vec<u8>,
    pub(super) end: Vec<u8>,
    pub(super) quote: String,
    pub(super) hash: [u8; 32],
}
impl TextAnchor {
    /// Quote retained when the cursor drifts.
    #[must_use]
    pub fn quote(&self) -> &str {
        &self.quote
    }
    /// Causal origin retained when the cursor drifts.
    #[must_use]
    pub fn frontier(&self) -> &[u8] {
        &self.frontier
    }
    /// Encoded Loro cursors at the captured document version.
    #[must_use]
    pub fn cursors(&self) -> (&[u8], &[u8]) {
        (&self.start, &self.end)
    }
}

/// Three anchored verbs. Each uses the live cursor, never stale integer offsets.
#[derive(Debug, Clone)]
pub enum EditVerb {
    /// Append immediately after the engine-pinned section span.
    AppendToSection { section: TextAnchor, text: String },
    /// Replace only while the current span still matches the pinned quote.
    ReplaceQuotedSpan { span: TextAnchor, text: String },
    /// Insert after an engine-pinned anchor span.
    InsertAfterAnchor { anchor: TextAnchor, text: String },
}

/// An edit with mandatory attribution. `None` is a typed refusal at admission.
#[derive(Debug, Clone)]
pub struct AnchoredEdit {
    /// Actor authenticated by the caller's authorization boundary.
    pub actor: Option<WriteActor>,
    /// Anchored mutation.
    pub verb: EditVerb,
}

/// Whole-text updates are based on a pinned frontier, not whichever head wins a race.
#[derive(Debug, Clone)]
pub struct TextUpdateRequest {
    /// Target entity.
    pub entity: EntityId,
    /// Proposal set to join if the diff times out or requires review.
    pub proposal: EntityId,
    /// Frontier whose text the caller edited.
    pub base: Vec<u8>,
    /// Complete output, retained without truncation on timeout.
    pub text: String,
    /// Authenticated actor of all generated operations.
    pub actor: WriteActor,
    /// Diff budget in milliseconds. Zero deterministically takes the timeout path.
    pub timeout_ms: u32,
    /// Commit timestamp.
    pub at: u64,
}

/// Either small operations merged into the live head, or a retained rewrite fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextUpdateOutcome {
    /// The update's operations landed without overwriting concurrent edits.
    Merged { frontier: Vec<u8> },
    /// A rewrite was retained; an explicit SWITCH is needed to publish it.
    RewriteFork { fork: EntityId, proposal: EntityId },
    /// A successful diff retained for review because no automatic grant covers it.
    ProposedFork { fork: EntityId, proposal: EntityId },
}

impl Vault {
    /// Captures a span from the current text using Unicode scalar offsets.
    pub fn entity_text_anchor(
        &self,
        entity: &EntityId,
        start: usize,
        end: usize,
    ) -> Result<TextAnchor> {
        self.read_entity_doc(entity, |doc| make_anchor(doc, *entity, start, end))?
    }

    /// Applies every operation atomically, however many (FIX 9848). Every
    /// actor is checked in the same write transaction; a rejected later
    /// operation rolls back the set.
    pub fn edit_entity_text(
        &self,
        entity: &EntityId,
        edits: &[AnchoredEdit],
        authorization: &DocAuthorization<'_>,
        at: u64,
    ) -> Result<Vec<u8>> {
        validate_edits(edits)?;
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        let (out, landed) = self.with_write_txn_grouped(|txn| {
            let mut h = storage::head(&self.store, txn, entity)?;
            let mut doc = storage::load(&self.store, txn, &h)?;
            let lifted = lifted_keys_for(&self.store, txn, &h, edits)?;
            let mut plan = Lifted::default();
            let before = doc.doc.oplog_vv();
            let mut landed = Vec::with_capacity(edits.len());
            for (index, edit) in edits.iter().enumerate() {
                let actor = edit
                    .actor
                    .ok_or(invalid("text operation requires an actor"))?;
                super::forks::authorize(self, txn, authorization, entity, actor)?;
                // A shared vault's role and record scope (FIX 9846).
                self.authorize_shared_content_write_in_txn(txn, *entity, &actor)?;
                doc.doc
                    .set_peer_id(loro::LoroDoc::new().peer_id())
                    .map_err(|_| invalid("document peer rotation"))?;
                super::forks::bind_actor(self, txn, &doc, actor, at)?;
                let text = admitted_prose_in_txn(self, txn, *entity, edit, &lifted, &mut plan)?;
                let place = apply(&mut doc, *entity, edit, &text.stored, at, &[], &lifted)?;
                if let Some(place) = place {
                    let slot = format!("/edits/{index}/text");
                    let said = LandedProse::anchored(actor, slot, &doc, place, &text, &lifted);
                    landed.push(said);
                }
            }
            storage::persist(self, txn, entity, &mut h, &doc, Some(&before))?;
            Ok((doc.frontier(), landed))
        })?;
        registry.remove(entity);
        drop(registry);
        // Landed prose's links, once the edits have landed (FIX 1227).
        admit_landed(self, EDIT_ROW, &landed);
        Ok(out)
    }

    /// Diffs against the caller's base on a scratch fork, then merges only its
    /// operations into the live head. Timeout output is persisted as a rewrite
    /// fork in the same transaction and cannot auto-switch even with a grant.
    pub fn update_entity_text(
        &self,
        request: &TextUpdateRequest,
        authorization: &DocAuthorization<'_>,
    ) -> Result<TextUpdateOutcome> {
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        let (out, landed) = self.with_write_txn_grouped(|txn| {
            let permitted =
                super::forks::covered(self, txn, authorization, &request.entity, request.actor)?;
            // A shared vault's role and record scope, whether the update lands
            // or is retained for review (FIX 9846).
            self.authorize_shared_content_write_in_txn(txn, request.entity, &request.actor)?;
            let mut h = storage::head(&self.store, txn, &request.entity)?;
            let live = storage::load(&self.store, txn, &h)?;
            let mut fork = live.fork(&request.base)?;
            let base_text = fork.text();
            // The new text is admitted before any operation holds it, and a
            // handle of a key the live text's lift marked writes its value
            // again (OF-067; FIX 2371).
            let lifted = LiftedKeys::of_in_txn(&self.store, txn, [live.text()])?;
            let admitted = admitted_text_in_txn(
                self,
                txn,
                request.entity,
                &request.text,
                &lifted,
                &mut Lifted::default(),
            )?;
            let text = &admitted.stored;
            super::forks::bind_actor(self, txn, &fork, request.actor, request.at)?;
            // The complete text is the writer's prose, wherever it lands; text
            // equal to its base says nothing new (FIX 1227).
            let landed = if *text == base_text {
                None
            } else {
                Some(LandedProse::whole(
                    request.actor,
                    "/text".to_owned(),
                    &admitted.said,
                ))
            };
            let before = live.doc.oplog_vv();
            let timed_out = request.timeout_ms == 0
                || fork
                    .doc
                    .get_text(BODY)
                    .update(
                        text,
                        UpdateOptions {
                            timeout_ms: Some(f64::from(request.timeout_ms)),
                            ..Default::default()
                        },
                    )
                    .is_err();
            if timed_out {
                // Never retain a partially calculated diff. Re-fork the base,
                // then store the complete output under the author's own stamp.
                fork = live.fork(&request.base)?;
                super::forks::bind_actor(self, txn, &fork, request.actor, request.at)?;
                fork.edit_as(request.actor, request.at, |body| {
                    body.delete(0, body.len_unicode())
                        .map_err(|_| invalid("rewrite delete"))?;
                    body.insert(0, text).map_err(|_| invalid("rewrite insert"))
                })?;
                let id = EntityId::now();
                let req = ForkRequest {
                    entity: request.entity,
                    base: request.base.clone(),
                    actor: request.actor,
                    edits: Vec::new(),
                    rewrite: Some(text.clone()),
                };
                super::forks::retain_fork(
                    self,
                    txn,
                    request.proposal,
                    id,
                    &req,
                    &h,
                    &fork,
                    ForkStatus::Pending,
                    request.at,
                )?;
                let outcome = TextUpdateOutcome::RewriteFork {
                    fork: id,
                    proposal: request.proposal,
                };
                return Ok((outcome, landed));
            }
            super::document::stamp(&fork.doc, request.actor, request.at, "update")?;
            if !permitted {
                let id = EntityId::now();
                let req = ForkRequest {
                    entity: request.entity,
                    base: request.base.clone(),
                    actor: request.actor,
                    edits: Vec::new(),
                    rewrite: None,
                };
                super::forks::retain_fork(
                    self,
                    txn,
                    request.proposal,
                    id,
                    &req,
                    &h,
                    &fork,
                    ForkStatus::Pending,
                    request.at,
                )?;
                let outcome = TextUpdateOutcome::ProposedFork {
                    fork: id,
                    proposal: request.proposal,
                };
                return Ok((outcome, landed));
            }
            super::forks::merge_into(&live, &fork, &request.base)?;
            storage::persist(self, txn, &request.entity, &mut h, &live, Some(&before))?;
            // The live update has its own receipt; the fork's immutable base is
            // not inferred later from author or wall-clock time.
            super::forks::write_receipt(
                self,
                txn,
                request.proposal,
                EntityId::now(),
                request.entity,
                request.actor,
                SettleVerb::Merge,
                request.at,
                &request.base,
                &live.frontier(),
            )?;
            let outcome = TextUpdateOutcome::Merged {
                frontier: live.frontier(),
            };
            Ok((outcome, landed))
        })?;
        registry.remove(&request.entity);
        drop(registry);
        admit_landed(self, UPDATE_ROW, landed.as_slice());
        Ok(out)
    }
}

impl Vault {
    /// [`Self::entity_text_anchor`] for a reader in its sight (FIX 2936;
    /// C-ANCHOR). `start..end` counts the text that reader reads: with
    /// `masked`, each key the live text's lift marked reads as its handle.
    /// The selection is widened so it splits no handle (an end inside one
    /// moves out to its edge, an empty selection inside one takes it whole).
    /// The anchor's cursors and frontier name the stored text it stands for;
    /// its quote and hash are the text the reader reads. Returns the anchor
    /// and the widened range. The document and its keys are read in one
    /// snapshot; an unmasked reader's anchor is the stored text's.
    pub(crate) fn entity_text_anchor_in_sight(
        &self,
        entity: &EntityId,
        start: usize,
        end: usize,
        masked: bool,
    ) -> Result<(TextAnchor, (usize, usize))> {
        if !masked {
            return Ok((self.entity_text_anchor(entity, start, end)?, (start, end)));
        }
        let txn = self.store.env.read_txn()?;
        let h = storage::head(&self.store, &txn, entity)?;
        let doc = storage::load(&self.store, &txn, &h)?;
        let text = doc.text();
        let shown = LiftedKeys::of_in_txn(&self.store, &txn, [text.as_str()])?.masked_text(&text);
        let selection = shown
            .selection(start, end)
            .ok_or(invalid("text span is out of bounds"))?;
        let (from, to) = (selection.shown.start, selection.shown.end);
        let mut anchor = make_anchor(&doc, *entity, selection.stored.start, selection.stored.end)?;
        let quote: String = shown.text().chars().skip(from).take(to - from).collect();
        anchor.hash = *blake3::hash(quote.as_bytes()).as_bytes();
        anchor.quote = quote;
        Ok((anchor, (from, to)))
    }
}

pub(super) fn validate_edits(edits: &[AnchoredEdit]) -> Result<()> {
    if edits.iter().any(|edit| edit.actor.is_none()) {
        return Err(invalid("text operation requires an actor"));
    }
    Ok(())
}

pub(super) fn make_anchor(
    doc: &EntityDoc,
    entity: EntityId,
    start: usize,
    end: usize,
) -> Result<TextAnchor> {
    let body = doc.doc.get_text(BODY);
    if start > end || end > body.len_unicode() {
        return Err(invalid("text span is out of bounds"));
    }
    let quote: String = body
        .to_string()
        .chars()
        .skip(start)
        .take(end - start)
        .collect();
    let start = body
        .get_cursor(start, Side::Right)
        .ok_or(invalid("text start cursor"))?
        .encode();
    let end = body
        .get_cursor(end, Side::Left)
        .ok_or(invalid("text end cursor"))?
        .encode();
    Ok(TextAnchor {
        entity: entity.to_hex(),
        frontier: doc.frontier(),
        start,
        end,
        hash: *blake3::hash(quote.as_bytes()).as_bytes(),
        quote,
    })
}

pub(super) fn resolve(
    doc: &EntityDoc,
    entity: EntityId,
    anchor: &TextAnchor,
) -> Result<(usize, usize)> {
    if anchor.entity != entity.to_hex() {
        return Err(invalid("anchor belongs to another document"));
    }
    resolve_cursors(doc, &anchor.frontier, &anchor.start, &anchor.end)
}

pub(super) fn resolve_cursors(
    doc: &EntityDoc,
    frontier: &[u8],
    start: &[u8],
    end: &[u8],
) -> Result<(usize, usize)> {
    let body = doc.doc.get_text(BODY);
    let start = Cursor::decode(start).map_err(|_| invalid("invalid start cursor"))?;
    let end = Cursor::decode(end).map_err(|_| invalid("invalid end cursor"))?;
    if start.container != body.id() || end.container != body.id() {
        return Err(invalid("anchor container mismatch"));
    }
    // Unknown origins fail closed. A retained shallow origin may still map a
    // live cursor, so the cursor query, not a scalar age, determines drift.
    let origin = decode_frontier(frontier)?;
    let vv = doc
        .doc
        .frontiers_to_vv(&origin)
        .ok_or(invalid("anchor origin purged"))?;
    if !vv.includes_vv(&doc.doc.shallow_since_vv().to_vv()) {
        return Err(invalid("anchor origin purged"));
    }
    let start = doc
        .doc
        .get_cursor_pos(&start)
        .map_err(|_| invalid("anchor drifted"))?
        .current
        .pos;
    let end = doc
        .doc
        .get_cursor_pos(&end)
        .map_err(|_| invalid("anchor drifted"))?
        .current
        .pos;
    if start > end {
        return Err(invalid("anchor drifted"));
    }
    Ok((start, end))
}

/// The anchor `edit` is placed by, and the text it writes as its writer
/// gave it.
fn verb_parts(edit: &AnchoredEdit) -> (&TextAnchor, &str) {
    match &edit.verb {
        EditVerb::AppendToSection { section, text } => (section, text.as_str()),
        EditVerb::ReplaceQuotedSpan { span, text } => (span, text.as_str()),
        EditVerb::InsertAfterAnchor { anchor, text } => (anchor, text.as_str()),
    }
}

/// [`admitted_text_in_txn`] over the text `edit` writes.
pub(super) fn admitted_prose_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: EntityId,
    edit: &AnchoredEdit,
    lifted: &LiftedKeys,
    plan: &mut Lifted,
) -> Result<Admitted> {
    admitted_text_in_txn(vault, txn, entity, verb_parts(edit).1, lifted, plan)
}

/// `text`, prose a writer authors for `entity`'s document, as the document
/// takes it (OF-067; FIX 2371): admitted with `plan`, the write's one plan,
/// so each secret the batch door's text rules place goes to custody and the
/// text keeps its handle before any operation holds it; then each handle of
/// a key the live text's lift marked (`lifted`) is the value it stands for
/// again (Engine ruling G2 = b). A handle this write minted stays a handle.
/// A hit no span places refuses as before.
pub(super) fn admitted_text_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: EntityId,
    text: &str,
    lifted: &LiftedKeys,
    plan: &mut Lifted,
) -> Result<Admitted> {
    let mut admitted = text.to_owned();
    admit_parts_in_txn(
        vault,
        txn,
        entity,
        &mut [("text:body", Part::Text(&mut admitted))],
        plan,
    )?;
    let stored = lifted
        .resolved(&admitted)
        .unwrap_or_else(|| admitted.clone());
    Ok(Admitted {
        stored,
        said: admitted,
    })
}

/// A writer's new text as admitted ([`admitted_text_in_txn`]).
pub(super) struct Admitted {
    /// As the document stores it: each handle of a key the live text's lift
    /// marked is the value it stands for again.
    pub(super) stored: String,
    /// As its writer said it, every handle still a handle: the text its
    /// prose links are read in (FIX 1227).
    pub(super) said: String,
}

/// `replacement` is the text `edit` writes as admitted
/// ([`admitted_prose_in_txn`]); `sources` are the rows its writer read for
/// it, which its commit's receipt names (FIX 7790); `lifted` are the keys the
/// live text's lift marked, for a quote a masked reader was issued (FIX 2936).
/// Returns the Unicode position `replacement` landed at, or `None` when it
/// replaced a span with the same text, which says nothing new (FIX 1227).
pub(super) fn apply(
    doc: &mut EntityDoc,
    entity: EntityId,
    edit: &AnchoredEdit,
    replacement: &str,
    at: u64,
    sources: &[EntityId],
    lifted: &LiftedKeys,
) -> Result<Option<usize>> {
    let actor = edit
        .actor
        .ok_or(invalid("text operation requires an actor"))?;
    let anchor = verb_parts(edit).0;
    let (start, end) = resolve(doc, entity, anchor)?;
    let replacing = matches!(edit.verb, EditVerb::ReplaceQuotedSpan { .. });
    let mut same = false;
    if replacing {
        let current: String = doc.text().chars().skip(start).take(end - start).collect();
        if !quotes(anchor, &current, lifted) {
            return Err(invalid("quoted span changed concurrently"));
        }
        same = current == replacement;
    }
    let place = if replacing { start } else { end };
    doc.edit_with(actor, at, sources, |body| {
        if replacing {
            body.delete(start, end - start)
                .map_err(|_| invalid("anchored delete"))?;
        }
        body.insert(place, replacement)
            .map_err(|_| invalid("anchored insert"))
    })?;
    Ok((!same).then_some(place))
}

/// Whether `current`, the span `anchor` resolves to, is still the quote it
/// was issued with: as stored, or as a reader who reads each lifted key as
/// its handle read it, in that reader's own text (FIX 2936).
fn quotes(anchor: &TextAnchor, current: &str, lifted: &LiftedKeys) -> bool {
    let same = |text: &str| {
        blake3::hash(text.as_bytes()).as_bytes() == &anchor.hash && text == anchor.quote
    };
    same(current) || lifted.masked(current).is_some_and(|shown| same(&shown))
}

/// The keys the lifted text of the document `h` heads holds, when one of
/// `edits` names a handle: an edit that carries one back writes its value,
/// and a quote a masked reader was issued is read as that reader read it.
fn lifted_keys_for(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    h: &storage::Head,
    edits: &[AnchoredEdit],
) -> Result<LiftedKeys> {
    let names = edits.iter().any(|edit| {
        let (anchor, text) = verb_parts(edit);
        let quoted = matches!(edit.verb, EditVerb::ReplaceQuotedSpan { .. });
        LiftedKeys::names_a_handle(text) || (quoted && LiftedKeys::names_a_handle(&anchor.quote))
    });
    if !names {
        return Ok(LiftedKeys::default());
    }
    super::lift::lifted_keys_in_txn(store, txn, h)
}
