//! Stable-cursor edit verbs and the lossless whole-text timeout path.

use super::document::{BODY, decode_frontier};
use super::{DocAuthorization, EntityDoc, ForkRequest, ForkStatus, SettleVerb, invalid, storage};
use crate::error::Result;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use loro::cursor::{Cursor, Side};
use loro::{ContainerTrait, UpdateOptions};
use serde::{Deserialize, Serialize};

/// An engine-created half-open Unicode span, bound to its origin document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Applies at most 50 operations atomically. Every actor is checked in the
    /// same write transaction; a rejected later operation rolls back the set.
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
        let out = self.with_write_txn(|txn| {
            let mut h = storage::head(&self.store, txn, entity)?;
            let mut doc = storage::load(&self.store, txn, &h)?;
            let before = doc.doc.oplog_vv();
            for edit in edits {
                let actor = edit
                    .actor
                    .ok_or(invalid("text operation requires an actor"))?;
                super::forks::authorize(self, txn, authorization, entity, actor)?;
                doc.doc
                    .set_peer_id(loro::LoroDoc::new().peer_id())
                    .map_err(|_| invalid("document peer rotation"))?;
                super::forks::bind_actor(self, txn, &doc, actor, at)?;
                apply(&mut doc, *entity, edit, at)?;
            }
            storage::persist(self, txn, entity, &mut h, &doc, Some(&before))?;
            Ok(doc.frontier())
        })?;
        registry.remove(entity);
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
        let out = self.with_write_txn(|txn| {
            let permitted =
                super::forks::covered(self, txn, authorization, &request.entity, request.actor)?;
            let mut h = storage::head(&self.store, txn, &request.entity)?;
            let live = storage::load(&self.store, txn, &h)?;
            let mut fork = live.fork(&request.base)?;
            crate::batch::secret_scan::scan_metadata_field(&request.text)?;
            super::forks::bind_actor(self, txn, &fork, request.actor, request.at)?;
            let before = live.doc.oplog_vv();
            let timed_out = request.timeout_ms == 0
                || fork
                    .doc
                    .get_text(BODY)
                    .update(
                        &request.text,
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
                    body.insert(0, &request.text)
                        .map_err(|_| invalid("rewrite insert"))
                })?;
                let id = EntityId::now();
                let req = ForkRequest {
                    entity: request.entity,
                    base: request.base.clone(),
                    actor: request.actor,
                    edits: Vec::new(),
                    rewrite: Some(request.text.clone()),
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
                return Ok(TextUpdateOutcome::RewriteFork {
                    fork: id,
                    proposal: request.proposal,
                });
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
                return Ok(TextUpdateOutcome::ProposedFork {
                    fork: id,
                    proposal: request.proposal,
                });
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
            Ok(TextUpdateOutcome::Merged {
                frontier: live.frontier(),
            })
        })?;
        registry.remove(&request.entity);
        Ok(out)
    }
}

pub(super) fn validate_edits(edits: &[AnchoredEdit]) -> Result<()> {
    if edits.len() > 50 {
        return Err(invalid("at most 50 text operations are allowed"));
    }
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
    let body = doc.doc.get_text(BODY);
    let start = Cursor::decode(&anchor.start).map_err(|_| invalid("invalid start cursor"))?;
    let end = Cursor::decode(&anchor.end).map_err(|_| invalid("invalid end cursor"))?;
    if start.container != body.id() || end.container != body.id() {
        return Err(invalid("anchor container mismatch"));
    }
    // Unknown origins fail closed. A retained shallow origin may still map a
    // live cursor, so the cursor query, not a scalar age, determines drift.
    let origin = decode_frontier(&anchor.frontier)?;
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

pub(super) fn apply(
    doc: &mut EntityDoc,
    entity: EntityId,
    edit: &AnchoredEdit,
    at: u64,
) -> Result<()> {
    let actor = edit
        .actor
        .ok_or(invalid("text operation requires an actor"))?;
    let (anchor, replacement) = match &edit.verb {
        EditVerb::AppendToSection { section, text } => (section, text),
        EditVerb::ReplaceQuotedSpan { span, text } => (span, text),
        EditVerb::InsertAfterAnchor { anchor, text } => (anchor, text),
    };
    crate::batch::secret_scan::scan_metadata_field(replacement)?;
    let (start, end) = resolve(doc, entity, anchor)?;
    let replacing = matches!(edit.verb, EditVerb::ReplaceQuotedSpan { .. });
    if replacing {
        let current: String = doc.text().chars().skip(start).take(end - start).collect();
        if blake3::hash(current.as_bytes()).as_bytes() != &anchor.hash || current != anchor.quote {
            return Err(invalid("quoted span changed concurrently"));
        }
    }
    doc.edit_as(actor, at, |body| {
        if replacing {
            body.delete(start, end - start)
                .map_err(|_| invalid("anchored delete"))?;
        }
        body.insert(if replacing { start } else { end }, replacement)
            .map_err(|_| invalid("anchored insert"))
    })
}
