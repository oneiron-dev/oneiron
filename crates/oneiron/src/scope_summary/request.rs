//! Scope-only declarations, exact-source fences and atomic Dreamer landings.

use super::codec::SummarySourceMessage;
use super::codec::{invalid, parse_scope, scope_value};
use super::derivation::{self, ScopeSummaryMetadata, SummaryDerivation, SummaryLineSources};
use super::doors::{
    LandedHeader, ScopeSources, SummaryContent, header_landed_in_txn, land_in_txn, mint_in_txn,
    note_sources_in_txn, reply_lane, scope_sources_in_txn, settle_header,
    standing_composition_in_txn, validate_landing_in_txn,
};
use super::purpose::SummaryPurpose;
use crate::attempt_queue::AttemptId;
use crate::conversation_dag::{
    AppendFailure, ScopePath, ScopeSelector, actor_in_txn, prove_branch_span,
    selected_thread_in_txn,
};
use crate::dreamer_consolidation::{
    DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE, ScopeSummaryEvidence, scope_summary_evidence_in_txn,
};
use crate::dreamer_runner::{DreamerAttemptPayload, DreamerConsolidationScope};
use crate::error::{Error, Result};
use crate::memory::Memory;
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};
use rmpv::Value;

pub(super) const REQUEST_VERSION: u64 = 2;
/// The declaration key an explicit source set rides under (FIX 3198).
pub(super) const SOURCES_KEY: &str = "sources";
const SUMMARY_ID_DOMAIN: &[u8] = b"oneiron:dreamer-scope-summary:v1";
const MEMO_DOMAIN: &[u8] = b"oneiron:dreamer-scope-summary-memo:v2";
/// The purpose a NOTE set's summary takes unless its caller names another
/// (FIX 5757): never a session recap.
const NOTE_SET_PURPOSE: &str = "note_summary";

/// What the caller asks the Dreamer to summarize; never caller-authored prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSummaryTarget {
    Scope {
        scope: ScopeSelector,
        land_on: Option<EntityId>,
        as_record: bool,
    },
    Thread {
        trunk: EntityId,
    },
    /// The records of `scope` a caller admitted, and only those (FIX 3198):
    /// a room's summary need not be its whole conversation. Each must be a
    /// record the scope summarizes, now and at every later read of the
    /// declaration, and there must be one. Nothing lands on a turn.
    ///
    /// With no `scope`, the sources are NOTEs named by id (FIX 5757): each a
    /// live NOTE its requester reads, now and at every later read, and the
    /// summary stands alone, in no conversation.
    Sources {
        scope: Option<ScopeSelector>,
        sources: Vec<EntityId>,
    },
    /// A sitting's retained turns (FIX 7509), as its close declares them:
    /// every TURN its membership names that still stands. The summary is
    /// the sitting's own actor's, stands in no conversation, lands on no
    /// turn, and is never written from its own earlier body.
    Session {
        session: EntityId,
    },
    /// A conversation's arc (FIX 7509 P8): written from the summary lines
    /// of the closed sittings below `scope`, never from its own earlier
    /// body. It lands on no turn.
    Arc {
        scope: ScopeSelector,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSummaryRequest {
    pub target: ScopeSummaryTarget,
    /// Lands the merge header, never authors the summary body.
    pub requester: WriteActor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeSummaryQueued {
    pub attempt: AttemptId,
    pub coalesced: bool,
}

/// The request, selector and editor state as read in the evidence snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopeSummaryPlan {
    pub(crate) input: Vec<u8>,
    /// `None` for a NOTE set's or a sitting's summary, in no conversation.
    pub(crate) scope: Option<ScopeSelector>,
    /// The sitting a session summary is written from (FIX 7509).
    pub(crate) session: Option<EntityId>,
    pub(crate) members: Vec<EntityId>,
    pub(crate) sources: Vec<EntityId>,
    pub(crate) land_on: Option<EntityId>,
    pub(crate) as_record: bool,
    pub(crate) requester: WriteActor,
    pub(crate) purpose: SummaryPurpose,
    pub(crate) previous: Option<EntityId>,
    pub(crate) keep: String,
    pub(crate) editor_text: Option<String>,
    pub(crate) editor_frontier: Option<Vec<u8>>,
    pub(crate) policy_frontier: [u8; 32],
    /// An Arc's sittings, their summary lines and its source set (P8).
    pub(crate) arc: Option<super::arc_sources::ArcSources>,
}

impl ScopeSummaryPlan {
    /// The impact gate omits generated landing replies and unrelated writes.
    pub(crate) fn observation(&self, evidence: &[u8; 32]) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MEMO_DOMAIN);
        let scope = self.scope.as_ref().map_or(Value::Nil, scope_value);
        hasher.update(&derivation::encode(&scope)?);
        hasher.update(evidence);
        hasher.update(&self.policy_frontier);
        let metadata = serde_json::to_vec(&(&self.purpose, &self.keep, &self.editor_text))
            .map_err(|_| invalid("summary metadata did not hash"))?;
        hasher.update(&metadata);
        Ok(*hasher.finalize().as_bytes())
    }

    /// The sole composition memo covers every input pin, the descriptor and
    /// editor memo, and the host's model/instruction/output contract.
    pub(crate) fn composition_memo(
        &self,
        evidence: &ScopeSummaryEvidence,
        params_hash: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let mut hash = blake3::Hasher::new();
        hash.update(&self.observation(&evidence.fingerprint()?)?);
        hash.update(params_hash);
        Ok(*hash.finalize().as_bytes())
    }

    /// The plan's evidence read in `txn`; a sitting's TURNs under the per-call
    /// labels its lines cite (FIX 7509).
    pub(crate) fn evidence_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<ScopeSummaryEvidence> {
        if let Some(arc) = &self.arc {
            return crate::dreamer_consolidation::arc_evidence_in_txn(vault, txn, arc);
        }
        scope_summary_evidence_in_txn(vault, txn, &self.sources, self.session.is_some())
    }

    /// The requester's surface a landing's reply is checked and receipted on
    /// (OF-063), bound from the declaration's admitted byline.
    fn requester_surface<'v>(&self, vault: &'v Vault) -> Memory<'v> {
        vault.memory(self.requester.entity_ref(), self.requester.actor_class())
    }

    /// Whether the declaration lands a reply TURN with its header.
    fn asks_reply(&self) -> bool {
        self.as_record && self.land_on.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComposedSummary<'a> {
    pub(crate) text: &'a str,
    pub(crate) keep: &'a str,
    pub(crate) params_hash: [u8; 32],
    pub(crate) instruction: &'a str,
    pub(crate) model: &'a str,
    pub(crate) covers: Vec<EntityId>,
    pub(crate) messages: Vec<SummarySourceMessage>,
    pub(crate) memo: [u8; 32],
    /// A session summary's lines and the TURNs each came from (FIX 7509).
    pub(crate) line_sources: Option<Vec<SummaryLineSources>>,
    /// An Arc composed in parts: its work generation, proven complete at the
    /// landing (FIX 7509 PR3). `None` for one call.
    pub(crate) arc_work: Option<[u8; 32]>,
}

pub(super) fn enqueue_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: Value,
) -> Result<ScopeSummaryQueued> {
    enqueue_with_lineage_in_txn(
        vault,
        txn,
        input,
        None,
        None,
        vault.store.clock.now_recorded_at(),
    )
}

pub(super) fn enqueue_with_lineage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: Value,
    parent_attempt: Option<AttemptId>,
    run_id: Option<&str>,
    now: u64,
) -> Result<ScopeSummaryQueued> {
    decode_request(vault, txn, &input)?;
    let encoded = derivation::encode(&input)?;
    let dedupe_key = format!(
        "{DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE}:{}:{}",
        blake3::hash(&encoded).to_hex(),
        parent_attempt
            .map(|id| crate::entity_id::bytes_to_hex_lower(id.as_bytes()))
            .unwrap_or_default()
    );
    let outcome = crate::dreamer_runner::DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        DreamerConsolidationScope::Micro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE.to_owned(),
            input,
            parent_attempt,
        },
        Some(dedupe_key),
        run_id.map(str::to_owned),
        now,
    )?;
    let (status, coalesced) = match outcome {
        crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Enqueued(status) => (status, false),
        crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Existing(status) => (status, true),
    };
    Ok(ScopeSummaryQueued {
        attempt: status.attempt.id,
        coalesced,
    })
}

pub(super) fn plan_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: &Value,
) -> Result<ScopeSummaryPlan> {
    let request = decode_request(vault, txn, input)?;
    actor_in_txn(&vault.store, txn, request.requester)?;
    let (purpose, previous, keep, editor_text) = derivation::options(vault, txn, input)?;
    let editor_frontier = previous
        .map(|id| crate::entity_doc::summary_frontier_in_txn(vault, txn, &id))
        .transpose()?;
    if let ScopeSummaryTarget::Arc { scope } = &request.target {
        let options = (purpose, previous, keep, editor_frontier);
        return super::arc_sources::plan_in_txn(vault, txn, input, &request, scope, options);
    }
    let session = match &request.target {
        ScopeSummaryTarget::Session { session } => Some(*session),
        _ => None,
    };
    let (scope, land_on, as_record, admitted) = match request.target {
        ScopeSummaryTarget::Scope {
            scope,
            land_on,
            as_record,
        } => (Some(scope), land_on, as_record, None),
        ScopeSummaryTarget::Sources { scope, sources } => (scope, None, false, Some(sources)),
        ScopeSummaryTarget::Thread { trunk } => {
            let selected = selected_thread_in_txn(vault, txn, trunk)?
                .ok_or_else(|| invalid("trunk has no thread"))?;
            let scope = ScopeSelector {
                conversation: selected.conversation,
                session: None,
                path: ScopePath::BranchSpan {
                    after: selected.trunk,
                    through: selected.tip,
                },
                include_forks: false,
            };
            if prove_branch_span(&vault.store, txn, &scope, selected.trunk, selected.tip)?
                != selected.replies
            {
                return Err(invalid("selected thread differs from bounded span"));
            }
            (Some(scope), Some(trunk), false, None)
        }
        ScopeSummaryTarget::Session { .. } => (None, None, false, None),
        ScopeSummaryTarget::Arc { .. } => return Err(invalid("an arc plans from its sittings")),
    };
    if as_record && land_on.is_none() {
        return Err(invalid("as_record requires land_on"));
    }
    let ScopeSources { members, sources } = match (&scope, session) {
        (Some(scope), _) => {
            if let Some(turn) = land_on {
                validate_landing_in_txn(vault, txn, scope, &turn)?;
            }
            let ScopeSources { members, sources } = scope_sources_in_txn(vault, txn, scope)?;
            let sources = match admitted {
                Some(admitted) => admitted_sources(sources, &admitted)?,
                None => sources,
            };
            ScopeSources { members, sources }
        }
        // A sitting's retained turns, read in this writer (FIX 7509).
        (None, Some(session)) => super::session::session_sources_in_txn(vault, txn, &session)?,
        // A NOTE set has no conversation to resolve: its NOTEs are read in
        // this writer, as its requester reads them (FIX 5757).
        (None, None) => note_sources_in_txn(
            vault,
            txn,
            request.requester,
            admitted.as_deref().unwrap_or_default(),
        )?,
    };
    // A sitting that retained no turns has no summary: its attempt completes
    // with none (FIX 7509), never with invented prose.
    if sources.is_empty() && session.is_none() {
        return Err(invalid("summary scope covers no records"));
    }
    Ok(ScopeSummaryPlan {
        input: derivation::encode(input)?,
        scope,
        session,
        members,
        sources,
        land_on,
        as_record,
        requester: request.requester,
        purpose,
        previous,
        keep,
        editor_text,
        editor_frontier,
        policy_frontier: crate::gate::resolve_policy_manifest(&vault.store, txn)?
            .read_frontier_hash()?,
        arc: None,
    })
}

impl Vault {
    pub fn request_scope_summary(
        &self,
        request: &ScopeSummaryRequest,
    ) -> Result<ScopeSummaryQueued> {
        let now = self.store.clock.now_recorded_at();
        let queued = self.with_write_txn(|txn| {
            self.request_scope_summary_in_txn(txn, request, None, None, now)
        })?;
        self.store.notify_attempt_observers();
        Ok(queued)
    }

    /// A recipe co-commits its declaration, parent/run binding and outbox
    /// consumption. No nested writer is opened.
    pub(crate) fn request_scope_summary_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: &ScopeSummaryRequest,
        parent_attempt: Option<AttemptId>,
        run_id: Option<&str>,
        now: u64,
    ) -> Result<ScopeSummaryQueued> {
        let purpose = match &request.target {
            ScopeSummaryTarget::Scope {
                scope:
                    ScopeSelector {
                        path: ScopePath::SubSession(_),
                        ..
                    },
                ..
            } => "sub_agent_merge_artifact",
            ScopeSummaryTarget::Sources { scope: None, .. } => NOTE_SET_PURPOSE,
            ScopeSummaryTarget::Arc { .. } => super::arc::ARC_PURPOSE,
            _ => "session_recap",
        };
        let previous = derivation::current_in_txn(self, txn, request, purpose)?;
        let input = derivation::declaration(request, purpose, previous);
        plan_in_txn(self, txn, &input)?;
        let queued = enqueue_with_lineage_in_txn(self, txn, input, parent_attempt, run_id, now)?;
        // FIX 3103: the asking run, as its request is queued.
        crate::skill_attribution::note_summary_request_in_txn(&self.store, txn, queued.attempt);
        Ok(queued)
    }

    /// Declares the descriptor row as well as the scope. Only approved rows
    /// resolve; there is no enum and no implicit "other" purpose.
    pub fn request_scope_summary_for(
        &self,
        request: &ScopeSummaryRequest,
        purpose: &str,
    ) -> Result<ScopeSummaryQueued> {
        self.with_write_txn_grouped(|txn| {
            let previous = derivation::current_in_txn(self, txn, request, purpose)?;
            let input = derivation::declaration(request, purpose, previous);
            plan_in_txn(self, txn, &input)?;
            let queued = enqueue_in_txn(self, txn, input)?;
            crate::skill_attribution::note_summary_request_in_txn(&self.store, txn, queued.attempt);
            Ok(queued)
        })
    }

    /// Selector, editor state and all source pins share the same snapshot.
    pub(crate) fn plan_scope_summary(
        &self,
        input: &Value,
    ) -> Result<(ScopeSummaryPlan, ScopeSummaryEvidence)> {
        self.store.authorization_now()?;
        self.with_write_txn_grouped(|txn| {
            let plan = plan_in_txn(self, txn, input)?;
            let evidence = plan.evidence_in_txn(self, txn)?;
            if plan.editor_text.is_some()
                && let Some(previous) = plan.previous
                && let Some(covers) =
                    crate::ports::EntityStoreRead::port_entity_record(&self.store, txn, &previous)?
            {
                let logical = crate::entity_doc::resolve_record_body(
                    &self.store,
                    txn,
                    &previous,
                    &covers.body,
                )?;
                let body = super::decode_scope_summary_body(&logical)?;
                if !body.covers.iter().all(|id| evidence.covers.contains(id))
                    || !body
                        .messages
                        .iter()
                        .all(|message| evidence.messages.contains(message))
                {
                    return Err(invalid(
                        "edited summary no longer has all its source evidence",
                    ));
                }
            }
            Ok((plan, evidence))
        })
    }

    pub(crate) fn composed_scope_summary_landed(&self, attempt: AttemptId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(super::status::result_in_txn(self, &txn, attempt)?.is_some())
    }

    pub(crate) fn reuse_composed_scope_summary(
        &self,
        attempt: AttemptId,
        plan: &ScopeSummaryPlan,
        evidence: &ScopeSummaryEvidence,
        first: &EntityId,
        memo: &[u8; 32],
        params_hash: &[u8; 32],
    ) -> Result<bool> {
        let requester = plan.requester_surface(self);
        let lane = reply_lane(&requester, plan.asks_reply())?;
        let outcome = self.try_with_write_txn_grouped::<_, _, AppendFailure>(|txn| {
            if plan_in_txn(self, txn, &derivation::decode(&plan.input)?)? != *plan
                || plan.evidence_in_txn(self, txn)? != *evidence
            {
                return Ok((false, None));
            }
            let previous = if let Some(previous) = plan.previous
                && plan.editor_text.is_none()
                && super::doors::summary_in_txn(self, txn, &previous).is_ok()
            {
                let meta = crate::entity_doc::summary_meta_in_txn(self, txn, &previous)?;
                (meta.derivation.content_hash == evidence.fingerprint()?
                    && &meta.derivation.params_hash == params_hash
                    && meta.derivation.policy_frontier == plan.policy_frontier
                    && meta.purpose == plan.purpose
                    && meta.keep == plan.keep)
                    .then_some(previous)
            } else {
                None
            };
            let summary = match previous {
                Some(summary) => summary,
                None => match standing_composition_in_txn(self, txn, first, memo)? {
                    Some(summary) => summary,
                    None => return Ok((false, None)),
                },
            };
            if !super::arc_completion::reuse_complete_in_txn(self, txn, plan, memo, &summary)? {
                return Ok((false, None));
            }
            let (landed, reply) = if let Some(turn) = plan.land_on
                && !header_landed_in_txn(self, txn, &summary, &turn)?
            {
                let (landed, reply) = land_in_txn(
                    self,
                    txn,
                    &summary,
                    &turn,
                    plan.requester,
                    lane.as_ref(),
                    self.store.clock.now_recorded_at(),
                )?;
                (Some(landed), reply)
            } else {
                (None, None)
            };
            super::status::record_result_in_txn(self, txn, attempt, summary, landed.as_ref())?;
            crate::skill_attribution::note_summary_landing_in_txn(self, txn, attempt, summary);
            derivation::register_in_txn(self, txn, &derivation::decode(&plan.input)?, summary)?;
            super::arc::landed_in_txn(self, txn, plan, evidence, summary)?;
            Ok((true, reply))
        });
        settle_header(&requester, outcome)
    }

    /// The final plan and every source version are read again in the SAME
    /// write transaction as mint, dependency registration, landing and result.
    pub(crate) fn land_composed_scope_summary(
        &self,
        attempt: AttemptId,
        plan: &ScopeSummaryPlan,
        evidence: &ScopeSummaryEvidence,
        composed: &ComposedSummary<'_>,
        author: WriteActor,
    ) -> Result<(EntityId, Option<LandedHeader>)> {
        if author != self.dreamer_authority()? {
            return Err(Error::InvalidClaimBody(
                "only the vault Dreamer writes a summary body",
            ));
        }
        let id = composed_summary_id(attempt);
        let requester = plan.requester_surface(self);
        let lane = reply_lane(&requester, plan.asks_reply())?;
        let outcome = self.try_with_write_txn_grouped::<_, _, AppendFailure>(|txn| {
            if let Some(result) = super::status::result_in_txn(self, txn, attempt)? {
                return Ok(((EntityId::from_hex(&result.summary)?, None), None));
            }
            let input = derivation::decode(&plan.input)?;
            if plan_in_txn(self, txn, &input)? != *plan
                || plan.evidence_in_txn(self, txn)? != *evidence
            {
                return Err(Error::ConcurrentWrite(
                    "summary sources or editor state changed during composition",
                )
                .into());
            }
            super::arc_validation::validate_landing(plan, composed)?;
            super::arc_completion::validate_in_txn(self, txn, plan, evidence, composed, &id)?;
            let now = self.store.clock.now_recorded_at();
            mint_in_txn(
                self,
                txn,
                id,
                plan.scope.as_ref(),
                author,
                now,
                SummaryContent {
                    text: composed.text,
                    covers: composed.covers.clone(),
                    messages: composed.messages.clone(),
                    memo: Some(composed.memo),
                    notes: evidence.notes.clone(),
                },
            )?;
            let metadata = ScopeSummaryMetadata {
                purpose: plan.purpose.clone(),
                keep: composed.keep.to_owned(),
                derivation: SummaryDerivation {
                    request: plan.input.clone(),
                    trigger: *attempt.as_bytes(),
                    content_hash: evidence.fingerprint()?,
                    params_hash: composed.params_hash,
                    instruction: composed.instruction.to_owned(),
                    model: composed.model.to_owned(),
                    policy_frontier: plan.policy_frontier,
                    sources: evidence.source_versions.clone(),
                    previous: plan.previous.map(|id| id.to_hex()),
                    recorded_at: now,
                    generated_text_hash: *blake3::hash(composed.text.as_bytes()).as_bytes(),
                    generated_keep_hash: *blake3::hash(composed.keep.as_bytes()).as_bytes(),
                    source_set: plan
                        .session
                        .map(|session| super::session::source_set_id(&session, &plan.sources))
                        .or_else(|| plan.arc.as_ref().map(|arc| arc.source_set)),
                    line_sources: composed.line_sources.clone(),
                },
            };
            crate::entity_doc::birth_summary_in_txn(self, txn, id, author, now, &metadata)?;
            let (landed, reply) = plan
                .land_on
                .map(|turn| land_in_txn(self, txn, &id, &turn, plan.requester, lane.as_ref(), now))
                .transpose()?
                .unzip();
            super::status::record_result_in_txn(self, txn, attempt, id, landed.as_ref())?;
            crate::skill_attribution::note_summary_landing_in_txn(self, txn, attempt, id);
            derivation::register_in_txn(self, txn, &input, id)?;
            super::arc::landed_in_txn(self, txn, plan, evidence, id)?;
            Ok(((id, landed), reply.flatten()))
        });
        settle_header(&requester, outcome)
    }
}

/// The scope's sources a declaration admitted, in the scope's own order. A
/// record the scope does not summarize, an earlier summary's reply among
/// them, refuses: an admitted set never reaches past its scope.
fn admitted_sources(sources: Vec<EntityId>, admitted: &[EntityId]) -> Result<Vec<EntityId>> {
    let admitted: std::collections::BTreeSet<EntityId> = admitted.iter().copied().collect();
    if admitted.is_empty() {
        return Err(invalid("summary source set is empty"));
    }
    let selected: Vec<EntityId> = sources
        .into_iter()
        .filter(|source| admitted.contains(source))
        .collect();
    if selected.len() != admitted.len() {
        return Err(invalid("summary source is not one its scope summarizes"));
    }
    Ok(selected)
}

/// One summary id per attempt, so a replayed attempt finds its own body.
fn composed_summary_id(attempt: AttemptId) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SUMMARY_ID_DOMAIN);
    hasher.update(attempt.as_bytes());
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    crate::commitment_wake::entity_id_from_digest_prefix(raw)
}

fn class_name(class: EdgeActorClass) -> &'static str {
    class.gate_actor_class()
}

pub(super) fn encode_request(request: &ScopeSummaryRequest) -> Value {
    let hex = |id: &EntityId| Value::from(id.to_hex());
    // A sitting's summary is its own actor's (FIX 7509): its declaration
    // names the sitting alone, and its requester is read with the sitting.
    if let ScopeSummaryTarget::Session { session } = &request.target {
        return Value::Map(vec![
            (Value::from("v"), Value::from(REQUEST_VERSION)),
            (Value::from(super::session::SESSION_KEY), hex(session)),
        ]);
    }
    let mut entries = vec![
        (Value::from("v"), Value::from(REQUEST_VERSION)),
        (
            Value::from("requester"),
            hex(&request.requester.entity_ref()),
        ),
        (
            Value::from("requester_class"),
            Value::from(class_name(request.requester.actor_class())),
        ),
    ];
    match &request.target {
        ScopeSummaryTarget::Scope {
            scope,
            land_on,
            as_record,
        } => entries.extend([
            (Value::from("scope"), scope_value(scope)),
            (
                Value::from("land_on"),
                land_on.as_ref().map_or(Value::Nil, hex),
            ),
            (Value::from("as_record"), Value::Boolean(*as_record)),
        ]),
        ScopeSummaryTarget::Thread { trunk } => {
            entries.push((Value::from("trunk"), hex(trunk)));
        }
        // The set is declared sorted and once each, so the same set is the
        // same declaration whatever order a caller named it in. A NOTE set
        // declares a nil scope.
        ScopeSummaryTarget::Sources { scope, sources } => {
            let sources: std::collections::BTreeSet<&EntityId> = sources.iter().collect();
            entries.extend([
                (
                    Value::from("scope"),
                    scope.as_ref().map_or(Value::Nil, scope_value),
                ),
                (
                    Value::from(SOURCES_KEY),
                    Value::Array(sources.into_iter().map(hex).collect()),
                ),
            ]);
        }
        // Encoded above, with no requester.
        ScopeSummaryTarget::Session { .. } => {}
        ScopeSummaryTarget::Arc { scope } => {
            entries.push((Value::from(super::arc::ARC_KEY), scope_value(scope)));
        }
    }
    Value::Map(entries)
}

/// A declaration's map entries, at the version this producer writes.
fn declared_fields(input: &Value) -> Result<&[(Value, Value)]> {
    let Value::Map(entries) = input else {
        return Err(invalid("summary request must be a map"));
    };
    if declared(entries, "v").and_then(Value::as_u64) != Some(REQUEST_VERSION) {
        return Err(invalid("unsupported summary request version"));
    }
    Ok(entries.as_slice())
}

fn declared<'v>(entries: &'v [(Value, Value)], name: &str) -> Option<&'v Value> {
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

fn declared_id(value: Option<&Value>) -> Result<EntityId> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("summary request id missing"))?;
    EntityId::from_hex(text).map_err(|_| invalid("summary request id invalid"))
}

/// The declaration with its requester. A sitting's declaration names none:
/// its summary is the sitting's own actor's, read in `txn` (FIX 7509).
pub(super) fn decode_request(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    input: &Value,
) -> Result<ScopeSummaryRequest> {
    let entries = declared_fields(input)?;
    let requester = match declared(entries, super::session::SESSION_KEY) {
        Some(session) => {
            super::session::requester_in_txn(vault, txn, &declared_id(Some(session))?)?
        }
        None => {
            let class = match declared(entries, "requester_class").and_then(Value::as_str) {
                Some("human") => EdgeActorClass::Human,
                Some("agent") => EdgeActorClass::Agent,
                Some("system") => EdgeActorClass::System,
                _ => return Err(invalid("summary request actor class invalid")),
            };
            WriteActor::new(declared_id(declared(entries, "requester"))?, class)
        }
    };
    Ok(ScopeSummaryRequest {
        target: decode_target(input)?,
        requester,
    })
}

/// A declaration's target alone, its requester unread. Each target is named
/// by its own keys, and a sitting's declaration names no requester.
pub(super) fn decode_target(input: &Value) -> Result<ScopeSummaryTarget> {
    let entries = declared_fields(input)?;
    let field = |name: &str| declared(entries, name);
    let session = field(super::session::SESSION_KEY);
    let target = match (field("scope"), field("trunk"), field(SOURCES_KEY), session) {
        (Some(scope), None, Some(Value::Array(sources)), None) => ScopeSummaryTarget::Sources {
            scope: if scope.is_nil() {
                None
            } else {
                Some(parse_scope(scope)?)
            },
            sources: sources
                .iter()
                .map(|source| declared_id(Some(source)))
                .collect::<Result<Vec<_>>>()?,
        },
        (Some(scope), None, None, None) => ScopeSummaryTarget::Scope {
            scope: parse_scope(scope)?,
            land_on: match field("land_on") {
                None | Some(Value::Nil) => None,
                value => Some(declared_id(value)?),
            },
            as_record: field("as_record")
                .and_then(Value::as_bool)
                .ok_or_else(|| invalid("summary request as_record missing"))?,
        },
        (None, Some(trunk), None, None) => ScopeSummaryTarget::Thread {
            trunk: declared_id(Some(trunk))?,
        },
        (None, None, None, Some(session))
            if field("requester").is_none() && field("requester_class").is_none() =>
        {
            ScopeSummaryTarget::Session {
                session: declared_id(Some(session))?,
            }
        }
        (None, None, None, None) if field(super::arc::ARC_KEY).is_some() => {
            super::arc::decode_target(field(super::arc::ARC_KEY))?
        }
        _ => return Err(invalid("summary request names no target")),
    };
    Ok(target)
}
