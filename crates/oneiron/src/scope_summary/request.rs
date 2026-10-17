//! Scope-only declarations, exact-source fences and atomic Dreamer landings.

use super::codec::SummarySourceMessage;
use super::codec::{invalid, parse_scope, scope_value};
use super::derivation::{self, ScopeSummaryMetadata, SummaryDerivation};
use super::doors::{
    LandedHeader, ScopeSources, SummaryContent, header_landed_in_txn, land_in_txn, mint_in_txn,
    reply_lane, scope_sources_in_txn, settle_header, standing_composition_in_txn,
    validate_landing_in_txn,
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

const REQUEST_VERSION: u64 = 2;
const SUMMARY_ID_DOMAIN: &[u8] = b"oneiron:dreamer-scope-summary:v1";
const MEMO_DOMAIN: &[u8] = b"oneiron:dreamer-scope-summary-memo:v2";

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
    pub(crate) scope: ScopeSelector,
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
}

impl ScopeSummaryPlan {
    /// The impact gate omits generated landing replies and unrelated writes.
    pub(crate) fn observation(&self, evidence: &[u8; 32]) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(MEMO_DOMAIN);
        hasher.update(&derivation::encode(&scope_value(&self.scope))?);
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

fn enqueue_with_lineage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    input: Value,
    parent_attempt: Option<AttemptId>,
    run_id: Option<&str>,
    now: u64,
) -> Result<ScopeSummaryQueued> {
    decode_request(&input)?;
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
    let request = decode_request(input)?;
    actor_in_txn(&vault.store, txn, request.requester)?;
    let (purpose, previous, keep, editor_text) = derivation::options(vault, txn, input)?;
    let editor_frontier = previous
        .map(|id| crate::entity_doc::summary_frontier_in_txn(vault, txn, &id))
        .transpose()?;
    let (scope, land_on, as_record) = match request.target {
        ScopeSummaryTarget::Scope {
            scope,
            land_on,
            as_record,
        } => (scope, land_on, as_record),
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
            (scope, Some(trunk), false)
        }
    };
    if as_record && land_on.is_none() {
        return Err(invalid("as_record requires land_on"));
    }
    if let Some(turn) = land_on {
        validate_landing_in_txn(vault, txn, &scope, &turn)?;
    }
    let ScopeSources { members, sources } = scope_sources_in_txn(vault, txn, &scope)?;
    if sources.is_empty() {
        return Err(invalid("summary scope covers no records"));
    }
    Ok(ScopeSummaryPlan {
        input: derivation::encode(input)?,
        scope,
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
            _ => "session_recap",
        };
        let previous = derivation::current_in_txn(self, txn, request, purpose)?;
        let input = derivation::declaration(request, purpose, previous);
        plan_in_txn(self, txn, &input)?;
        enqueue_with_lineage_in_txn(self, txn, input, parent_attempt, run_id, now)
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
            enqueue_in_txn(self, txn, input)
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
            let evidence = scope_summary_evidence_in_txn(self, txn, &plan.sources)?;
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
                || scope_summary_evidence_in_txn(self, txn, &plan.sources)? != *evidence
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
            derivation::register_in_txn(self, txn, &derivation::decode(&plan.input)?, summary)?;
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
                || scope_summary_evidence_in_txn(self, txn, &plan.sources)? != *evidence
            {
                return Err(Error::ConcurrentWrite(
                    "summary sources or editor state changed during composition",
                )
                .into());
            }
            let now = self.store.clock.now_recorded_at();
            mint_in_txn(
                self,
                txn,
                id,
                &plan.scope,
                author,
                now,
                SummaryContent {
                    text: composed.text,
                    covers: composed.covers.clone(),
                    messages: composed.messages.clone(),
                    memo: Some(composed.memo),
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
                },
            };
            crate::entity_doc::birth_summary_in_txn(self, txn, id, author, now, &metadata)?;
            let (landed, reply) = plan
                .land_on
                .map(|turn| land_in_txn(self, txn, &id, &turn, plan.requester, lane.as_ref(), now))
                .transpose()?
                .unzip();
            super::status::record_result_in_txn(self, txn, attempt, id, landed.as_ref())?;
            derivation::register_in_txn(self, txn, &input, id)?;
            Ok(((id, landed), reply.flatten()))
        });
        settle_header(&requester, outcome)
    }
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
    }
    Value::Map(entries)
}

pub(super) fn decode_request(input: &Value) -> Result<ScopeSummaryRequest> {
    let Value::Map(entries) = input else {
        return Err(invalid("summary request must be a map"));
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    let id = |value: Option<&Value>| -> Result<EntityId> {
        let text = value
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("summary request id missing"))?;
        EntityId::from_hex(text).map_err(|_| invalid("summary request id invalid"))
    };
    if field("v").and_then(Value::as_u64) != Some(REQUEST_VERSION) {
        return Err(invalid("unsupported summary request version"));
    }
    let class = match field("requester_class").and_then(Value::as_str) {
        Some("human") => EdgeActorClass::Human,
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => return Err(invalid("summary request actor class invalid")),
    };
    let requester = WriteActor::new(id(field("requester"))?, class);
    let target = match (field("scope"), field("trunk")) {
        (Some(scope), None) => ScopeSummaryTarget::Scope {
            scope: parse_scope(scope)?,
            land_on: match field("land_on") {
                None | Some(Value::Nil) => None,
                value => Some(id(value)?),
            },
            as_record: field("as_record")
                .and_then(Value::as_bool)
                .ok_or_else(|| invalid("summary request as_record missing"))?,
        },
        (None, Some(trunk)) => ScopeSummaryTarget::Thread {
            trunk: id(Some(trunk))?,
        },
        _ => return Err(invalid("summary request names no target")),
    };
    Ok(ScopeSummaryRequest { target, requester })
}
