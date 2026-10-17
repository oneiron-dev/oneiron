//! A caller declares a summary scope; the Dreamer writes the body
//! (ARCH-0006a "the worker declares the scope; the system writes the body").
//!
//! The declaration is a typed Dreamer attempt on the Micro consolidation
//! queue. The Dreamer resolves the scope when it composes, and the body lands
//! under its own byline; the merge header and optional reply stay the
//! requester's move on its own turn.

use super::codec::SummarySourceMessage;
use super::codec::{invalid, parse_scope, scope_value};
use super::doors::{
    LandedHeader, ScopeSources, SummaryContent, header_landed_in_txn, land_in_txn, mint_in_txn,
    reply_lane, scope_sources_in_txn, settle_header, standing_composition_in_txn,
    validate_landing_in_txn,
};
use crate::attempt_queue::AttemptId;
use crate::conversation_dag::{
    AppendFailure, ScopePath, ScopeSelector, actor_in_txn, prove_branch_span,
    selected_thread_in_txn,
};
use crate::dreamer_consolidation::DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE;
use crate::dreamer_runner::{DreamerAttemptPayload, DreamerConsolidationScope};
use crate::error::{Error, Result};
use crate::memory::Memory;
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};
use rmpv::Value;

const REQUEST_VERSION: u64 = 1;
const SUMMARY_ID_DOMAIN: &[u8] = b"oneiron:dreamer-scope-summary:v1";
const MEMO_DOMAIN: &[u8] = b"oneiron:dreamer-scope-summary-memo:v1";

/// What the caller asks the Dreamer to summarize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSummaryTarget {
    /// A selector, optionally landed as a header (and reply) on `land_on`.
    Scope {
        scope: ScopeSelector,
        land_on: Option<EntityId>,
        as_record: bool,
    },
    /// The first thread chain under `trunk`, landed on the trunk.
    Thread { trunk: EntityId },
}

/// One declared summary: the scope and who asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSummaryRequest {
    pub target: ScopeSummaryTarget,
    /// Lands the merge header; never the body's author.
    pub requester: WriteActor,
}

/// The queued Dreamer attempt. An identical declaration still queued
/// coalesces onto it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeSummaryQueued {
    pub attempt: AttemptId,
    pub coalesced: bool,
}

/// The scope as the Dreamer resolved it when it composed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopeSummaryPlan {
    pub(crate) scope: ScopeSelector,
    /// Everything the scope resolved to: the landing fence.
    pub(crate) members: Vec<EntityId>,
    /// The members a body may be written from (never an earlier summary's
    /// reply). The covers are those of them the Dreamer could read.
    pub(crate) sources: Vec<EntityId>,
    pub(crate) land_on: Option<EntityId>,
    pub(crate) as_record: bool,
    pub(crate) requester: WriteActor,
}

impl ScopeSummaryPlan {
    /// The composition memo (ARCH-0006a scope content hash): this scope,
    /// each covered record with the content hash of the body read, each
    /// MESSAGE at its revision, the transcript the model reads (finality
    /// changes it without changing a body), and the composing `policy`.
    /// Landing requests are not part of it: they never change the body.
    pub(crate) fn composition_memo(
        &self,
        covers: &[(EntityId, [u8; 32])],
        messages: &[SummarySourceMessage],
        transcript: &str,
        policy: &[&str],
    ) -> Result<[u8; 32]> {
        let mut scope = Vec::new();
        rmpv::encode::write_value(&mut scope, &scope_value(&self.scope))
            .map_err(|_| invalid("summary scope encode failed"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(MEMO_DOMAIN);
        hasher.update(&(scope.len() as u64).to_be_bytes());
        hasher.update(&scope);
        hasher.update(&(covers.len() as u64).to_be_bytes());
        for (record, version) in covers {
            hasher.update(record.as_bytes());
            hasher.update(version);
        }
        hasher.update(&(messages.len() as u64).to_be_bytes());
        for message in messages {
            hasher.update(message.id.as_bytes());
            hasher.update(&message.revision);
        }
        hasher.update(&(transcript.len() as u64).to_be_bytes());
        hasher.update(transcript.as_bytes());
        for part in policy {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        Ok(*hasher.finalize().as_bytes())
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

/// A body the Dreamer composed, and what it was written from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComposedSummary<'a> {
    pub(crate) text: &'a str,
    pub(crate) covers: Vec<EntityId>,
    pub(crate) messages: Vec<SummarySourceMessage>,
    pub(crate) memo: [u8; 32],
}

impl Vault {
    /// Declares a summary scope for the Dreamer to compose.
    ///
    /// The scope, landing turn and requester are checked now, so a bad
    /// declaration is refused to its caller rather than parked in the queue.
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
        if let ScopeSummaryTarget::Scope {
            land_on: None,
            as_record: true,
            ..
        } = request.target
        {
            return Err(invalid("as_record requires land_on"));
        }
        actor_in_txn(&self.store, txn, request.requester)?;
        match &request.target {
            ScopeSummaryTarget::Scope { scope, land_on, .. } => {
                if scope_sources_in_txn(self, txn, scope)?.sources.is_empty() {
                    return Err(invalid("summary scope covers no records"));
                }
                if let Some(turn) = land_on {
                    validate_landing_in_txn(self, txn, scope, turn)?;
                }
            }
            ScopeSummaryTarget::Thread { trunk } => {
                selected_thread_in_txn(self, txn, *trunk)?
                    .ok_or_else(|| invalid("trunk has no thread"))?;
            }
        }
        let input = encode_request(request);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &input)
            .map_err(|_| invalid("summary request encode failed"))?;
        let dedupe_key = format!(
            "{DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE}:{}:{}",
            blake3::hash(&encoded).to_hex(),
            parent_attempt
                .map(|id| crate::entity_id::bytes_to_hex_lower(id.as_bytes()))
                .unwrap_or_default()
        );
        let outcome = crate::dreamer_runner::DreamerRunnerStore::new(self).enqueue_kind_in_txn(
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
            crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Enqueued(status) => {
                (status, false)
            }
            crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Existing(status) => (status, true),
        };
        Ok(ScopeSummaryQueued {
            attempt: status.attempt.id,
            coalesced,
        })
    }

    /// Resolves a queued declaration against the vault as it is now.
    pub(crate) fn plan_scope_summary(&self, input: &Value) -> Result<ScopeSummaryPlan> {
        let request = decode_request(input)?;
        self.with_write_txn(|txn| {
            actor_in_txn(&self.store, txn, request.requester)?;
            let (scope, land_on, as_record) = match request.target {
                ScopeSummaryTarget::Scope {
                    scope,
                    land_on,
                    as_record,
                } => (scope, land_on, as_record),
                ScopeSummaryTarget::Thread { trunk } => {
                    let selected = selected_thread_in_txn(self, txn, trunk)?
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
                    if prove_branch_span(&self.store, txn, &scope, selected.trunk, selected.tip)?
                        != selected.replies
                    {
                        return Err(invalid("selected thread differs from bounded span"));
                    }
                    (scope, Some(trunk), false)
                }
            };
            let ScopeSources { members, sources } = scope_sources_in_txn(self, txn, &scope)?;
            if sources.is_empty() {
                return Err(invalid("summary scope covers no records"));
            }
            Ok(ScopeSummaryPlan {
                scope,
                members,
                sources,
                land_on,
                as_record,
                requester: request.requester,
            })
        })
    }

    /// Whether this attempt's body already landed.
    pub(crate) fn composed_scope_summary_landed(&self, attempt: AttemptId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(matches!(
            live_entity_row_in_txn(&self.store, &rtxn, &composed_summary_id(attempt))?,
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_SUMMARY
        ))
    }

    /// Reuses a standing summary of exactly this composition (`memo`), so an
    /// unchanged declaration makes no second model call and no second
    /// SUMMARY. Only the landing this declaration asks for is done, and only
    /// once per summary and turn. `first` is the first record the body would
    /// cover. False when the scope moved or no such summary stands.
    pub(crate) fn reuse_composed_scope_summary(
        &self,
        plan: &ScopeSummaryPlan,
        first: &EntityId,
        memo: &[u8; 32],
    ) -> Result<bool> {
        let requester = plan.requester_surface(self);
        let lane = reply_lane(&requester, plan.asks_reply())?;
        let outcome = self.try_with_write_txn::<_, _, AppendFailure>(|txn| {
            let current = scope_sources_in_txn(self, txn, &plan.scope)?;
            if current.members != plan.members || current.sources != plan.sources {
                return Ok((false, None));
            }
            let Some(summary) = standing_composition_in_txn(self, txn, first, memo)? else {
                return Ok((false, None));
            };
            let mut reply = None;
            if let Some(turn) = plan.land_on
                && !header_landed_in_txn(self, txn, &summary, &turn)?
            {
                let now = self.store.clock.now_recorded_at();
                reply = land_in_txn(
                    self,
                    txn,
                    &summary,
                    &turn,
                    plan.requester,
                    lane.as_ref(),
                    now,
                )?
                .1;
            }
            Ok((true, reply))
        });
        settle_header(&requester, outcome)
    }

    /// Lands a body the Dreamer composed over `plan`, once per attempt.
    ///
    /// The scope must still resolve as it did when the body was written, so
    /// the minted `covers` are the records the body was written from; a moved
    /// scope is refused and the attempt composes again.
    pub(crate) fn land_composed_scope_summary(
        &self,
        attempt: AttemptId,
        plan: &ScopeSummaryPlan,
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
        let outcome = self.try_with_write_txn::<_, _, AppendFailure>(|txn| {
            if let LiveEntityRow::Live { entity_type, .. } =
                live_entity_row_in_txn(&self.store, txn, &id)?
            {
                if entity_type != ENTITY_TYPE_SUMMARY {
                    return Err(
                        Error::CorruptedIndex("composed summary id names another entity").into(),
                    );
                }
                return Ok(((id, None), None));
            }
            let current = scope_sources_in_txn(self, txn, &plan.scope)?;
            if current.members != plan.members || current.sources != plan.sources {
                return Err(Error::ConcurrentWrite(
                    "summary scope changed while the Dreamer composed it",
                )
                .into());
            }
            let now = self.store.clock.now_recorded_at();
            let content = SummaryContent {
                text: composed.text,
                covers: composed.covers.clone(),
                messages: composed.messages.clone(),
                memo: Some(composed.memo),
            };
            mint_in_txn(self, txn, id, &plan.scope, author, now, content)?;
            let (landed, reply) = plan
                .land_on
                .map(|turn| land_in_txn(self, txn, &id, &turn, plan.requester, lane.as_ref(), now))
                .transpose()?
                .unzip();
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

fn encode_request(request: &ScopeSummaryRequest) -> Value {
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

fn decode_request(input: &Value) -> Result<ScopeSummaryRequest> {
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
