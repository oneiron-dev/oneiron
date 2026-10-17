//! The highway's Post arm, its brief revisions, and settlement: the one
//! continuation that turns an approved proposal into intent exactly once
//! (OF-220).
//!
//! A post the gate does not answer Auto parks as the ordinary `tasks.create`
//! Proposed CLAIM, its typed brief inside: content approval and creation
//! approval are one proposal, so `settle(proposal)` runs once (ARCH-0035).
//! Only the existing approval doors approve; after either one sets
//! approval it calls [`settle_task_proposal_in_txn`] in the same
//! transaction, and the TASK lands under an id derived from the claim, so a
//! second settlement finds it already there.

use serde::{Deserialize, Serialize};

use rmpv::Value;

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::record_scope::BirthPosition;
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::task_authority::{
    TaskAuthorityFact, TaskAuthorityFactKind, put_task_authority_fact_in_txn,
};
use crate::task_type::TaskTypeRef;
use crate::write_envelope::WriteActor;

use super::brief::{QueueTaskBrief, StoredBrief, brief_digest, hex32};
use super::consts::{
    TASK_BRIEF_PROPOSAL_PREDICATE, TASK_CREATE_PROPOSAL_PREDICATE, TASK_POST_ID_DOMAIN,
    TASK_POST_STAMP_KEY, TASK_SETTLE_ID_DOMAIN,
};
use super::create_origin::{TaskCreateOrigin, proposal_origin_in, task_create_origin_in_txn};
use super::create_spec::{TaskCreateRateLimit, TaskCreateSpec};
use super::create_validation::{
    task_body_in_txn, task_create_proposal_value, validate_task_create, validate_task_create_in,
};
use super::decision_port::{PortAnswer, TaskDecisions, TaskQuestion, ask};
use super::highway::{
    forbidden, invalid_state, not_found, post_provenance, provenance_digest, qualified_key,
    stamp_fields,
};
use super::highway_types::{TaskCall, TaskCallReceipt, TaskHandle, TaskOutcome, TaskPost, TaskVia};
use super::rate_limit::{record_task_create, task_actor_ceiling};
use super::route_receipts::{TaskCreateReceipt, TaskRouteOutcome};
use super::verb_kind::{TaskAssignee, TaskKind, TaskTtl};
use super::wire_decode::{
    decode_task_assignee, task_body_field, task_body_optional, task_verb_body_in,
};
use super::wire_encode::canonical_bytes;

/// Domain of a post's request digest.
const POST_REQUEST_DOMAIN: &[u8] = b"oneiron.tasks.post.request.v1";
/// Reason code of a proposal the addressed agent declined.
const TAKE_DECLINED_REASON: &str = "tasks.take.declined";

/// The typed stamp a highway post's proposal value carries: everything
/// settlement needs that the create value does not hold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostStamp {
    intent_key: String,
    #[serde(with = "hex32")]
    request_digest: [u8; 32],
    actor_class: u8,
    #[serde(default)]
    birth_world: Option<EntityId>,
    #[serde(default)]
    birth_facet: Option<EntityId>,
    brief: QueueTaskBrief,
}

/// The value of one `tasks.brief` revision proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BriefRevision {
    task_ref: EntityId,
    base_rev: u32,
    report_key: String,
    actor_class: u8,
    brief: QueueTaskBrief,
}

/// What the Auto branch of one post found.
enum PostDirect {
    Created(TaskRouteOutcome),
    Replay(Option<TaskAssignee>),
    Gated,
}

/// One earlier proposal under the same actor and key.
struct HeldProposal {
    proposal_ref: EntityId,
    digest: [u8; 32],
    approval: ClaimApprovalStatus,
}

fn typed_value<T: Serialize>(value: &T) -> MemoryResult<Value> {
    let encoded = rmp_serde::to_vec_named(value)
        .map_err(|_| MemoryError::bad_request("task proposal does not encode"))?;
    rmpv::decode::read_value(&mut encoded.as_slice())
        .map_err(|_| MemoryError::bad_request("task proposal does not encode"))
}

fn from_value<T: for<'de> Deserialize<'de>>(value: &Value) -> Option<T> {
    rmp_serde::from_slice(&canonical_bytes(value)).ok()
}

fn map_entry<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    task_body_optional(entries, key).ok().flatten()
}

/// The digest one post's request binds: the actor, the key, the brief and
/// every routed field. A replay under the same key with any other request is
/// refused, as an ask's is.
fn request_digest(actor: EntityId, key: &str, post: &TaskPost) -> MemoryResult<[u8; 32]> {
    let bytes = rmp_serde::to_vec_named(&(
        actor,
        key,
        brief_digest(&post.brief).to_vec(),
        post.assignee,
        &post.spec,
        post.ttl,
        &post.label,
    ))
    .map_err(|_| MemoryError::bad_request("task post does not encode"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(POST_REQUEST_DOMAIN);
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

/// The brief's type stamp in the create spec's spelling (OF-541): the
/// node its `type_ref` names, resolved through the live tree of the brief's
/// project (the team-shape skill's data) to the node whose id it is, at the
/// version the brief read. A node that tree does not hold leaves the stamp
/// unset, and the create places it.
fn brief_type_ref_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    brief: &QueueTaskBrief,
) -> MemoryResult<Option<TaskTypeRef>> {
    let tree = crate::agent_dispatch::load_team_type_tree_in_txn(vault, txn, brief.project_ref)?;
    Ok(tree
        .node_by_entity(brief.type_ref.node_id)
        .map(|node| TaskTypeRef::new(node.node_id.clone(), brief.type_ref.tree_version)))
}

/// The create spec one post validates and mints as: a standard task, with
/// the brief's resolved stamp and its project's tree to place against.
fn create_spec_of(
    post: &TaskPost,
    owner: EntityId,
    type_ref: Option<TaskTypeRef>,
    now: u64,
) -> TaskCreateSpec {
    let mut spec = TaskCreateSpec::new(
        post.spec.clone().unwrap_or(Value::Nil),
        post.label.clone(),
        Some(owner),
        Some(now),
    )
    .with_kind(TaskKind::Standard)
    .with_assignee(post.assignee);
    if let Some(ttl) = post.ttl {
        spec = spec.with_ttl(ttl);
    }
    if let Some(type_ref) = type_ref {
        spec = spec.with_type_ref(type_ref);
    }
    spec.brief = Some(post.brief.clone());
    spec
}

fn changed_arguments() -> MemoryError {
    MemoryError::bad_request_with(
        "this intent key already names a different request",
        &["Re-issue the same request to replay it, or post under a new intent key."],
    )
}

/// Writes the Assigned fact for an addressed lane: who the TASK is for, as
/// an immutable companion fact, so the body's `assignee` stays display.
pub(super) fn put_assignment_fact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    owner: EntityId,
    assignee: TaskAssignee,
    now: u64,
) -> MemoryResult<()> {
    if let Some(assigned) = assignee.entity_ref() {
        put_task_authority_fact_in_txn(
            vault,
            wtxn,
            TaskAuthorityFact {
                task_ref,
                kind: TaskAuthorityFactKind::Assigned,
                actor_ref: owner,
                assigned_ref: Some(assigned),
                actor_generation: None,
                assigned_generation: None,
                occurred_at: now,
            },
        )?;
    }
    Ok(())
}

pub(super) fn settle_refusal(error: MemoryError) -> Error {
    Error::InvalidConfig(format!(
        "task proposal settlement refused: {}",
        error.message
    ))
}

impl Memory<'_> {
    /// `tasks_create` for a briefed spec: the post it describes, run through
    /// the highway and answered in the create receipt's shape. A surface a
    /// host bound to its creator posts as that host (OF-532); any other
    /// posts on the wire.
    pub(super) fn post_create_spec(
        &self,
        spec: &TaskCreateSpec,
    ) -> MemoryResult<TaskCreateReceipt> {
        let (Some(intent_key), Some(brief)) = (spec.intent_key.clone(), spec.brief.clone()) else {
            return Err(MemoryError::bad_request(
                "a briefed create names both its intent key and its brief",
            ));
        };
        if spec.kind.is_some_and(|kind| kind != TaskKind::Standard) || spec.consult.is_some() {
            return Err(MemoryError::bad_request(
                "a briefed create is a standard task",
            ));
        }
        let via = match self.task_host() {
            Some(binding) => TaskVia::Host(binding.clone()),
            None => TaskVia::Wire,
        };
        let receipt = self.tasks_highway(
            via,
            TaskCall::Post(TaskPost {
                intent_key,
                brief,
                assignee: spec.assignee.unwrap_or(TaskAssignee::Dreamer),
                spec: Some(spec.spec.clone()),
                ttl: spec.ttl,
                label: spec.label.clone(),
            }),
        )?;
        let landed = receipt.related.iter().find_map(|handle| match handle {
            TaskHandle::Task { task_ref } => Some(*task_ref),
            _ => None,
        });
        let created = match (receipt.handle, receipt.outcome) {
            (TaskHandle::Task { task_ref }, TaskOutcome::Created { route }) => TaskCreateReceipt {
                task_ref: Some(task_ref),
                proposal_ref: None,
                approval: ClaimApprovalStatus::Auto,
                effected: true,
                route,
                task_record: None,
                proposal_record: None,
            },
            (TaskHandle::Proposed { proposal_ref }, TaskOutcome::Created { route }) => {
                TaskCreateReceipt {
                    task_ref: landed,
                    proposal_ref: Some(proposal_ref),
                    approval: ClaimApprovalStatus::Approved,
                    effected: true,
                    route,
                    task_record: None,
                    proposal_record: None,
                }
            }
            (TaskHandle::Proposed { proposal_ref }, TaskOutcome::Rejected { .. }) => {
                TaskCreateReceipt {
                    task_ref: None,
                    proposal_ref: Some(proposal_ref),
                    approval: ClaimApprovalStatus::Rejected,
                    effected: false,
                    route: None,
                    task_record: None,
                    proposal_record: None,
                }
            }
            (TaskHandle::Proposed { proposal_ref }, _) => TaskCreateReceipt {
                task_ref: None,
                proposal_ref: Some(proposal_ref),
                approval: ClaimApprovalStatus::Proposed,
                effected: false,
                route: None,
                task_record: None,
                proposal_record: None,
            },
            _ => {
                return Err(MemoryError::from(Error::InvariantViolation(
                    "a post answered with neither a task nor a proposal",
                )));
            }
        };
        Ok(created.with_record_refs())
    }

    /// Post: under Auto, one transaction mints the TASK at an id derived
    /// from the actor and key, routes it, and writes its Assigned fact.
    /// Otherwise the post parks as one Proposed `tasks.create` CLAIM. A
    /// replay of the same request answers the same handle; a different
    /// request under the same key is refused.
    ///
    /// A `Host` post is its creator's (OF-532): its binding is re-proved in
    /// the write transaction, and an agent TASK it creates runs inside that
    /// creator's lease tree, or, parked, lands there on approval.
    pub(super) fn highway_post(
        &self,
        via: &TaskVia,
        post: TaskPost,
        decisions: Option<&TaskDecisions<'_>>,
    ) -> MemoryResult<TaskCallReceipt> {
        let key = qualified_key(via, &post.intent_key, "intent key")?;
        let now = self.vault().now_recorded_at();
        post.brief.admit_references(self, "tasks.create")?;
        let type_ref = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            post.brief.validate_in(self.vault(), &txn)?;
            brief_type_ref_in(self.vault(), &txn, &post.brief)?
        };
        let digest = request_digest(self.actor(), &key, &post)?;
        let spec = create_spec_of(&post, self.actor(), type_ref, now);
        let validated = validate_task_create(self.vault(), &spec, now)?;
        let stored = StoredBrief::first(post.brief.clone());
        let task_ref = EntityId::derive(
            TASK_POST_ID_DOMAIN,
            &[self.actor().as_bytes(), key.as_bytes()],
        )?;
        let provenance = post_provenance(&key, &digest, None);
        let rate_now = self.vault().store.clock.now_recorded_at();

        let direct = self.with_verified_actor_write_txn(|wtxn| {
            if let Some(body) = task_verb_body_in(self.vault(), &*wtxn, task_ref)? {
                return if provenance_digest(&body.provenance) == Some(digest) {
                    Ok(PostDirect::Replay(body.assignee))
                } else {
                    Err(changed_arguments())
                };
            }
            if self.vault().get_raw_in(&*wtxn, &task_ref)?.is_some() {
                return Err(MemoryError::bad_request("task post id is already occupied"));
            }
            let creator = match via {
                TaskVia::Host(binding) => Some(binding),
                TaskVia::Wire => None,
            };
            let origin = task_create_origin_in_txn(self, &*wtxn, creator)?;
            if task_actor_ceiling(self.vault(), &*wtxn, self.actor(), self.actor_class())?
                != PolicyApprovalCeiling::Auto
            {
                return Ok(PostDirect::Gated);
            }
            record_task_create(
                self.vault(),
                wtxn,
                self.actor(),
                rate_now,
                TaskCreateRateLimit::default(),
            )?;
            self.mint_task_with_brief_at_in_txn(
                wtxn,
                (task_ref, self.actor()),
                &validated,
                post.label.clone(),
                &provenance,
                Some(stored.clone()),
                now,
            )?;
            let route = self.route_created_task_with_origin_in_txn(
                wtxn,
                task_ref,
                &validated,
                origin.as_ref(),
                now,
            )?;
            put_assignment_fact_in_txn(
                self.vault(),
                wtxn,
                task_ref,
                self.actor(),
                post.assignee,
                now,
            )?;
            self.witness_human_assignment_in_txn(wtxn, task_ref, &validated, self.actor(), now)?;
            Ok(PostDirect::Created(route))
        })?;

        let mut lifecycle =
            self.lifecycle_record(via, "post", "created", Some(task_ref), None, now);
        stamp_fields(&mut lifecycle.fields, Some(&stored));
        lifecycle
            .fields
            .insert("intent_key".to_owned(), key.clone());
        lifecycle
            .fields
            .insert("assignee".to_owned(), post.assignee.as_str().to_owned());
        if let Some(composed) = &post.brief.composed {
            lifecycle
                .fields
                .insert("composer_seat".to_owned(), composed.seat.clone());
            lifecycle.fields.insert(
                "one_liner_digest".to_owned(),
                crate::entity_id::bytes_to_hex_lower(&composed.one_liner_digest),
            );
            lifecycle.fields.insert(
                "lens_refs".to_owned(),
                composed
                    .lens_refs
                    .iter()
                    .map(EntityId::to_hex)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        match direct {
            PostDirect::Created(route) => {
                lifecycle
                    .fields
                    .insert("route".to_owned(), format!("{:?}", route.lane()));
                self.vault().store.notify_attempt_observers();
                Ok(TaskCallReceipt {
                    handle: TaskHandle::Task { task_ref },
                    related: Vec::new(),
                    outcome: TaskOutcome::Created { route: Some(route) },
                    receipt_ref: None,
                    lifecycle: Some(lifecycle),
                    idempotent_replay: false,
                })
            }
            PostDirect::Replay(assignee) => {
                lifecycle.outcome = "replayed".to_owned();
                lifecycle
                    .fields
                    .insert("replayed".to_owned(), "true".to_owned());
                Ok(TaskCallReceipt {
                    handle: TaskHandle::Task { task_ref },
                    related: Vec::new(),
                    outcome: TaskOutcome::Created {
                        route: self.replayed_route(task_ref, assignee)?,
                    },
                    receipt_ref: None,
                    lifecycle: Some(lifecycle),
                    idempotent_replay: true,
                })
            }
            PostDirect::Gated => {
                let creator = match via {
                    TaskVia::Host(binding) => Some(binding),
                    TaskVia::Wire => None,
                };
                self.park_post(
                    &post, &spec, &key, digest, now, decisions, lifecycle, creator,
                )
            }
        }
    }

    /// The route an earlier landing of this post took, as far as this node
    /// can still name it.
    fn replayed_route(
        &self,
        task_ref: EntityId,
        assignee: Option<TaskAssignee>,
    ) -> MemoryResult<Option<TaskRouteOutcome>> {
        Ok(match assignee {
            None | Some(TaskAssignee::Dreamer) => {
                crate::attempt_queue::AttemptQueue::new(self.vault())
                    .pending_task_route(
                        super::consts::TASK_REALIZE_ATTEMPT_KIND,
                        &super::create_validation::task_route_dedupe_key(task_ref),
                        task_ref,
                    )?
                    .map(|record| TaskRouteOutcome::DreamerAttempt {
                        attempt_ref: record.id,
                    })
            }
            Some(TaskAssignee::AgentDef { .. }) => None,
            Some(TaskAssignee::Peer { actor_ref }) => {
                Some(TaskRouteOutcome::PeerSyncedOnly { actor_ref })
            }
            Some(TaskAssignee::Child { actor_ref }) => {
                Some(TaskRouteOutcome::ChildAddressed { actor_ref })
            }
            Some(TaskAssignee::Human { actor_ref }) => {
                Some(TaskRouteOutcome::HumanFollowup { actor_ref })
            }
        })
    }

    /// The gated branch: replay an earlier proposal under this key, or park
    /// a new one; then, for a guest addressing a non-pre-admitted agent, ask
    /// whether the agent takes it. A host's key is qualified by its creator,
    /// so a replay is always the same creator's; a new proposal witnesses
    /// that creator beside it (OF-532).
    #[expect(
        clippy::too_many_arguments,
        reason = "the parked post's request, its identity, the surface's decisions and its creator"
    )]
    fn park_post(
        &self,
        post: &TaskPost,
        spec: &TaskCreateSpec,
        key: &str,
        digest: [u8; 32],
        now: u64,
        decisions: Option<&TaskDecisions<'_>>,
        mut lifecycle: super::highway_types::TaskLifecycleRecord,
        creator: Option<&super::highway_types::HostBinding>,
    ) -> MemoryResult<TaskCallReceipt> {
        if let Some(held) = self.held_proposal(TASK_CREATE_PROPOSAL_PREDICATE, key)? {
            if held.digest != digest {
                return Err(changed_arguments());
            }
            lifecycle.outcome = "replayed".to_owned();
            lifecycle
                .fields
                .insert("replayed".to_owned(), "true".to_owned());
            let landed = EntityId::derive(TASK_SETTLE_ID_DOMAIN, &[held.proposal_ref.as_bytes()])?;
            let landed_exists = held.approval == ClaimApprovalStatus::Approved && {
                let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
                task_verb_body_in(self.vault(), &txn, landed)?.is_some()
            };
            let (related, outcome) = match held.approval {
                ClaimApprovalStatus::Rejected => {
                    (Vec::new(), TaskOutcome::Rejected { decision_ref: None })
                }
                ClaimApprovalStatus::Approved if landed_exists => (
                    vec![TaskHandle::Task { task_ref: landed }],
                    TaskOutcome::Created { route: None },
                ),
                _ => (
                    Vec::new(),
                    TaskOutcome::Proposed {
                        decision_ref: None,
                        reason_codes: Vec::new(),
                    },
                ),
            };
            return Ok(TaskCallReceipt {
                handle: TaskHandle::Proposed {
                    proposal_ref: held.proposal_ref,
                },
                related,
                outcome,
                receipt_ref: None,
                lifecycle: Some(lifecycle),
                idempotent_replay: true,
            });
        }

        let position = self.birth_position();
        let stamp = PostStamp {
            intent_key: key.to_owned(),
            request_digest: digest,
            actor_class: self.actor_class() as u8,
            birth_world: position.world,
            birth_facet: position.facet,
            brief: post.brief.clone(),
        };
        let Value::Map(mut entries) = task_create_proposal_value(spec, now) else {
            return Err(MemoryError::from(Error::InvariantViolation(
                "a create proposal value is a map",
            )));
        };
        entries.push((Value::from(TASK_POST_STAMP_KEY), typed_value(&stamp)?));
        let (proposal_ref, decision_ref) = self.persist_task_proposal_with_origin(
            TASK_CREATE_PROPOSAL_PREDICATE,
            Value::Map(entries),
            self.actor(),
            now,
            post_provenance(key, &digest, None),
            creator,
        )?;
        lifecycle.outcome = "proposed".to_owned();
        lifecycle.trigger_ref = None;
        lifecycle
            .fields
            .insert("proposal_ref".to_owned(), proposal_ref.to_hex());
        if let Some(decision_ref) = &decision_ref {
            lifecycle
                .fields
                .insert("decision_ref".to_owned(), decision_ref.clone());
        }

        // A guest proposing work for one of the owner's agents: the agent
        // decides whether to take it, and escalates to the owner when that is
        // relevant (ARCH-0028). Its "take" still needs the authority rule
        // that this agent may accept work addressed to it; until that rule
        // answers, a take stays in the owner's tray, which is the escalation.
        let mut outcome = TaskOutcome::Proposed {
            decision_ref: decision_ref.clone(),
            reason_codes: Vec::new(),
        };
        if let (Some(decisions), TaskAssignee::AgentDef { agent_def_ref }) =
            (decisions, post.assignee)
            && self.verify_owner().is_err()
        {
            let state = serde_json::json!({
                "proposal_ref": proposal_ref.to_hex(),
                "objective": post.brief.objective,
                "need": post.brief.intent.need,
            });
            let answer = ask(
                Some(decisions),
                TaskQuestion::Take,
                agent_def_ref,
                &[proposal_ref],
                &state,
                post.brief.escalation.reversibility,
            );
            lifecycle
                .fields
                .insert("take".to_owned(), answer.as_str().to_owned());
            if answer == PortAnswer::No {
                self.vault().with_write_txn_grouped(|wtxn| {
                    self.vault().store.close_pending_gate_consent_in_txn(
                        wtxn,
                        &proposal_ref,
                        now,
                        "rejected",
                        vec![TAKE_DECLINED_REASON.to_owned()],
                        None,
                    )
                })?;
                outcome = TaskOutcome::Rejected {
                    decision_ref: decision_ref.clone(),
                };
            }
        }

        Ok(TaskCallReceipt {
            handle: TaskHandle::Proposed { proposal_ref },
            related: Vec::new(),
            outcome,
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        })
    }

    /// This actor's earlier proposal of `predicate` under `key`, by the
    /// writer identity the envelope stamped, at any approval.
    fn held_proposal(&self, predicate: &str, key: &str) -> MemoryResult<Option<HeldProposal>> {
        let rtxn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let actor = self.actor();
        Ok(self
            .vault()
            .find_claim_for_subject_in_txn(&rtxn, &actor, |id, body| {
                if body.predicate != predicate
                    || crate::claim::session_claim_producer(body) != Some(actor)
                {
                    return None;
                }
                let digest = if predicate == TASK_CREATE_PROPOSAL_PREDICATE {
                    let stamp: PostStamp =
                        from_value(map_entry(&body.value, TASK_POST_STAMP_KEY)?)?;
                    (stamp.intent_key == key).then_some(stamp.request_digest)?
                } else {
                    let revision: BriefRevision = from_value(&body.value)?;
                    (revision.report_key == key).then(|| brief_digest(&revision.brief))?
                };
                Some(HeldProposal {
                    proposal_ref: *id,
                    digest,
                    approval: body.approval,
                })
            })?)
    }

    /// Report `Brief`: parks a `tasks.brief` proposal. The revision lands as
    /// `rev + 1` only through settlement, and a try already leased keeps the
    /// stamp it was leased under.
    pub(super) fn report_brief(
        &self,
        via: &TaskVia,
        task_ref: EntityId,
        key: &str,
        next: QueueTaskBrief,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        if self.credential_withholds(task_ref)? {
            return Err(not_found());
        }
        next.admit_references(self, "tasks.update")?;
        let base_rev = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            let body = task_body_in_txn(self.vault(), &txn, task_ref)?;
            let standing = self
                .vault()
                .task_standing_in(&txn, task_ref)?
                .ok_or_else(not_found)?;
            if standing.owner != self.actor() {
                return Err(forbidden(
                    "only the task's owner revises its brief",
                    "Ask the task's owner to revise the brief.",
                ));
            }
            if body.terminal().is_some() {
                return Err(invalid_state(
                    "a settled task's brief cannot change",
                    "Post a new task for new work.",
                ));
            }
            next.validate_in(self.vault(), &txn)?;
            body.brief.as_ref().map_or(0, |brief| brief.rev)
        };
        let digest = brief_digest(&next);
        let mut lifecycle =
            self.lifecycle_record(via, "report", "proposed", Some(task_ref), None, now);
        lifecycle
            .fields
            .insert("report_key".to_owned(), key.to_owned());
        lifecycle
            .fields
            .insert("body".to_owned(), "brief".to_owned());
        lifecycle.fields.insert(
            "brief_digest".to_owned(),
            crate::entity_id::bytes_to_hex_lower(&digest),
        );
        if let Some(held) = self.held_proposal(TASK_BRIEF_PROPOSAL_PREDICATE, key)? {
            if held.digest != digest {
                return Err(changed_arguments());
            }
            lifecycle.outcome = "replayed".to_owned();
            return Ok(TaskCallReceipt {
                handle: TaskHandle::Task { task_ref },
                related: vec![TaskHandle::Proposed {
                    proposal_ref: held.proposal_ref,
                }],
                outcome: TaskOutcome::Proposed {
                    decision_ref: None,
                    reason_codes: Vec::new(),
                },
                receipt_ref: None,
                lifecycle: Some(lifecycle),
                idempotent_replay: true,
            });
        }
        let revision = BriefRevision {
            task_ref,
            base_rev,
            report_key: key.to_owned(),
            actor_class: self.actor_class() as u8,
            brief: next,
        };
        let (proposal_ref, decision_ref) = self.persist_task_proposal(
            TASK_BRIEF_PROPOSAL_PREDICATE,
            typed_value(&revision)?,
            self.actor(),
            now,
            crate::memory::facade_provenance("tasks.update"),
        )?;
        lifecycle
            .fields
            .insert("proposal_ref".to_owned(), proposal_ref.to_hex());
        Ok(TaskCallReceipt {
            handle: TaskHandle::Task { task_ref },
            related: vec![TaskHandle::Proposed { proposal_ref }],
            outcome: TaskOutcome::Proposed {
                decision_ref,
                reason_codes: Vec::new(),
            },
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        })
    }

    /// Lands one approved post inside the approving transaction: the TASK at
    /// the settlement id, its route under the creator its proposal witnessed
    /// (OF-532), and its Assigned fact.
    fn land_settled_post_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        post: &TaskPost,
        provenance: &Value,
        origin: Option<&TaskCreateOrigin>,
        now: u64,
    ) -> MemoryResult<TaskRouteOutcome> {
        let type_ref = brief_type_ref_in(self.vault(), &*wtxn, &post.brief)?;
        let spec = create_spec_of(post, self.actor(), type_ref, now);
        let validated = validate_task_create_in(self.vault(), &*wtxn, &spec, now)?;
        post.brief.validate_in(self.vault(), &*wtxn)?;
        self.mint_task_with_brief_at_in_txn(
            wtxn,
            (task_ref, self.actor()),
            &validated,
            post.label.clone(),
            provenance,
            Some(StoredBrief::first(post.brief.clone())),
            now,
        )?;
        let route =
            self.route_created_task_with_origin_in_txn(wtxn, task_ref, &validated, origin, now)?;
        put_assignment_fact_in_txn(
            self.vault(),
            wtxn,
            task_ref,
            self.actor(),
            post.assignee,
            now,
        )?;
        Ok(route)
    }
}

/// The settlement continuation of the two approval doors (OF-220).
///
/// Called in the transaction that set a claim's approval, after it did. A
/// claim that is not an approved `tasks.create` post or `tasks.brief`
/// revision is left alone. An approved post lands its TASK under the id the
/// claim derives, so a second settlement finds it and changes nothing; an
/// approved revision lands as the TASK's next brief revision. Approval is
/// the door's, never the body's: the body's own approval decides nothing,
/// and the opener never settles its own proposal (DEC-0006).
///
/// A refusal fails the approving transaction, so the proposal stays pending
/// and the approver is told why.
pub(crate) fn settle_task_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: EntityId,
    approver: Option<WriteActor>,
    now: u64,
) -> Result<()> {
    let Some(claim) = vault.get_claim_in_txn(wtxn, &claim_id)? else {
        return Ok(());
    };
    if claim.approval != ClaimApprovalStatus::Approved {
        return Ok(());
    }
    if claim.predicate == TASK_CREATE_PROPOSAL_PREDICATE {
        settle_post(vault, wtxn, claim_id, &claim, approver, now)
    } else if claim.predicate == TASK_BRIEF_PROPOSAL_PREDICATE {
        settle_brief(vault, wtxn, &claim, approver, now)
    } else {
        Ok(())
    }
}

/// The proposer of a settled claim, refused when it is the approver.
pub(super) fn proposer_of(claim: &ClaimBody, approver: Option<WriteActor>) -> Result<EntityId> {
    let proposer = crate::claim::session_claim_producer(claim)
        .ok_or(Error::InvariantViolation("task proposal names no producer"))?;
    if approver.is_some_and(|approver| approver.entity_ref() == proposer) {
        return Err(Error::InvariantViolation(
            "a proposal's opener never settles its own proposal",
        ));
    }
    Ok(proposer)
}

/// The actor class a claim's write envelope stamped into its evidence:
/// immutable, unlike its subject or any approver.
pub(super) fn envelope_actor_class(claim: &ClaimBody) -> Option<EdgeActorClass> {
    let Value::Map(entries) = claim.evidence.as_ref()? else {
        return None;
    };
    let mut classes = entries.iter().filter(|(key, _)| {
        key.as_str() == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY)
    });
    let (_, class) = classes.next()?;
    if classes.next().is_some() {
        return None;
    }
    EdgeActorClass::try_from_u8(u8::try_from(class.as_u64()?).ok()?)
}

fn class_of(byte: u8) -> Result<EdgeActorClass> {
    EdgeActorClass::try_from_u8(byte).ok_or(Error::Record(
        crate::error::RecordError::InvalidTaskBody("tasks.proposal.actor_class"),
    ))
}

fn settle_post(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: EntityId,
    claim: &ClaimBody,
    approver: Option<WriteActor>,
    now: u64,
) -> Result<()> {
    let Value::Map(entries) = &claim.value else {
        return Ok(());
    };
    // A brief-less create proposal carries no post stamp: it lands from
    // its stored create fields.
    let Some(stamp_value) = task_body_optional(entries, TASK_POST_STAMP_KEY)? else {
        return super::proposal_create::settle_create_in_txn(
            vault, wtxn, claim_id, claim, approver, now,
        );
    };
    let stamp: PostStamp = from_value(stamp_value).ok_or(Error::Record(
        crate::error::RecordError::InvalidTaskBody("tasks.proposal.post"),
    ))?;
    let proposer = proposer_of(claim, approver)?;
    let class = class_of(stamp.actor_class)?;
    let task_ref = EntityId::derive(TASK_SETTLE_ID_DOMAIN, &[claim_id.as_bytes()])?;
    if vault.get_raw_in(wtxn, &task_ref)?.is_some() {
        return Ok(());
    }
    // The approved value is what lands: an approver's amendment to the
    // assignee, spec, label or TTL rides through the same keys it was parked
    // under, and the brief through the stamp.
    let assignee = match task_body_optional(entries, "assignee")? {
        Some(value) => decode_task_assignee(value)?,
        None => TaskAssignee::Dreamer,
    };
    let label = task_body_optional(entries, "label")?
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or(Error::Record(
                crate::error::RecordError::InvalidTaskBody("tasks.proposal.label"),
            ))
        })
        .transpose()?;
    let ttl = task_body_optional(entries, "ttl")?
        .map(|value| {
            value
                .as_map()
                .and_then(|ttl| task_body_field(ttl, "deadline_at").ok())
                .and_then(Value::as_u64)
                .map(TaskTtl::at)
                .ok_or(Error::Record(crate::error::RecordError::InvalidTaskBody(
                    "tasks.proposal.ttl",
                )))
        })
        .transpose()?;
    let spec = task_body_field(entries, "spec")?.clone();
    let post = TaskPost {
        intent_key: stamp.intent_key.clone(),
        brief: stamp.brief,
        assignee,
        spec: (spec != Value::Nil).then_some(spec),
        ttl,
        label,
    };
    let memory = vault
        .memory(proposer, class)
        .with_birth_position(BirthPosition {
            world: stamp.birth_world,
            facet: stamp.birth_facet,
        });
    // The creator the proposal witnessed, never its approver: approval may
    // outlive the worker's lease, so the route rechecks the stored creator.
    let origin = proposal_origin_in(vault, wtxn, claim_id).map_err(settle_refusal)?;
    memory
        .land_settled_post_in_txn(
            wtxn,
            task_ref,
            &post,
            &post_provenance(&stamp.intent_key, &stamp.request_digest, Some(claim_id)),
            origin.as_ref(),
            now,
        )
        .map_err(settle_refusal)?;
    Ok(())
}

fn settle_brief(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &ClaimBody,
    approver: Option<WriteActor>,
    now: u64,
) -> Result<()> {
    let revision: BriefRevision = from_value(&claim.value).ok_or(Error::Record(
        crate::error::RecordError::InvalidTaskBody("tasks.proposal.brief"),
    ))?;
    let proposer = proposer_of(claim, approver)?;
    let class = class_of(revision.actor_class)?;
    let mut body =
        task_verb_body_in(vault, wtxn, revision.task_ref)?.ok_or(Error::EntityNotFound)?;
    let held = body.brief.as_ref().map_or(0, |brief| brief.rev);
    if held != revision.base_rev {
        // Another revision landed since this one was proposed: approving it
        // would overwrite one the approver never saw.
        return Err(Error::InvalidConfig(format!(
            "task brief revision is stale: proposed against rev {}, the task holds rev {held}",
            revision.base_rev
        )));
    }
    let memory = vault.memory(proposer, class);
    revision
        .brief
        .validate_in(vault, wtxn)
        .map_err(settle_refusal)?;
    body.brief = Some(StoredBrief {
        rev: held.saturating_add(1),
        digest: brief_digest(&revision.brief),
        brief: revision.brief,
    });
    memory
        .rewrite_task_in_txn(wtxn, revision.task_ref, body, now)
        .map_err(settle_refusal)
}
