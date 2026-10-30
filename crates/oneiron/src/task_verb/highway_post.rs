//! The highway's Post arm, its brief revisions, and settlement: the one
//! continuation that turns an approved proposal into intent exactly once
//! (OF-220).
//!
//! A post the gate does not answer Auto parks as the ordinary `tasks.create`
//! Proposed CLAIM, its typed brief inside: content approval and creation
//! approval are one proposal, so `settle(proposal)` runs once (ARCH-0035).
//! Only the existing approval doors approve, and the addressed agent's take
//! of a guest's proposal when L02's rule admits it; after any of them sets
//! approval it calls [`settle_task_proposal_in_txn`] in the same
//! transaction, and the TASK lands under an id derived from the claim, so a
//! second settlement finds it already there.
//!
//! Entry: `Memory::highway_post`.
//! Parking, brief and settlement definitions live in children.

use serde::{Deserialize, Serialize};

use rmpv::Value;

use crate::Vault;
use crate::authority::TaskActorVerb;
use crate::claim::{ClaimApprovalStatus, ClaimBody};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::federation::record_scope::BirthPosition;
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::task_authority::{
    TaskAuthorityFact, TaskAuthorityFactKind, put_task_authority_fact_in_txn,
};
use crate::task_type::TaskTypeRef;
use crate::write_envelope::WriteActor;

use super::brief::{QueueTaskBrief, StoredBrief, brief_digest, hex32};
use super::consts::{
    TASK_BRIEF_PROPOSAL_PREDICATE, TASK_CANCEL_PROPOSAL_PREDICATE, TASK_CREATE_PROPOSAL_PREDICATE,
    TASK_POST_ID_DOMAIN, TASK_POST_STAMP_KEY, TASK_SETTLE_ID_DOMAIN,
};
use super::create_origin::{
    TaskCreateOrigin, proposal_origin_in, put_proposal_origin_in_txn, task_create_origin_in_txn,
};
use super::create_spec::{TaskCreateRateLimit, TaskCreateSpec};
use super::create_validation::{
    admit_task_parent, task_body_in_txn, task_create_proposal_value, task_parent_refusal_in,
    validate_task_create, validate_task_create_in,
};
use super::decision_port::{PortAnswer, TaskDecisions, TaskQuestion, ask};
use super::highway::{
    forbidden, invalid_state, not_found, post_provenance, provenance_digest, qualify, stamp_fields,
};
use super::highway_types;
use super::highway_types::{TaskCall, TaskCallReceipt, TaskHandle, TaskOutcome, TaskPost, TaskVia};
use super::lifecycle_receipt;
use super::proposal_create;
use super::rate_limit::{record_task_create, task_actor_ceiling};
use super::route_receipts::{TaskCreateReceipt, TaskRouteOutcome};
use super::verb_kind::{TaskAssignee, TaskKind, TaskTtl};
use super::wire_decode::{
    decode_entity_ref, decode_task_assignee, task_body_field, task_body_optional, task_verb_body_in,
};
use super::wire_encode::canonical_bytes;

mod brief;
mod key;
mod parking;
mod settlement;
use self::key::{PostKey, observe_key_in};
pub(crate) use self::settlement::settle_task_proposal_in_txn;
pub(super) use self::settlement::{envelope_actor_class, proposer_of};

/// Domain of a post's request digest.
const POST_REQUEST_DOMAIN: &[u8] = b"oneiron.tasks.post.request.v1";
/// Reason code of a proposal the addressed agent declined.
const TAKE_DECLINED_REASON: &str = "gate.tasks.take.declined";
/// Reason code of a proposal the addressed agent took.
const TAKE_ACCEPTED_REASON: &str = "gate.tasks.take.accepted";
/// Reason code of a post whose addressed agent said yes but whose take was
/// refused: the proposal stays in the owner's tray, and the post still
/// answers `Proposed`.
const TAKE_REFUSED_REASON: &str = "tasks.take.refused";

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
    /// The TASK a redo copies (FIX 9001): settlement lands the copy as the
    /// post did, its moved pins reported, never refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redo_of: Option<EntityId>,
}

/// The value of one `tasks.brief` revision proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BriefRevision {
    pub(super) task_ref: EntityId,
    pub(super) base_rev: u32,
    report_key: String,
    actor_class: u8,
    pub(super) brief: QueueTaskBrief,
    /// The brief this revision replaces when that is the TASK's first, read
    /// in the snapshot `base_rev` was (FIX 9005): no `tasks.brief` CLAIM
    /// landed a first brief, so the history reads it here once it moves on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) base_brief: Option<QueueTaskBrief>,
}

/// What a post copied from an earlier TASK carries (FIX 9001): the TASK it
/// copies, and the parent that TASK filed under when that parent can no
/// longer take a Task, which the copy is born without. A copy keeps its
/// brief as written: a pin whose row moved since is reported, never refused.
pub(super) struct PostCopy {
    pub(super) of: EntityId,
    pub(super) dropped_parent: Option<EntityId>,
}

/// The receipt field naming the TASK a redo copied.
const REDO_OF_FIELD: &str = "redo_of";
/// The receipt field naming the parent a redo was born without.
const REDO_PARENT_DROPPED_FIELD: &str = "redo_parent_dropped";
/// The receipt field naming a copied brief's pins whose rows moved.
const STALE_PINS_FIELD: &str = "stale_pins";

/// What the Auto branch of one post found.
enum PostDirect {
    /// The TASK landed: its receipt, its lifecycle kept beside it.
    Created(Box<TaskCallReceipt>),
    /// An earlier landing of the same post: its assignee, and the receipt
    /// the first landing kept.
    Replay(Option<TaskAssignee>, Option<String>),
    Gated,
}

/// What an agent's yes to a guest's proposal came to.
enum AgentTake {
    /// The agent approved the proposal and its TASK landed.
    Landed(EntityId),
    /// The take was refused and rolled back, in the highway's shapes; the
    /// proposal stays in the owner's tray.
    Refused(MemoryError),
    /// Nothing was taken: the proposal left the tray, changed since it was
    /// parked, or waits on the owner's own critical confirm.
    Untaken,
}

/// Rewrites the receipt a parked post kept (`kept`: its id and what it last
/// held) to `lifecycle`, in the transaction of the effect it records (FIX
/// 3273). A post that keeps no receipt writes nothing.
fn restamp_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    kept: Option<&mut (String, super::highway_types::TaskLifecycleRecord)>,
    lifecycle: &super::highway_types::TaskLifecycleRecord,
    brief: &QueueTaskBrief,
) -> MemoryResult<()> {
    if let Some((id, stamped)) = kept {
        lifecycle_receipt::stamp_record_in(vault, wtxn, lifecycle, id.clone(), Some(brief))?;
        *stamped = lifecycle.clone();
    }
    Ok(())
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

/// A copy's receipt fields (FIX 9001): the TASK it copied, the parent it
/// was born without, and its brief's pins whose rows moved since, as hex.
fn stamp_copy_fields(
    fields: &mut std::collections::BTreeMap<String, String>,
    copy: &PostCopy,
    stale_pins: &[EntityId],
) {
    fields.insert(REDO_OF_FIELD.to_owned(), copy.of.to_hex());
    if let Some(parent) = copy.dropped_parent {
        fields.insert(REDO_PARENT_DROPPED_FIELD.to_owned(), parent.to_hex());
    }
    if !stale_pins.is_empty() {
        let pins = stale_pins.iter().map(EntityId::to_hex).collect::<Vec<_>>();
        fields.insert(STALE_PINS_FIELD.to_owned(), pins.join(","));
    }
}

/// The digest one post's request binds: the actor, the key, the brief,
/// every routed field and `parent_ref`, the parent it files under
/// (DOOR-113). A replay under the same key with any other request is
/// refused, as an ask's is.
fn request_digest(
    actor: EntityId,
    key: &str,
    post: &TaskPost,
    parent_ref: Option<EntityId>,
) -> MemoryResult<[u8; 32]> {
    let bytes = rmp_serde::to_vec_named(&(
        actor,
        key,
        brief_digest(&post.brief).to_vec(),
        post.assignee,
        &post.spec,
        post.ttl,
        &post.label,
        parent_ref,
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
pub(super) fn brief_type_ref_in(
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
/// the brief's resolved stamp and its project's tree to place against, and
/// the parent it files under.
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
    if let Some(parent_ref) = post.parent_ref {
        spec = spec.with_parent_ref(parent_ref);
    }
    spec.brief = Some(post.brief.clone());
    spec
}

/// An agent's take of one proposal, inside the take's transaction: the
/// agent approves it as the owner's inbox door does, settlement lands its
/// TASK, and L02's rule proves the agent may accept work addressed to it.
/// That rule reads the landed TASK's facts, so it runs last. Answers the
/// landed TASK.
fn take_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    proposal_ref: EntityId,
    raw: crate::ports::EntityRecord,
    mut approved: ClaimBody,
    agent: WriteActor,
    now: u64,
) -> Result<EntityId> {
    approved.approval = ClaimApprovalStatus::Approved;
    crate::batch::ClaimMaterialization::apply_approval(
        vault,
        wtxn,
        crate::batch::BatchOp::Put {
            id: proposal_ref,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred: raw.occurred,
            learned_at: raw.learned_at,
            data: crate::claim::encode_claim_body(&approved)?,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        },
        true,
        Some(agent),
    )?;
    vault.complete_deferred_claim_in_txn(wtxn, &proposal_ref, false, now, Some(agent))?;
    settle_task_proposal_in_txn(vault, wtxn, proposal_ref, Some(agent), now)?;
    let task_ref = EntityId::derive(TASK_SETTLE_ID_DOMAIN, &[proposal_ref.as_bytes()])?;
    vault.prove_task_actor_in_txn(wtxn, task_ref, &agent, TaskActorVerb::Accept)?;
    Ok(task_ref)
}

/// A refused take in the highway's shapes: a TASK the agent is no party to
/// is not found; a party L02's rule does not admit is told why.
fn take_refusal(error: Error) -> MemoryError {
    match error {
        Error::EntityNotFound => not_found(),
        Error::Claim(ClaimError::ActorLacksClaimAuthority { reason }) => {
            forbidden(reason, "The owner answers this proposal from the tray.")
        }
        other => MemoryError::from(other),
    }
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
                parent_ref: spec.parent_ref,
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
        self.post_as(via, post, decisions, None)
    }

    /// [`Self::highway_post`] of `post`, the copy `copy` describes when it
    /// names one (FIX 9001). The key's hash is the post's identity (FIX
    /// 9002); its receipt shows the caller's key text.
    pub(super) fn post_as(
        &self,
        via: &TaskVia,
        post: TaskPost,
        decisions: Option<&TaskDecisions<'_>>,
        copy: Option<&PostCopy>,
    ) -> MemoryResult<TaskCallReceipt> {
        let key = PostKey::of(via, &post.intent_key)?;
        let now = self.vault().now_recorded_at();
        post.brief.admit_references(self, "tasks.create")?;
        admit_task_parent(self, post.parent_ref)?;
        let task_ref = EntityId::derive(
            TASK_POST_ID_DOMAIN,
            &[self.actor().as_bytes(), key.stored.as_bytes()],
        )?;
        let (type_ref, stale_pins) = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            observe_key_in(self.vault(), &txn, &post.intent_key, task_ref);
            let stale_pins = if copy.is_some() {
                post.brief
                    .validate_copy_in(self.vault(), &txn, Some(post.assignee))?
            } else {
                post.brief
                    .validate_in(self.vault(), &txn, Some(post.assignee))?;
                Vec::new()
            };
            (
                brief_type_ref_in(self.vault(), &txn, &post.brief)?,
                stale_pins,
            )
        };
        // A redo binds its source's parent, the one a copy drops when it
        // turned unfit too (FIX 11106): a parent that turns unfit or fit
        // again between two calls under one key changes no request.
        let parent_ref = post
            .parent_ref
            .or(copy.and_then(|copy| copy.dropped_parent));
        let digest = request_digest(self.actor(), &key.text, &post, parent_ref)?;
        let spec = create_spec_of(&post, self.actor(), type_ref, now);
        let validated = validate_task_create(self.vault(), &spec, now)?;
        let stored = StoredBrief::first(post.brief.clone());
        let provenance = post_provenance(&key.stored, &digest, None);
        let rate_now = self.vault().store.clock.now_recorded_at();
        let keep = self.keeps_lifecycle();

        let mut lifecycle =
            self.lifecycle_record(via, "post", "created", Some(task_ref), None, now);
        stamp_fields(&mut lifecycle.fields, Some(&stored));
        lifecycle
            .fields
            .insert("intent_key".to_owned(), key.text.clone());
        lifecycle
            .fields
            .insert("intent_key_hash".to_owned(), key.stored.clone());
        if let Some(copy) = copy {
            stamp_copy_fields(&mut lifecycle.fields, copy, &stale_pins);
        }
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
        // The landed TASK's id is the post's identity, so its receipt's is too.
        let receipt_id = lifecycle_receipt::receipt_id("post", &[task_ref.as_bytes()])?;

        let direct = self.with_verified_actor_write_txn(|wtxn| {
            if let Some(body) = task_verb_body_in(self.vault(), &*wtxn, task_ref)? {
                return if provenance_digest(&body.provenance) == Some(digest) {
                    let kept =
                        lifecycle_receipt::replayed_in(self.vault(), &*wtxn, receipt_id.clone())?;
                    Ok(PostDirect::Replay(body.assignee, kept))
                } else {
                    Err(changed_arguments())
                };
            }
            if self.vault().get_raw_in(&*wtxn, &task_ref)?.is_some() {
                return Err(MemoryError::bad_request("task post id is already occupied"));
            }
            // An earlier proposal of this post, landed or not, answers it
            // whatever the actor's ceiling is now (FIX 10180): the gated
            // branch replays that proposal's handle and its landed TASK,
            // and refuses changed arguments, instead of minting another.
            if self
                .held_proposal_in(&*wtxn, TASK_CREATE_PROPOSAL_PREDICATE, &key.stored)?
                .is_some()
            {
                return Ok(PostDirect::Gated);
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
            // CUA E4: a binding is judged again in the writer that mints its
            // TASK; an unbound brief is not read again here.
            if let Some(binding) = &post.brief.context.workflow {
                binding.validate_in(self.vault(), &*wtxn, Some(post.assignee))?;
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
            self.attach_task_parent_in_txn(wtxn, task_ref, post.parent_ref)?;
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
            // The lifecycle lands with the TASK, in this transaction.
            let mut created = lifecycle.clone();
            created
                .fields
                .insert("route".to_owned(), format!("{:?}", route.lane()));
            let mut receipt = TaskCallReceipt {
                handle: TaskHandle::Task { task_ref },
                related: Vec::new(),
                outcome: TaskOutcome::Created { route: Some(route) },
                receipt_ref: None,
                lifecycle: Some(created),
                idempotent_replay: false,
            };
            if keep {
                lifecycle_receipt::stamp_in(
                    self.vault(),
                    wtxn,
                    &mut receipt,
                    receipt_id.clone(),
                    Some(&post.brief),
                )?;
            }
            Ok(PostDirect::Created(Box::new(receipt)))
        })?;

        match direct {
            PostDirect::Created(receipt) => {
                self.vault().store.notify_attempt_observers();
                Ok(*receipt)
            }
            PostDirect::Replay(assignee, kept) => {
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
                    receipt_ref: kept,
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
                    &post,
                    &spec,
                    &key.stored,
                    digest,
                    now,
                    decisions,
                    lifecycle,
                    creator,
                    keep,
                    copy.map(|copy| copy.of),
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
}
