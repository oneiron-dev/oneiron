//! Parked posts and agent takes.
//! Entry: `Memory::park_post`.
//! Post vocabulary and digests stay in `highway_post`.

use super::*;

impl Memory<'_> {
    /// The gated branch: replay an earlier proposal under this key, or park
    /// a new one; then, for a guest addressing a non-pre-admitted agent, ask
    /// whether the agent takes it. A host's key is qualified by its creator,
    /// so a replay is always the same creator's; a new proposal witnesses
    /// that creator beside it (OF-532), and its lifecycle receipt beside
    /// that, in the proposal's own transaction, once the gate has decided,
    /// naming that decision. A take rewrites the same receipt in the
    /// transaction of its effect, a decline or a landing (FIX 3273); a take
    /// that moves nothing reaches it in one receipt-only write after. A
    /// redo's proposal names the TASK it copies (`redo_of`, FIX 9001), so its
    /// settlement lands the copy as the post would have.
    #[expect(
        clippy::too_many_arguments,
        reason = "the parked post's request, its identity, the surface's decisions, its creator, whether it keeps a receipt and the TASK it copies"
    )]
    pub(super) fn park_post(
        &self,
        post: &TaskPost,
        spec: &TaskCreateSpec,
        key: &str,
        digest: [u8; 32],
        now: u64,
        decisions: Option<&TaskDecisions<'_>>,
        mut lifecycle: super::highway_types::TaskLifecycleRecord,
        creator: Option<&super::highway_types::HostBinding>,
        keep: bool,
        redo_of: Option<EntityId>,
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
            let kept = lifecycle_receipt::replayed(
                self.vault(),
                lifecycle_receipt::receipt_id("post", &[held.proposal_ref.as_bytes()])?,
            )?;
            return Ok(TaskCallReceipt {
                handle: TaskHandle::Proposed {
                    proposal_ref: held.proposal_ref,
                },
                related,
                outcome,
                receipt_ref: kept,
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
            redo_of,
        };
        let Value::Map(mut entries) = task_create_proposal_value(spec, now) else {
            return Err(MemoryError::from(Error::InvariantViolation(
                "a create proposal value is a map",
            )));
        };
        entries.push((Value::from(TASK_POST_STAMP_KEY), typed_value(&stamp)?));
        lifecycle.outcome = "proposed".to_owned();
        lifecycle.trigger_ref = None;
        // The proposal's id is the parked post's identity, so its receipt's is
        // too; both are written in the proposal's transaction, the receipt
        // after the claim lands, with the gate's decision about it.
        let mut kept: Option<(String, super::highway_types::TaskLifecycleRecord)> = None;
        let mut decision_ref = None;
        let proposal_ref = self.land_proposal_claim(
            TASK_CREATE_PROPOSAL_PREDICATE,
            Value::Map(entries),
            self.actor(),
            now,
            post_provenance(key, &digest, None),
            |wtxn, proposal_ref| {
                if let Some(origin) = task_create_origin_in_txn(self, &*wtxn, creator)? {
                    put_proposal_origin_in_txn(self.vault(), wtxn, proposal_ref, &origin)?;
                }
                Ok(())
            },
            |wtxn, proposal_ref| {
                decision_ref = self.proposal_decision_ref_in(&*wtxn, proposal_ref)?;
                if keep {
                    let mut proposed = lifecycle.clone();
                    proposed
                        .fields
                        .insert("proposal_ref".to_owned(), proposal_ref.to_hex());
                    if let Some(decision_ref) = &decision_ref {
                        proposed
                            .fields
                            .insert("decision_ref".to_owned(), decision_ref.clone());
                    }
                    let id = lifecycle_receipt::stamp_record_in(
                        self.vault(),
                        wtxn,
                        &proposed,
                        lifecycle_receipt::receipt_id("post", &[proposal_ref.as_bytes()])?,
                        Some(&post.brief),
                    )?;
                    kept = Some((id, proposed));
                }
                Ok(())
            },
        )?;
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
        // relevant (ARCH-0028). Its yes is a take only when L02's rule admits
        // the agent to work addressed to it; a refused take, like an ask up,
        // stays in the owner's tray, which is the escalation.
        let mut outcome = TaskOutcome::Proposed {
            decision_ref: decision_ref.clone(),
            reason_codes: Vec::new(),
        };
        let mut related = Vec::new();
        if let (Some(decisions), TaskAssignee::AgentDef { agent_def_ref }) =
            (decisions, post.assignee)
            && self.verify_owner().is_err()
        {
            let state = serde_json::json!({
                "proposal_ref": proposal_ref.to_hex(),
                "objective": post.brief.objective,
                "need": post.brief.intent.need,
            });
            let decision = ask(
                Some(decisions),
                TaskQuestion::Take,
                agent_def_ref,
                &[proposal_ref],
                &state,
                post.brief.escalation.reversibility,
            );
            let answer = decision.answer;
            lifecycle
                .fields
                .insert("take".to_owned(), answer.as_str().to_owned());
            // The ladder's receipt rides with the take it decided (FIX 10179).
            if let Some(receipt) = decision.receipt_field() {
                lifecycle
                    .fields
                    .insert("take_decision_receipt".to_owned(), receipt);
            }
            if answer == PortAnswer::No {
                // The decline and the receipt naming it land together.
                self.vault()
                    .try_with_write_txn_grouped(|wtxn| -> MemoryResult<()> {
                        self.vault().store.close_pending_gate_consent_in_txn(
                            wtxn,
                            &proposal_ref,
                            now,
                            "rejected",
                            vec![TAKE_DECLINED_REASON.to_owned()],
                            None,
                        )?;
                        restamp_in(self.vault(), wtxn, kept.as_mut(), &lifecycle, &post.brief)
                    })?;
                outcome = TaskOutcome::Rejected {
                    decision_ref: decision_ref.clone(),
                };
            } else if answer == PortAnswer::Yes {
                // A landed take and the receipt naming its TASK land together.
                let taken =
                    self.take_for_agent(proposal_ref, agent_def_ref, now, |wtxn, task_ref| {
                        let mut created = lifecycle.clone();
                        created.outcome = "created".to_owned();
                        created.trigger_ref = Some(task_ref.to_hex());
                        restamp_in(self.vault(), wtxn, kept.as_mut(), &created, &post.brief)
                    })?;
                match taken {
                    AgentTake::Landed(task_ref) => {
                        lifecycle.outcome = "created".to_owned();
                        lifecycle.trigger_ref = Some(task_ref.to_hex());
                        related.push(TaskHandle::Task { task_ref });
                        outcome = TaskOutcome::Created { route: None };
                        self.vault().store.notify_attempt_observers();
                    }
                    AgentTake::Refused(refusal) => {
                        lifecycle
                            .fields
                            .insert("take_refused".to_owned(), refusal.code);
                        outcome = TaskOutcome::Proposed {
                            decision_ref: decision_ref.clone(),
                            reason_codes: vec![TAKE_REFUSED_REASON.to_owned()],
                        };
                    }
                    AgentTake::Untaken => {}
                }
            }
        }

        // What no effect carried (a take answer that moved nothing, a take
        // refused and rolled back) reaches the kept receipt in one
        // receipt-only write: no effect committed without its receipt.
        let receipt_ref = match kept {
            Some((id, proposed)) if proposed != lifecycle => {
                Some(self.vault().try_with_write_txn_grouped(|wtxn| {
                    lifecycle_receipt::stamp_record_in(
                        self.vault(),
                        wtxn,
                        &lifecycle,
                        id,
                        Some(&post.brief),
                    )
                })?)
            }
            Some((id, _)) => Some(id),
            None => None,
        };
        Ok(TaskCallReceipt {
            handle: TaskHandle::Proposed { proposal_ref },
            related,
            outcome,
            receipt_ref,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        })
    }

    /// An agent's yes to a guest's proposal, run as its take along the
    /// owner's approval path: in one transaction the agent approves the
    /// proposal, settlement lands its TASK, L02's rule proves the agent, the
    /// tray row closes approved, and `stamp` writes the post's receipt of the
    /// landed TASK (FIX 3273). A refusal of any of the take's steps rolls the
    /// whole take back.
    pub(super) fn take_for_agent(
        &self,
        proposal_ref: EntityId,
        agent_def_ref: EntityId,
        now: u64,
        stamp: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    ) -> MemoryResult<AgentTake> {
        // The dispatched agent's own write actor (`agent_dispatch_actor`):
        // its AGENT_DEF row, class Agent.
        let agent = WriteActor::new(agent_def_ref, EdgeActorClass::Agent);
        let vault = self.vault();
        let store = &vault.store;
        let mut refused = false;
        let taken: MemoryResult<Option<EntityId>> = vault.try_with_write_txn_grouped(|wtxn| {
            let Some(pending) = store.pending_gate_consent_in_txn(wtxn, &proposal_ref)? else {
                return Ok(None);
            };
            if crate::gate::pending_row_holds_critical_confirm(&pending) {
                return Ok(None);
            }
            let original = store
                .gate_decision_in_txn(wtxn, pending.decision_id)?
                .ok_or(Error::CorruptedIndex("pending gate consent"))?;
            let Some(raw) = store.port_entity_record(wtxn, &proposal_ref)? else {
                return Ok(None);
            };
            let reviewed = crate::claim::decode_claim_body(&raw.body, true)?;
            // The agent was asked about the proposal as parked, under the
            // policy floor it was parked under.
            let (diff_handle, read_frontier_hash) =
                crate::gate::claim_consent_binding_parts(store, wtxn, &reviewed)?;
            if reviewed.approval != ClaimApprovalStatus::Proposed
                || diff_handle != pending.diff_handle
                || read_frontier_hash != pending.read_frontier_hash
            {
                return Ok(None);
            }
            let task_ref = match take_in_txn(vault, wtxn, proposal_ref, raw, reviewed, agent, now) {
                Ok(task_ref) => task_ref,
                Err(error) => {
                    refused = true;
                    return Err(take_refusal(error));
                }
            };
            // The approval may already have redeemed the row; the delete is
            // idempotent either way, and the decision is recorded here.
            store.delete_pending_gate_consent_in_txn(wtxn, &proposal_ref)?;
            store.append_gate_decision_in_txn(
                wtxn,
                &crate::store::GateDecisionRecord {
                    version: crate::store::GATE_DECISION_LEDGER_VERSION,
                    decision_id: crate::store::GateDecisionId::from_bytes(store.clock.ulid()?),
                    created_at: now,
                    outcome: "approved".to_owned(),
                    reason_codes: vec![TAKE_ACCEPTED_REASON.to_owned()],
                    receipt_reasons: Vec::new(),
                    system_notices: Vec::new(),
                    actor_class: original.actor_class,
                    actor_ref: original.actor_ref,
                    content_kind: original.content_kind,
                    policy_manifest_version: original.policy_manifest_version,
                    claim_id: Some(pending.claim_id),
                    grant_ref: None,
                    diff_handle: pending.diff_handle,
                    read_frontier_hash: pending.read_frontier_hash,
                    context: Default::default(),
                    redacted_at: None,
                },
            )?;
            stamp(wtxn, task_ref)?;
            Ok(Some(task_ref))
        });
        match taken {
            Ok(Some(task_ref)) => Ok(AgentTake::Landed(task_ref)),
            Ok(None) => Ok(AgentTake::Untaken),
            Err(refusal) if refused => Ok(AgentTake::Refused(refusal)),
            Err(error) => Err(error),
        }
    }

    /// This actor's earlier proposal of `predicate` under `key`, by the
    /// writer identity the envelope stamped, at any approval.
    pub(super) fn held_proposal(
        &self,
        predicate: &str,
        key: &str,
    ) -> MemoryResult<Option<HeldProposal>> {
        let rtxn = self.vault().store.env.read_txn().map_err(Error::from)?;
        self.held_proposal_in(&rtxn, predicate, key)
    }

    /// [`Self::held_proposal`] in `rtxn`, a snapshot the caller holds: a
    /// writer finds the earlier proposal without opening a read of its own.
    pub(super) fn held_proposal_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        predicate: &str,
        key: &str,
    ) -> MemoryResult<Option<HeldProposal>> {
        let actor = self.actor();
        Ok(self
            .vault()
            .find_claim_for_subject_in_txn(rtxn, &actor, |id, body| {
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
}
