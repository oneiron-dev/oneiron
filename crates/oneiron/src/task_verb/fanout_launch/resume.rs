//! Fan-out launch reads, rulings and resume.
//! Entry: `Memory::resume_task_fanout`.
//! Stored launch vocabulary stays in `fanout_launch`.

use super::*;

impl Memory<'_> {
    /// One held or launched fan-out, for its own actor, the vault's owner or
    /// a live holder of its bound lead or board role. Any other reader, and
    /// a ref that names nothing, read `None`.
    pub fn task_fanout_launch(
        &self,
        launch_ref: EntityId,
    ) -> MemoryResult<Option<FanoutLaunchReceipt>> {
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        Ok(self
            .readable_task_fanout_in(&txn, launch_ref)?
            .map(|launch| self.listed_receipt(&launch)))
    }

    /// `launch`'s receipt, listing the TASKs it launched: the rows behind it
    /// that no caller names (DEC-0005).
    pub(super) fn listed_receipt(&self, launch: &StoredLaunch) -> FanoutLaunchReceipt {
        self.produced_from(launch.task_refs.iter().copied());
        launch.receipt()
    }

    /// The launch door's same admission inside a batch observation's snapshot.
    pub(in crate::task_verb) fn readable_task_fanout_in(
        &self,
        txn: &heed::RoTxn<'_>,
        launch_ref: EntityId,
    ) -> MemoryResult<Option<StoredLaunch>> {
        let vault = self.vault();
        verify_actor_binding_in_txn(vault, txn, self.actor(), self.actor_class())?;
        let Some(launch) = load_launch(vault, txn, launch_ref)? else {
            return Ok(None);
        };
        let own = launch.actor.is(self.actor()) && launch.actor_class == self.actor_class() as u8;
        if !own
            && !actor_is_vault_owner_in_txn(vault, &txn, self.actor(), self.actor_class())?
            && !launch_role_is_held_in(
                vault,
                &txn,
                launch.approval_project,
                self.actor(),
                self.actor_class(),
            )?
        {
            return Ok(None);
        }
        Ok(Some(launch))
    }

    /// Rules on a held launch by the digest the authenticated owner saw; no
    /// replacement payload is accepted. Approve-once launches the frozen
    /// payload; approve-and-remember also persists the receipted standing row
    /// AUTO reads next time, under a cap no smaller than this launch; deny
    /// records the ruling and keeps the hold, durable and visible. Before it
    /// launches, the original actor's binding and task-create authority and
    /// its creator's run and spend lease are checked again. The ruling, any
    /// remembered row and the launched TASKs commit together, and each
    /// planning attempt parked under the hold is re-leased and completed in
    /// the same transaction. A replay returns the same launch and TASKs and
    /// never launches again.
    pub fn resume_task_fanout(
        &self,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
        choice: ConsultFanOutChoice,
        owner: &AuthenticatedOwner,
        remembered_cap: Option<u64>,
    ) -> MemoryResult<FanoutLaunchReceipt> {
        let owner_actor = self.reauthenticate_fanout_owner(owner)?;
        if remembered_cap.is_some() && choice != ConsultFanOutChoice::ApproveAndRemember {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "a remembered cap requires a standing approval",
                "Choose approve-and-remember for this cap.",
            ));
        }
        let now = self.vault().now_recorded_at();
        let receipt = self
            .vault()
            .memory(owner_actor, EdgeActorClass::Human)
            .with_verified_actor_write_txn(|txn| {
                // In the writer's own snapshot (FIX 11354).
                self.reauthenticate_fanout_owner_in_txn(txn, owner)?;
                self.resume_task_fanout_in(
                    txn,
                    launch_ref,
                    expected_digest,
                    choice,
                    remembered_cap,
                    Some(owner),
                    &WriteActor::new(owner_actor, EdgeActorClass::Human),
                    now,
                )
            })?;
        self.vault().store.notify_attempt_observers();
        Ok(receipt)
    }

    /// A live holder's ruling on a held launch whose bound project it leads
    /// or sits on the board of, by the digest it saw: approve once or deny,
    /// never remember. The holder is verified as the writer and its role
    /// read again in the ruling's transaction; the launch commits as
    /// [`Self::resume_task_fanout`]'s does, with the holder as the approver.
    pub fn resume_task_fanout_as(
        &self,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
        choice: ConsultFanOutChoice,
        holder: &WriteActor,
        remembered_cap: Option<u64>,
    ) -> MemoryResult<FanoutLaunchReceipt> {
        require_holder_launch_choice(choice, remembered_cap)?;
        let now = self.vault().now_recorded_at();
        let receipt = self.vault().try_with_write_txn_grouped(|txn| {
            self.resume_task_fanout_in(
                txn,
                launch_ref,
                expected_digest,
                choice,
                None,
                None,
                holder,
                now,
            )
        })?;
        self.vault().store.notify_attempt_observers();
        Ok(receipt)
    }

    /// One ruling on a held launch in the approval's transaction, by the
    /// owner (`owner` names its proof, revalidated by the caller) or by a
    /// live holder of the launch's bound role, authorized here before any
    /// replay or write. Only the owner's ruling is recorded as an explicit
    /// escalation ruling: that record carries the owner's authentication.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn resume_task_fanout_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
        choice: ConsultFanOutChoice,
        remembered_cap: Option<u64>,
        owner: Option<&AuthenticatedOwner>,
        approver: &WriteActor,
        now: u64,
    ) -> MemoryResult<FanoutLaunchReceipt> {
        let (mut launch, plan) = self.frozen_launch_in(txn, launch_ref, expected_digest)?;
        let principal_ref = match owner {
            Some(owner) => owner.principal_ref_in_txn(self.vault(), &*txn)?.to_owned(),
            None => {
                self.vault().verify_write_actor_in_txn(&*txn, approver)?;
                if !launch_role_is_held_in(
                    self.vault(),
                    &*txn,
                    launch.approval_project,
                    approver.entity_ref(),
                    approver.actor_class(),
                )? {
                    return Err(consult_refusal(
                        MEMORY_CODE_FORBIDDEN,
                        "actor does not hold this launch's approval role",
                        "Ask a live project lead, its board, or the vault owner.",
                    ));
                }
                approver.entity_ref().to_hex()
            }
        };
        if launch.dispatched_at.is_some() {
            if choice == ConsultFanOutChoice::Deny {
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "a launched fan-out cannot be denied retroactively",
                    "Use the TASK cancellation door.",
                ));
            }
            return Ok(self.listed_receipt(&launch));
        }
        let row = launch.pause.clone().ok_or_else(|| {
            consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "fan-out launch has no surfaced approval",
                "Apply the plan again.",
            )
        })?;
        let count = u64::from(launch.estimate.total_count);
        if remembered_cap.is_some_and(|cap| cap < count) {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "a standing cap cannot exclude the approved launch",
                "Set a cap at or above the approved estimate.",
            ));
        }
        let core_choice = match choice {
            ConsultFanOutChoice::ApproveOnce => FanoutApprovalChoice::ApproveOnce,
            ConsultFanOutChoice::ApproveAndRemember => {
                FanoutApprovalChoice::ApproveAndRememberBriefVerb
            }
            ConsultFanOutChoice::Deny => FanoutApprovalChoice::KeepPaused,
        };
        let action = core_choice.action_id();
        let resumed = approve_and_resume_fanout(
            &plan,
            &row,
            core_choice,
            action,
            &principal_ref,
            &mut LaunchSurface {
                vault: self.vault(),
                txn,
                launch: &mut launch,
                clearance: None,
            },
            now.saturating_mul(1000),
        )
        .map_err(approval_error)?;
        let approved = resumed.is_some();
        if let Some(owner) = owner {
            record_explicit_ruling_in_txn(
                self.vault(),
                txn,
                owner,
                EscalationReceipt {
                    task_ref: launch_ref,
                    scope: launch.scope.clone(),
                    trigger: EscalationTrigger::Budget,
                    question: launch.plan.brief_ref.clone(),
                    ruling: if approved {
                        EscalationRuling::Approve
                    } else {
                        EscalationRuling::Deny
                    },
                    rationale: launch.choice_receipt_ref.clone().unwrap_or_default(),
                    // The launch's TASK count is the magnitude; the ED-06
                    // ceiling comparison enforces <=, never an unbounded grant.
                    budget_band: Some(remembered_cap.unwrap_or(count)),
                },
                choice == ConsultFanOutChoice::ApproveAndRemember,
                now,
            )?;
        }
        launch.denied = !approved;
        if let Some(resume) = resumed {
            if resume.plan_digest != expected_digest {
                return Err(stale_digest());
            }
            launch.choice_receipt_ref = Some(resume.choice_receipt_ref);
            // A remembered width approval is not an outbound grant:
            // the primitive's verb intent has no count cap and MUST
            // NOT widen the remembered cap.
            drop(resume.grant_mint_intent);
            self.launch_approved_in(txn, &mut launch, approver.entity_ref(), now)?;
        }
        save_launch(self.vault(), txn, &launch)?;
        Ok(self.listed_receipt(&launch))
    }

    /// The owner's answer to the width check of a fan-out that went out
    /// above the threshold, an ask or a wave, by the digest they saw. It
    /// held nothing, so the answers are ack and ack-and-remember, never a
    /// denial, and no TASK is touched. The answer receipt and any remembered
    /// standing row, under a cap no smaller than the launch, commit
    /// together; a repeated answer returns the recorded one.
    pub fn ack_task_fanout_check(
        &self,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
        choice: FanoutCheckChoice,
        owner: &AuthenticatedOwner,
        remembered_cap: Option<u64>,
    ) -> MemoryResult<FanoutLaunchReceipt> {
        let owner_actor = self.reauthenticate_fanout_owner(owner)?;
        if remembered_cap.is_some() && choice != FanoutCheckChoice::AckAndRemember {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "a remembered cap requires ack-and-remember",
                "Choose ack-and-remember for this cap.",
            ));
        }
        let now = self.vault().now_recorded_at();
        self.vault()
            .memory(owner_actor, EdgeActorClass::Human)
            .with_verified_actor_write_txn(|txn| {
                // In the writer's own snapshot (FIX 11354).
                self.reauthenticate_fanout_owner_in_txn(txn, owner)?;
                let (mut launch, plan) = self.frozen_launch_in(txn, launch_ref, expected_digest)?;
                let Some(row) = launch
                    .check_row
                    .clone()
                    .filter(|_| launch.dispatched_at.is_some())
                else {
                    return Err(consult_refusal(
                        MEMORY_CODE_INVALID_STATE,
                        "fan-out launch has no width check to acknowledge",
                        "Rule on a held launch through its resume door.",
                    ));
                };
                // One ruling per check: a repeated answer returns the recorded one.
                if launch.choice_receipt_ref.is_some() {
                    return Ok(self.listed_receipt(&launch));
                }
                let count = u64::from(launch.estimate.total_count);
                if remembered_cap.is_some_and(|cap| cap < count) {
                    return Err(consult_refusal(
                        MEMORY_CODE_INVALID_STATE,
                        "a standing cap cannot exclude the acknowledged launch",
                        "Set a cap at or above the acknowledged estimate.",
                    ));
                }
                let core_choice = match choice {
                    FanoutCheckChoice::Ack => FanoutApprovalChoice::Ack,
                    FanoutCheckChoice::AckAndRemember => FanoutApprovalChoice::AckAndRemember,
                };
                let action = core_choice.action_id();
                let principal_ref = owner.principal_ref_in_txn(self.vault(), &*txn)?;
                answer_fanout_width_check(
                    &plan,
                    &row,
                    core_choice,
                    action,
                    principal_ref,
                    &mut LaunchSurface {
                        vault: self.vault(),
                        txn,
                        launch: &mut launch,
                        clearance: None,
                    },
                    now.saturating_mul(1000),
                )
                .map_err(approval_error)?;
                record_explicit_ruling_in_txn(
                    self.vault(),
                    txn,
                    owner,
                    EscalationReceipt {
                        task_ref: launch_ref,
                        scope: launch.scope.clone(),
                        trigger: EscalationTrigger::Budget,
                        question: launch.plan.brief_ref.clone(),
                        ruling: EscalationRuling::Approve,
                        rationale: launch.choice_receipt_ref.clone().unwrap_or_default(),
                        // The band AUTO's standing read compares the next
                        // width against.
                        budget_band: Some(remembered_cap.unwrap_or(count)),
                    },
                    choice == FanoutCheckChoice::AckAndRemember,
                    now,
                )?;
                save_launch(self.vault(), txn, &launch)?;
                Ok(self.listed_receipt(&launch))
            })
    }

    /// The launch under `launch_ref`, with its plan recomputed from the
    /// frozen payload and bound to the digest the owner saw: never a
    /// comparison of two caller-supplied hashes. The original actor must
    /// still bind; its launch runs as it.
    pub(super) fn frozen_launch_in(
        &self,
        txn: &heed::RoTxn<'_>,
        launch_ref: EntityId,
        expected_digest: [u8; 32],
    ) -> MemoryResult<(StoredLaunch, FanoutPlan)> {
        let launch = load_launch(self.vault(), txn, launch_ref)?
            .ok_or_else(|| MemoryError::not_found("fan-out launch not found"))?;
        let actor = launch.launcher()?;
        verify_actor_binding_in_txn(self.vault(), txn, actor, launch.class()?)?;
        if launch.estimate.plan_digest != expected_digest {
            return Err(stale_digest());
        }
        let plan = launch.payload.plan(launch_ref, actor, launch.plan.mode)?;
        if plan != launch.plan || fanout_plan_digest(&plan)? != expected_digest {
            return Err(stale_digest());
        }
        Ok((launch, plan))
    }

    /// Launches an approved hold's frozen payload in the approval's
    /// transaction and settles the planning attempts parked under it.
    pub(super) fn launch_approved_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        launch: &mut StoredLaunch,
        owner_actor: EntityId,
        now: u64,
    ) -> MemoryResult<()> {
        let (actor, class) = (launch.launcher()?, launch.class()?);
        let task_refs: Vec<EntityId> = match &launch.payload {
            LaunchPayload::Wave {
                cut,
                creator_origin,
            } => super::wave_port::land_approved_cut_in(
                self.vault(),
                txn,
                super::wave_port::ApprovedCut {
                    actor,
                    actor_class: class,
                    origin: creator_origin.clone(),
                    cut: cut.clone(),
                    statement: &launch.statement,
                    now,
                },
            )?
            .iter()
            .map(|write| write.task_ref)
            .collect(),
            // The ask goes out as its asker, then its door's effect runs,
            // revalidated in this same transaction.
            LaunchPayload::Ask {
                group_ref,
                requested,
                holders,
                context_class,
                question_digest,
                request_digest,
                effect,
                ..
            } => {
                // FIX 11691: its dispatches keep the requester the ask was
                // admitted under, judged again when each is claimed.
                let asker = self
                    .vault()
                    .memory(actor, class)
                    .with_kept_requester(launch.requester.clone());
                let task_refs = asker.release_held_ask_in(
                    txn,
                    *group_ref,
                    ReleasedAsk {
                        requested,
                        holders,
                        context_class,
                        question_digest: *question_digest,
                        request_digest,
                        statement: &launch.statement,
                    },
                )?;
                if let Some(effect) = effect {
                    asker.apply_ask_effect_in(txn, *group_ref, effect)?;
                }
                task_refs
            }
            LaunchPayload::AdmittedAsk { .. } => {
                return Err(Error::InvariantViolation("an admitted ask is never held").into());
            }
        };
        launch.dispatched_at = Some(self.vault().now_recorded_at());
        launch.task_refs = task_refs;
        settle_held_attempts_in(self.vault(), txn, launch, owner_actor, now)
    }
}

impl Memory<'_> {
    /// Every fan-out launch that waits on the owner, as the board shows it
    /// (OF-393): a held launch, denied or not, and a launched one whose width
    /// check is not yet answered. The vault's owner reads all of them; any
    /// other actor reads its own and those whose bound lead or board role it
    /// holds live, as [`Self::task_fanout_launch`] does.
    pub fn pending_task_fanout_launches(&self) -> MemoryResult<Vec<FanoutLaunchReceipt>> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        let owner = actor_is_vault_owner_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        let mut pending = Vec::new();
        for (_, launch) in FANOUT_LAUNCHES.scan(&vault.store, &txn)? {
            let own =
                launch.actor.is(self.actor()) && launch.actor_class == self.actor_class() as u8;
            if !owner
                && !own
                && !launch_role_is_held_in(
                    vault,
                    &txn,
                    launch.approval_project,
                    self.actor(),
                    self.actor_class(),
                )?
            {
                continue;
            }
            let receipt = self.listed_receipt(&launch);
            if receipt.paused.is_some()
                || (receipt.check_row_ref.is_some() && receipt.choice_receipt_ref.is_none())
            {
                pending.push(receipt);
            }
        }
        Ok(pending)
    }
}
