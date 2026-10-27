//! Task brief revision reports and post landing.
//! Entry: `Memory::report_brief`.
//! Post vocabulary stays in `highway_post`.

use super::*;

impl Memory<'_> {
    /// Report `Brief`: parks a `tasks.brief` proposal. The revision lands as
    /// `rev + 1` only through settlement, and a try already leased keeps the
    /// stamp it was leased under.
    pub(in crate::task_verb) fn report_brief(
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
        // The first brief is kept beside a revision of it, read in the same
        // snapshot as its revision number (FIX 9005).
        let (base_rev, base_brief) = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            let body = task_body_in_txn(self.vault(), &txn, task_ref)?;
            self.highway_task_actor_in(
                &txn,
                task_ref,
                TaskActorVerb::Owner,
                "Ask the task's owner to revise the brief.",
            )?;
            if body.terminal().is_some() {
                return Err(invalid_state(
                    "a settled task's brief cannot change",
                    "Post a new task for new work.",
                ));
            }
            next.validate_in(self.vault(), &txn, body.assignee)?;
            match body.brief {
                Some(held) if held.rev == 1 => (1, Some(held.brief)),
                Some(held) => (held.rev, None),
                None => (0, None),
            }
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
            let kept = lifecycle_receipt::replayed(
                self.vault(),
                lifecycle_receipt::receipt_id("brief", &[held.proposal_ref.as_bytes()])?,
            )?;
            return Ok(TaskCallReceipt {
                handle: TaskHandle::Task { task_ref },
                related: vec![TaskHandle::Proposed {
                    proposal_ref: held.proposal_ref,
                }],
                outcome: TaskOutcome::Proposed {
                    decision_ref: None,
                    reason_codes: Vec::new(),
                },
                receipt_ref: kept,
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
            base_brief,
        };
        let keep = self.keeps_lifecycle();
        // The revision's lifecycle is kept beside its proposal, in the
        // proposal's transaction, under the id the proposal derives.
        let mut receipt_ref = None;
        let (proposal_ref, decision_ref) = self.persist_proposal_claim(
            TASK_BRIEF_PROPOSAL_PREDICATE,
            typed_value(&revision)?,
            self.actor(),
            now,
            crate::memory::facade_provenance("tasks.update"),
            |wtxn, proposal_ref| {
                if keep {
                    let mut proposed = lifecycle.clone();
                    proposed
                        .fields
                        .insert("proposal_ref".to_owned(), proposal_ref.to_hex());
                    receipt_ref = Some(lifecycle_receipt::stamp_record_in(
                        self.vault(),
                        wtxn,
                        &proposed,
                        lifecycle_receipt::receipt_id("brief", &[proposal_ref.as_bytes()])?,
                        None,
                    )?);
                }
                Ok(())
            },
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
            receipt_ref,
            lifecycle: Some(lifecycle),
            idempotent_replay: false,
        })
    }

    /// Lands one approved post inside the approving transaction: the TASK at
    /// the settlement id filed under its parent, its route under the creator
    /// its proposal witnessed (OF-532), and its Assigned fact. `copied` lands
    /// a redo's copy (FIX 9001).
    #[expect(
        clippy::too_many_arguments,
        reason = "one landing over its post, its identity, its creator and whether it is a copy"
    )]
    pub(super) fn land_settled_post_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        post: &TaskPost,
        provenance: &Value,
        origin: Option<&TaskCreateOrigin>,
        now: u64,
        copied: bool,
    ) -> MemoryResult<TaskRouteOutcome> {
        // A redo lands as its post did (FIX 9001): a parent that can no
        // longer take a Task is left out, never the approval's refusal, and
        // a pin whose row moved since is no refusal either.
        let unparented;
        let post = match post.parent_ref {
            Some(parent)
                if copied && task_parent_refusal_in(self.vault(), &*wtxn, parent)?.is_some() =>
            {
                unparented = TaskPost {
                    parent_ref: None,
                    ..post.clone()
                };
                &unparented
            }
            _ => post,
        };
        let type_ref = brief_type_ref_in(self.vault(), &*wtxn, &post.brief)?;
        let spec = create_spec_of(post, self.actor(), type_ref, now);
        let validated = validate_task_create_in(self.vault(), &*wtxn, &spec, now)?;
        if copied {
            post.brief
                .validate_copy_in(self.vault(), &*wtxn, Some(post.assignee))?;
        } else {
            post.brief
                .validate_in(self.vault(), &*wtxn, Some(post.assignee))?;
        }
        self.mint_task_with_brief_at_in_txn(
            wtxn,
            (task_ref, self.actor()),
            &validated,
            post.label.clone(),
            provenance,
            Some(StoredBrief::first(post.brief.clone())),
            now,
        )?;
        self.attach_task_parent_in_txn(wtxn, task_ref, post.parent_ref)?;
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
