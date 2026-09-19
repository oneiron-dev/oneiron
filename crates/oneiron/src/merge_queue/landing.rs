//! Crash-consistent gated landing and trailing-check green/rollback transitions.
use super::types::{EffectIntent, QueueRecord};
use super::{
    BatchState, LandingPermit, MergeBatch, MergeLanding, MergeQueue, MergeQueuePointers,
    TestedBatch,
};
use crate::{
    contract_oracle::{ContractOracle, invalid},
    error::{Error, Result},
    git_wire::{GitWire, lock_repository},
    repo_mutation::{RepoMutationOplogEntry, RepoMutationStatus},
};

impl MergeQueue<'_> {
    /// Invoke the host's gated repo mutation only after every inclusion path has
    /// passed. The permit binds repo identity and expected HEAD under the shared
    /// repository lock. A rejected or interrupted effect keeps its recovery intent.
    pub fn land<L: MergeLanding>(&self, id: &str, landing: &mut L) -> Result<MergeBatch> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let mut queue = self.queue()?;
        self.require_current(&queue)?;
        let mut batch = self.batch(id)?;
        if batch.state != BatchState::Ready || !self.all_paths_green(&batch)? {
            return Err(invalid("merge batch lacks all-path agreement"));
        }
        if queue.pointers.head != batch.expected_head {
            return Err(Error::ConcurrentWrite("tested merge base moved"));
        }
        self.require_clean(self.repo.repo_root())?;
        self.verify_worktree(
            batch
                .paths
                .last()
                .ok_or_else(|| invalid("batch has no full path"))?,
        )?;
        let after_seq = self
            .vault
            .repo_mutation_oplog(self.repo.repo_ref())?
            .last()
            .map_or(0, |entry| entry.seq);
        queue.intent = Some(EffectIntent::Landing {
            batch: id.to_owned(),
            after_seq,
        });
        batch.state = BatchState::Landing;
        self.save(&queue, &[&batch])?;
        let permit = LandingPermit {
            batch_id: batch.id.clone(),
            repo_identity: self.repo.identity().as_hex(),
            expected_head: batch.expected_head.clone(),
        };
        let tested = TestedBatch {
            batch: batch.clone(),
        };
        let outcomes = landing.land(&permit, &tested)?;
        let oplog = self.vault.repo_mutation_oplog(self.repo.repo_ref())?;
        if outcomes.is_empty()
            || outcomes
                .iter()
                .any(|outcome| !oplog.contains(&outcome.entry))
        {
            return Err(invalid(
                "landing did not return persisted repo mutation receipts",
            ));
        }
        let entries: Vec<_> = outcomes.iter().map(|outcome| &outcome.entry).collect();
        let last_hash = receipt_chain(&entries, &batch, after_seq)?;
        if last_hash != self.capture_current_snapshot(&batch)? {
            return Err(Error::ConcurrentWrite(
                "landing receipt chain does not bind the live result",
            ));
        }
        self.finish_landing(&mut queue, &mut batch)?;
        Ok(batch)
    }

    fn finish_landing(&self, queue: &mut QueueRecord, batch: &mut MergeBatch) -> Result<()> {
        let expected_tree = &batch
            .paths
            .last()
            .ok_or(Error::CorruptedIndex("landing path missing"))?
            .tree;
        if &self.tree()? != expected_tree {
            return Err(Error::ConcurrentWrite(
                "landed tree differs from tested tree",
            ));
        }
        self.require_clean(self.repo.repo_root())?;
        let head = self.head()?;
        if head == batch.expected_head {
            return Err(invalid("landing did not create a commit"));
        }
        queue.pointers.head = head.clone();
        queue.pointers.pending_slow.push(batch.id.clone());
        queue.intent = None;
        batch.landed_head = Some(head);
        batch.state = BatchState::HeadAdvanced;
        self.save(queue, &[batch])
    }

    /// Consume slow results in commit order. Later successes wait for earlier
    /// results. Any red result rolls the full ungreen suffix back to last green.
    pub fn settle_slow(&self) -> Result<MergeQueuePointers> {
        let _guard = lock_repository(self.repo.common_dir())?;
        let mut queue = self.queue()?;
        self.require_current(&queue)?;
        let mut batches: Vec<_> = queue
            .pointers
            .pending_slow
            .iter()
            .map(|id| self.batch(id))
            .collect::<Result<_>>()?;
        let oracle = ContractOracle::new(self.vault);
        let mut passing = Vec::new();
        let mut red = false;
        for batch in &batches {
            let status = if let Some(id) = &batch.slow_verdict {
                let verdict = oracle
                    .verdict(id)?
                    .ok_or(Error::CorruptedIndex("slow verdict missing"))?;
                let path = batch
                    .paths
                    .last()
                    .ok_or(Error::CorruptedIndex("slow path missing"))?;
                let expected = format!("{}:{}:Slow:{}", batch.id, path.mask, path.tree);
                if verdict.candidate != expected || verdict.baseline_id != batch.baseline_id {
                    return Err(Error::CorruptedIndex("slow verdict scope differs"));
                }
                red |= !verdict.passes();
                Some(verdict.passes())
            } else {
                None
            };
            passing.push(status);
        }
        if red {
            let snapshot = batches
                .first()
                .and_then(|b| b.pre_snapshot)
                .ok_or(Error::CorruptedIndex("rollback snapshot missing"))?;
            queue.intent = Some(EffectIntent::Rollback {
                snapshot,
                expected_head: queue.pointers.head.clone(),
            });
            for batch in &mut batches {
                batch.state = BatchState::RollingBack;
            }
            self.save(&queue, &batches.iter().collect::<Vec<_>>())?;
            self.finish_rollback(&mut queue, snapshot)?;
        } else {
            let mut consumed = 0;
            for (batch, status) in batches.iter_mut().zip(passing) {
                if status != Some(true) {
                    break;
                }
                queue.pointers.green = batch
                    .landed_head
                    .clone()
                    .ok_or(Error::CorruptedIndex("landed HEAD missing"))?;
                batch.state = BatchState::GreenAdvanced;
                consumed += 1;
            }
            queue.pointers.pending_slow.drain(..consumed);
            self.save(&queue, &batches.iter().collect::<Vec<_>>())?;
        }
        Ok(queue.pointers)
    }

    fn finish_rollback(&self, queue: &mut QueueRecord, snapshot: [u8; 32]) -> Result<()> {
        if self.head()? != queue.pointers.green {
            let outcome = self
                .vault
                .recover_repo_snapshot(self.repo.repo_ref(), snapshot)?;
            if outcome.entry.status != RepoMutationStatus::Applied {
                return Err(invalid("rollback mutation was not applied"));
            }
        }
        if self.head()? != queue.pointers.green {
            return Err(Error::ConcurrentWrite(
                "rollback did not restore green HEAD",
            ));
        }
        self.require_clean(self.repo.repo_root())?;
        let mut batches: Vec<_> = queue
            .pointers
            .pending_slow
            .iter()
            .map(|id| self.batch(id))
            .collect::<Result<_>>()?;
        for batch in &mut batches {
            batch.state = BatchState::RolledBack;
        }
        queue.pointers.head = queue.pointers.green.clone();
        queue.pointers.pending_slow.clear();
        queue.intent = None;
        self.save(queue, &batches.iter().collect::<Vec<_>>())
    }

    /// Reconcile the physical repo with durable intent after restart. A changed
    /// HEAD without a matching persisted repo-mutation receipt fails closed.
    /// Prepared worktree/check rows may simply be restaged/rechecked afterwards.
    pub fn recover(&self) -> Result<MergeQueuePointers> {
        let _guard = lock_repository(self.repo.common_dir())?;
        GitWire::new(self.vault)?.recover(&self.repo, 0)?;
        self.vault
            .recover_prepared_repo_mutations(self.repo.repo_ref())?;
        let mut queue = self.queue()?;
        match queue.intent.clone() {
            None => self.require_current(&queue)?,
            Some(EffectIntent::Landing {
                batch: id,
                after_seq,
            }) => {
                let mut batch = self.batch(&id)?;
                if self.vault.has_reviewed_merge_stack(&self.repo, &batch)? {
                    // Admission was atomic and all votes are immutable. Resume
                    // only the proven journaled prefix, rather than rolling Git
                    // back while document edits / conflict claims stay applied.
                    if !self.all_paths_green(&batch)? {
                        return Err(invalid("reviewed recovery lacks all-path agreement"));
                    }
                    self.verify_worktree(
                        batch
                            .paths
                            .last()
                            .ok_or(Error::CorruptedIndex("landing path missing"))?,
                    )?;
                    let permit = LandingPermit {
                        batch_id: batch.id.clone(),
                        repo_identity: self.repo.identity().as_hex(),
                        expected_head: batch.expected_head.clone(),
                    };
                    let tested = TestedBatch {
                        batch: batch.clone(),
                    };
                    let outcomes = self.vault.apply_tested_repo_proposals(
                        self.repo.repo_ref(),
                        &permit,
                        &tested,
                    )?;
                    let entries = outcomes
                        .iter()
                        .map(|outcome| &outcome.entry)
                        .collect::<Vec<_>>();
                    let last_hash = receipt_chain(&entries, &batch, after_seq)?;
                    if last_hash != self.capture_current_snapshot(&batch)? {
                        return Err(Error::ConcurrentWrite("reviewed recovery receipt diverged"));
                    }
                    self.finish_landing(&mut queue, &mut batch)?;
                } else if self.head()? == batch.expected_head {
                    self.require_clean(self.repo.repo_root())?;
                    batch.state = BatchState::Ready;
                    queue.intent = None;
                    self.save(&queue, &[&batch])?;
                } else {
                    let entries = self.vault.repo_mutation_oplog(self.repo.repo_ref())?;
                    let writes: Vec<_> = entries
                        .iter()
                        .filter(|entry| {
                            entry.seq > after_seq
                                && entry.status == RepoMutationStatus::Applied
                                && is_content_write(entry)
                        })
                        .collect();
                    let last_hash = receipt_chain(&writes, &batch, after_seq)?;
                    if last_hash != self.capture_current_snapshot(&batch)? {
                        return Err(Error::ConcurrentWrite(
                            "landing recovery receipt does not bind live tree",
                        ));
                    }
                    if self.tree()?
                        == batch
                            .paths
                            .last()
                            .ok_or(Error::CorruptedIndex("landing path missing"))?
                            .tree
                    {
                        self.finish_landing(&mut queue, &mut batch)?;
                    } else {
                        // A crash between gated per-operation writes leaves a
                        // proper prefix. Undo that exact journaled prefix; never
                        // auto-approve or silently rebase the remainder.
                        let snapshot = batch
                            .pre_snapshot
                            .ok_or(Error::CorruptedIndex("landing snapshot missing"))?;
                        self.vault
                            .recover_repo_snapshot(self.repo.repo_ref(), snapshot)?;
                        if self.head()? != batch.expected_head {
                            return Err(Error::ConcurrentWrite(
                                "partial landing recovery diverged",
                            ));
                        }
                        batch.state = BatchState::Ready;
                        queue.intent = None;
                        self.save(&queue, &[&batch])?;
                    }
                }
            }
            Some(EffectIntent::Rollback {
                snapshot,
                expected_head,
            }) => {
                let actual = self.head()?;
                if actual != expected_head && actual != queue.pointers.green {
                    return Err(Error::ConcurrentWrite("rollback recovery HEAD diverged"));
                }
                self.finish_rollback(&mut queue, snapshot)?;
            }
        }
        Ok(queue.pointers)
    }
}

fn is_content_write(entry: &RepoMutationOplogEntry) -> bool {
    !matches!(
        entry.operation_kind.as_str(),
        "create_worktree" | "remove_worktree" | "recover_snapshot"
    )
}
fn receipt_chain(
    entries: &[&RepoMutationOplogEntry],
    batch: &MergeBatch,
    after_seq: u64,
) -> Result<[u8; 32]> {
    if entries.is_empty() {
        return Err(invalid("landing has no content mutation receipts"));
    }
    let mut hash = batch
        .pre_snapshot
        .ok_or(Error::CorruptedIndex("landing snapshot missing"))?;
    let mut sequence = after_seq;
    for entry in entries {
        if entry.seq <= sequence
            || entry.status != RepoMutationStatus::Applied
            || !is_content_write(entry)
            || entry.pre_action_fork_hash != hash
        {
            return Err(Error::ConcurrentWrite("landing receipt chain diverged"));
        }
        hash = entry
            .expected_post_action_fork_hash
            .ok_or(Error::CorruptedIndex(
                "landing receipt postcondition missing",
            ))?;
        sequence = entry.seq;
    }
    Ok(hash)
}
