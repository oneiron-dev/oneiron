//! `self.code.symbols.declare`, `.renew` and `.release` (FIX 6867, G1
//! PR2b): a leased run's own symbol declaration for its TASK, fenced by a
//! declaration id. A fresh declaration mints a fresh id and reacquires; a
//! renewal keeps the id; a declaration that is missing, released, replaced
//! or expired answers `repo_stale_lease`. An overlap with another TASK's
//! live declaration leaves the run's declaration waiting, never refused.
//! Each door is judged again in the writer that changes the declaration,
//! at the vault clock read inside that writer (FIX 8801).
//! The owner's `vault.code.symbols.*` doors are unchanged.

use std::collections::{BTreeMap, BTreeSet};

use super::work::RepoOwnWork;
use super::{
    NO_PATHS, RepoRunAnswer, RepoRunBinding, RepoRunStamp, RepoSymbolDeclarationView,
    RepoSymbolsDeclareInput, RepoSymbolsDeclareOutput, RepoSymbolsReleaseInput,
    RepoSymbolsReleaseOutput, RepoSymbolsRenewInput, RepoSymbolsRenewOutput, repo_target,
};
use crate::code_symbol::code_symbol_entity_id;
use crate::federation::{RepoAccessIntent, RepoAccessRefusal, RepoTarget};
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::task_verb::{SymbolLease, SymbolLeaseFence, SymbolLeaseRun};
use crate::{EntityId, Vault};

/// The largest lifetime a run declares: the largest integer a JavaScript
/// number holds exactly, so the guest's number is the engine's.
const MAX_SAFE_TTL_SECONDS: u64 = (1 << 53) - 1;

/// The run a work's declarations are made under: the work's lease and its
/// repo ref.
pub(super) fn symbol_run(stamp: &RepoRunStamp) -> SymbolLeaseRun {
    SymbolLeaseRun {
        attempt: stamp.attempt,
        lease_owner: stamp.lease_owner.clone(),
        generation: stamp.generation,
        repo: stamp.repo,
        git_ref: stamp.git_ref.clone(),
    }
}

/// The fence a run names `declaration` by, under its binding and work.
pub(super) fn symbol_fence(
    binding: &RepoRunBinding,
    stamp: &RepoRunStamp,
    declaration: EntityId,
) -> SymbolLeaseFence {
    SymbolLeaseFence {
        declaration_id: declaration,
        task: binding.task,
        holder: binding.actor.entity_ref(),
        run: symbol_run(stamp),
    }
}

impl Vault {
    /// Whether the run is admitted to `target` for `intent` in `txn` under the
    /// lease its work `own` was bound with: the refusal otherwise.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(super) fn readmit_repo_work_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        binding: &RepoRunBinding,
        own: &RepoOwnWork,
        target: &RepoTarget,
        intent: RepoAccessIntent,
    ) -> crate::error::Result<std::result::Result<(), RepoAccessRefusal>> {
        Ok(
            match self.admit_repo_run_in_txn(txn, binding, target, intent)? {
                Ok(again) if again.holds(&own.stamp) => Ok(()),
                Ok(_) => Err(RepoAccessRefusal::StaleLease),
                Err(refused) => Err(refused),
            },
        )
    }
}

impl Memory<'_> {
    /// `self.code.symbols.declare` for a run: declares `symbols`, current
    /// symbols of its work's repo on paths the Grant edits, for the run's
    /// TASK under a fresh id. It replaces this holder's earlier declaration
    /// of the TASK; another holder's live declaration of the same TASK is
    /// not taken over. An overlap with another TASK waits behind it.
    pub fn repo_symbols_declare_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoSymbolsDeclareInput,
    ) -> MemoryResult<RepoRunAnswer<RepoSymbolsDeclareOutput>> {
        if input.ttl_seconds == 0 || input.ttl_seconds > MAX_SAFE_TTL_SECONDS {
            return Err(MemoryError::bad_request(
                "ttl_seconds must be a positive safe integer",
            ));
        }
        let own = self.repo_own_work(binding, input.work, NO_PATHS, RepoAccessIntent::Read)?;
        let paths = self.repo_symbol_paths(own.stamp.repo, &input.symbols)?;
        let target = repo_target(own.stamp.repo, &own.stamp.git_ref, &paths);
        let keys: BTreeSet<String> = input.symbols.iter().map(EntityId::to_hex).collect();
        let declared = self.vault.with_write_txn_grouped(|txn| {
            let now = self.vault.now_recorded_at();
            if let Err(refused) = self.vault.readmit_repo_work_in_txn(
                txn,
                binding,
                &own,
                &target,
                RepoAccessIntent::Edit,
            )? {
                return Ok(Err(refused));
            }
            Ok(Ok(crate::task_verb::declare_symbols_for_run_in_txn(
                self.vault,
                txn,
                binding.task,
                binding.actor.entity_ref(),
                symbol_run(&own.stamp),
                keys,
                input.ttl_seconds,
                now,
            )?))
        })?;
        let Some((lease, blockers)) = declared.map_err(super::refusal_error)? else {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "another holder's live declaration holds this run's TASK",
                &["Wait for it to be released or to expire, then declare again."],
            ));
        };
        self.repo_declaration_answer(binding, &own, &lease, blockers)
    }

    /// `self.code.symbols.renew` for a run: extends its own declaration by
    /// the declared lifetime, keeping its id and whether it is held (CALL
    /// "FIX 6867 run-only waiting renewal"). A declaration that is not the
    /// TASK's current one of this run, or has expired, is a stale lease.
    pub fn repo_symbols_renew_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoSymbolsRenewInput,
    ) -> MemoryResult<RepoRunAnswer<RepoSymbolsRenewOutput>> {
        let own = self.repo_own_work(binding, input.work, NO_PATHS, RepoAccessIntent::Read)?;
        let fence = symbol_fence(binding, &own.stamp, input.declaration);
        let target = repo_target(own.stamp.repo, &own.stamp.git_ref, NO_PATHS);
        let renewed = self.vault.with_write_txn_grouped(|txn| {
            let now = self.vault.now_recorded_at();
            if let Err(refused) = self.vault.readmit_repo_work_in_txn(
                txn,
                binding,
                &own,
                &target,
                RepoAccessIntent::Edit,
            )? {
                return Ok(Err(refused));
            }
            Ok(
                crate::task_verb::renew_symbols_for_run_in_txn(self.vault, txn, &fence, now)?
                    .ok_or(RepoAccessRefusal::StaleLease),
            )
        })?;
        let lease = renewed.map_err(super::refusal_error)?;
        self.repo_declaration_answer(binding, &own, &lease, Vec::new())
    }

    /// `self.code.symbols.release` for a run: removes its own declaration.
    /// Giving a hold up needs the run's membership and lease, not an edit
    /// glob. A declaration that is not the TASK's current one of this run,
    /// or has expired, is a stale lease, and nothing is removed.
    pub fn repo_symbols_release_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoSymbolsReleaseInput,
    ) -> MemoryResult<RepoRunAnswer<RepoSymbolsReleaseOutput>> {
        let own = self.repo_own_work(binding, input.work, NO_PATHS, RepoAccessIntent::Read)?;
        let fence = symbol_fence(binding, &own.stamp, input.declaration);
        let target = repo_target(own.stamp.repo, &own.stamp.git_ref, NO_PATHS);
        let released = self.vault.with_write_txn_grouped(|txn| {
            let now = self.vault.now_recorded_at();
            if let Err(refused) = self.vault.readmit_repo_work_in_txn(
                txn,
                binding,
                &own,
                &target,
                RepoAccessIntent::Read,
            )? {
                return Ok(Err(refused));
            }
            Ok(
                if crate::task_verb::release_symbols_for_run_in_txn(self.vault, txn, &fence, now)? {
                    Ok(())
                } else {
                    Err(RepoAccessRefusal::StaleLease)
                },
            )
        })?;
        released.map_err(super::refusal_error)?;
        Ok(RepoRunAnswer {
            rows: vec![own.stamp.repo],
            output: RepoSymbolsReleaseOutput {
                work: input.work,
                declaration: input.declaration,
                task: binding.task,
            },
        })
    }

    /// The paths of `symbols` in the stored symbol manifest of `repo`: each
    /// must be a current CODE_SYMBOL id of it, as the owner's declaration
    /// requires. A bare name or another revision's symbol refuses.
    fn repo_symbol_paths(
        &self,
        repo: EntityId,
        symbols: &[EntityId],
    ) -> MemoryResult<BTreeSet<String>> {
        let manifest = self.vault.get_code_symbol_manifest(&repo)?.ok_or_else(|| {
            MemoryError::not_found("the repository has no stored symbol manifest")
        })?;
        let mut current = BTreeMap::new();
        for symbol in &manifest.symbols {
            current.insert(
                code_symbol_entity_id(&manifest.repo_ref, symbol)?,
                symbol.path.clone(),
            );
        }
        symbols
            .iter()
            .map(|symbol| {
                current.get(symbol).cloned().ok_or_else(|| {
                    MemoryError::bad_request(format!(
                        "symbol {} is not in the current symbol manifest of the repository",
                        symbol.to_hex()
                    ))
                })
            })
            .collect()
    }

    /// A declaration as the run reads it, with the blockers its lane reads.
    fn repo_declaration_answer(
        &self,
        binding: &RepoRunBinding,
        own: &RepoOwnWork,
        lease: &SymbolLease,
        blockers: Vec<EntityId>,
    ) -> MemoryResult<RepoRunAnswer<RepoSymbolDeclarationView>> {
        let symbols = lease
            .symbols
            .iter()
            .map(|symbol| EntityId::from_hex(symbol))
            .collect::<crate::error::Result<Vec<EntityId>>>()?;
        let blockers = self.repo_lane_readable(binding, blockers)?;
        let mut rows = vec![own.stamp.repo];
        rows.extend(blockers.iter().copied());
        Ok(RepoRunAnswer {
            rows,
            output: RepoSymbolDeclarationView {
                work: own.receipt.view_id,
                declaration: lease.declaration_id,
                task: binding.task,
                symbols,
                expires_at: lease.expires_at,
                held: lease.held,
                blockers,
            },
        })
    }
}
