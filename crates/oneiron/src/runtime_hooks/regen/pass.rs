//! The engine's own regen pass (ARCH-0080 §8, FIX 4689): once the verb table
//! or the sandbox contract moved, each due hook of the vault's own packs runs
//! its intent again, and an identical fingerprint adopts without a question.
//! A hook an agent authored adopts through that agent's own put; any other
//! hook adopts through the owner's put when the host holds the owner's proof,
//! and otherwise its AutoAdopt waits on the record for the owner's adopt. A
//! diff waits for the owner's stamp. A regen that failed under this contract
//! is not run again by the pass; the owner reruns it by hand.

use crate::consent::AuthenticatedOwner;
use crate::skill_hub::pack_catalog::{HookAuthor, PackInstallDisposition};
use crate::{EdgeActorClass, EntityId, Result, Vault, WriteActor};

use super::super::body::HookBodyRuntime;
use super::{HookContractStamp, HookPut, HookRegenActor, HookRegenOutcome, HookRegenerator};

/// What one regen pass did, in counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HookRegenPassReport {
    /// Hooks whose intent ran again.
    pub regenerated: usize,
    /// AutoAdopt candidates installed.
    pub adopted: usize,
    /// Decisions left waiting: a diff for the owner's stamp, an AutoAdopt no
    /// held proof could enact, or a put that answered Candidate or Blocked.
    pub waiting: usize,
    /// Regens that rolled back, and hooks whose regen or adoption errored.
    pub failed: usize,
}

impl Vault {
    /// Runs the regen pass once over [`Self::hooks_due_for_regen`].
    /// `regenerator_for` gives each hook its own regenerator (its own budget);
    /// `owner` is the owner's proof the host holds, if any; `keep_going` is
    /// asked before each hook, so a stopping host starts no further regen.
    ///
    /// # Errors
    ///
    /// Storage errors reading the due list. A hook's own failure is counted
    /// in the report and the pass goes on.
    pub fn run_hook_regen_pass<R: HookRegenerator>(
        &self,
        runtime: &dyn HookBodyRuntime,
        mut regenerator_for: impl FnMut(EntityId) -> Result<R>,
        owner: Option<&AuthenticatedOwner>,
        keep_going: impl Fn() -> bool,
    ) -> Result<HookRegenPassReport> {
        let current = HookContractStamp::current();
        let mut report = HookRegenPassReport::default();
        for binding in self.hooks_due_for_regen()? {
            if !keep_going() {
                break;
            }
            let tried = self
                .hook_regen_record(binding)?
                .and_then(|record| record.pending)
                .is_some_and(|pending| {
                    matches!(pending, HookRegenOutcome::RolledBack { .. })
                        && *pending.target() == current
                });
            if tried {
                continue;
            }
            let outcome = regenerator_for(binding).and_then(|regenerator| {
                self.regenerate_hook_as(runtime, &regenerator, binding, &HookRegenActor::Engine)
            });
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(_) => {
                    report.failed += 1;
                    continue;
                }
            };
            report.regenerated += 1;
            let candidate = match &outcome {
                HookRegenOutcome::AutoAdopt { .. } => outcome.candidate_hash(),
                HookRegenOutcome::NeedsHumanStamp { .. } => {
                    report.waiting += 1;
                    continue;
                }
                HookRegenOutcome::RolledBack { .. } => {
                    report.failed += 1;
                    continue;
                }
            };
            let Some(candidate) = candidate else {
                continue;
            };
            let Some(put) = self.engine_regen_put(binding, owner)? else {
                report.waiting += 1;
                continue;
            };
            match self.enact_hook_regen(put, &HookRegenActor::Engine, binding, &candidate, false) {
                Ok(PackInstallDisposition::Installed(_)) => report.adopted += 1,
                Ok(_) => report.waiting += 1,
                Err(_) => report.failed += 1,
            }
        }
        Ok(report)
    }

    /// The put the pass adopts `binding`'s AutoAdopt through: its authoring
    /// agent's own, else the owner's when the host holds the proof, else
    /// none.
    fn engine_regen_put<'a>(
        &self,
        binding: EntityId,
        owner: Option<&'a AuthenticatedOwner>,
    ) -> Result<Option<HookPut<'a>>> {
        let author = self
            .pack_hook_bindings()?
            .into_iter()
            .find(|(id, _)| *id == binding)
            .map(|(_, row)| row.author);
        Ok(match (author, owner) {
            (Some(HookAuthor::Agent { agent }), _) => Some(HookPut::Agent {
                agent: WriteActor::new(agent, EdgeActorClass::Agent),
                owner: None,
            }),
            (Some(_), Some(owner)) => Some(HookPut::Owner(owner)),
            _ => None,
        })
    }
}
