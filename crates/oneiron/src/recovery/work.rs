//! A canonical window recovery as resumable work (Rule 5, FIX 8821).
//!
//! How much a recovery repairs never refuses it. Its work runs a page at a
//! time on the vault's one task-work line: each page waits its turn there,
//! in the fair line (each principal's oldest work first, principals in
//! turn, the host's own work only when no caller waits), runs, and hands its
//! turn back before the next page queues again. A turn that does not come by
//! the caller's deadline leaves the work pending where it stands, never run
//! without a turn, never refused and never reported Healthy.
//!
//! What must hold of the whole runs whole: the artifact's validation, the
//! preflight that admits every row in one aborted transaction, the NOTE
//! workflow plan, the equivalence of the recaptured window, and the manifest,
//! published last and only once every page is done. The rebuild, the
//! forward replay and the per-row checks after it run a page at a time, with
//! the replay's cross-pass ledgers kept from page to page.

use std::path::{Path, PathBuf};
use std::time::Instant;

use loro::LoroDoc;

use super::canonical::{CanonicalSnapshot, RebuildAt, invalid, rebuild_page, rebuild_start};
use super::ladder::{
    PreparedRecovery, RecoveryBudget, RecoveryTier, limit, prepare_rebuilt, verify_page,
};
use crate::error::Result;
use crate::sync::bridge::Materializer;
use crate::sync::types::WindowKey;
use crate::sync::window::ForwardRun;
use crate::work_line::{LinePermit, WaitTimedOut};
use crate::{EntityId, Vault};

/// The phase a recovery stands in, in the order it runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryPhase {
    /// The artifact as this vault recovers it, validated whole.
    Validate,
    /// The fresh window, a page of rows at a time.
    Rebuild,
    /// The whole-bundle preflight, the manifest's tier and its quarantine.
    Preflight,
    /// The forward replay, a page of rows at a time.
    Replay,
    /// The per-row checks, a page at a time, and the equivalence, whole.
    Verify,
    /// The repaired manifest, published last.
    Publish,
    Complete,
}

/// Where a recovery stands: the artifact it is bound to, its phase, and
/// where its next page starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryCursor {
    pub(crate) digest: [u8; 32],
    pub(crate) phase: RecoveryPhase,
    pub(crate) next_key: Option<String>,
}

/// What one [`RecoveryWork::step`] left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryProgress {
    /// More pages are owed; the work resumes where the cursor stands.
    Pending(RecoveryCursor),
    Complete,
}

/// One window's recovery from its canonical artifact, owning that artifact
/// for its whole life: every page reads the same source.
pub(crate) struct RecoveryWork {
    path: PathBuf,
    budget: RecoveryBudget,
    /// Whose turns the pages take: the owner of an owner act, else the
    /// host's own work.
    principal: Option<EntityId>,
    source: CanonicalSnapshot,
    digest: [u8; 32],
    phase: RecoveryPhase,
    doc: Option<LoroDoc>,
    rebuilt: RebuildAt,
    prepared: Option<PreparedRecovery>,
    forward: Option<ForwardRun>,
    verified: usize,
}

impl RecoveryWork {
    pub(crate) fn new(
        manifest_path: &Path,
        snapshot: &CanonicalSnapshot,
        budget: RecoveryBudget,
        principal: Option<EntityId>,
    ) -> Self {
        Self {
            path: manifest_path.to_owned(),
            budget,
            principal,
            source: snapshot.clone(),
            digest: [0; 32],
            phase: RecoveryPhase::Validate,
            doc: None,
            rebuilt: RebuildAt::default(),
            prepared: None,
            forward: None,
            verified: 0,
        }
    }

    /// Runs pages, each on its own turn, until the work completes or
    /// `deadline` passes. `None` waits for each turn as long as the line
    /// waits; a wait that ends without a turn leaves the work pending.
    pub(crate) fn step(
        &mut self,
        vault: &Vault,
        materializer: &Materializer,
        deadline: Option<Instant>,
    ) -> Result<RecoveryProgress> {
        loop {
            if self.phase == RecoveryPhase::Complete {
                return Ok(RecoveryProgress::Complete);
            }
            let Ok(turn) = self.turn(vault, deadline) else {
                return Ok(RecoveryProgress::Pending(self.cursor()));
            };
            self.page(vault, materializer)?;
            drop(turn);
            if self.phase != RecoveryPhase::Complete
                && deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                return Ok(RecoveryProgress::Pending(self.cursor()));
            }
        }
    }

    /// Runs the work to its end, as a synchronous call or the CLI does: the
    /// same pages and turns, each wait that ends without a turn queued again.
    pub(crate) fn drain(
        mut self,
        vault: &Vault,
        materializer: &Materializer,
    ) -> Result<PreparedRecovery> {
        while let RecoveryProgress::Pending(cursor) = self.step(vault, materializer, None)? {
            tracing::debug!(
                artifact = %crate::entity_id::bytes_to_hex_lower(&cursor.digest[..16]),
                phase = ?cursor.phase,
                next = cursor.next_key.as_deref().unwrap_or(""),
                "canonical recovery waits for its next turn"
            );
        }
        self.prepared
            .ok_or_else(|| invalid("recovery completed without its preparation"))
    }

    /// Where the work stands.
    pub(crate) fn cursor(&self) -> RecoveryCursor {
        let next_key = match self.phase {
            RecoveryPhase::Rebuild => Some(self.rebuilt.position()),
            RecoveryPhase::Replay => self.forward.as_ref().map(|forward| {
                let (pass, key) = forward.position();
                format!("{pass}:{}", key.unwrap_or_default())
            }),
            RecoveryPhase::Verify => Some(format!("check {}", self.verified)),
            _ => None,
        };
        RecoveryCursor {
            digest: self.digest,
            phase: self.phase,
            next_key,
        }
    }

    /// This work's next turn on the vault's task-work line.
    fn turn(
        &self,
        vault: &Vault,
        deadline: Option<Instant>,
    ) -> std::result::Result<LinePermit, WaitTimedOut> {
        let wait = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        match (self.principal, wait) {
            (Some(principal), Some(wait)) => vault.task_work.admit_blocking_for(principal, wait),
            (Some(principal), None) => vault.task_work.admit_blocking(principal),
            (None, Some(wait)) => vault.task_work.admit_background_blocking_for(wait),
            (None, None) => vault.task_work.admit_background_blocking(),
        }
    }

    /// One page of the phase the work stands in.
    fn page(&mut self, vault: &Vault, materializer: &Materializer) -> Result<()> {
        let page = self.budget.max_obligations.max(1);
        match self.phase {
            RecoveryPhase::Validate => {
                // An actor this vault erased reads as no one in the artifact
                // too (FIX 3878): the recovery checks, installs and compares
                // only that form. Full domain validation precedes quarantine
                // and every durable write.
                self.source = self.source.with_actors_erased_here(vault)?;
                let encoded = self.source.encode()?;
                limit(encoded.len(), self.budget.max_bytes)?;
                self.digest = *blake3::hash(&encoded).as_bytes();
                self.doc = Some(rebuild_start());
                self.phase = RecoveryPhase::Rebuild;
            }
            RecoveryPhase::Rebuild => {
                let doc = self
                    .doc
                    .as_ref()
                    .ok_or_else(|| invalid("recovery rebuild"))?;
                if rebuild_page(doc, &self.source, &mut self.rebuilt, page)? {
                    doc.commit();
                    self.phase = RecoveryPhase::Preflight;
                }
            }
            RecoveryPhase::Preflight => self.preflight(vault, materializer)?,
            RecoveryPhase::Replay => {
                let (Some(forward), Some(prepared)) = (self.forward.as_mut(), &self.prepared)
                else {
                    return Err(invalid("recovery replay"));
                };
                let key = WindowKey::new(&self.source.window);
                if forward
                    .recovery_page(
                        vault,
                        &prepared.window,
                        materializer,
                        &key,
                        &self.source,
                        page,
                    )?
                    .is_some()
                {
                    self.forward = None;
                    self.phase = RecoveryPhase::Verify;
                }
            }
            RecoveryPhase::Verify => {
                let prepared = self
                    .prepared
                    .as_ref()
                    .ok_or_else(|| invalid("recovery verify"))?;
                if verify_page(vault, prepared, &self.source, &mut self.verified, page)? {
                    self.phase = RecoveryPhase::Publish;
                }
            }
            RecoveryPhase::Publish => {
                let prepared = self
                    .prepared
                    .as_ref()
                    .ok_or_else(|| invalid("recovery publish"))?;
                if prepared.tier != RecoveryTier::Healthy {
                    prepared.publish(&self.path)?;
                }
                self.phase = RecoveryPhase::Complete;
            }
            RecoveryPhase::Complete => {}
        }
        Ok(())
    }

    /// The whole-bundle preflight over the rebuilt window, then the
    /// manifest's tier and quarantine, before any durable write.
    fn preflight(&mut self, vault: &Vault, materializer: &Materializer) -> Result<()> {
        let doc = self
            .doc
            .take()
            .ok_or_else(|| invalid("recovery preflight"))?;
        crate::sync::bridge::preflight_canonical_recovery(vault, materializer, &self.source, &doc)?;
        let prepared = prepare_rebuilt(&self.path, &self.source, self.budget, doc)?;
        // A task whose fact the source refused reads as a refusal here before
        // the replay can read its authority.
        if !self.source.suppressed_tasks.is_empty() {
            vault.with_write_txn(|txn| {
                crate::task_authority::restore_suppressed_in_txn(
                    &vault.store,
                    txn,
                    &self.source.suppressed_tasks,
                )
            })?;
        }
        let key = WindowKey::new(&self.source.window);
        self.forward = Some(ForwardRun::open_recovery(
            vault,
            &prepared.window,
            materializer,
            &key,
            &self.source,
        )?);
        self.prepared = Some(prepared);
        self.phase = RecoveryPhase::Replay;
        Ok(())
    }
}
