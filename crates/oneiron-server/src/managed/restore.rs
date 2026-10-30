//! The cold managed restore start mode (LC FIX 5384/5385; the contract is
//! lanes/l14/t3/restore-contract.md, its wire `oneiron_vault_contract::restore`).
//!
//! A `--restore` start proves its two pipes, reads its plan before the
//! credential frame and checks every binding the plan names against argv and
//! the destination's isolation, all before anything is written. In place of
//! the ordinary open it then lands the vault through the engine's admitted
//! restore (`Vault::restore_checkpoint_admitted`), with the managed checks
//! and the source's host-order legal holds (`host_holds`) in its `finish`
//! step and the commit marker in its after-keep step. Nothing
//! listens, no worker runs and no ctl answers before the vault is verified
//! and kept: the boot then goes on as an ordinary start's over the same
//! vault, and just before ctl serves and ready is said the receipt and the
//! `verified` frame go out on the result pipe. A failure on the way says
//! why there once, with the step and what the destination holds.

mod commit_marker;
mod host_holds;
mod input;
mod receipt;
mod result;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::federation::derivation::{DerivationBindError, DerivationOwner};
use oneiron::recovery::checkpoint::{
    AdmittedRestore, CheckpointKey, HostOrderHolds, RestoreAdmission, RestoreAdmissionError,
    RestoreAdmissionReason, RestoreCommitFacts, RestoreDestinationState, RestorePhase,
    RestoreReport,
};
#[cfg(target_os = "linux")]
use oneiron_vault_contract::restore::FreshRecipient;
use oneiron_vault_contract::restore::plan::RestoreCustodyPlan;
use oneiron_vault_contract::restore::{
    ManagedRestoreDestination as Destination, ManagedRestoreIdentity, ManagedRestorePhase as Phase,
    ManagedRestorePlan, ManagedRestoreResultFrame, RestoreFailureReason, RestoreHostHoldsStatus,
};
use zeroize::Zeroizing;

// A vault VM host proves and takes over its own restore pipes the same way.
use self::host_holds::AdmittedHostOrderHolds;
#[cfg(target_os = "linux")]
pub(super) use self::input::adopt;
// The carrier watch's first look runs the begin-check's plan check again.
#[cfg(target_os = "linux")]
pub(super) use self::input::fresh_authorizes;
use self::receipt::ReceiptContext;
pub(super) use self::receipt::RestoreOutcome;
use self::result::ResultSink;
use super::args::{ManagedArgs, ManagedStartMode};
use super::isolation::{RestoreDestination, RestoreDestinationRefusal};
use super::vault_gates::{DekMac, check_dek_mac};
use crate::config::ServeConfig;
use crate::owner::backup::CustodyAnchorCredentials;
use crate::pipe_proof::pipe_end;

/// Where a restore stands, which names the failure its drop reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Its input is admitted, and the credentials are read next.
    Credentials,
    /// The engine's restore is running.
    Landing,
    /// The restore is kept, and the ordinary start goes on.
    Kept,
    /// Its terminal frame is out.
    Done,
}

/// One start's cold restore, from its admitted input to its `verified`
/// frame. Dropped before that, it reports the failure its stage names on the
/// result pipe, once: a credential refused before the restore ran, an
/// interrupted restore whose destination is uncertain, or a kept vault whose
/// start failed, committed and not serving.
pub(super) struct ManagedRestore {
    sink: Arc<ResultSink>,
    identity: ManagedRestoreIdentity,
    plan: ManagedRestorePlan,
    /// The host-order family the input pipe carried, admitted by where it
    /// came from; none without one. Its job takes it.
    host_holds: AdmittedHostOrderHolds,
    destination: Arc<RestoreDestination>,
    stage: Stage,
    kept: Option<Kept>,
    outcome: Option<Arc<RestoreOutcome>>,
}

/// What a kept restore returned beside its vault, for its receipt.
struct Kept {
    report: RestoreReport,
    admission: RestoreAdmission,
    /// The data directory the restore landed: (`st_dev`, `st_ino`).
    directory: (u64, u64),
    /// Where its host-order legal holds came from.
    host_holds: RestoreHostHoldsStatus,
}

impl ManagedRestore {
    /// A `--restore` start's restore, its input admitted; `None` for an
    /// ordinary start. The result pipe is proven first: a descriptor that is
    /// not a pipe's write end carries not even a refusal. Then the input
    /// pipe, its plan read to EOF and parsed (`started` goes out once it
    /// has), each binding it names checked against argv and `config`'s
    /// settled tier, the source's host-order family beside it admitted when
    /// there is one, and the destination's isolation proven with every name
    /// it makes free. The plan's custody anchor is this process's from here
    /// on: the restore admits its custody against it, and the restored vault
    /// publishes to it.
    pub(super) fn begin(
        managed: &ManagedArgs,
        config: &mut ServeConfig,
    ) -> anyhow::Result<Option<Self>> {
        let ManagedStartMode::Restore {
            input_fd,
            result_fd,
        } = managed.start_mode
        else {
            return Ok(None);
        };
        pipe_end(result_fd, true).map_err(|reason| {
            anyhow::anyhow!("--restore-result-fd {result_fd} refused: {reason}")
        })?;
        let input_pipe = pipe_end(input_fd, false);
        let sink = Arc::new(ResultSink::new(input::adopt(result_fd)));
        let unparsed = |reason: &str| {
            sink.failed(
                None,
                RestoreFailureReason::RestoreInputInvalid,
                Phase::ValidatingInput,
                Destination::Removed,
            );
            anyhow::anyhow!("the cold restore's input was refused: {reason}")
        };
        input_pipe.map_err(unparsed)?;
        let input = input::read(input::adopt(input_fd)).map_err(unparsed)?;
        let plan = input.plan;
        let identity = ManagedRestoreIdentity::of(&plan.request);
        sink.send(&ManagedRestoreResultFrame::Started {
            identity: identity.clone(),
        });
        sink.progress(&identity, Phase::ValidatingInput);
        let refuse = |reason, state, why: String| {
            sink.failed(Some(&identity), reason, Phase::ValidatingInput, state);
            anyhow::anyhow!("the cold restore was refused: {why}")
        };
        let invalid = |why: &str| {
            refuse(
                RestoreFailureReason::RestoreInputInvalid,
                Destination::Removed,
                why.to_owned(),
            )
        };
        input::check(&plan, managed, config.maximum_tier).map_err(invalid)?;
        let host_holds = host_holds::admit(input.host_holds, &plan).map_err(invalid)?;
        let destination = RestoreDestination::probe(&managed.data_dir, &managed.vault_name)
            .map_err(|refusal| {
                let (reason, state) = refusal_wire(&refusal);
                refuse(reason, state, refusal.what())
            })?;
        let backup = &mut config.backup;
        (backup.custody_anchor_root, backup.custody_anchor_url) = match &plan.custody {
            RestoreCustodyPlan::Unset => (None, None),
            RestoreCustodyPlan::Root { root } => (Some(root.clone()), None),
            RestoreCustodyPlan::Http { url } => (None, Some(url.clone())),
        };
        Ok(Some(Self {
            sink,
            identity,
            plan,
            host_holds,
            destination: Arc::new(destination),
            stage: Stage::Credentials,
            kept: None,
            outcome: None,
        }))
    }

    /// Lands the vault the plan names at `--data-dir`, in place of the
    /// ordinary open, under the delivered `dek` and the anchor credential
    /// the supervisor handed, off the async workers. Returns the kept vault,
    /// held from here on, and the config a rehearsal's scratch opens with.
    pub(super) async fn land(
        &mut self,
        managed: &ManagedArgs,
        config: &ServeConfig,
        vault_config: oneiron::VaultConfig,
        dek: &[u8; 32],
        anchor: Option<Arc<CustodyAnchorCredentials>>,
    ) -> anyhow::Result<(oneiron::Vault, oneiron::VaultConfig)> {
        self.stage = Stage::Landing;
        let job = Job {
            sink: Arc::clone(&self.sink),
            identity: self.identity.clone(),
            plan: self.plan.clone(),
            host_holds: std::mem::take(&mut self.host_holds),
            destination: Arc::clone(&self.destination),
            data_dir: managed.data_dir.clone(),
            owner: managed.derivation_owner,
            backup: config.backup.clone(),
            anchor,
            dek: Zeroizing::new(*dek),
            vault_config,
        };
        match tokio::task::spawn_blocking(move || job.run()).await {
            Ok(Ok(landed)) => {
                super::vault_gates::warn_if_reader_table_short(&landed.vault);
                self.stage = Stage::Kept;
                self.sink.progress(&self.identity, Phase::StartingService);
                self.kept = Some(Kept {
                    report: landed.report,
                    admission: landed.admission,
                    directory: landed.directory,
                    host_holds: landed.host_holds,
                });
                Ok((landed.vault, landed.rehearsal))
            }
            Ok(Err(refused)) => {
                self.fail(refused.reason, refused.phase, refused.destination);
                Err(refused.error)
            }
            Err(_) => {
                self.fail(
                    RestoreFailureReason::StartupFailed,
                    Phase::Restoring,
                    Destination::Uncertain,
                );
                Err(anyhow::anyhow!(
                    "the cold restore stopped before it returned"
                ))
            }
        }
    }

    /// The plan's fresh escrow recipients, for the carrier watch's first
    /// look (FIX 11851): it seals only to those the begin-check accepted.
    /// Read before [`Self::verified`] spends the restore.
    #[cfg(target_os = "linux")]
    pub(super) fn fresh_recipients(&self) -> &[FreshRecipient] {
        &self.plan.request.fresh
    }

    /// Seals the kept restore's receipt once the start spooled its escrow
    /// reports (`spooled`: the report ids the outbox holds, `None` without
    /// one), and keeps it for `restore_status` from here on.
    pub(super) fn seal_receipt(
        &mut self,
        spooled: Option<&BTreeSet<String>>,
    ) -> anyhow::Result<Arc<RestoreOutcome>> {
        let kept = self
            .kept
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no kept restore to seal a receipt for"))?;
        let context = ReceiptContext {
            identity: &self.identity,
            plan: &self.plan,
            spooled,
            completed_at: oneiron_vault_contract::now_ts(),
            host_holds: kept.host_holds,
        };
        let receipt = receipt::receipt(&context, &kept.report, &kept.admission)?;
        let outcome = Arc::new(RestoreOutcome::new(
            self.identity.clone(),
            serde_json::to_vec(&receipt)?,
        ));
        self.outcome = Some(Arc::clone(&outcome));
        Ok(outcome)
    }

    /// The restore's last step, once the ordinary start's fallible steps
    /// are done and before ctl serves or ready is said: the data directory
    /// checked again to be the one the restore landed, under the kept
    /// vault's lease, then the receipt and `verified` on the result pipe,
    /// which closes after them.
    pub(super) fn verified(mut self, vault: &oneiron::Vault) -> anyhow::Result<()> {
        let (Some(kept), Some(outcome)) = (&self.kept, &self.outcome) else {
            anyhow::bail!("no sealed receipt for the kept restore");
        };
        let (landed, outcome) = (kept.directory, Arc::clone(outcome));
        let leased = vault
            .writer_lease()
            .is_some_and(|lease| lease.validate_directory(self.destination.path()).is_ok());
        let refusal = match self.destination.landed(&self.plan.vault_name) {
            Ok(directory) if directory == landed && leased => None,
            Ok(_) => Some(RestoreDestinationRefusal::Moved),
            Err(refusal) => Some(refusal),
        };
        if let Some(refusal) = refusal {
            let (reason, _) = refusal_wire(&refusal);
            self.fail(reason, Phase::StartingService, Destination::Uncertain);
            anyhow::bail!(
                "the restored data directory was refused before it served: {}",
                refusal.what()
            );
        }
        for frame in ManagedRestoreResultFrame::verified(outcome.identity(), outcome.receipt())? {
            self.sink.send(&frame);
        }
        self.stage = Stage::Done;
        Ok(())
    }

    /// Reports the restore's one failure and marks it done.
    fn fail(&mut self, reason: RestoreFailureReason, phase: Phase, destination: Destination) {
        self.sink
            .failed(Some(&self.identity), reason, phase, destination);
        self.stage = Stage::Done;
    }
}

impl Drop for ManagedRestore {
    fn drop(&mut self) {
        let (reason, phase, destination) = match self.stage {
            Stage::Credentials => (
                RestoreFailureReason::CredentialsRejected,
                Phase::ValidatingInput,
                Destination::Removed,
            ),
            Stage::Landing => (
                RestoreFailureReason::StartupFailed,
                Phase::Restoring,
                Destination::Uncertain,
            ),
            Stage::Kept => (
                RestoreFailureReason::StartupFailed,
                Phase::StartingService,
                Destination::CommittedNotServing,
            ),
            Stage::Done => return,
        };
        self.fail(reason, phase, destination);
    }
}

/// A destination refusal's reason, and what the destination holds after it.
fn refusal_wire(refusal: &RestoreDestinationRefusal) -> (RestoreFailureReason, Destination) {
    match refusal {
        RestoreDestinationRefusal::Unproven(_) => (
            RestoreFailureReason::IsolationUnproven,
            Destination::Removed,
        ),
        RestoreDestinationRefusal::NotFresh => (
            RestoreFailureReason::DestinationNotFresh,
            Destination::Uncertain,
        ),
        RestoreDestinationRefusal::Moved => (
            RestoreFailureReason::DestinationMoved,
            Destination::Uncertain,
        ),
    }
}

/// The restore's blocking work and everything it owns.
struct Job {
    sink: Arc<ResultSink>,
    identity: ManagedRestoreIdentity,
    plan: ManagedRestorePlan,
    host_holds: AdmittedHostOrderHolds,
    destination: Arc<RestoreDestination>,
    data_dir: std::path::PathBuf,
    owner: DerivationOwner,
    backup: crate::config::BackupConfig,
    anchor: Option<Arc<CustodyAnchorCredentials>>,
    dek: Zeroizing<[u8; 32]>,
    vault_config: oneiron::VaultConfig,
}

/// A restore the engine kept.
struct Landed {
    vault: oneiron::Vault,
    rehearsal: oneiron::VaultConfig,
    report: RestoreReport,
    admission: RestoreAdmission,
    directory: (u64, u64),
    host_holds: RestoreHostHoldsStatus,
}

/// A restore refused, as its failure frame names it.
struct Refused {
    reason: RestoreFailureReason,
    phase: Phase,
    destination: Destination,
    error: anyhow::Error,
}

impl Refused {
    /// The engine's refusal, under the managed check's own reason and
    /// destination state where its `finish` step named a refusal the
    /// engine's vocabulary does not have, and with its two numbers where the
    /// artifact's sequence is below the plan's floor.
    fn engine(
        error: RestoreAdmissionError,
        own: Option<(RestoreFailureReason, Destination)>,
    ) -> Self {
        let (reason, destination) = own.unwrap_or_else(|| {
            (
                receipt::refusal_reason(&error),
                receipt::destination_wire(error.destination),
            )
        });
        Self {
            reason,
            phase: receipt::phase_wire(error.phase),
            destination,
            error: anyhow::Error::new(error),
        }
    }
}

/// What the managed checks observed inside the restore, for the steps after
/// them: the managed reason for a refusal and what it leaves at the
/// destination, the directory landed, and where the host-order legal holds
/// installed came from.
#[derive(Default)]
struct Observed {
    refusal: Cell<Option<(RestoreFailureReason, Destination)>>,
    directory: Cell<Option<(u64, u64)>>,
    host_holds: Cell<Option<RestoreHostHoldsStatus>>,
}

impl Job {
    /// The delivered key checked against the plan, the destination's seal
    /// the plan's tier, the custody source beside the artifact under the
    /// plan's anchor, then the engine's restore with the managed checks and
    /// the host-order legal holds, and the commit marker.
    fn run(self) -> Result<Landed, Refused> {
        let Self {
            sink,
            identity,
            plan,
            host_holds,
            destination,
            data_dir,
            owner,
            backup,
            anchor,
            dek,
            mut vault_config,
        } = self;
        let expected = receipt::expectation(&plan.source);
        sink.progress(&identity, Phase::SourceCheck);
        let key = CheckpointKey::from_delivered(&dek, &expected)
            .map_err(|error| Refused::engine(error, None))?;
        // A wake or migrate holds the artifact's signed sequence to the
        // plan's floor (FIX 969); a historical restore takes none.
        let key = match plan.wake_sequence_floor {
            Some(floor) => key.with_wake_sequence_floor(floor),
            None => key,
        };
        // So does the vault's mode-root policy, beside the plan's pins (FIX
        // 968); one that does not read delegates no signer.
        let key = match plan
            .backup_mode_roots
            .as_ref()
            .map(|bytes| oneiron::authority::BackupModeRoots::from_bytes(&bytes.0))
        {
            Some(Ok(roots)) => key.trusting_mode_roots(&roots.policy, &roots.delegations),
            Some(Err(_)) => {
                tracing::warn!(
                    reason = "backup_mode_roots_invalid",
                    "the plan's backup mode roots did not read; they delegate no signer"
                );
                key
            }
            None => key,
        };
        // The family the artifact's member held rides the key with its tag:
        // the restore passes it on only when the tag names that member (FIX
        // 6817). The pipe's live family stays here and wins.
        let AdmittedHostOrderHolds {
            pipe: host_holds,
            artifact,
        } = host_holds;
        let key = match artifact {
            Some(artifact) => key.with_artifact_host_holds(artifact),
            None => key,
        };
        let seal = if plan.maximum_tier {
            key.restored_page_seal()
        } else {
            Ok(None)
        };
        let seal = seal.map_err(|error| {
            let reason = receipt::by_kind(&error);
            Refused::engine(
                RestoreAdmissionError::new(
                    reason,
                    RestorePhase::SourceCheck,
                    RestoreDestinationState::Removed,
                    error,
                ),
                None,
            )
        })?;
        let mut rehearsal = vault_config.clone();
        rehearsal.page_seal = None;
        vault_config.page_seal = seal;
        let recovery = crate::owner::backup::custody_recovery(&plan.artifact, &backup, anchor);
        let observed = Observed::default();
        let finish = |vault: &oneiron::Vault,
                      artifact: Option<&HostOrderHolds>|
         -> Result<(), RestoreAdmissionError> {
            managed_checks(
                vault,
                &destination,
                &plan.vault_name,
                owner,
                &dek,
                &observed,
            )?;
            // The pipe's, else the one the artifact's member held, else none
            // (FIX 6598, FIX 6817).
            let installed = host_holds::install(vault, host_holds.as_ref(), artifact)?;
            observed.host_holds.set(Some(installed));
            Ok(())
        };
        let after_keep = |vault: &oneiron::Vault,
                          facts: &RestoreCommitFacts|
         -> Result<(), RestoreAdmissionError> {
            sink.progress(&identity, Phase::CommitMarker);
            let landed = observed.directory.get().ok_or_else(|| {
                RestoreAdmissionError::new(
                    RestoreAdmissionReason::StartupFailed,
                    RestorePhase::CommitMarker,
                    RestoreDestinationState::CommittedNotServing,
                    oneiron::Error::InvalidConfig(
                        "the restore kept a directory its checks never saw".into(),
                    ),
                )
            })?;
            commit_marker::publish(vault, facts, &destination, landed)
        };
        sink.progress(&identity, Phase::Restoring);
        let (vault, report, admission) = oneiron::Vault::restore_checkpoint_admitted(
            AdmittedRestore {
                artifact: &plan.artifact,
                key: &key,
                destination: &data_dir,
                config: vault_config,
                restored_at: oneiron_vault_contract::now_ts(),
                recovery: &recovery,
                plan: &plan.request,
            },
            finish,
            after_keep,
        )
        .map_err(|error| Refused::engine(error, observed.refusal.get()))?;
        let directory = observed.directory.get().ok_or_else(|| Refused {
            reason: RestoreFailureReason::StartupFailed,
            phase: Phase::StartingService,
            destination: Destination::CommittedNotServing,
            error: anyhow::anyhow!("the restore kept a directory its checks never saw"),
        })?;
        Ok(Landed {
            vault,
            rehearsal,
            report,
            admission,
            directory,
            // `finish` ran before the keep, so it said; not known otherwise.
            host_holds: observed
                .host_holds
                .get()
                .unwrap_or(RestoreHostHoldsStatus::HostHoldsUnknown),
        })
    }
}

/// The managed checks on the vault the restore landed, before its takeover
/// fence, in the order a managed open runs them: the data directory proven
/// isolated through its held parent, the delivered DEK against the vault's
/// sealed MAC (sealed where it carries none), then the derivation owner bound
/// or checked. Only a real mismatch is named one; a failure to read or write
/// keeps its own reason.
fn managed_checks(
    vault: &oneiron::Vault,
    destination: &RestoreDestination,
    vault_name: &str,
    owner: DerivationOwner,
    dek: &[u8; 32],
    observed: &Observed,
) -> Result<(), RestoreAdmissionError> {
    let refuse = |reason, error| {
        RestoreAdmissionError::new(
            reason,
            RestorePhase::Finish,
            RestoreDestinationState::Removed,
            error,
        )
    };
    match destination.landed(vault_name) {
        Ok(directory) => observed.directory.set(Some(directory)),
        Err(refusal) => {
            observed.refusal.set(Some(refusal_wire(&refusal)));
            return Err(refuse(
                RestoreAdmissionReason::StartupFailed,
                oneiron::Error::InvalidConfig(format!(
                    "the restored data directory was refused: {}",
                    refusal.what()
                )),
            ));
        }
    }
    match check_dek_mac(vault, dek) {
        Ok(DekMac::Matched) => {}
        Ok(DekMac::Mismatched) => {
            return Err(refuse(
                RestoreAdmissionReason::ManagedDekMacMismatch,
                oneiron::Error::InvalidConfig(format!(
                    "managed vault {vault_name:?} DEK MAC mismatch: the delivered DEK does not match the one the restored vault was sealed under"
                )),
            ));
        }
        Err(error) => return Err(refuse(receipt::by_kind(&error), error)),
    }
    match vault.bind_derivation_owner_checked(owner) {
        Ok(_) => Ok(()),
        Err(DerivationBindError::Mismatch) => Err(refuse(
            RestoreAdmissionReason::DerivationOwnerMismatch,
            oneiron::Error::InvalidConfig("derivation owner already bound".into()),
        )),
        Err(DerivationBindError::Engine(error)) => Err(refuse(receipt::by_kind(&error), error)),
    }
}
