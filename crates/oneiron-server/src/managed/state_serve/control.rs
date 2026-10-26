//! The ctl dispatcher: every parsed ctl request a managed vault answers.

use std::sync::atomic::Ordering;

use oneiron_vault_contract::artifact_origin::ARTIFACT_INTERNAL_HOST_REVISION;
use oneiron_vault_contract::relay_delete::RELAY_DELETE_REVISION;
use oneiron_vault_contract::settings_paths::SETTINGS_PATHS_REVISION;
use oneiron_vault_contract::slim_control::SLIM_RECOVERY_REVISION;
use oneiron_vault_contract::{
    CONTRACT_VERSION, CtlRequest, CtlResponse, LegalHoldsNotProven, LegalHoldsWire,
};

use super::ManagedState;
use super::admission::WriteKind;
use crate::managed::ManagedError;

impl ManagedState {
    /// This state with `revision`, the vault VM outbox carrier's its
    /// companion reported at boot (FIX 5235), for every `Ping` to carry;
    /// none until set.
    #[must_use]
    pub(in crate::managed) fn with_vm_outbox_revision(mut self, revision: Option<u32>) -> Self {
        *self.vm_outbox_revision.get_mut() = revision.unwrap_or(0);
        self
    }

    /// The vault VM outbox carrier's revision, when it has one now.
    pub(in crate::managed) fn vm_outbox_revision(&self) -> Option<u32> {
        Some(self.vm_outbox_revision.load(Ordering::Relaxed)).filter(|revision| *revision != 0)
    }

    /// The carrier's revision as its companion answered a later look, or
    /// `None` once it did not answer (FIX 6683); returns the one before.
    #[cfg(target_os = "linux")]
    pub(in crate::managed) fn set_vm_outbox_revision(&self, revision: Option<u32>) -> Option<u32> {
        let was = self
            .vm_outbox_revision
            .swap(revision.unwrap_or(0), Ordering::Relaxed);
        Some(was).filter(|revision| *revision != 0)
    }

    /// Dispatches one parsed ctl request.
    ///
    /// [`CtlRequest::validate`] runs first on every request: deserialization
    /// alone does not enforce the wire limits, so an `alarm_due` carrying an
    /// out-of-bounds id or reason tag is refused here rather than reaching the
    /// reconciler.
    pub async fn handle_request(&self, request: CtlRequest) -> Result<CtlResponse, ManagedError> {
        request
            .validate()
            .map_err(|error| ManagedError::CtlRequestRefused {
                reason: error.to_string(),
            })?;
        match request {
            CtlRequest::Ping => Ok(CtlResponse::Ping {
                ok: true,
                vault: self.vault_name.clone(),
                pid: std::process::id(),
                contract_version: CONTRACT_VERSION,
                readiness: self.readiness.clone(),
                // How the browser stands now, read as the last guest start
                // left it (FIX 7670); no state of it turns `ok` false.
                browser: Some(self.server.browser_readiness().snapshot()),
                managed_backup: self.backup_facts.clone(),
                settings_paths_revision: Some(SETTINGS_PATHS_REVISION),
                artifact_internal_host_revision: Some(ARTIFACT_INTERNAL_HOST_REVISION),
                slim_recovery_revision: Some(SLIM_RECOVERY_REVISION),
                vm_outbox_revision: self.vm_outbox_revision(),
                relay_delete_revision: Some(RELAY_DELETE_REVISION),
                engine_instance: Some(self.relay_delete.instance().to_owned()),
            }),
            CtlRequest::Shed {
                cause,
                waited_secs,
                wait_id,
            } => {
                let _admission = self.admit(WriteKind::OwnerWrite)?;
                crate::managed::shed::shed(self.server.vault(), cause, waited_secs, wait_id)
            }
            CtlRequest::PrepareReap => self.prepare_reap().await,
            // The idle reap's attempt goes before the vault thaws, so no
            // answer of it outlives the abort.
            CtlRequest::ReapAbort => {
                self.idle_backup.drop_attempt();
                self.ledger.drop_frozen().await;
                self.unfreeze()?;
                Ok(CtlResponse::Ok { ok: true })
            }
            CtlRequest::AlarmDue { id, reason_tag } => {
                self.record_alarm(id, reason_tag).await;
                Ok(CtlResponse::Ok { ok: true })
            }
            CtlRequest::TrainingPurge => {
                let _admission = self.admit(WriteKind::OwnerWrite)?;
                let training_purge = self.server.vault().training_purge().map_err(|error| {
                    ManagedError::CtlRequestRefused {
                        reason: error.to_string(),
                    }
                })?;
                Ok(CtlResponse::TrainingPurge { training_purge })
            }
            // Recovery reads the token the process already holds and writes
            // nothing, so a vault frozen for reap answers it and stays frozen.
            // Past the challenge's shape, every failure answers `false`, never
            // a generic refusal, so the supervisor asks again.
            CtlRequest::RecoverOwnerSigning { challenge } => {
                let owner_signing_recovered =
                    match self.ledger.prove_owner_signing(&challenge).await {
                        Ok(recovered) => recovered,
                        Err(error) => {
                            tracing::warn!(
                                error = %format!("{error:#}"),
                                reason = "owner_signing_proof_failed",
                                "owner-signing recovery proof failed; the supervisor asks again"
                            );
                            false
                        }
                    };
                Ok(CtlResponse::OwnerSigningRecovered {
                    owner_signing_recovered,
                })
            }
            // A read: a vault frozen for reap answers it and stays frozen. A
            // read that fails answers not proven, never a count of none, so
            // the erase that asked waits.
            CtlRequest::LegalHolds => {
                let legal_holds = match self.server.vault().standing_legal_holds() {
                    Ok(standing) => LegalHoldsWire::Proven { standing },
                    Err(error) => {
                        tracing::warn!(
                            kind = ?error.kind(),
                            reason = "legal_hold_read_failed",
                            "the standing legal holds did not read; answered not proven"
                        );
                        LegalHoldsWire::NotProven {
                            reason: LegalHoldsNotProven::ReadFailed,
                        }
                    }
                };
                Ok(CtlResponse::LegalHolds { legal_holds })
            }
            // A read: a vault frozen for reap answers it and stays frozen. A
            // journal that does not read answers a generic refusal, never "no
            // eligible wait".
            CtlRequest::SlimStatus => crate::managed::shed::slim_status(self.server.vault()),
            // Through the write gate, as `shed`: a vault frozen for reap
            // answers the typed reap pause and stays frozen.
            CtlRequest::Unslim => {
                let _admission = self.admit(WriteKind::OwnerWrite)?;
                crate::managed::shed::unslim(self.server.vault())
            }
            // A read of the cold restore this process kept: it writes nothing
            // and changes no reap state, so a vault frozen for reap answers
            // it too and stays frozen.
            CtlRequest::RestoreStatus { identity, cursor } => {
                let restore_status = crate::managed::restore::RestoreOutcome::status(
                    self.restore.as_deref(),
                    &identity,
                    cursor,
                )?;
                Ok(CtlResponse::RestoreStatus { restore_status })
            }
            // Past the write gate, as `prepare_reap`: it freezes the vault
            // itself, and a frozen vault answers it too.
            CtlRequest::PrepareIdleReap => self.prepare_idle_reap().await,
            // A read under the reap freeze, never through the write gate,
            // which refuses exactly when frozen: it writes no hold and the
            // vault stays frozen.
            CtlRequest::HostOrderHolds {
                identity,
                source,
                cursor,
            } => {
                let host_order_holds = self
                    .host_order_holds(&identity, &source, cursor.as_ref())
                    .await?;
                Ok(CtlResponse::HostOrderHolds { host_order_holds })
            }
            // Past the write gate: a vault frozen for reap answers it
            // `unknown` (`not_ready`) and starts nothing, and an admitted
            // delete counts among the writes in flight until its job ends.
            CtlRequest::RelayDeleteExecute { request } => {
                Ok(self.relay_delete_execute(request).await)
            }
            // A read: a vault frozen for reap answers it and stays frozen.
            CtlRequest::RelayDeleteRechecks { request } => {
                Ok(self.relay_delete_rechecks(request).await)
            }
            // The supervisor's alone; a vault frozen for reap binds nothing.
            CtlRequest::RelayLockerBind { request } => Ok(self.relay_locker_bind(request).await),
            // Reads of the report the freeze holds and its release (FIX
            // 9549): token-authenticated, never through the write gate, so a
            // vault frozen for reap answers them and stays frozen.
            CtlRequest::LedgerPage { request } => Ok(CtlResponse::LedgerPage {
                ledger_page: self.ledger.frozen_page(&request).await?,
            }),
            CtlRequest::LedgerPulled { request } => {
                self.ledger.pulled(&request).await?;
                Ok(CtlResponse::Ok { ok: true })
            }
        }
    }
}
