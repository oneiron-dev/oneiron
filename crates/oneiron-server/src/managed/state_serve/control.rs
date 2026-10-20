//! The ctl dispatcher: every parsed ctl request a managed vault answers.

use oneiron_vault_contract::artifact_origin::ARTIFACT_PUBLIC_SLUG_REVISION;
use oneiron_vault_contract::settings_paths::SETTINGS_PATHS_REVISION;
use oneiron_vault_contract::slim_control::SLIM_RECOVERY_REVISION;
use oneiron_vault_contract::{
    CONTRACT_VERSION, CtlRequest, CtlResponse, LegalHoldsNotProven, LegalHoldsWire,
};

use super::ManagedState;
use crate::managed::ManagedError;

impl ManagedState {
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
                managed_backup: self.backup_facts.clone(),
                settings_paths_revision: Some(SETTINGS_PATHS_REVISION),
                artifact_public_slug_revision: Some(ARTIFACT_PUBLIC_SLUG_REVISION),
                slim_recovery_revision: Some(SLIM_RECOVERY_REVISION),
            }),
            CtlRequest::Shed {
                cause,
                waited_secs,
                wait_id,
            } => {
                self.guard_write()?;
                crate::managed::shed::shed(self.server.vault(), cause, waited_secs, wait_id)
            }
            CtlRequest::PrepareReap => self.prepare_reap().await,
            CtlRequest::ReapAbort => {
                self.unfreeze()?;
                Ok(CtlResponse::Ok { ok: true })
            }
            CtlRequest::AlarmDue { id, reason_tag } => {
                self.record_alarm(id, reason_tag).await;
                Ok(CtlResponse::Ok { ok: true })
            }
            CtlRequest::TrainingPurge => {
                self.guard_write()?;
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
                self.guard_write()?;
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
        }
    }
}
