//! The ctl dispatcher: every parsed ctl request a managed vault answers.

use oneiron_vault_contract::{CONTRACT_VERSION, CtlRequest, CtlResponse};

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
            }),
            CtlRequest::Shed { cause, waited_secs } => {
                self.guard_write()?;
                crate::managed::shed::shed(self.server.vault(), cause, waited_secs)
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
        }
    }
}
