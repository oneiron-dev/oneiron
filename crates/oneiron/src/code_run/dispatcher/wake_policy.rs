//! Owner-authorized Dreamer wake-policy action; off-record never writes base.

use super::HostSelfDispatcher;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{SelfDispatchOutcome, SelfWakePolicyWriteCall};
use crate::error::{Error, GateError, Result};

impl HostSelfDispatcher<'_> {
    pub(super) fn dispatch_wake_policy_write(
        &self,
        call: SelfWakePolicyWriteCall,
    ) -> Result<SelfDispatchOutcome> {
        let owner =
            self.owner_proof
                .ok_or(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "wake policy action needs host owner proof",
                )))?;
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Err(Error::InvalidConfig(
                "wake policy action requires a canonical vault".into(),
            ));
        };
        vault.set_dreamer_wake_policy(owner, call.policy)?;
        Ok(SelfDispatchOutcome::WakePolicyWritten(call.policy))
    }
}
