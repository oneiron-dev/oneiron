//! A granted `reveal.wait` made again by its step, resumed after a park
//! (FIX 2360).

use super::{
    REVEALS, RevealAsker, RevealAuthority, SecretRevealDecision, SecretRevealState,
    SecretRevealWait,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::vault::Vault;

impl Vault {
    /// `reveal.wait` made again by the step that collected it, resumed after
    /// a park (FIX 2360): the value its first wait delivered, read again
    /// under the T1 lease it went out under, for the replayed guest only.
    /// The reveal must be this asker's (agent, project, run, connection),
    /// delivered under `lease` to the provider the host binds now; no grant
    /// is spent, no lease is stamped and no window grows. A lease that lapsed
    /// answers `expired` with no value. A second wait that is no replay stays
    /// [`Self::wait_secret_reveal`]'s, with no value.
    ///
    /// # Errors
    /// [`Error::EntityNotFound`] for another agent's reveal, a file's, or one
    /// not delivered; [`GateError::InvalidConsentBound`] for a lease or a
    /// provider other than the delivery's.
    pub(crate) fn replay_secret_reveal(
        &self,
        asker: &RevealAsker,
        reveal: &EntityId,
        lease: &EntityId,
    ) -> Result<SecretRevealWait> {
        let txn = self.store.env.read_txn()?;
        let row = REVEALS
            .get(&self.store, &txn, reveal)?
            .filter(|row| {
                row.is_agents(&asker.agent)
                    && row.file.is_none()
                    && row.person.is_none()
                    && row.state == SecretRevealState::Delivered
                    && row.project == asker.project
                    && row.run == asker.run
                    && row.connection.as_deref() == Some(asker.connection().as_str())
            })
            .ok_or(Error::EntityNotFound)?;
        if row.lease != Some(*lease) || row.provider != asker.provider {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "the replayed reveal names another lease or provider than its delivery",
            )));
        }
        let authority = RevealAuthority {
            secret: row.secret,
            handle: row.handle.clone(),
            class: row.class()?,
            effector: format!("model:{}", asker.connection()),
        };
        let value =
            crate::secret_lease::reread_reveal_lease_in_txn(self, &txn, &authority, lease)?;
        Ok(SecretRevealWait {
            decision: if value.is_some() {
                SecretRevealDecision::Granted
            } else {
                SecretRevealDecision::Expired
            },
            value,
            receipt: Some(row.receipt(*reveal)?),
        })
    }
}
