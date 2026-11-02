//! A granted `reveal.wait` made again by the step that collected it: resumed
//! after a park (FIX 2360), or re-attempted live after its commit (FIX
//! 11683). Either reads the value again under the reveal's own lease: a
//! custody reveal's T1 lease, or the lease a PERSON reveal keeps on its row.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    REVEAL_LEASE_TTL_SECS, REVEALS, RevealAsker, RevealAuthority, RevealRow, SecretRevealDecision,
    SecretRevealState, SecretRevealWait,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::runtime_hooks::InvocationId;
use crate::vault::Vault;

/// What a delivered reveal keeps for the step that collected it (FIX
/// 11683): that step, and when a PERSON reveal's own lease ends. A custody
/// reveal's lease is its T1 lease row, which keeps its own window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RevealCollection {
    /// The code-mode step whose wait collected the value, as its run's
    /// dispatcher named it; `None` when no durable step did.
    step: Option<InvocationId>,
    /// When a PERSON reveal's lease ends: its delivery plus
    /// [`REVEAL_LEASE_TTL_SECS`], the life of a T1 reveal lease. `None` for
    /// a custody reveal.
    person_until: Option<u64>,
}

impl RevealCollection {
    /// A custody reveal collected by `asker`'s step.
    pub(super) const fn custody(asker: &RevealAsker) -> Self {
        Self {
            step: asker.step,
            person_until: None,
        }
    }

    /// A PERSON reveal collected by `asker`'s step at `now`: its lease lives
    /// as a T1 reveal lease does.
    pub(super) const fn person(asker: &RevealAsker, now: u64) -> Self {
        Self {
            step: asker.step,
            person_until: Some(now.saturating_add(REVEAL_LEASE_TTL_SECS)),
        }
    }
}

impl RevealRow {
    /// Whether `asker` is a live re-attempt of the durable step that
    /// collected this reveal, on the provider it went to (FIX 11683): that
    /// step reads the value again under the reveal's lease. Never for another
    /// step, nor for a call no durable step makes.
    pub(super) fn collected_by(&self, asker: &RevealAsker) -> bool {
        self.lease.is_some()
            && self.provider == asker.provider
            && self
                .collected
                .as_ref()
                .and_then(|collected| collected.step)
                .is_some_and(|step| asker.step == Some(step))
    }
}

impl Vault {
    /// `reveal.wait` made again by the step that collected it, resumed after
    /// a park (FIX 2360): the value its first wait delivered, read again
    /// under the lease it went out under, for the replayed guest only. The
    /// reveal must be this asker's (agent, project, run, connection),
    /// delivered under `lease` to the provider the host binds now; no grant
    /// is spent, no lease is stamped and no window grows. A lease that lapsed
    /// answers `expired` with no value. A second wait that is no replay stays
    /// [`Self::wait_secret_reveal`]'s, which reads again only for a live
    /// re-attempt of the same step.
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
        self.reread_delivered_in(&txn, asker, reveal, &row)
    }

    /// A delivered reveal's value read again in `txn` under the lease its row
    /// names, for `asker`, whom the caller matched to the row: `granted` with
    /// the value while the lease holds it, `expired` with none once it lapsed
    /// or outlived its value. Nothing is spent, stamped or extended.
    ///
    /// # Errors
    /// [`Error::EntityNotFound`] for a row that names no lease; the custody
    /// lease's refusals ([`crate::secret_lease`]); a PERSON claim this asker
    /// can no longer read; storage faults.
    pub(super) fn reread_delivered_in(
        &self,
        txn: &heed::RoTxn<'_>,
        asker: &RevealAsker,
        reveal: &EntityId,
        row: &RevealRow,
    ) -> Result<SecretRevealWait> {
        let lease = row.lease.ok_or(Error::EntityNotFound)?;
        let value = match &row.person {
            Some(_) => person_lease_value_in(self, txn, asker, row)?,
            None => {
                let authority = RevealAuthority {
                    secret: row.secret,
                    handle: row.handle.clone(),
                    class: row.class()?,
                    effector: format!("model:{}", asker.connection()),
                };
                crate::secret_lease::reread_reveal_lease_in_txn(self, txn, &authority, &lease)?
            }
        };
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

/// The value a PERSON reveal's own lease still holds (FIX 11683): the claim
/// revision the owner was asked about, read again as its delivery read it,
/// while the lease's window is open. `None` once the window closed, or once
/// that revision no longer stands (changed, unsupported or out of reach), as
/// a T1 lease that outlived its value gives none.
fn person_lease_value_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    asker: &RevealAsker,
    row: &RevealRow,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let until = row
        .collected
        .as_ref()
        .and_then(|collected| collected.person_until);
    let now = vault.store.clock.now_recorded_at();
    if until.is_none_or(|until| now >= until) {
        return Ok(None);
    }
    match super::person::value_in(vault, txn, asker, row) {
        Ok(value) => Ok(Some(value)),
        Err(Error::EntityNotFound) => Ok(None),
        Err(error) => Err(error),
    }
}
