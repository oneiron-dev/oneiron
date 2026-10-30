//! `self.use` under a secret grant (FIX 4313): the holder names a grant in
//! place of a handle. The grant is redeemed, on one witnessed vault instant,
//! for the operation's own target; then the use runs exactly as `self.use`
//! does: the same operation table, the same clearing of the value from what
//! came back, the same Gate record (which also names the grant). There is no
//! other dispatch.
//!
//! A table operation redeems the grant at its real send, inside the
//! provider check's door, and that redemption counts the send (FIX 4491):
//! the value sent is the generation the grant pins, and a rotation landing
//! between the admission here and the send refuses as stale, as a connector
//! call's does, so the caller renews and asks again. A connector call carries
//! the grant on its row and redeems it again at every real send, a held send
//! resumed later included, so a stale grant sends nothing.

use serde_json::Value;

use super::{
    SECRET_USE_OPERATIONS, SecretUseConsumed, SecretUseOutcome, SecretUseTarget, SecretUser, Used,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::secret_custody::read_secret_custody_admission_in_txn;
use crate::secret_lease::{SecretGrantCaller, SecretGrantRef, SecretGrantTarget};
use crate::vault::Vault;

impl Vault {
    /// Hands the secret the grant `grant` redeems to `operation`, one of
    /// [`SECRET_USE_OPERATIONS`], with its `arguments`, for `caller`. The
    /// grant must be a door grant for exactly this operation.
    ///
    /// # Errors
    /// [`GateError::InvalidConsentBound`] for an operation the table does not
    /// hold or arguments that are not an object; then as
    /// [`Self::use_secret_grant_with`].
    pub(crate) fn use_secret_grant(
        &self,
        caller: &SecretGrantCaller,
        grant: &EntityId,
        operation: &str,
        arguments: &Value,
    ) -> Result<SecretUseOutcome> {
        let op = SECRET_USE_OPERATIONS
            .iter()
            .find(|op| op.name == operation)
            .ok_or(Error::Gate(GateError::InvalidConsentBound(
                "self.use takes one of its operations, such as slack.auth_test",
            )))?;
        if !arguments.is_object() {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "an operation's arguments are a JSON object",
            )));
        }
        let target = SecretGrantTarget::Operation {
            name: op.name.to_owned(),
        };
        self.use_secret_grant_with(caller, grant, &target, op.name, &mut |used, _| {
            // A consumer blocks on its provider. It runs on a thread of its
            // own, outside whatever async runtime the caller's door is on.
            let answer = std::thread::scope(|scope| {
                scope.spawn(|| (op.consume)(self, used, arguments)).join()
            })
            .unwrap_or_else(|_| Err("the operation stopped before it answered".to_owned()));
            SecretUseConsumed::of_answer(answer)
        })
    }

    /// The use under a grant every target shares: the grant `caller` holds
    /// is read and checked for `target`, counting nothing (a table
    /// operation redeems it at its real send, which counts it; a connector
    /// call counts each real send at its door), and then `consume` runs on
    /// its record with the grant as `caller` presents it, what came back is
    /// cleared of the value, and one Gate record of `operation` is written.
    /// A grant `caller` does not hold reads as unknown and writes no record.
    ///
    /// # Errors
    /// [`SecretError::SecretLeaseNotFound`] for a grant `caller` does not
    /// hold. Then, each with its refused Gate record, the redemption's
    /// refusals ([`Vault::check_secret_grant`]), and for a table operation
    /// its redemption's at the send: [`SecretError::SecretGrantStale`] once
    /// the record rotated after the check, nothing sent.
    pub(crate) fn use_secret_grant_with(
        &self,
        caller: &SecretGrantCaller,
        grant: &EntityId,
        target: &SecretGrantTarget,
        operation: &str,
        consume: &mut dyn FnMut(&SecretUseTarget<'_>, &SecretGrantRef) -> SecretUseConsumed,
    ) -> Result<SecretUseOutcome> {
        let presented = SecretGrantRef::new(*grant, caller.holder());
        let held = self.secret_grant(caller, grant)?;
        let (handle, rec) = {
            let txn = self.store.env.read_txn()?;
            let handle = crate::ports::ShortIdStoreRead::port_short_id_reference(
                &self.store,
                &txn,
                &held.custody,
            )?
            .map(|(short, _)| short);
            let rec = read_secret_custody_admission_in_txn(&self.store, &txn, &held.custody)?;
            (handle, rec)
        };
        let (Some(handle), Some(rec)) = (handle, rec) else {
            return Err(Error::Secret(SecretError::SecretRefNotFound {
                name: held.custody.to_hex(),
            }));
        };
        let used = Used {
            user: SecretUser::new(caller.actor(), caller.actor_class()),
            handle,
            secret: held.custody,
            generation: held.generation,
            operation,
            effector: &held.effector,
            grant: Some(held.grant_id),
            first_intent: None,
        };
        let admitted = self.check_secret_grant(&presented, target).map(drop);
        let granted =
            matches!(target, SecretGrantTarget::Operation { .. }).then_some((presented, target));
        self.use_admitted(&used, &rec.name, admitted, granted, &mut |target| {
            consume(target, &presented)
        })
    }
}
