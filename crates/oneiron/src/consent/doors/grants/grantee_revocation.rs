//! A grantee's reduce-only revocation of its own consent Grant.

use super::*;
use crate::EdgeActorClass;

impl Vault {
    /// Revokes one Grant held by the authenticated caller, with the same row transition and receipt
    /// as an owner revoke. Admission, revocation and receipt share one write transaction. Unknown
    /// Grants and Grants held by another actor give the same refusal. Disclosure bounds name no
    /// actor grantee; action bounds (including bypass Grants) match the actor and any pinned class.
    ///
    /// # Errors
    ///
    /// `ConsentOwnerNotAuthenticated` when the caller does not hold the named Grant or it is unknown;
    /// a store error.
    pub fn consent_revocation_as_grantee(
        &self,
        actor: EntityId,
        actor_class: EdgeActorClass,
        grant_ref: &str,
    ) -> Result<ConsentRevocation> {
        let caller = actor.to_hex();
        let caller_class = actor_class.gate_actor_class();
        let key = grant_ref.to_owned();
        let mut wtxn = self.store.env.write_txn()?;
        let row = GRANTS.get(&self.store, &wtxn, &key)?;
        if !grantee_admits(row.as_ref(), &caller, caller_class) {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "this grant is not yours to revoke",
            )));
        }
        let from = row.as_ref().map(|row| row.status);
        match ConsentLifecycle::grant(from, GrantCommand::Revoke) {
            // Unreachable: a missing row never admits above. Refuse as not-held so no path leaks
            // existence.
            GrantStep::Missing => Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "this grant is not yours to revoke",
            ))),
            GrantStep::AlreadyRevoked => {
                let mut revocation = self.repeat_revocation_in_txn(&wtxn, grant_ref)?;
                revocation.revoked_by = Some(caller);
                Ok(revocation)
            }
            GrantStep::Write { .. } => {
                if !revoke_standing_grant_in_txn(&self.store, &mut wtxn, grant_ref)? {
                    return Err(Error::InvariantViolation("the grant table revoked nothing"));
                }
                let receipt = ConsentReceipt::Revoked {
                    decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
                    grant_ref: grant_ref.to_owned(),
                };
                let record = GateDecisionRecord {
                    version: GATE_DECISION_LEDGER_VERSION,
                    decision_id: receipt.decision_id(),
                    created_at: crate::ports::recorded_at_in_txn(&self.store, &mut wtxn)?,
                    outcome: receipt.gate_outcome().to_owned(),
                    reason_codes: vec![receipt.reason_code().to_owned()],
                    receipt_reasons: Vec::new(),
                    system_notices: Vec::new(),
                    actor_class: caller_class.to_owned(),
                    actor_ref: Some(caller.clone()),
                    content_kind: CONSENT_CONTENT_KIND.to_owned(),
                    policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
                    claim_id: None,
                    grant_ref: crate::consent::consent_receipt_grant_ref(&receipt),
                    diff_handle: crate::consent::consent_receipt_diff_handle(&receipt),
                    read_frontier_hash: [0_u8; 32],
                    context: Default::default(),
                    redacted_at: None,
                };
                self.store.append_gate_decision_in_txn(&mut wtxn, &record)?;
                wtxn.commit()?;
                Ok(ConsentRevocation {
                    receipt: Some(receipt),
                    already_revoked: false,
                    revoked_by: Some(caller),
                })
            }
        }
    }
}

/// Whether `caller` may renounce `row`: the row exists, its bound names an actor grantee (an action
/// Grant; a disclosure Grant has none and never admits), and that grantee's ref and, when the Grant
/// records one, class equal the caller's. No audience-membership shortcut.
fn grantee_admits(row: Option<&ConsentGrantRow>, caller: &str, caller_class: &str) -> bool {
    let Some(row) = row else {
        return false;
    };
    let Some(grantee) = row.grant.bound().actor() else {
        return false;
    };
    if grantee.actor_ref() != caller {
        return false;
    }
    grantee.actor_class().is_none_or(|class| class == caller_class)
}
