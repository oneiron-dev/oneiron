//! An ACCESS_GRANT write's grant act (Fable pass 28 R2e; Engine RULING SR-5 ACCESS-GRANT-KIND = A,
//! 16 Nov 02:10): an access grant's row travels between the owner's devices, so every write of it
//! that someone decided signs a grant act of family `AccessGrant` in the writer's transaction,
//! and the row holds on every device with proof, as every Grant row does. Until then its owner's
//! act was a local receipt (L02 kind ruling, 5 Nov), which nothing beyond this install can read.
//!
//! The act follows the row it writes. A live body restates the row: its giving commits to the
//! whole new body, status included, under a terms key fresh for that write
//! ([`super::encode_access_grant_body_keyed`]). So a revoke and a re-grant at the same id
//! (FIX 10962) are givings on one line, and the newest stands; a replayed older row opens no
//! act. An erased body (its principal scrubbed) ends the line.
//!
//! Engine RULING GRANT-ACT-FAILURE-POLICY = A (16 Nov 03:42): the giving of an Active row
//! refuses when this install cannot carry its act (its door loads the install key before its
//! writer opens), and nothing is written. A revoke (any row not Active) and an erase never
//! refuse: each is signed in the writer's transaction when this install can carry it, and is
//! otherwise owed and carried later (`crate::federation::grant_ending`).
//!
//! An engine write by standing policy (a connector witness read grant its landing or repair
//! issues) signs nothing: such a grant reads as derived (pass 28 R4).

use crate::Vault;
use crate::authority::{GrantActBy, GrantActChange, GrantFamily, authority_refused};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{GRANT_ID_ENDED, fresh_grant_terms_key};

use super::{
    AccessGrantStatus, access_grant_terms, decode_live_access_grant_body,
    encode_access_grant_body_keyed,
};

/// Who decided an ACCESS_GRANT row write, as the writer's door judged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessGrantDecider {
    /// The engine, by standing policy: no act. Such a grant reads as derived (pass 28 R4).
    Policy,
    /// The decider the door authenticated: a person; an agent within its own live Grant; or,
    /// for an erase, a rule.
    Act(GrantActBy),
}

impl Vault {
    /// The body to put at the access grant `id` for the write of `data`, which `decider`
    /// decided, with its act signed in the writer's transaction `wtxn` or owed there. A
    /// decided live body comes back keyed by a fresh terms key, which its act commits to; an
    /// erased or policy body comes back as it came.
    ///
    /// The caller judged in `wtxn` that the decider may write these terms (the act's decider is
    /// audit here; the reader judges it again in pass 28 R3).
    ///
    /// # Errors
    /// For an Active body: an id whose line a counted act already ended (an end is forever, so
    /// the row would stand for nothing), or the act's refusal
    /// ([`Vault::append_grant_act_in_txn`]): an install that cannot carry it, more heads than
    /// one entry may name, or an act the fold did not count. Nothing is written then, and the
    /// caller must not commit the row. For any body: a body that fails to decode, or a debt's
    /// own write.
    pub(super) fn access_grant_act_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: Vec<u8>,
        decider: AccessGrantDecider,
    ) -> Result<Vec<u8>> {
        let AccessGrantDecider::Act(by) = decider else {
            return Ok(data);
        };
        let Some(grant) = decode_live_access_grant_body(&data)? else {
            self.end_grant_in_txn(wtxn, by, id, GrantFamily::AccessGrant)?;
            return Ok(data);
        };
        let key = fresh_grant_terms_key();
        let terms = access_grant_terms(id, &grant, &key)?;
        let body = encode_access_grant_body_keyed(&grant, &key)?;
        if grant.status != AccessGrantStatus::Active {
            self.restate_revoked_grant_in_txn(wtxn, by, id, terms)?;
            return Ok(body);
        }
        if self
            .authority_view_readonly_in_txn(wtxn)?
            .grant_line(id)
            .is_some_and(|line| line.ended)
        {
            return Err(authority_refused(GRANT_ID_ENDED));
        }
        self.append_grant_act_in_txn(
            wtxn,
            by,
            id,
            GrantFamily::AccessGrant,
            GrantActChange::Give { terms },
        )?;
        self.settle_owed_restatement_in_txn(wtxn, id)?;
        Ok(body)
    }
}
