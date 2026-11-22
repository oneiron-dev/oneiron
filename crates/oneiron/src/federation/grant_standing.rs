//! Whether a Grant row stands (Fable pass 28, DESIGN 3.1): what the verified fold's counted
//! acts say of it, never the row alone. A row gives nothing by itself.
//!
//! [`StandingGrant`] is the witness a conferring reader takes. Only
//! [`Vault::standing_grant_in_txn`] builds one, so a reader that takes it cannot confer from a
//! row the fold does not stand behind. A row that does not stand is skipped, never an error,
//! so a forged row cannot block a reader either.
//!
//! The readers move to it in pass 28 R3, each with the hand-written guard it replaces; the
//! Grant kinds with no act of their own before R2 get the general grant act, whose giving
//! commits to the row's terms under the row's own terms key; own-device and engine-default
//! Grants are read as derived in R4.

use crate::Vault;
use crate::authority::{AuthorityEntryHash, GrantFamily};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::{FederationGrant, decode_federation_grant_body_keyed};

/// A Grant the verified fold stands behind: its row, and the counted act that gives it.
#[derive(Debug, Clone)]
pub(crate) struct StandingGrant {
    id: EntityId,
    grant: FederationGrant,
    act: AuthorityEntryHash,
}

#[allow(dead_code, reason = "pass 28 R3's conferring readers take the witness")]
impl StandingGrant {
    /// The FEDERATION_GRANT row's id.
    pub(crate) fn id(&self) -> EntityId {
        self.id
    }

    /// The Grant as its row holds it, which is what its act states.
    pub(crate) fn grant(&self) -> &FederationGrant {
        &self.grant
    }

    /// The counted act that gives the Grant.
    pub(crate) fn act(&self) -> &AuthorityEntryHash {
        &self.act
    }
}

impl Vault {
    /// What the Grant row `id` of `family` confers at `now`, read in `txn`: the row, when it
    /// is live, decodes, has not expired, is given in `family` and is exactly what the one
    /// counted act that gives it states (a general grant act's commitment opens with the row's
    /// own terms key), and no counted act ended it. `None` for every other row: one no counted
    /// act gives (a forged row), one put again after its end, one whose terms are not its
    /// act's, one that two acts the fold cannot order both give, and one given in another
    /// family.
    ///
    /// The reader names the family it reads and judges the giver by that family's own rule.
    /// A row's shape does not tell its family (a house link and a member row are both
    /// `FederationGrant::new` rows; a base agent's Steward Grant and a house's steward link
    /// can match), so the family is the act's, never the row's.
    ///
    /// # Errors
    ///
    /// A store or authority-fold read failure; never a row that does not stand.
    pub(crate) fn standing_grant_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        family: GrantFamily,
        now: u64,
    ) -> Result<Option<StandingGrant>> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(None);
        };
        let Ok((grant, terms_key)) = decode_federation_grant_body_keyed(&body) else {
            return Ok(None);
        };
        // Expiry alone: what a live Grant then confers (a verb, a class, a git push) is
        // its reader's, so `FederationGrant::is_live_at`, Access's predicate, is not
        // asked here (it refuses every git push Grant and a class-only scope).
        if grant.expires_at.is_some_and(|expires_at| now >= expires_at) {
            return Ok(None);
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let Some(line) = fold
            .grant_line(id)
            .filter(|line| !line.ended && line.family == Some(family))
        else {
            return Ok(None);
        };
        let Some((act, terms)) = &line.giving else {
            return Ok(None);
        };
        Ok(terms
            .matches_row(id, &grant, terms_key.as_ref())
            .then_some(StandingGrant {
                id,
                grant,
                act: *act,
            }))
    }
}
