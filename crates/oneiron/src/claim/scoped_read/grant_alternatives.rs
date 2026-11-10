//! FIX AGENT-GRAPHFS-GRANT-WORLDS: a credential bound by two or more of its
//! holder's agent Grants reads a row only where one of them, alone, admits
//! the row's whole position (Engine RULING GRANT-COMBINE Q1 = A, 11 Nov
//! 04:30; Grants are never unioned). The key's own Scope is their envelope,
//! so every other check already binds; this adds the one conjunct the
//! envelope cannot answer. A key with one or no Grant binding it carries no
//! alternatives: its own Scope is exact.

use super::ScopedRead;
use crate::EntityId;
use crate::error::Result;
use crate::federation::facet_read::facets_admit_in;

impl ScopedRead<'_> {
    /// Whether the row `raw` of `id` lies inside one of this key's Grant
    /// alternatives alone: its record position as
    /// [`Self::grant_admits_position_in`] judges it under that Scope, and
    /// its facets under that Scope's facets. A key with no alternatives
    /// admits every row here.
    ///
    /// # Errors
    /// A store or decode failure reading the row's position or facets.
    pub(super) fn one_grant_alternative_admits_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let Some(alternatives) = self.actor_key.grant_alternatives() else {
            return Ok(true);
        };
        for alternative in alternatives {
            if !self.grant_admits_position_in(rtxn, id, raw, alternative)? {
                continue;
            }
            let facets = match self.session_view {
                Some(view) => {
                    facets_admit_in(self.vault, view, rtxn, *id, raw, &alternative.facets)?
                }
                None => facets_admit_in(
                    self.vault,
                    &self.vault.store,
                    rtxn,
                    *id,
                    raw,
                    &alternative.facets,
                )?,
            };
            if facets {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
