//! Whether a companion profile reader's own credential keeps out the world
//! its read names or one of the snapshot's recorded sources (FIX 11174,
//! 8141). A source is kept out when its world lies outside the credential's
//! world ceiling, or when its record, where one still stands, is kept from a
//! caller off this device or lies outside the facets the credential is
//! limited to. Only such a positive exclusion counts: a judgement that cannot
//! be read keeps the read as it was, and the relationship gate, which the
//! profile's own grant stands in for, is not asked.

use super::ScopedRead;
use crate::EntityId;
use crate::error::Result;
use crate::psych_profile::PsychProfileSource;

impl ScopedRead<'_> {
    /// Whether this read's credential keeps out `world`, the world a profile
    /// read names (`None` names none), or any of `sources`, judged in `txn`.
    pub(crate) fn companion_profile_excluded_in(
        &self,
        txn: &heed::RoTxn<'_>,
        world: Option<EntityId>,
        sources: &[PsychProfileSource],
    ) -> bool {
        if world.is_some() && matches!(self.world_readable_in(txn, world), Ok(false)) {
            return true;
        }
        sources.iter().any(|source| {
            matches!(
                self.companion_profile_source_excluded_in(txn, source),
                Ok(true)
            )
        })
    }

    /// Whether this read's credential keeps out `source`: its world, then
    /// its record where a live row still stands under it.
    fn companion_profile_source_excluded_in(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &PsychProfileSource,
    ) -> Result<bool> {
        if !self.world_readable_in(txn, source.world_ref)? {
            return Ok(true);
        }
        let document = &source.document_ref;
        let Some(raw) = self.vault.get_raw_in(txn, document)? else {
            return Ok(false);
        };
        Ok(self.device_withholds_in(txn, document, None)?
            || !self.facets_allow_in(txn, document, &raw)?)
    }
}
