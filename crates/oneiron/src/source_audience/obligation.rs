//! The source-audience obligation's authority (fix list row 16256): the
//! proof a source landing holds to stamp the obligation on the rows it
//! lands, and the reading of a row's own stamp.
//!
//! The obligation is one engine-owned key in a bound row's own body
//! ([`crate::store::source_audience_obligation`]). A row a source landed
//! carries it from its first byte, so the judge knows it as a source's row
//! whatever its kind and whatever has arrived beside it. Only a writer that
//! holds a [`SourceAudienceBirth`] stamps it; every other door refuses it.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::store::source_audience_obligation::{
    SourceAudienceObligation, decode_source_audience_obligation,
};
use crate::{EntityId, Vault};

use super::{POLICIES, SourceAudienceKind, SourceAudiencePolicy};

/// The proof that a source landing writes under a live source policy: the
/// one capability that stamps the source-audience obligation on a row. It
/// names the source policy and nothing a read decides by: no reader, no
/// share, no revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceAudienceBirth {
    source: EntityId,
}

impl SourceAudienceBirth {
    /// The proof for a landing under the source policy `source`, read in
    /// `txn`: the policy exists there and is a source's, not a thread's.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] for a policy `txn` does not hold, and
    /// [`Error::InvalidConfig`] for a thread policy.
    pub(crate) fn mint_in(vault: &Vault, txn: &heed::RoTxn<'_>, source: &EntityId) -> Result<Self> {
        match POLICIES.get(&vault.store, txn, source)? {
            Some(SourceAudiencePolicy {
                kind: SourceAudienceKind::Source { .. },
                ..
            }) => Ok(Self { source: *source }),
            Some(_) => Err(Error::InvalidConfig(
                "a source landing writes under a source policy".into(),
            )),
            None => Err(Error::EntityNotFound),
        }
    }
}

/// The obligation the entity row `raw` states in its own body, whatever its
/// kind. A row with no readable header states none.
pub(crate) fn row_obligation(raw: &[u8]) -> SourceAudienceObligation {
    if EntityMetadataHeader::parse(raw).is_none() {
        return SourceAudienceObligation::Absent;
    }
    decode_source_audience_obligation(raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default())
}
