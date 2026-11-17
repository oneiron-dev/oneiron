//! A reaction claim names its reactor twice: `by` in its value and the writer
//! stamp in its evidence, and its birth names its writer. A scoped read serves
//! them only to a reader who may read the reactor's PERSON row: "an id must
//! not reach a reader who may not read the reactor's PERSON row, by any door"
//! (FIX REACTION-CLAIM-VALUE-REACTOR-ID; Engine ANSWER = A, 17 Nov 07:32). Any
//! other reader gets the claim with both read as nil, and the reaction still
//! counts.
//! Every door that serves a stored claim's bytes, a decoded claim or a row's
//! birth to a scoped reader judges here; the JSON doors null each binary, so a
//! served value or evidence never spells an id (`msgpack_value_projection`).
use super::*;
use crate::claim::reaction_record::{
    PREDICATE_CONVERSATION_REACTION, named_reactor, withhold_reactor,
};

impl ScopedRead<'_> {
    /// Whether this lane may not read the reactor `claim` names. The lane is
    /// judged under its own request, as a door that names none resolves it,
    /// and the authority that request holds, as its reaction pills judge a
    /// reactor: a door's narrower request never withholds a reactor the lane
    /// reads. A claim that is no reaction names no reactor to withhold.
    pub(crate) fn reaction_reactor_withheld_in(
        &self,
        txn: &heed::RoTxn<'_>,
        claim: &ClaimBody,
    ) -> Result<bool> {
        let Some(reactor) = named_reactor(claim) else {
            return Ok(false);
        };
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        let authority = self.held_for(None);
        Ok(!self.is_entity_readable_held_in(txn, &policy, &reactor, &filter, &authority)?)
    }

    /// `claim` as this lane serves it: without its reactor when the lane may
    /// not read them, else whole.
    pub(super) fn redact_reaction_claim_in(
        &self,
        txn: &heed::RoTxn<'_>,
        mut claim: ClaimBody,
    ) -> Result<ClaimBody> {
        if self.reaction_reactor_withheld_in(txn, &claim)? {
            withhold_reactor(&mut claim);
        }
        Ok(claim)
    }

    /// `raw`, a stored row (header and body) as this lane serves it: a
    /// reaction claim whose reactor the lane may not read leaves without
    /// them; every other row, and a body that does not decode, is unchanged.
    pub(super) fn redact_reaction_row_in(
        &self,
        txn: &heed::RoTxn<'_>,
        mut raw: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let claim = reaction_claim_body(&raw)
            .and_then(|body| crate::claim::decode_claim_body(body, true).ok());
        let Some(mut claim) = claim else {
            return Ok(raw);
        };
        if !self.reaction_reactor_withheld_in(txn, &claim)? {
            return Ok(raw);
        }
        withhold_reactor(&mut claim);
        let served = crate::claim::encode_claim_body(&claim)?;
        raw.truncate(ENTITY_METADATA_HEADER_LEN);
        raw.extend_from_slice(&served);
        Ok(raw)
    }

    /// Whether this lane serves the birth of the row `id`. A reaction claim's
    /// birth names its writer, the reactor of a first-party reaction, so it is
    /// served only to a reader who may read the reactor; any other row's is.
    pub(crate) fn serves_birth_of_in(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let Some(raw) = self.entity_record_in(txn, id)?.map(|row| row.encode()) else {
            return Ok(true);
        };
        let claim = reaction_claim_body(&raw)
            .and_then(|body| crate::claim::decode_claim_body(body, true).ok());
        let Some(claim) = claim else {
            return Ok(true);
        };
        Ok(!self.reaction_reactor_withheld_in(txn, &claim)?)
    }
}

/// The body of `raw` when it is a CLAIM whose bytes spell the reaction
/// predicate: the claim codec stores the predicate as its text, so no other
/// claim is decoded here.
fn reaction_claim_body(raw: &[u8]) -> Option<&[u8]> {
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return None;
    }
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..)?;
    let predicate = PREDICATE_CONVERSATION_REACTION.as_bytes();
    body.windows(predicate.len())
        .any(|window| window == predicate)
        .then_some(body)
}
