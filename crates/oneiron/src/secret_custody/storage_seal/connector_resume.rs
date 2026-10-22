//! A connector call's durable resume state at rest (FIX 9157): sealed under
//! the call's own erasable custody key, one per call ref and round
//! generation, opened only by this vault, and retired with its PENDING_CALLS
//! row. The seal reuses the credential value's AEAD and format
//! ([`super::seal_value`], [`super::open_value`]); the keys keep the
//! namespaces apart.

use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Seals `state` for the connector call `call_ref` at `generation` under the
/// vault's own custody (FIX 9157): the call's ConnectorResume leaf, minted in
/// `wtxn` on first use and journaled before this row commits.
#[allow(
    dead_code,
    reason = "the connector call row seals its resume state next (FIX 9157)"
)]
pub(crate) fn seal_connector_resume_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    call_ref: &EntityId,
    generation: u32,
    state: &[u8],
) -> Result<Vec<u8>> {
    let leaf = store.connector_resume_leaf_in_txn(wtxn, call_ref, generation)?;
    super::seal_value(&leaf, call_ref, generation, state)
}

/// Opens what `seal_connector_resume_in_txn` sealed for `call_ref` at
/// `generation`: a strict read; a retired, damaged or missing leaf is an
/// error. The caller holds a writer or the custody read guard.
#[allow(
    dead_code,
    reason = "the connector call row opens its resume state next (FIX 9157)"
)]
pub(crate) fn open_connector_resume_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    call_ref: &EntityId,
    generation: u32,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let _ = txn;
    let leaf = store.read_connector_resume_leaf(call_ref, generation)?;
    super::open_value(&leaf, call_ref, generation, sealed)
}

/// Stages retirement of the connector call `call_ref`'s resume leaves in
/// `wtxn`, the writer that deletes its PENDING_CALLS row; the custody
/// finisher retires the keys after commit, so a restored pre-erase image
/// cannot open them.
#[allow(
    dead_code,
    reason = "the PENDING_CALLS row delete stages its retirement next (FIX 9157)"
)]
pub(crate) fn retire_connector_resume_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    call_ref: &EntityId,
) -> Result<()> {
    store.stage_connector_resume_retirement_in_txn(wtxn, call_ref)
}
