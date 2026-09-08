//! Commitment claim substrate (CMT-1).
//!
//! Commitments are stored as typed `commitment.*` CLAIM entities. CMT-1 keeps
//! the obligation fact, strength tier, status, opaque schedule payload, and
//! birth provenance in one atomic bitemporal claim; schedule evaluation,
//! wakes, and projections are handled by later CMT tickets.

mod codec;
mod lapse_batch;
mod types;
mod write;

#[cfg(test)]
mod codec_tests;
#[cfg(test)]
mod verbs_tests;

pub(crate) use self::codec::validate_commitment_claim_structure;
pub use self::codec::{
    commitment_claim_candidate, decode_commitment_claim, decode_commitment_value,
    encode_commitment_value, is_commitment_claim_predicate,
};
pub(crate) use self::lapse_batch::{lapse_commitments_in_txn, pending_commitment_lapses_in_txn};
pub use self::types::{
    COMMITMENT_CLAIM_PREDICATES, COMMITMENT_VALUE_KEYS, COMMITMENT_VALUE_SCHEMA_VERSION,
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
    FulfillmentSource, PREDICATE_COMMITMENT_RECORD,
};
