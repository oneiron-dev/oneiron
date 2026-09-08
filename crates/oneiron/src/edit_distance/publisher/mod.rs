//! ED-08 (ONE-1764, ARCH-0056 §9 · OF-401): the publisher loop's engine
//! substrate — content-free issue signatures UP, an ordinary comm channel as
//! the transport, and interview digests that ride ED-00/ED-01's doors.
//!
//! # Content-freedom is structural, not a naming convention
//!
//! ARCH-0056 §9's rung-1 row is safe to default on "because the leak is
//! structurally impossible, not checkbox-prevented". That claim only holds if
//! free text has nowhere to sit. [`IssueSignature`] therefore has PRIVATE
//! fields and exactly one door — [`IssueSignature::new`] — and every one of
//! its arguments is a shape that cannot carry a message:
//!
//! | field | why text cannot enter |
//! |---|---|
//! | `category` | [`IssueCategory`], a closed enum — not a string |
//! | `artifact` | [`EntityId`], 16 opaque bytes |
//! | `version` | `u32` |
//! | `model_id` | must parse as a [`ModelStackId`] AND be registered in the caller's [`ModelStackRegistry`]; an unknown id is refused, so "model id" is not a smuggling channel |
//! | `counts` | keys are [`CountKey`], a closed enum; values are `u32` |
//! | `content_hash` | exactly [`CONTENT_HASH_LEN`] lowercase hex characters |
//!
//! The honest bound: `content_hash` is caller-supplied, so an in-vault caller
//! that wanted to could stuff 32 bytes into it. That is a fixed-width opaque
//! field, not a text channel, and a caller who can call this door is already
//! inside the vault — the guarantee this door makes is that no free-form,
//! variable-length content can cross, which is what the rung-1 consent posture
//! was ratified against. Stating the bound beats implying a stronger one.
//!
//! # Counts are tallies, never deltas
//!
//! Rung 1 carries "counts, pattern hashes. NEVER text, NEVER deltas". So
//! [`CountKey`] is the three-arm tally of [`ProposalOutcome`] — how many judged
//! outcomes, how many the human had to amend, how many the human threw away —
//! and deliberately NOT the edit mass in [`OpsSummary`](super::delta::OpsSummary)
//! (`ins`/`del`/`kept`/`d_norm`). Those numbers ARE the delta; they stay home.
//!
//! # The channel is nothing new
//!
//! ARCH-0056 r7: "publisher ↔ user channel = a normal comm channel with the
//! publisher ACTOR as counterparty — zero new primitives". This module calls
//! [`resolve_or_create_comm_party`] and [`record_comm_send_receipt`] and owns
//! nothing about send or retry; SPINE-COMM owns those internals. The DOWN
//! direction (platform-voice notices, EC-7) is ordinary channel content and
//! needs no engine surface at all.
//!
//! # The dial is a dial
//!
//! Dial off means signatures are still computed and stored locally and nothing
//! is sent — the local ledger keeps working, only the outbound hop stops. The
//! withheld fact is durable ([`SignatureSendState::Withheld`]) rather than
//! merely returned, because a skip nobody can read afterwards is not a skip
//! anyone can audit.
//!
//! Outbound consent rails already ride the comm send path (`disclosure.rs`),
//! so this module adds no second consent check.

use crate::Vault;
use crate::comm::CommError;
use crate::error::{Error, Result};

mod dial;
mod interview;
mod signature;
mod signature_store;
mod transport;
mod vocab;

pub use self::dial::{
    PUBLISHER_ENABLED_COMPILED_DEFAULT, PUBLISHER_ENABLED_KEY, PUBLISHER_INSTALL_DEFAULT_KEY,
    publisher_enabled, set_publisher_enabled, set_publisher_install_default,
};
pub use self::interview::{
    InterviewSession, InterviewState, interview_session, submit_interview_for_review,
};
#[cfg(feature = "sync")]
pub use self::interview::{open_interview, settle_interview_digest};
pub use self::signature::{CONTENT_HASH_LEN, IssueSignature, tally_judged_outcomes};
pub use self::signature_store::{emit_issue_signature, issue_signature};
pub use self::transport::{
    PUBLISHER_CHANNEL_CLASS, PUBLISHER_PARTY_KEY, SendOutcome, SignatureSendState, publisher_party,
    send_signatures_if_enabled, signature_send_state,
};
pub use self::vocab::{CountKey, IssueCategory};

#[cfg(feature = "sync")]
use crate::edit_distance::register_peer_actor;

#[cfg(test)]
mod tests;

// The flat publisher.rs module used to provide these names to the sibling test
// module through `use super::*`: the publisher-internal items the tests name
// bare. After the directory split the seam re-imports them so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use self::signature_store::signature_key;
#[cfg(test)]
use crate::identity_topology::ProposalOutcome;
#[cfg(test)]
use crate::receipt::ReceiptRecord;
#[cfg(test)]
use crate::skill_attribution::AttributionVerdict;
#[cfg(feature = "sync")]
#[cfg(test)]
use crate::write_envelope::WriteActor;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed error for the publisher loop's doors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PublisherError {
    /// Underlying vault operation failed.
    #[error(transparent)]
    Engine(#[from] Error),
    /// The comm doors this module rides refused.
    #[error(transparent)]
    Comm(#[from] CommError),
    /// The offered model id is not a stack the caller's registry serves —
    /// either it is not a well-formed [`ModelStackId`] at all, or it names no
    /// registered stack. One fact, one error: it is not a model this vault
    /// knows, and an unknown model id is how free text would get out.
    #[error("issue signature model id is not a registered model stack")]
    UnknownModelStack,
    /// The same [`CountKey`] was offered twice. The keys are closed, so a
    /// repeat is the only shape left for smuggling a second value under one
    /// name.
    #[error("issue signature repeats a count key")]
    DuplicateCountKey,
    /// `content_hash` was not exactly [`CONTENT_HASH_LEN`] lowercase hex
    /// characters.
    #[error("issue signature content hash is not fixed-length lowercase hex")]
    MalformedContentHash,
    /// A signature id was offered to the send door with no stored record
    /// behind it.
    #[error("issue signature not found")]
    SignatureNotFound,
}

/// Result alias for the publisher loop's doors.
pub type PublisherResult<T> = std::result::Result<T, PublisherError>;

fn put_meta(vault: &Vault, key: &[u8], value: &[u8]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, key, value)?;
        Ok(())
    })
}
