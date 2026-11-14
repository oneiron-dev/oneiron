//! Moved from `crates/oneiron/src/task_verb/ask_record/link_proof.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::task_verb::ask_record::*;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use rand_core::OsRng;
use rand_core::RngCore;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkProof {
    pub token_digest: [u8; 32],
    pub revision: u64,
    pub signature: Vec<u8>,
}

pub const FORWARD_RESULT_TRANSCRIPT: &[u8] = b"oneiron.tasks.ask.forward_result_signature.v1\0";

/// The message a relayed intent's result signature covers (FIX 7494).
pub fn forward_result_message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(FORWARD_RESULT_TRANSCRIPT.len() + body.len());
    message.extend_from_slice(FORWARD_RESULT_TRANSCRIPT);
    message.extend_from_slice(body);
    message
}
