//! K-proof door for code-run digests that existing rows, ids and keys hold.
//! Compiled only under `oneiron_test_support`; never part of the engine API.
#![cfg(oneiron_test_support)]

use crate::attempt_queue::AttemptId;
use crate::code_run::consent::CodeSourceTrust;
use crate::code_run::{self, CodeConsentRunOrigin, live_run};
use crate::code_sandbox::SandboxGuestTier;
use crate::{EntityId, LlmMessage, Result};

/// A code run replay generation's digest of a pending step's MessagePack.
#[must_use]
pub fn pending_step_digest(bytes: &[u8]) -> [u8; 32] {
    code_run::pending_step_bytes_digest_for_test(bytes)
}

/// A code consent binding's digest of the run origin it was admitted for.
#[must_use]
pub fn consent_run_origin_digest(origin: &CodeConsentRunOrigin) -> [u8; 32] {
    code_run::code_consent_run_origin_digest_for_test(origin)
}

/// A code consent site's request digest over a verb call's identity bytes.
#[must_use]
pub fn consent_request_digest(identity: &[u8]) -> [u8; 32] {
    code_run::consent_request_digest_for_test(identity)
}

/// The id of a code emission's admission record.
///
/// # Errors
/// No salt gives an id outside the reserved sentinels.
pub fn emission_record_id(
    tier: SandboxGuestTier,
    source_trust: CodeSourceTrust,
    dreamer_run_id: &str,
    run_ref: &str,
) -> Result<EntityId> {
    code_run::code_emission_record_id_for_test(tier, source_trust, dreamer_run_id, run_ref)
}

/// A leader spawn's slip id over the child's id and the fresh id it signs with.
#[must_use]
pub fn leader_spawn_slip_id(child: EntityId, fresh: EntityId) -> [u8; 32] {
    code_run::spawn_slip_id_for_test(child, fresh)
}

/// A program write's call digest over its verb and its call input's JSON.
#[must_use]
pub fn program_call_digest(verb: &str, input: &[u8]) -> [u8; 32] {
    code_run::program_call_digest_for_test(verb, input)
}

/// A program write's answer digest over its first outcome's MessagePack.
#[must_use]
pub fn program_answer_digest(outcome: &[u8]) -> [u8; 32] {
    code_run::program_answer_digest_for_test(outcome)
}

/// A repo request witness's hex params hash over the params pair's JSON.
#[must_use]
pub fn repo_params_hash(params: &[u8]) -> String {
    code_run::repo_params_hash_for_test(params)
}

/// The id of a team submit's review claim.
///
/// # Errors
/// No salt gives an id outside the reserved sentinels.
pub fn team_review_claim_id(
    leader: AttemptId,
    team: &str,
    output_revision: &str,
) -> Result<EntityId> {
    code_run::review_claim_id_for_test(leader, team, output_revision)
}

/// A live-run credential's digest of its idempotency identity.
#[must_use]
pub fn live_run_credential_digest(principal: &str) -> [u8; 32] {
    live_run::credential_digest_for_test(principal)
}

/// A live-run action's idempotency key, past the caller key's checks.
#[must_use]
pub fn live_run_action_key(issued: &[u8], credential: &[u8; 32], key: &str) -> String {
    live_run::action_key_text_for_test(issued, credential, key)
}

/// A step replay capsule's messages digest; `None` when they do not encode.
#[must_use]
pub fn capsule_messages_digest(messages: &[LlmMessage]) -> Option<[u8; 32]> {
    code_run::messages_digest_for_test(messages)
}
