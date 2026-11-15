//! Door for `tests/fingerprint_keep_synced_keys.rs` (PLAN-UC-04 stage 5): the keys peers
//! recompute (a split custody input's part, a custody input witness's part, and a workplace
//! filing's intent), which the engine computes in private code.

use crate::authority::AuthorityEntryHash;
use crate::entity_id::EntityId;
use crate::workspace_roster::JoinSubject;

/// The key part `index` of the split input the request names `digest` of is kept under.
#[must_use]
pub fn custody_input_part_key(digest: &[u8; 32], index: u32) -> [u8; 32] {
    crate::secret_custody::custody_input_part_key_for_test(digest, index)
}

/// The key part `index` of a witness over `request`, `input` and `commitment` is kept under.
#[must_use]
pub fn custody_witness_part_key(
    request: &AuthorityEntryHash,
    input: &[u8; 32],
    commitment: &[u8; 32],
    index: u32,
) -> [u8; 32] {
    crate::secret_custody::custody_witness_part_key_for_test(request, input, commitment, index)
}

/// A workplace filing's intent key for the purpose whose text is `purpose`
/// (`workplace.house`, `workplace.companion` or `workplace.member`); `None` for another text.
#[must_use]
pub fn workplace_join_intent_key(
    purpose: &str,
    room: EntityId,
    subject: &JoinSubject,
) -> Option<String> {
    crate::workspace_roster::workplace_join_intent_key_for_test(purpose, room, subject)
}
