//! Doors for `oneiron-server`'s `tests/compaction_seat_exact_model.rs`
//! (FIX-LIST SELF-WRITER-HOUSE-FALLBACK-SEAT-EXACT-REFUSED): one sealed
//! compaction request over a window the test writes, for a pass a host's
//! backend is sent directly. Compiled only under `--cfg oneiron_test_support`;
//! never API.

use crate::compaction::{CompactionRequest, CompactionWindowMessage};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// One request over `texts`, one turn each numbered from 1, on a fresh
/// SESSION id, its summary held to `summary_token_budget` tokens. No row
/// is read, and the request names no source.
///
/// # Errors
///
/// An empty `texts`: a window carries at least one message.
pub fn sealed_window(
    vault: &Vault,
    texts: &[&str],
    summary_token_budget: u64,
) -> Result<CompactionRequest> {
    let window = texts
        .iter()
        .zip(1..)
        .map(|(text, turn)| CompactionWindowMessage {
            message_id: EntityId::now(),
            turn_id: EntityId::now(),
            content: (*text).to_owned(),
            turn,
            tokens: crate::count_context_pack_tokens(text) as u64,
        })
        .collect();
    CompactionRequest::for_test_window(vault, EntityId::now(), window, summary_token_budget)
}
