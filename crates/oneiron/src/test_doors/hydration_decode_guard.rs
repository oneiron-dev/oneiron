//! Door for `tests/hydration_decode_guard.rs` (census L6-30b; ARCH-0069
//! #readers-followups-open, "an isolating check for hydration's decode
//! guard"): hydration's decode of one entity body, called alone, so a test
//! reads its whole-read guard with no write-door check or serializer in front
//! of it. Compiled only under `--cfg oneiron_test_support` (`test_doors`).
//! Hidden; never API. Every assertion stays in the test file: this returns a
//! plain value.

use std::collections::HashMap;

/// The fields hydration decodes from `payload`, an entity body without its
/// metadata header (`context_pack::hydration::decode_entity_fields`):
/// none from a body that reads as a secret whole, `None` when `payload` is
/// not one MessagePack map. `write_accepted`: the write door's scan has read
/// and accepted `payload`.
#[doc(hidden)]
pub fn decode_entity_fields(
    payload: &[u8],
    write_accepted: bool,
) -> Option<HashMap<String, serde_json::Value>> {
    crate::context_pack::decode_entity_fields(payload, write_accepted)
}
