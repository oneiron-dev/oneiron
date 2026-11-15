//! Door for `oneiron-server/tests/off_record_room_context_pack.rs` (census
//! row L6-12): a context pack assembled in a live stretch through the
//! deferred door, whose stretch flips on record before the pack finishes.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::context_pack::{DEFAULT_MAX_FIELD_CHARS, TokenAllocation};
use crate::error::Result;
use crate::off_record::OffRecordBackendClass;
use crate::serialize::SerializeConfig;
use crate::serialize::pack_format::{FieldProfile, PackFormat};

/// Enters the live stretch `session_key`, assembles a context pack for
/// `query` in it through the deferred door, flips the stretch on record as
/// `owner`, then finishes the pack for a JSON response. Answers with what
/// that finish answered, once the pack's run row can no longer land in the
/// stretch.
///
/// # Errors
///
/// The first failed step before the finish: entering the stretch, the
/// assembly, or the flip.
pub fn finish_stretch_pack_after_flip(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    session_key: &str,
    query: &str,
) -> Result<Result<()>> {
    let session = vault
        .off_record_session_vault()
        .enter(session_key, OffRecordBackendClass::Local)?;
    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    let pack = vault
        .context_pack()
        .search_text(query, 10)
        .in_session(&door)
        .run_unfinalized_with_telemetry()?;
    session.flip_on_record_as(owner)?;
    let projection = SerializeConfig {
        format: PackFormat::Json,
        profile: FieldProfile::Minimal,
        budget: 8192,
        allocation: TokenAllocation::default(),
        include_stats: false,
        merge_neighbors: true,
        max_field_chars: DEFAULT_MAX_FIELD_CHARS,
        max_item_tokens: 0,
    };
    Ok(pack
        .finish_projected_json(&projection, |_| Ok(Vec::new()))
        .map(|_| ()))
}
