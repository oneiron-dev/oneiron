//! `vault.coach.training_offers.sources` (FIX 11352): the owner's read of a
//! reservoir scope before he prepares a training run over it. It lists each
//! source the run's corpus would hold to his "I obtained consent" tick (a
//! source with other people, or people that cannot be read) and how many
//! pairs the source check would carry and leave out under the ticks given
//! so far, so he ticks by what he sees. Read only: the prepare route and
//! its consent decision stay as they are.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::edit_distance::reservoir::{
    ReservoirScope, ReservoirSourcePreview, reservoir_source_preview,
};
use crate::memory::MemoryResult;
use crate::{EntityId, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::reservoir_sources::ReservoirSourcesRequest;

/// `vault.coach.training_offers.sources`: the scope's sources a run holds to
/// the owner's tick, and the pairs it would carry and leave out.
///
/// # Errors
/// Every refusal of [`reservoir_source_preview`].
pub fn reservoir_sources_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ReservoirSourcesRequest,
) -> MemoryResult<ReservoirSourcePreview> {
    let scope = ReservoirScope {
        task_classes: input.task_classes,
        since: input.since,
    };
    Ok(reservoir_source_preview(
        vault,
        owner,
        scope,
        &input.consented_sources,
    )?)
}
