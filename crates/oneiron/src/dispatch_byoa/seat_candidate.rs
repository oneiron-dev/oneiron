//! A seat as an ordered route's candidate (FIX 7505): a CLI seat whose argv
//! cannot carry the work's task is passed over and named, and the route goes
//! on to its next seat, instead of the whole route failing on it.
//!
//! Only the ordered searches ask here: a NextSeat bind, the automatic
//! hand-off and a resume's NextSeat search. A direct dispatch and an explicit
//! seat keep the connector's own refusal. The rule a run's argv is held to
//! is unchanged: a candidate is judged by the same validator its dispatch
//! and execution use.

use crate::checkout::CheckoutId;
use crate::error::{ArtifactError, Error};

use super::connector::ByoaConnectorSpec;
use super::error::{ByoaError, ByoaResult, ERR_ARGV_ENTRY};
use super::provider::ProviderAdapterRegistry;
use super::seat::RunnerSeat;
use super::validate::validate_connector;

/// The connector `seat` would run the work on: its adapter's connector,
/// judged by the dispatch validator before any custody is claimed for it,
/// a custom adapter's included. `None` when its CLI argv cannot carry the
/// task: a control character in it. An unknown runner and
/// every other refusal stand.
///
/// # Errors
/// Every refusal but a CLI argv's shape.
pub(super) fn runner_seat_candidate(
    seat: &RunnerSeat,
    registry: &ProviderAdapterRegistry,
    task: String,
    checkout_id: CheckoutId,
) -> ByoaResult<Option<ByoaConnectorSpec>> {
    let candidate = seat
        .connector(registry, task, checkout_id)
        .and_then(|connector| validate_connector(&connector).map(|()| connector));
    match candidate {
        Ok(connector) => Ok(Some(connector)),
        Err(error) if cli_argv_shape(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether `error` is the CLI validator's refusal of an argv's shape.
fn cli_argv_shape(error: &ByoaError) -> bool {
    matches!(
        error,
        ByoaError::Store(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(reason)))
            if *reason == ERR_ARGV_ENTRY
    )
}
