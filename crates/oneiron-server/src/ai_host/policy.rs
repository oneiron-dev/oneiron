//! The Dreamer's extraction route: what vault policy must already allow
//! before a pass may send a transcript to the configured model.
//!
//! Extraction defaults to the device (ARCH-0036's counter-arrow), and a model
//! reached over HTTP is never on the device. So two owner acts must both be
//! there, and the server makes neither on its own: `models.extraction_egress
//! = true` (the host predicate, which then admits only the Dreamer's own seat
//! model), and vault defaults that route extraction and consolidation to the
//! seat's widest rung within the owner's extraction bound. The second is the
//! owner's edit of the vault table, through `oneiron dreamer grant
//! --extraction-route` or `PUT /v1/llm/defaults`; boot only reads it, so a
//! later owner tightening is never undone by a restart.
use std::sync::Arc;

use oneiron::llm::ExtractionEgressPredicate;
use oneiron::{CallPurpose, LlmRequest, ModelLocality, Vault};

use super::status::IdleReason;
use crate::models::Seat;

pub(super) enum DreamerRoute {
    Ready(Option<Arc<dyn ExtractionEgressPredicate>>),
    Blocked(IdleReason),
}

const fn rank(locality: ModelLocality) -> u8 {
    match locality {
        ModelLocality::OnDevice => 0,
        ModelLocality::OwnServer => 1,
        ModelLocality::ThirdParty => 2,
    }
}

/// The Dreamer's purposes: transcript extraction and conflict merges.
const DREAMER_PURPOSES: [CallPurpose; 2] = [CallPurpose::Extraction, CallPurpose::Consolidation];

pub(super) fn dreamer_route(
    vault: &Vault,
    seat: &Seat,
    allow_egress: bool,
) -> oneiron::Result<DreamerRoute> {
    let locality = seat.locality;
    if locality == ModelLocality::OnDevice {
        return Ok(DreamerRoute::Ready(None));
    }
    if !allow_egress {
        return Ok(DreamerRoute::Blocked(
            IdleReason::ExtractionEgressNotAllowed,
        ));
    }
    let table = vault.purpose_default_table()?;
    let routed = DREAMER_PURPOSES.iter().all(|purpose| {
        table
            .purposes
            .get(purpose)
            .is_some_and(|row| row.locality == locality)
    }) && rank(table.extraction_max_locality) >= rank(locality);
    if !routed {
        return Ok(DreamerRoute::Blocked(IdleReason::ExtractionRouteNotSet));
    }
    let seat_model = seat.model.clone();
    let admits = move |request: &LlmRequest| request.model == seat_model;
    Ok(DreamerRoute::Ready(Some(Arc::new(admits))))
}

/// The owner's edit behind `oneiron dreamer grant --extraction-route`: routes
/// the Dreamer's purposes to `locality` and raises the extraction bound to
/// it if lower. Returns whether the table changed.
pub(crate) fn route_dreamer_extraction(
    vault: &Vault,
    locality: ModelLocality,
) -> oneiron::Result<bool> {
    let mut table = vault.purpose_default_table()?;
    let mut changed = false;
    for purpose in &DREAMER_PURPOSES {
        if let Some(row) = table.purposes.get_mut(purpose)
            && row.locality != locality
        {
            row.locality = locality;
            changed = true;
        }
    }
    if rank(table.extraction_max_locality) < rank(locality) {
        table.extraction_max_locality = locality;
        changed = true;
    }
    if changed {
        vault.set_purpose_default_table(&table)?;
    }
    Ok(changed)
}
