//! The Dreamer's extraction route: what vault policy must allow before a
//! pass may send a transcript to the configured model.
//!
//! Extraction defaults to the device (ARCH-0036's counter-arrow). A model
//! reached over HTTP is never on the device, so the Dreamer runs only when
//! the owner opts in with `models.extraction_egress = true`. With the opt-in,
//! the vault's purpose defaults are aligned to the seat's widest route and a
//! host predicate admits the Dreamer's own seat model, and nothing else.
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

pub(super) fn align_dreamer_route(
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
    let mut table = vault.purpose_default_table()?;
    let mut changed = false;
    // Without a model manifest, a role-bound call must run at its purpose's
    // default route; the Dreamer's extraction and merge calls ride the seat.
    for purpose in [CallPurpose::Extraction, CallPurpose::Consolidation] {
        if let Some(row) = table.purposes.get_mut(&purpose)
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
        tracing::info!(
            ?locality,
            "aligned the vault's extraction and consolidation defaults to the configured Dreamer seat (models.extraction_egress = true)"
        );
    }
    let seat_model = seat.model.clone();
    let admits = move |request: &LlmRequest| request.model == seat_model;
    Ok(DreamerRoute::Ready(Some(Arc::new(admits))))
}
