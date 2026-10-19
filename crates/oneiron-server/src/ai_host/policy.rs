//! The Dreamer's extraction route: what vault policy must already allow
//! before a pass may send a transcript to the configured model.
//!
//! Extraction defaults to the device (ARCH-0036's counter-arrow), and a model
//! reached over HTTP is never on the device. So two owner acts must both be
//! there, and the server makes neither on its own: `models.extraction_egress
//! = true` (the host predicate, which then admits only the model each pass
//! selected: the Dreamer's seat, or the extraction teacher the vault's model
//! manifest pins), and vault defaults that route extraction and consolidation
//! to that model's route (the seat's widest rung, or the route the teacher is
//! served at) within the owner's extraction bound. The second is the
//! owner's edit of the vault table, through `oneiron dreamer grant
//! --extraction-route` or `PUT /v1/llm/defaults`; boot only reads it, so a
//! later owner tightening is never undone by a restart.
use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::dreamer_consolidation::DREAMER_VERDICT_ROLE;
use oneiron::llm::ExtractionEgressPredicate;
use oneiron::llm::manifest::ModelRole;
use oneiron::{CallPurpose, LlmRequest, ModelId, ModelLocality, Vault};

use super::status::IdleReason;

pub(super) enum DreamerRoute {
    /// `egress`: the owner lets extraction leave the device.
    Ready {
        egress: bool,
    },
    Blocked(IdleReason),
}

const fn rank(locality: ModelLocality) -> u8 {
    match locality {
        ModelLocality::OnDevice => 0,
        ModelLocality::OwnServer => 1,
        ModelLocality::ThirdParty => 2,
    }
}

/// The Dreamer's purposes: transcript extraction, conflict merges and an
/// agent's free time. The autonomy labels have no defaults row of their own
/// (they are admitted on extraction's), so the grant finds none to route.
const DREAMER_PURPOSES: [CallPurpose; 4] = [
    CallPurpose::Extraction,
    CallPurpose::Consolidation,
    CallPurpose::AutonomyForHuman,
    CallPurpose::AutonomyOwnTime,
];

/// The purpose a Dreamer role's calls go out under: the verdict is a
/// consolidation call; extraction and narrative send transcript text, as an
/// extraction does.
pub(super) fn dreamer_role_purpose(role: ModelRole) -> CallPurpose {
    if role == DREAMER_VERDICT_ROLE {
        CallPurpose::Consolidation
    } else {
        CallPurpose::Extraction
    }
}

/// `routes`: each Dreamer role's purpose, and where the model a pass calls
/// that role on is served. A role off the device needs the owner's egress
/// and a default for its purpose at its route, within the extraction bound.
pub(super) fn dreamer_route(
    vault: &Vault,
    routes: &[(CallPurpose, ModelLocality)],
    allow_egress: bool,
) -> oneiron::Result<DreamerRoute> {
    let remote = routes
        .iter()
        .filter(|(_, locality)| *locality != ModelLocality::OnDevice)
        .collect::<Vec<_>>();
    if remote.is_empty() {
        return Ok(DreamerRoute::Ready {
            egress: allow_egress,
        });
    }
    if !allow_egress {
        return Ok(DreamerRoute::Blocked(
            IdleReason::ExtractionEgressNotAllowed,
        ));
    }
    let table = vault.purpose_default_table()?;
    let routed = remote.iter().all(|(purpose, locality)| {
        table
            .purposes
            .get(purpose)
            .is_some_and(|row| row.locality == *locality)
            && rank(table.extraction_max_locality) >= rank(*locality)
    });
    if !routed {
        return Ok(DreamerRoute::Blocked(IdleReason::ExtractionRouteNotSet));
    }
    Ok(DreamerRoute::Ready { egress: true })
}

/// One pass's nonlocal-extraction authority: the models that pass selected
/// for its roles, and no other.
pub(super) fn extraction_egress(models: BTreeSet<ModelId>) -> Arc<dyn ExtractionEgressPredicate> {
    Arc::new(move |request: &LlmRequest| models.contains(&request.model))
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
