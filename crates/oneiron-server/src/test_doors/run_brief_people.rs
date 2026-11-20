//! Door for `tests/run_brief_roster_off_device.rs`: the PEOPLE roster a
//! pumped run's self brief reads, built as the run's host door builds it,
//! and the rows a held brief's recheck finds fallen, with nothing delivered
//! or recorded.

use std::collections::BTreeSet;

use oneiron::{EdgeActorClass, EntityId, WriteActor};

use crate::server::SyncServer;

/// Each person on agent `agent`'s run brief roster, with the `about` line
/// that brief reads now.
///
/// # Errors
///
/// The roster did not build; the text is the gateway error.
pub fn run_brief_about_lines(
    server: &SyncServer,
    agent: EntityId,
) -> Result<Vec<(EntityId, Option<String>)>, String> {
    let people =
        crate::api::run_brief_people(server, WriteActor::new(agent, EdgeActorClass::Agent))
            .map_err(|error| error.to_string())?;
    Ok(people
        .rows()
        .iter()
        .map(|row| (row.person, row.about.clone()))
        .collect())
}

/// The rows of a brief agent `agent`'s run holds past its boundary, which
/// showed `sources` with `resident` on its roster, that no longer stand
/// now: the recheck the run's self-brief port makes before the held prefix
/// goes again.
///
/// # Errors
///
/// A read failed; the text is the gateway error.
pub fn run_brief_fallen_rows(
    server: &SyncServer,
    agent: EntityId,
    sources: &[EntityId],
    resident: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>, String> {
    crate::api::run_brief_fallen_rows(
        server,
        WriteActor::new(agent, EdgeActorClass::Agent),
        sources,
        resident,
    )
    .map_err(|error| error.to_string())
}
