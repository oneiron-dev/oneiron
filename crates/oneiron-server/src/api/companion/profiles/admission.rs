//! The companion profile read through its one-snapshot admission (FIX
//! 8141): the grant, the profile and the owner's recipient choice are read
//! together by the engine, for the request's authenticated principal and
//! the destination its connection proved.

use oneiron::companion::CompanionProfileAdmission;
use oneiron::psych_profile::{PsychProfileKey, psych_profile_entity_id};

use super::super::access_grants::companion_scope_response;
use super::super::errors::{companion_access_denied, companion_engine_error};
use super::{CompanionProfileAccess, CompanionProfileResponse, companion_profile_response_state};
use crate::auth::CoreAuth;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;

/// The state a withheld profile reads as (CALLS "OF-8141 withheld state",
/// open): missing, with nothing of the profile, its sources, its staleness
/// or a next step.
const COMPANION_PROFILE_WITHHELD_STATE: &str = "missing";

/// `principal_ref`'s read of the profile at `key`, as the engine admits it
/// toward `auth`'s destination. No grant naming the profile is today's 403;
/// a profile the owner's recipient choice keeps from that destination, one
/// whose world or recorded source `auth`'s own credential keeps out, or one
/// a grant names but its delegated bounds keep this read out of, reads as
/// missing and says nothing of itself.
pub(super) fn admitted_companion_profile(
    server: &SyncServer,
    auth: &CoreAuth,
    principal_ref: &oneiron::EntityId,
    key: &PsychProfileKey,
    selected_source_revision_ids: Option<&[oneiron::EntityId]>,
) -> Result<CompanionProfileResponse, EnvelopedApiError> {
    // The caller's own read lane judges the profile's world and sources (FIX
    // 11174); one that cannot be built leaves the read as it was.
    let reader = crate::api::scoped_read_for_core_auth(server.vault(), auth).ok();
    let admission = server
        .vault()
        .companion_profile_snapshot_admitted(
            principal_ref,
            key,
            &auth.destination(),
            reader.as_ref(),
            selected_source_revision_ids,
        )
        .map_err(|error| {
            tracing::error!(
                error = %error,
                principal_ref = %principal_ref.to_hex(),
                person_ref = %key.person.to_hex(),
                facet_ref = ?key.facet.map(|facet| facet.to_hex()),
                "companion profile admission failed"
            );
            companion_engine_error("companion profile grant lookup failed", error)
        })?;
    let access = |grant: oneiron::EntityId| CompanionProfileAccess {
        grant_id: grant.to_hex(),
        principal_ref: principal_ref.to_hex(),
        scope: companion_scope_response(&key.person, key.facet.as_ref()),
    };
    match admission {
        CompanionProfileAdmission::Denied => Err(companion_access_denied()),
        CompanionProfileAdmission::Admitted { grant, state } => {
            Ok(companion_profile_response_state(
                key,
                access(grant),
                state,
                selected_source_revision_ids,
            ))
        }
        CompanionProfileAdmission::Withheld { grant } => Ok(CompanionProfileResponse {
            person_ref: key.person.to_hex(),
            facet_ref: key.facet.map(|facet| facet.to_hex()),
            world_ref: key.world.map(|world| world.to_hex()),
            profile_ref: psych_profile_entity_id(key).to_hex(),
            access: access(grant),
            state: COMPANION_PROFILE_WITHHELD_STATE.to_owned(),
            profile: None,
            stale_reason: None,
            next_action: None,
            drift_anchors: Vec::new(),
        }),
    }
}
