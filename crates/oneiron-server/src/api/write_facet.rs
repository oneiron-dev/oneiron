//! Where a write by a credential narrowed to some facets lands (owner ruling
//! FACET-READ = A; placement stays derived, ARCH-0028): in the facet the mode
//! of the session it names says, when the credential reads that facet, and
//! otherwise in the credential's write facet. MCP and the facade both ask here.
use axum::http::HeaderMap;
use oneiron::EntityId;
use oneiron::federation::{ScopeAxis, ScopeId};

/// Names the session a request is made in; its mode may name the facet the
/// request's writes land in.
pub(crate) const SESSION_HEADER: &str = "x-oneiron-session";

/// A write that cannot land: the session it names is missing or names no
/// facet the credential reads. Every such session answers alike, so the
/// refusal says nothing about one the credential may not write in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LandingRefused;

/// The session a request names, or `Err` for a header that is no id.
pub(crate) fn request_session(headers: &HeaderMap) -> Result<Option<EntityId>, ()> {
    let Some(value) = headers.get(SESSION_HEADER) else {
        return Ok(None);
    };
    value
        .to_str()
        .ok()
        .and_then(|session| EntityId::from_hex(session).ok())
        .map(Some)
        .ok_or(())
}

/// The facet a write by a credential reading `facets` lands in. `None` for a
/// credential never narrowed to facets: its writes keep their derived
/// placement. A session places a narrowed credential's writes only when its
/// mode names a facet the credential reads; any other session, a missing one
/// included, refuses alike. With no session, the write lands in
/// `write_facet` (the owner's pick at pairing), else the smallest. A SESSION
/// sits in base reality, which no device keeps to itself, so the caller's
/// locality does not judge it.
pub(crate) fn landing_facet(
    vault: &oneiron::Vault,
    session: Option<EntityId>,
    facets: &ScopeAxis<ScopeId>,
    write_facet: Option<EntityId>,
) -> Result<Option<EntityId>, LandingRefused> {
    let ScopeAxis::Some(set) = facets else {
        return Ok(None);
    };
    match session {
        Some(session) => match vault.session_facet(session) {
            Ok(Some(facet)) if set.contains(&ScopeId(facet)) => Ok(Some(facet)),
            _ => Err(LandingRefused),
        },
        None => Ok(write_facet
            .filter(|facet| set.contains(&ScopeId(*facet)))
            .or_else(|| set.first().map(|facet| facet.0))),
    }
}
