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

/// A write that cannot land: the session it names does not read, or names a
/// facet the credential does not read. The two answer alike, so the refusal
/// says nothing about a session the caller cannot read.
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
/// placement. Otherwise the session's facet when the credential reads it,
/// else `write_facet` (the owner's pick at pairing), else the smallest.
pub(crate) fn landing_facet(
    vault: &oneiron::Vault,
    session: Option<EntityId>,
    facets: &ScopeAxis<ScopeId>,
    write_facet: Option<EntityId>,
) -> Result<Option<EntityId>, LandingRefused> {
    let ScopeAxis::Some(set) = facets else {
        return Ok(None);
    };
    let session_facet = match session {
        Some(session) => vault.session_facet(session).map_err(|_| LandingRefused)?,
        None => None,
    };
    match session_facet {
        Some(facet) if set.contains(&ScopeId(facet)) => Ok(Some(facet)),
        Some(_) => Err(LandingRefused),
        None => Ok(write_facet
            .filter(|facet| set.contains(&ScopeId(*facet)))
            .or_else(|| set.first().map(|facet| facet.0))),
    }
}
