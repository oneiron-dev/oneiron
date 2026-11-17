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

/// The session a request names in [`SESSION_HEADER`], read as the HTTP
/// transport reads it ([`crate::api::call_receipt::request_session_ref`]):
/// its text is the off-record session the caller's handles bind (a stretch
/// entered alone by its ref, a room's stretch by `room:<room>:<ref>`, or a
/// SESSION by its id), and it is a SESSION only when the text is an id.
/// Only a SESSION places a write ([`landing_facet`]).
#[derive(Clone, Debug)]
pub(crate) struct RequestSession {
    session_ref: String,
    id: Option<EntityId>,
}

impl RequestSession {
    /// The session `headers` name, or `Err` for a header that is no text or
    /// is blank.
    pub(crate) fn of_request(headers: &HeaderMap) -> Result<Option<Self>, ()> {
        let Some(value) = headers.get(SESSION_HEADER) else {
            return Ok(None);
        };
        let session_ref = value
            .to_str()
            .map(crate::api::call_receipt::spelled_session_ref)
            .map_err(|_| ())?;
        if session_ref.is_empty() {
            return Err(());
        }
        Ok(Some(Self {
            session_ref: session_ref.to_owned(),
            id: EntityId::from_hex(session_ref).ok(),
        }))
    }

    /// The SESSION `id`, named by its id.
    pub(crate) fn of_id(id: EntityId) -> Self {
        Self {
            session_ref: id.to_hex(),
            id: Some(id),
        }
    }

    /// The off-record session this names, as the request spelled it.
    pub(crate) fn session_ref(&self) -> &str {
        &self.session_ref
    }

    /// The SESSION this names, when its text is an id.
    pub(crate) const fn id(&self) -> Option<EntityId> {
        self.id
    }
}

/// The facet a write by a credential reading `facets` lands in. `None` for a
/// credential never narrowed to facets: its writes keep their derived
/// placement. A session places a narrowed credential's writes only when it
/// is a SESSION whose mode names a facet the credential reads; any other
/// session, a missing one and an off-record stretch included, refuses
/// alike. With no session, the write lands in `write_facet` (the owner's
/// pick at pairing), else the smallest. A SESSION sits in base reality,
/// which no device keeps to itself, so the caller's locality does not
/// judge it.
pub(crate) fn landing_facet(
    vault: &oneiron::Vault,
    session: Option<&RequestSession>,
    facets: &ScopeAxis<ScopeId>,
    write_facet: Option<EntityId>,
) -> Result<Option<EntityId>, LandingRefused> {
    let ScopeAxis::Some(set) = facets else {
        return Ok(None);
    };
    match session {
        Some(session) => match session.id().map(|id| vault.session_facet(id)) {
            Some(Ok(Some(facet))) if set.contains(&ScopeId(facet)) => Ok(Some(facet)),
            _ => Err(LandingRefused),
        },
        None => Ok(write_facet
            .filter(|facet| set.contains(&ScopeId(*facet)))
            .or_else(|| set.first().map(|facet| facet.0))),
    }
}
