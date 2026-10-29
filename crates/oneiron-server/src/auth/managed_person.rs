//! A managed shared vault's member, as his supervisor signed one request at
//! a member door (FIX 1302 stage 1, Engine ruling 10-29).
//!
//! A member on a managed host who carries no slip of his own acts at the
//! member doors on a supervisor-signed person action (`ManagedPersonAction`),
//! verified at managed ingress over the method, path, query, placing headers
//! and exact body of that one request. The action names the person and
//! nothing more: a human with core read and write, and no slip, instrument,
//! token id or Grant of anyone's, never owner grade and never the host's
//! root. Every door check then runs on him (`shared_act_doors::person`), and
//! the engine's roster, role and Grant checks decide. A request with a slip
//! keeps its slip; one with the owner's attestation is the owner's.
//!
//! Stage 1 serves the member reads, his receipts and notices, and his own
//! leave ([`MANAGED_PERSON_DOORS`]). The Admin powers (adding, changing and
//! removing members; proposing and executing shared acts) are a later stage
//! with their own ask, and a person action admits none of them.

use axum::http::{Extensions, HeaderMap};
use oneiron::claim::CallerLocality;

use super::{CoreAuth, CoreScope};
use crate::server::SyncServer;

/// The member doors a person action serves (FIX 1302 stage 1, CALLS `FIX
/// 1302 managed person action, stage 1`), as facade verbs: the member reads
/// (his own invitations, the erase asks he may see), his receipts and
/// notices (a receipt he was told of, outcomes, started and matured acts),
/// and his own leave.
pub(crate) const MANAGED_PERSON_DOORS: [&str; 7] = [
    "vault.members.invitations",
    "vault.shared.erase_asks",
    "vault.shared.receipt",
    "vault.shared.outcomes",
    "vault.shared.started",
    "vault.shared.matured",
    "vault.members.leave",
];

/// The root every member door's route sits under.
const FACADE_ROOT: &str = "/v1/core/facade/";

/// The prefix of a person action caller's principal, apart from every
/// other credential's.
const MANAGED_PERSON_PRINCIPAL: &str = "managed-person:";

/// The member door `path` names, when a person action serves it.
pub(crate) fn managed_person_door(path: &str) -> Option<&'static str> {
    let verb = path.strip_prefix(FACADE_ROOT)?;
    MANAGED_PERSON_DOORS.into_iter().find(|door| *door == verb)
}

/// The person a supervisor signed this one request for at a member door,
/// as managed ingress verified it (`ManagedPersonAction`): on a managed
/// vault, at a path a person action serves, on a request that carries no
/// caller slip. `None` for any other request. Only managed ingress installs
/// it, and only on a verified action.
fn attested_person(
    headers: &HeaderMap,
    extensions: &Extensions,
    path: &str,
    server: &SyncServer,
) -> Option<oneiron::EntityId> {
    if server.managed_issuer.is_none()
        || super::carries_caller_slip(headers)
        || managed_person_door(path).is_none()
    {
        return None;
    }
    extensions
        .get::<crate::managed::ManagedPersonHolder>()
        .map(|holder| holder.0)
}

impl CoreAuth {
    /// The person a supervisor-signed person action names for a request at
    /// a member door ([`attested_person`]), as that request's caller: a
    /// human with core read and write, built without reading any credential
    /// header, with no slip, instrument, token id or Grant of anyone's, and
    /// never owner grade. `None` for any other request, which keeps its own
    /// caller. Only [`Self::for_managed_request`] builds one, where the
    /// request would otherwise be anonymous.
    pub(super) fn for_attested_person(
        headers: &HeaderMap,
        extensions: &Extensions,
        path: &str,
        server: &SyncServer,
    ) -> Option<Self> {
        let holder = attested_person(headers, extensions, path, server)?;
        Some(Self {
            principal: format!("{MANAGED_PERSON_PRINCIPAL}{}", holder.to_hex()),
            principal_ref: Some(holder.to_hex()),
            scopes: [CoreScope::Read, CoreScope::Write].into_iter().collect(),
            implicit_all_scopes: false,
            jti: None,
            actor_class: Some("human".to_owned()),
            org_ref: None,
            verified_slip: None,
            invocation_slip: None,
            instrument: None,
            locality: CallerLocality::OffDevice,
            peer: oneiron::authority::PeerMachine::Unknown,
            facets_owner_exempt: false,
            off_record_session: None,
            managed_owner: None,
            managed_person: Some(holder),
        })
    }

    /// The person a supervisor-signed person action names as this request's
    /// caller at a member door (FIX 1302), or `None`.
    pub(crate) fn managed_person(&self) -> Option<oneiron::EntityId> {
        self.managed_person
    }
}
