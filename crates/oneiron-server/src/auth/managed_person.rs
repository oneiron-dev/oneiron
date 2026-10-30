//! A managed shared vault's member, as his supervisor signed one request at
//! a member door (FIX 1302, Engine ruling 10-29).
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
//! The doors a person action serves ([`MANAGED_PERSON_DOORS`]) are every door
//! that takes a person's own proof among the shared-vault rows: the member
//! reads, his receipts and notices and his own leave (stage 1), and the
//! Admin powers, the invitee's answer, objections and erase asks, his own
//! record erase, the shared policy, trusted contacts and the workspace rows
//! (stage 2). Whether he holds a power is the engine's roster and role check,
//! never this list. The same action signs his `/mcp` call of one of those
//! doors and the upgrade of his held MCP socket, whose calls reach those
//! doors alone (`api::mcp_gateway::person_call`).

use axum::http::{Extensions, HeaderMap};
use oneiron::claim::CallerLocality;

use super::{CoreAuth, CoreScope};
use crate::server::SyncServer;

/// The member doors a person action serves (FIX 1302 stages 1 and 2,
/// CALLS `FIX 1302 managed person action`), as facade verbs: every door that
/// takes a person's own proof (`shared_act_doors::person`) among the
/// shared-vault rows. Stage 1: the member reads (his own invitations, the
/// erase asks he may see), his receipts and notices (a receipt he was told
/// of, outcomes, started and matured acts) and his own leave. Stage 2: the
/// Admin powers (members added, changed, removed and delegated, invitations
/// withdrawn and their slips, shared acts proposed and executed), the
/// invitee's accept and decline, objections and erase asks, his own record
/// erase, the shared policy's proposal and answer, his trusted contacts and
/// the workspace rows.
pub(crate) const MANAGED_PERSON_DOORS: [&str; 37] = [
    "vault.members.invitations",
    "vault.shared.erase_asks",
    "vault.shared.receipt",
    "vault.shared.outcomes",
    "vault.shared.started",
    "vault.shared.matured",
    "vault.members.leave",
    "vault.members.add",
    "vault.members.change",
    "vault.members.remove",
    "vault.members.delegate",
    "vault.members.withdraw_invitation",
    "vault.members.invitation_slip",
    "vault.shared.propose_delete",
    "vault.shared.propose_transfer",
    "vault.shared.propose_remove_owner",
    "vault.shared.execute",
    "vault.members.accept",
    "vault.members.decline",
    "vault.shared.object",
    "vault.shared.withdraw_objection",
    "vault.shared.erase_ask",
    "vault.shared.close_erase_ask",
    "vault.records.erase_preview",
    "vault.records.erase_confirm",
    "vault.shared.policy.propose",
    "vault.shared.policy.answer",
    "vault.trusted_contacts.name",
    "vault.trusted_contacts.list",
    "vault.trusted_contacts.consent",
    "vault.trusted_contacts.revoke",
    "vault.trusted_contacts.dial.set",
    "vault.trusted_contacts.concern.asks",
    "vault.trusted_contacts.concern.authorize",
    "vault.trusted_contacts.concern.propose",
    "vault.workspace.establish",
    "vault.workspace.members.onboard",
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
    /// a member door ([`attested_person`]), as that request's caller
    /// ([`Self::managed_person_caller`]). `None` for any other request,
    /// which keeps its own caller. Only [`Self::for_managed_request`] builds
    /// one, where the request would otherwise be anonymous.
    pub(super) fn for_attested_person(
        headers: &HeaderMap,
        extensions: &Extensions,
        path: &str,
        server: &SyncServer,
    ) -> Option<Self> {
        attested_person(headers, extensions, path, server).map(Self::managed_person_caller)
    }

    /// The person `holder` a supervisor signed one `/mcp` call or the
    /// upgrade of a held MCP socket for (FIX 1302 stage 2,
    /// `api::mcp_gateway::person_call`), as that call's caller
    /// ([`Self::managed_person_caller`]), placed where the call's connection
    /// sits and toward the machine it proved. `None` on a vault no
    /// supervisor manages.
    pub(crate) fn for_managed_person_call(
        holder: oneiron::EntityId,
        headers: &HeaderMap,
        extensions: &Extensions,
        server: &SyncServer,
    ) -> Option<Self> {
        server.managed_issuer.as_ref()?;
        Some(
            Self::managed_person_caller(holder)
                .at(super::caller_locality(headers, extensions))
                .toward(super::proved_peer(headers, extensions)),
        )
    }

    /// `holder` as a person action's caller: a human with core read and
    /// write, built without reading any credential header, with no slip,
    /// instrument, token id or Grant of anyone's, and never owner grade.
    fn managed_person_caller(holder: oneiron::EntityId) -> Self {
        Self {
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
        }
    }

    /// The person a supervisor-signed person action names as this request's
    /// caller at a member door, or for his `/mcp` call (FIX 1302), or
    /// `None`.
    pub(crate) fn managed_person(&self) -> Option<oneiron::EntityId> {
        self.managed_person
    }
}
