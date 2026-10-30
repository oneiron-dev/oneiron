//! The input and answer of the owner's guest revoke row (OF-232):
//! `vault.guests.revoke`, a host door. A server withdraws the guest's grant
//! under the vault owner's proof, as `/v1/owner/guests/revoke` takes it, and
//! hands the engine its own slip issuer, which signs each pact disconnect.
//! An embedded handle holds no host signing key, so it refuses after the
//! owner check. With `peer`, the former peer's host origin, the server also
//! queues one courtesy-delete ask per ended pact once the revoke is durable
//! (FIX 1634); this crate holds no outbox door, so the engine call here
//! never reads it.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::HostSlipIssuer;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::receipt::{GuestRevokeResponse, project_guest_revoke};

/// The producer of a guest revoke's owner notice.
const GUEST_REVOKE_NOTIFICATION_PRODUCER: &str = "guest_revoke";

/// `vault.guests.revoke`'s input: the guest's FEDERATION_GRANT, an ask
/// guest's or a Connect peer's, and where to send the courtesy deletes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestRevokeRequest {
    pub grant_ref: EntityId,
    /// The former peer's host origin, `https://host[:port]`, as
    /// `vault.courtesy_delete.send` takes it: the server queues one
    /// courtesy-delete ask to it per courtesy target. No grant or pact
    /// records it; omitted, the revoke sends nothing. The revoke always
    /// commits: a `peer` a verb hook rewrote that fails the origin check
    /// skips only the asks, and the answer says why (`courtesy_skipped`).
    #[serde(
        default = "default_guest_revoke_peer",
        skip_serializing_if = "Option::is_none"
    )]
    pub peer: Option<String>,
}

/// The courtesy deletes a revoke sends with no origin named: none. No grant
/// or pact records the peer's host, and a revoke never guesses one.
const DEFAULT_GUEST_REVOKE_PEER: Option<String> = None;

fn default_guest_revoke_peer() -> Option<String> {
    DEFAULT_GUEST_REVOKE_PEER
}

/// `vault.guests.revoke` on a server: [`Vault::revoke_guest_access`] under
/// the owner's proof and the host's own `issuer`, projected through
/// [`project_guest_revoke`]. A repeat answers the first revoke with
/// `changed: false`; an unknown or non-guest grant is not found. `peer` is
/// the server's to send to, after this returns.
pub fn revoke_guest_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    input: GuestRevokeRequest,
) -> MemoryResult<GuestRevokeResponse> {
    let outcome = vault.revoke_guest_access(owner, issuer, input.grant_ref)?;
    Ok(project_guest_revoke(outcome))
}

/// `vault.guests.revoke` on an embedded handle: the owner's call, refused,
/// because the disconnects are signed with a host key no embedded vault
/// holds.
pub fn revoke_guest_embedded(
    memory: &Memory<'_>,
    _input: GuestRevokeRequest,
) -> MemoryResult<GuestRevokeResponse> {
    let _owner = memory.embedded_owner("vault.guests.revoke")?;
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "vault.guests.revoke signs each pact disconnect with the host's own key; an embedded vault holds none",
        &[super::host::SERVED_CLIENT_HINT],
    ))
}

/// Tells the revoking owner, in their inbox, that `revoked` sent no
/// courtesy-delete ask and why (`reason`, as `revoked.courtesy_skipped`
/// says it): a Finding whose result names the withdrawn grant (FIX 4186).
/// Keyed by grant and revoke time, so a repeat revoke finds its row.
pub fn notify_guest_revoke_courtesy_skipped(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    revoked: &GuestRevokeResponse,
    reason: &str,
) -> crate::Result<()> {
    let grant = revoked.grant_ref.to_hex();
    vault.with_write_txn(|txn| {
        let recipient = owner.revalidate_in_txn(vault, txn)?;
        vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Finding,
                source: NotificationSource {
                    producer: GUEST_REVOKE_NOTIFICATION_PRODUCER.to_owned(),
                    event: format!("{grant}:{}:courtesy_skipped", revoked.revoked_at),
                    result: Some(grant.clone()),
                    detail: Some(reason.to_owned()),
                    ..NotificationSource::default()
                },
                subject_refs: Vec::new(),
                recipient: Some(recipient),
                created_at: revoked.revoked_at,
                origin_conversation: None,
            },
        )?;
        Ok(())
    })
}
