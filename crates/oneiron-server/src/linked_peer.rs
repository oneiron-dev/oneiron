//! The owner's linked hosted peer (L10-16; canon cross-arch-0024 `#path-e`,
//! M4.25): `oneiron link` adds the cloud's always-on machine of this vault
//! through the built machine pairing, as a hosted node, never mine;
//! `oneiron link status` reads it; `oneiron unlink` takes it away. Local
//! stays primary: nothing migrates, and an unlink leaves the local vault
//! whole.
//!
//! A link mints the owner's hosted-node link and the vault's linked-peer row
//! together ([`oneiron::Vault::issue_linked_peer_link`]) and hands the
//! control plane the link's one-line form, at the origin the peer redeems it
//! at, as `oneiron device enrol` does; the redeem records the machine it
//! enrolled. A control plane that does not take the request leaves nothing:
//! the link is spent unread and the row dropped.
//!
//! An unlink (RULING L10-16-UNLINK = A) revokes the peer here at once: its
//! machine is removed, which is terminal, its mesh pairing and grants are
//! revoked, and so is every slip its holder holds. Then the control plane is
//! asked to remove the peer, at which it erases the peer's live copy and its
//! keys; backups age out on the disaster-recovery schedule of 90 days or
//! less, and the unlink's receipt says so. A removal the control plane did
//! not take keeps the row, and the next unlink asks again.

use oneiron::authority::{
    ActSurface, FoldedMachine, LinkedPeer, LinkedPeerIssued, MachineRole,
    format_pinned_pairing_link,
};
use oneiron::consent::AuthenticatedOwner;
use serde::Serialize;

use crate::cloud_registration::{PeerControl, PeerReport};
use crate::server::SyncServer;

/// What the unlink's receipt says of the peer's copy (RULING
/// L10-16-UNLINK = A).
pub(crate) const PEER_ERASURE: &str = "The control plane erases the hosted peer's live copy and \
    its keys when it removes the peer. Backups age out on the disaster-recovery schedule of 90 \
    days or less.";

/// The slip id no slip has (each is random), so a holder's revoke keeps
/// none of its slips.
const KEEP_NO_SLIP: [u8; 32] = [0; 32];

/// The vault's linked-peer row as the owner reads it.
#[derive(Debug, Serialize)]
pub(crate) struct LinkedPeerView {
    cloud_origin: String,
    holder: String,
    linked_at: u64,
    peer_id: Option<String>,
    machine: Option<String>,
    unlinked_at: Option<u64>,
}

impl From<&LinkedPeer> for LinkedPeerView {
    fn from(peer: &LinkedPeer) -> Self {
        Self {
            cloud_origin: peer.cloud_origin.clone(),
            holder: peer.holder.to_hex(),
            linked_at: peer.linked_at,
            peer_id: peer.peer_id.clone(),
            machine: peer.machine.map(|machine| machine.to_hex()),
            unlinked_at: peer.unlinked_at,
        }
    }
}

/// The peer's machine as this vault's roster holds it.
#[derive(Debug, Serialize)]
pub(crate) struct PeerMachine {
    machine: String,
    hosted_node: bool,
    live: bool,
    removed: bool,
    mine: bool,
}

impl PeerMachine {
    fn of(machine: oneiron::EntityId, folded: Option<&FoldedMachine>) -> Self {
        let roster = folded.and_then(|folded| folded.roster.as_ref());
        Self {
            machine: machine.to_hex(),
            hosted_node: roster
                .is_some_and(|roster| matches!(roster.profile.role, MachineRole::HostedNode)),
            live: roster.is_some_and(oneiron::authority::MachineRevision::is_live),
            removed: roster.is_some_and(|roster| roster.removed),
            mine: folded.is_some_and(|folded| folded.is_mine(None)),
        }
    }
}

/// Why a link was not made.
#[derive(Debug)]
pub(crate) enum LinkRefusal {
    /// The vault holds a linked peer, or one whose unlink is still owed.
    AlreadyLinked,
    /// The vault's cloud registration is not live, and why: the control
    /// plane takes a peer request only from the linked cloud account.
    CloudRegistrationRequired(String),
    /// This serve runs no mesh listener, and the peer dials this machine
    /// over the mesh (canon 0024: "The link rides the iroh mesh").
    MeshListenerRequired,
    /// The origin is neither `https://` nor `http://` on this machine, so
    /// no peer's redeem would go there.
    OriginNotRedeemable,
    /// The host holds no slip issuer, so no link can be signed.
    NoHostIssuer,
    /// The control plane did not take the request; nothing is left here.
    ControlPlane(String),
}

/// Where the vault's linked peer stands.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum LinkStatus {
    NotLinked,
    /// Linked: the row, the peer's machine once it redeemed, and what the
    /// control plane says of the peer now (or why it was not asked).
    Linked {
        peer: LinkedPeerView,
        machine: Option<PeerMachine>,
        cloud: Option<PeerReport>,
        cloud_error: Option<String>,
    },
    /// An unlink revoked the peer here; its removal is still owed to the
    /// control plane, and the next unlink asks again.
    UnlinkOwed {
        peer: LinkedPeerView,
        machine: Option<PeerMachine>,
    },
}

/// What the control plane did with an unlink's removal.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum PeerRemoval {
    /// It took the removal, or holds no such peer.
    Accepted,
    /// It never took the link, so it runs no peer to remove.
    NothingToRemove,
    /// Asked, and it did not take it: the next unlink asks again.
    Failed { reason: String },
    /// Not asked, because the cloud registration is not live: the next
    /// unlink asks again.
    NotAsked { reason: String },
}

/// The unlink's receipt.
#[derive(Debug, Serialize)]
pub(crate) struct UnlinkReceipt {
    peer: LinkedPeerView,
    /// The peer's machine as the roster holds it after the unlink; `None`
    /// when the peer never redeemed, and its link was spent unread.
    machine: Option<PeerMachine>,
    /// Whether the machine's mesh pairing and grants were revoked now.
    mesh_revoked: bool,
    /// How many live slips of the peer's holder were revoked now.
    slips_revoked: usize,
    removal: PeerRemoval,
    erasure: &'static str,
}

/// Links a hosted peer: mints the hosted-node link and the row, and hands
/// the control plane the link's one-line form at `origin`. Nothing is
/// minted unless the vault holds no linked peer, `control` is the live
/// registration's peer calls, `mesh_listener` says this serve's mesh
/// listener runs, and the peer's redeem would go to `origin`.
///
/// # Errors
/// The owner proof's own; storage faults.
pub(crate) fn link(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    origin: &str,
    control: Result<&dyn PeerControl, String>,
    mesh_listener: bool,
) -> oneiron::Result<Result<LinkedPeerView, LinkRefusal>> {
    let vault = server.vault();
    if vault.linked_peer_as_owner(owner)?.is_some() {
        return Ok(Err(LinkRefusal::AlreadyLinked));
    }
    let control = match control {
        Ok(control) => control,
        Err(reason) => return Ok(Err(LinkRefusal::CloudRegistrationRequired(reason))),
    };
    if !mesh_listener {
        return Ok(Err(LinkRefusal::MeshListenerRequired));
    }
    let Ok(origin_url) = reqwest::Url::parse(origin) else {
        return Ok(Err(LinkRefusal::OriginNotRedeemable));
    };
    if !crate::device_sync::enrolment::redeemable(&origin_url) {
        return Ok(Err(LinkRefusal::OriginNotRedeemable));
    }
    let Some(issuer) = server.host_issuer() else {
        return Ok(Err(LinkRefusal::NoHostIssuer));
    };
    let (link, holder) =
        match vault.issue_linked_peer_link(issuer, owner, surface, &control.origin())? {
            LinkedPeerIssued::Issued { link, holder } => (link, holder),
            LinkedPeerIssued::AlreadyLinked(_) => return Ok(Err(LinkRefusal::AlreadyLinked)),
        };
    let line = format_pinned_pairing_link(origin, &link.code, &holder.to_hex(), link.pin.as_ref());
    match control.create(&line) {
        Ok(peer_id) => match vault.record_linked_peer_id_as_owner(owner, &peer_id)? {
            Some(peer) => Ok(Ok(LinkedPeerView::from(&peer))),
            // An unlink ran while the request did: the peer it made goes too.
            None => {
                let removal = control.remove(&peer_id).map_err(|failure| failure.reason());
                Ok(Err(LinkRefusal::ControlPlane(format!(
                    "an unlink ran while the link did; the peer's removal: {}",
                    removal.err().as_deref().unwrap_or("accepted")
                ))))
            }
        },
        Err(failure) => {
            vault.unlink_linked_peer_as_owner(owner)?;
            vault.forget_linked_peer_as_owner(owner)?;
            Ok(Err(LinkRefusal::ControlPlane(failure.reason())))
        }
    }
}

/// Where the vault's linked peer stands; `control` is the control plane's
/// peer calls, or why they cannot go.
///
/// # Errors
/// The owner proof's own; storage faults.
pub(crate) fn status(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    control: Result<&dyn PeerControl, String>,
) -> oneiron::Result<LinkStatus> {
    let vault = server.vault();
    let Some(peer) = vault.linked_peer_as_owner(owner)? else {
        return Ok(LinkStatus::NotLinked);
    };
    let fold = vault.authority_fold()?;
    let machine = peer
        .machine
        .map(|machine| PeerMachine::of(machine, fold.machine(machine)));
    if peer.unlinked_at.is_some() {
        return Ok(LinkStatus::UnlinkOwed {
            peer: LinkedPeerView::from(&peer),
            machine,
        });
    }
    let (cloud, cloud_error) = match (&peer.peer_id, control) {
        (None, _) => (None, None),
        (Some(peer_id), Ok(control)) => match control.report(peer_id) {
            Ok(report) => (Some(report), None),
            Err(failure) => (None, Some(failure.reason())),
        },
        (Some(_), Err(reason)) => (None, Some(reason)),
    };
    Ok(LinkStatus::Linked {
        peer: LinkedPeerView::from(&peer),
        machine,
        cloud,
        cloud_error,
    })
}

/// Unlinks the hosted peer: revokes it here at once, then asks the control
/// plane to remove it; `None` when the vault has no linked peer.
///
/// # Errors
/// The owner proof's own; the machine removal's and the revokes' own;
/// storage faults.
pub(crate) fn unlink(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    control: Result<&dyn PeerControl, String>,
) -> oneiron::Result<Option<UnlinkReceipt>> {
    let vault = server.vault();
    let Some(peer) = vault.unlink_linked_peer_as_owner(owner)? else {
        return Ok(None);
    };
    let issuer = server.host_issuer();
    // Its slips go first: nothing after this can leave one live.
    let slips_revoked = match issuer {
        Some(issuer) => vault
            .revoke_held_capability_slips(issuer, &peer.holder.to_hex(), KEEP_NO_SLIP)?
            .len(),
        None => 0,
    };
    let mut mesh_revoked = false;
    if let Some(machine) = peer.machine {
        let removed = vault
            .authority_fold()?
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .is_some_and(|roster| roster.removed);
        if !removed {
            vault.set_machine_role(owner, surface, machine, MachineRole::Removed, None)?;
        }
        if let Some(issuer) = issuer {
            mesh_revoked = vault.revoke_removed_machine_mesh(issuer, machine)?;
        }
    }
    let removal = match (&peer.peer_id, control) {
        (None, _) => PeerRemoval::NothingToRemove,
        (Some(peer_id), Ok(control)) => match control.remove(peer_id) {
            Ok(()) => PeerRemoval::Accepted,
            Err(failure) => PeerRemoval::Failed {
                reason: failure.reason(),
            },
        },
        (Some(_), Err(reason)) => PeerRemoval::NotAsked { reason },
    };
    if matches!(
        removal,
        PeerRemoval::Accepted | PeerRemoval::NothingToRemove
    ) {
        vault.forget_linked_peer_as_owner(owner)?;
    }
    let fold = vault.authority_fold()?;
    Ok(Some(UnlinkReceipt {
        peer: LinkedPeerView::from(&peer),
        machine: peer
            .machine
            .map(|machine| PeerMachine::of(machine, fold.machine(machine))),
        mesh_revoked,
        slips_revoked,
        removal,
        erasure: PEER_ERASURE,
    }))
}
