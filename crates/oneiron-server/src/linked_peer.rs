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
//! not take keeps the row, and the next unlink asks again. So does a machine
//! removal the roster refused (this install carrying no live profile to sign
//! the owner's act, for one): the peer's slips are revoked all the same, and
//! the control plane is still asked.

use oneiron::authority::{
    ActSurface, FoldedMachine, LinkedPeer, LinkedPeerIssued, MachineRole,
    format_pinned_pairing_link,
};
use oneiron::consent::AuthenticatedOwner;
use serde::Serialize;
use zeroize::Zeroizing;

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
            removed: folded.is_some_and(machine_removed),
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
    /// no peer's redeem would go there, or it carries a query or a fragment,
    /// which the one-line link cannot.
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
    /// control plane, or its machine's removal to this roster, and the next
    /// unlink asks again.
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

/// What an unlink did with the peer's machine in this vault's roster.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum MachineRemoval {
    /// No machine of the peer stands in the roster: it never redeemed its
    /// link, or the roster holds no revision of the machine its redeem
    /// recorded.
    NoMachine,
    /// Removed now.
    Removed,
    /// Removed before: by an earlier unlink, the owner, or an unlink that
    /// ran at the same time.
    AlreadyRemoved,
    /// The roster refused the removal, and why (this install carries no live
    /// profile to sign the owner's act, for one). The peer's slips are
    /// revoked all the same, and the next unlink removes it again.
    Refused { reason: String },
}

/// The unlink's receipt.
#[derive(Debug, Serialize)]
pub(crate) struct UnlinkReceipt {
    peer: LinkedPeerView,
    /// The peer's machine as the roster holds it after the unlink; `None`
    /// when the peer never redeemed, and its link was spent unread.
    machine: Option<PeerMachine>,
    /// What the unlink did with that machine in the roster.
    machine_removal: MachineRemoval,
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
    let Ok(origin) = reqwest::Url::parse(origin) else {
        return Ok(Err(LinkRefusal::OriginNotRedeemable));
    };
    // The peer redeems at the origin's path, as `oneiron device enrol` does;
    // a query or a fragment would not survive the one-line link.
    if !crate::device_sync::enrolment::redeemable(&origin)
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
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
    // The code is the peer's enrolment grant until it is spent: this act's
    // copies of it are wiped when they go.
    let code = Zeroizing::new(link.code);
    let line = Zeroizing::new(format_pinned_pairing_link(
        origin.as_str(),
        &code,
        &holder.to_hex(),
        link.pin.as_ref(),
    ));
    match control.create(line.as_str()) {
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
/// The owner proof's own; the revokes' own; storage faults. A machine
/// removal the roster refuses is not one: the receipt names it, and the row
/// stays owed.
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
    let machine_removal = match peer.machine {
        None => MachineRemoval::NoMachine,
        Some(machine) => {
            let removal = remove_machine(vault, owner, surface, machine)?;
            if let Some(issuer) = issuer {
                mesh_revoked = vault.revoke_removed_machine_mesh(issuer, machine)?;
            }
            removal
        }
    };
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
    ) && !matches!(machine_removal, MachineRemoval::Refused { .. })
    {
        vault.forget_linked_peer_as_owner(owner)?;
    }
    let fold = vault.authority_fold()?;
    Ok(Some(UnlinkReceipt {
        peer: LinkedPeerView::from(&peer),
        machine: peer
            .machine
            .map(|machine| PeerMachine::of(machine, fold.machine(machine))),
        machine_removal,
        mesh_revoked,
        slips_revoked,
        removal,
        erasure: PEER_ERASURE,
    }))
}

/// Removes the peer's machine from the roster, unless a removal already
/// stands or no revision names it. A refusal that a removal made meanwhile
/// explains (an unlink at the same time) reads as that removal; any other
/// refusal is the answer, not an error, so the unlink goes on to the
/// control plane.
fn remove_machine(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    machine: oneiron::EntityId,
) -> oneiron::Result<MachineRemoval> {
    match machine_removed_in_roster(vault, machine)? {
        None => return Ok(MachineRemoval::NoMachine),
        Some(true) => return Ok(MachineRemoval::AlreadyRemoved),
        Some(false) => {}
    }
    match vault.set_machine_role(owner, surface, machine, MachineRole::Removed, None) {
        Ok(_) => Ok(MachineRemoval::Removed),
        Err(error) => Ok(
            if machine_removed_in_roster(vault, machine)? == Some(true) {
                MachineRemoval::AlreadyRemoved
            } else {
                MachineRemoval::Refused {
                    reason: error.to_string(),
                }
            },
        ),
    }
}

/// Whether the roster holds `machine` removed; `None` when no revision
/// names it.
fn machine_removed_in_roster(
    vault: &oneiron::Vault,
    machine: oneiron::EntityId,
) -> oneiron::Result<Option<bool>> {
    Ok(vault
        .authority_fold()?
        .machine(machine)
        .map(machine_removed))
}

/// Whether any chain of `folded` removed it: the roster's or an anchor's, as
/// the roster refuses a second removal and the mesh revoke reads it.
fn machine_removed(folded: &FoldedMachine) -> bool {
    folded.chains().any(|(_, chain)| chain.removed)
}
