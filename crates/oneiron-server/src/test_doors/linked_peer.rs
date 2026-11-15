//! Doors for `tests/hosted_peer_link.rs` (L10-16): the hosted-peer link
//! act (`crate::linked_peer`) over a control plane the test scripts. No
//! test can pin an https issuer, so no test registration is live, and an
//! in-process server binds no mesh listener; these doors pass the act a
//! scripted control plane and a running mesh listener, and the routes' own
//! gates before them are tested over HTTP (`tests/owner_link_routes.rs`).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use serde_json::Value;

use crate::cloud_registration::{Failure, PeerControl, PeerReport, PeerState};
use crate::server::SyncServer;

/// What the scripted control plane does with a link before it answers: a
/// peer that redeems it first, say.
pub type OnCreate = Box<dyn FnMut(&str) + Send>;

/// A control plane the test scripts: it keeps each call it took, takes or
/// refuses each as the test sets, and reports the peer as the test sets.
#[derive(Default)]
pub struct ScriptedControlPlane {
    /// The one-line pairing links it was handed, in order, refused ones
    /// included.
    pub links: Mutex<Vec<String>>,
    /// The peer ids it took a removal of, in order.
    pub removals: Mutex<Vec<String>>,
    /// Runs with each link it is handed, before it answers.
    pub on_create: Mutex<Option<OnCreate>>,
    /// It refuses every peer request (a 503) once it has seen its link.
    pub refuse_create: AtomicBool,
    /// Every removal is lost on the way (no answer).
    pub lose_remove: AtomicBool,
    /// It reports the peer enrolled; provisioning otherwise.
    pub enrolled: AtomicBool,
}

impl PeerControl for ScriptedControlPlane {
    fn origin(&self) -> String {
        "https://cloud.example".to_owned()
    }

    fn create(&self, pairing_link: &str) -> Result<String, Failure> {
        let handed = {
            let mut links = self.links.lock().expect("scripted links");
            links.push(pairing_link.to_owned());
            links.len()
        };
        if let Some(on_create) = self.on_create.lock().expect("scripted hook").as_mut() {
            on_create(pairing_link);
        }
        if self.refuse_create.load(Ordering::SeqCst) {
            return Err(Failure::Unavailable(Some(
                "the control plane is down".to_owned(),
            )));
        }
        Ok(format!("peer-{handed}"))
    }

    fn report(&self, _peer_id: &str) -> Result<PeerReport, Failure> {
        let state = if self.enrolled.load(Ordering::SeqCst) {
            PeerState::Enrolled
        } else {
            PeerState::Provisioning
        };
        Ok(PeerReport { state, error: None })
    }

    fn remove(&self, peer_id: &str) -> Result<(), Failure> {
        if self.lose_remove.load(Ordering::SeqCst) {
            return Err(Failure::Lost);
        }
        self.removals
            .lock()
            .expect("scripted removals")
            .push(peer_id.to_owned());
        Ok(())
    }
}

/// `POST /v1/owner/link`'s act with `control` and a running mesh listener:
/// the linked-peer row as JSON, or the refusal's name.
///
/// # Errors
/// The refusal, as its `Debug` form.
pub fn link(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    origin: &str,
    control: &ScriptedControlPlane,
) -> Result<Value, String> {
    match crate::linked_peer::link(
        server,
        owner,
        ActSurface::ThisInstall,
        origin,
        Ok(control as &dyn PeerControl),
        true,
    ) {
        Ok(Ok(view)) => Ok(serde_json::to_value(view).expect("the row encodes")),
        Ok(Err(refusal)) => Err(format!("{refusal:?}")),
        Err(error) => Err(error.to_string()),
    }
}

/// `GET /v1/owner/link`'s act with `control`.
///
/// # Panics
/// On a storage fault.
#[must_use]
pub fn status(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    control: &ScriptedControlPlane,
) -> Value {
    let status = crate::linked_peer::status(server, owner, Ok(control as &dyn PeerControl))
        .expect("link status");
    serde_json::to_value(status).expect("the status encodes")
}

/// `DELETE /v1/owner/link`'s act with `control`, or with none when the
/// registration is not live: the receipt as JSON, `None` with no peer.
///
/// # Panics
/// On a storage fault or a revoke that fails.
#[must_use]
pub fn unlink(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    control: Option<&ScriptedControlPlane>,
) -> Option<Value> {
    let control = control
        .map(|control| control as &dyn PeerControl)
        .ok_or_else(|| "this vault is not linked to a cloud account".to_owned());
    crate::linked_peer::unlink(server, owner, ActSurface::ThisInstall, control)
        .expect("unlink")
        .map(|receipt| serde_json::to_value(receipt).expect("the receipt encodes"))
}
