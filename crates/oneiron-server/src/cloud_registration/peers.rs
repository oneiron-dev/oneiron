//! The hosted-peer calls of `oneiron link` (L10-16; canon cross-arch-0024
//! M4.25, the control plane's half M4.26). The engine asks the control
//! plane for a hosted peer of this vault, handing it the owner's hosted-node
//! pairing link, reads the peer's state, and asks for its removal, at which
//! the control plane erases the peer's live copy and its keys. Each call
//! goes to the pinned origin (the issuer's and the audience's own),
//! `/v1/vaults/{vault_id}/peers`, with the registration's verified access
//! token, so a peer is asked only of the cloud account this vault is linked
//! to. The control plane carries the link the owner made and mints none.
//!
//! The contract the control plane serves:
//! - `POST .../peers` `{"pairing_link": "<one-line link>"}` answers 202
//!   `{"peer_id", "state": "provisioning"}`;
//! - `GET .../peers/{peer_id}` answers 200 `{"state", "error"?}`, the state
//!   `provisioning`, `enrolled`, `failed` or `removed`;
//! - `DELETE .../peers/{peer_id}` answers 202, or 404 for a peer it holds no
//!   more.

use reqwest::Url;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{CloudRegistrationPhase, CloudRegistrationTokenUse};

use super::http::Http;
use super::wire::Failure;
use super::{CloudRegistration, Status, held_token, jwt, unix_now};

/// The longest peer id the control plane may name: it goes into a URL path
/// and the vault's linked-peer row.
const PEER_ID_MAX_BYTES: usize = 128;

/// The bytes of `{"pairing_link":""}` around the link.
const PEER_CREATE_FRAME_BYTES: usize = 19;

/// The peer request's body.
#[derive(Serialize)]
struct PeerCreate<'a> {
    pairing_link: &'a str,
}

/// A hosted peer's state at the control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PeerState {
    Provisioning,
    Enrolled,
    Failed,
    Removed,
}

/// What the control plane says of one peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerReport {
    pub(crate) state: PeerState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

/// `POST .../peers`'s 202.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerCreated {
    peer_id: String,
    state: PeerState,
}

/// The control plane's peer calls, so the link act runs against the cloud
/// or a test's stand-in.
pub(crate) trait PeerControl {
    /// The control plane's origin, as the vault's linked-peer row keeps it.
    fn origin(&self) -> String;
    /// Asks for a peer of this vault that redeems `pairing_link`; the
    /// peer's id there.
    fn create(&self, pairing_link: &str) -> Result<String, Failure>;
    /// What the control plane says of the peer `peer_id`.
    fn report(&self, peer_id: &str) -> Result<PeerReport, Failure>;
    /// Asks for the removal of the peer `peer_id`, at which the control
    /// plane erases its live copy and its keys. `Ok` once it took the
    /// removal, or holds no such peer.
    fn remove(&self, peer_id: &str) -> Result<(), Failure>;
}

/// The peer calls of the owner's live registration.
pub(crate) struct CloudPeers {
    http: Http,
    origin: String,
    /// `{origin}/v1/vaults/{vault_id}/peers`.
    peers: Url,
    access_token: Zeroizing<String>,
}

impl CloudPeers {
    fn peer(&self, peer_id: &str) -> Result<Url, Failure> {
        if !peer_id_on_wire(peer_id) {
            return Err(Failure::OffWire(
                "the control plane named a peer id off the wire".to_owned(),
            ));
        }
        let mut url = self.peers.clone();
        url.path_segments_mut()
            .map_err(|()| Failure::OffWire("the peers URL takes no path".to_owned()))?
            .push(peer_id);
        Ok(url)
    }
}

/// Whether `peer_id` is one the wire carries: 1 to 128 bytes of letters,
/// digits, `-`, `_` and `.`.
fn peer_id_on_wire(peer_id: &str) -> bool {
    !peer_id.is_empty()
        && peer_id.len() <= PEER_ID_MAX_BYTES
        && peer_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

impl PeerControl for CloudPeers {
    fn origin(&self) -> String {
        self.origin.clone()
    }

    fn create(&self, pairing_link: &str) -> Result<String, Failure> {
        // The link's code is the peer's enrolment grant until it is spent:
        // the body is sized first, as the form body is, so it never grows and
        // leaves no partial copy behind (JSON writes one byte as six at
        // most), and it is wiped when it goes.
        let mut body = Zeroizing::new(Vec::with_capacity(
            PEER_CREATE_FRAME_BYTES.saturating_add(pairing_link.len().saturating_mul(6)),
        ));
        serde_json::to_writer(&mut *body, &PeerCreate { pairing_link })
            .map_err(|_| Failure::OffWire("the peer request did not encode".to_owned()))?;
        let reply = self
            .http
            .post_json(&self.peers, body, self.access_token.as_str())?;
        if reply.status != 202 {
            return Err(reply.failure("peer create"));
        }
        let created = reply.json::<PeerCreated>("peer create")?;
        if !peer_id_on_wire(&created.peer_id) || created.state != PeerState::Provisioning {
            return Err(Failure::OffWire(
                "the peer create answer is not the wire's shape".to_owned(),
            ));
        }
        Ok(created.peer_id)
    }

    fn report(&self, peer_id: &str) -> Result<PeerReport, Failure> {
        let reply = self
            .http
            .get(&self.peer(peer_id)?, Some(self.access_token.as_str()))?;
        if reply.status != 200 {
            return Err(reply.failure("peer state"));
        }
        reply.json("peer state")
    }

    fn remove(&self, peer_id: &str) -> Result<(), Failure> {
        let reply = self
            .http
            .delete(&self.peer(peer_id)?, self.access_token.as_str())?;
        match reply.status {
            202 | 404 => Ok(()),
            _ => Err(reply.failure("peer removal")),
        }
    }
}

impl CloudRegistration {
    /// The peer calls of the owner's live registration: its access token,
    /// verified against the pins, and with `refresh` refreshed first when it
    /// has stopped (an owner's link or unlink is the act that asks for it;
    /// a status read never refreshes). The inner `Err` is why no call can
    /// go, in the owner's words.
    ///
    /// # Errors
    /// The owner proof's own; storage faults.
    pub(crate) fn peers(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        refresh: bool,
    ) -> oneiron::Result<Result<CloudPeers, String>> {
        let pins = match self.pins() {
            Ok(pins) => pins,
            Err(failure) => return Ok(Err(failure.reason())),
        };
        let Some(vault_id) = vault.authority_vault_id()? else {
            return Ok(Err("this vault has no authority id yet".to_owned()));
        };
        let mut refreshed = false;
        let (binding, access_token) = loop {
            let held = {
                let _family = self.family();
                let Some(binding) = vault.cloud_registration_as_owner(owner, &pins.issuer)? else {
                    return Ok(Err("this vault is not linked to a cloud account".to_owned()));
                };
                if binding.phase != CloudRegistrationPhase::Linked {
                    return Ok(Err("the cloud account link needs a login".to_owned()));
                }
                let Some((token, expires_at)) = held_token(
                    vault,
                    owner,
                    &binding.fence(),
                    CloudRegistrationTokenUse::Access,
                ) else {
                    return Ok(Err(
                        "the cloud account link's token does not open here".to_owned()
                    ));
                };
                (expires_at > unix_now()).then_some((binding, token))
            };
            if let Some(held) = held {
                break held;
            }
            if refreshed || !refresh {
                return Ok(Err("the cloud account link's token has stopped".to_owned()));
            }
            refreshed = true;
            match self.refresh(vault, owner)? {
                Status::Registered { .. } => {}
                _ => return Ok(Err("the cloud account link did not refresh".to_owned())),
            }
        };
        match jwt::verify(pins, &access_token, unix_now()) {
            Ok(verified) if verified.subject == binding.subject => {}
            Ok(_) | Err(_) => {
                return Ok(Err(
                    "the cloud account link's token does not verify".to_owned()
                ));
            }
        }
        let vault_hex: String = vault_id.iter().map(|byte| format!("{byte:02x}")).collect();
        let Ok(peers) = pins
            .issuer_url
            .join(&format!("/v1/vaults/{vault_hex}/peers"))
        else {
            return Ok(Err("the pinned origin takes no peers path".to_owned()));
        };
        let http = match Http::new() {
            Ok(http) => http,
            Err(failure) => return Ok(Err(failure.reason())),
        };
        Ok(Ok(CloudPeers {
            http,
            origin: pins.issuer_url.origin().ascii_serialization(),
            peers,
            access_token,
        }))
    }
}
