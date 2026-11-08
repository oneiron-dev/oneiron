//! A sync session's upgrade: its request, proved with this machine's
//! credential, and the socket it opens, to the home or to a peer (FIX 4748).
//! A peer session's probe of the home signs its upgrade here too.

use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::HeaderMap;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

use crate::sync::carrier::SyncSocket;
use crate::sync::client::{SyncClient, SyncClientConfig, SyncEvent};
use crate::sync::home_proof::UpgradeBinding;

use super::super::SyncConnection;
use super::super::session::SessionFault;

/// The upgrade request of a sync session over `config`: to its home, or, for
/// a `peer` session (FIX 4748), to the peer it dials on the paired mesh.
/// Returns the request, the proof it was signed with, and whether a
/// credential held here was withheld from it.
///
/// Sync pulls the full root snapshot. The upgrade therefore proves an
/// unattenuated logged slip with a fresh holder signature; a device-key lease
/// or an issuer secret never grants this read. Each upgrade has its own
/// nonce, so it cannot replay a previous upgrade's proof. It is signed on the
/// wall clock, as every holder signs: the recording clock may still hold a
/// floor a host clock that ran ahead left.
///
/// FIX 11111: no credential rides a clear `ws` upgrade that is neither
/// loopback nor mesh; the socket opens as one with no credential. A peer
/// session rides the paired mesh to its peer.
pub(in crate::sync::connection) fn upgrade_request(
    vault: &crate::Vault,
    config: &SyncClientConfig,
    peer: bool,
) -> Result<(Request, Option<UpgradeBinding>, bool), String> {
    let mut request = config
        .server_url
        .as_str()
        .into_client_request()
        .map_err(|e| format!("WS connect failed: {e}"))?;
    let admitted = peer || config.server_admits_credentials();
    let withheld =
        !admitted && (config.transport_credential.is_some() || !config.auth_token.is_empty());
    let (slip, bearer) = if admitted {
        (
            config.transport_credential.as_ref(),
            config.auth_token.as_str(),
        )
    } else {
        (None, "")
    };
    let mut binding = None;
    if let Some(credential) = slip {
        binding = Some(
            credential
                .sign_upgrade(vault, vault.store.clock.wall_now(), &mut request)
                .map_err(str::to_owned)?,
        );
    } else if !bearer.is_empty() {
        let header_value = format!("Bearer {bearer}")
            .parse()
            .map_err(|_| "Auth token is not a valid header value".to_string())?;
        request.headers_mut().insert(AUTHORIZATION, header_value);
    }
    Ok((request, binding, withheld))
}

impl SyncConnection {
    /// Opens the session's socket, its upgrade proved: to the home on the
    /// configured carrier, or to the session's peer on its mesh dial (FIX
    /// 4748). Returns the upgrade answer's headers and the proof the upgrade
    /// was signed with.
    pub(super) async fn open_socket(
        &self,
        client: &mut SyncClient,
        event_tx: &mpsc::UnboundedSender<SyncEvent>,
    ) -> Result<(SyncSocket, HeaderMap, Option<UpgradeBinding>), SessionFault> {
        let config = &self.config.client_config;
        // The request is this machine's own: its URL, credential and proof.
        let (request, binding, withheld) =
            upgrade_request(self.manager.vault(), config, client.peer_session.is_some())
                .map_err(SessionFault::Local)?;
        if withheld && !client.cleartext_withhold_logged {
            client.cleartext_withhold_logged = true;
            tracing::warn!("sync server is clear ws off loopback and mesh: no credential sent");
        }
        let peer_dial = client
            .peer_session
            .zip(config.peer_dialer.as_deref())
            .map(|(peer, dialer)| crate::sync::carrier::PeerDial { dialer, peer });
        let dialer = match &peer_dial {
            Some(dial) => Some(dial as &dyn crate::sync::SyncDialer),
            None => config.mesh_dialer.as_deref(),
        };
        let (ws_stream, response) = crate::sync::carrier::connect_sync_socket(request, dialer)
            .await
            .map_err(|e| {
                // A home's refused credential may mean a removed membership:
                // the host asks the home, and this socket decides nothing
                // (FIX 12442). A peer's refusal is not the home's.
                if client.peer_session.is_none() && crate::sync::carrier::upgrade_unauthorized(&e) {
                    let _ = event_tx.send(SyncEvent::UpgradeUnauthorized);
                }
                // A carrier this machine cannot set up for its URL is its
                // own fault; any other failure is the far end's (FIX 22217).
                let message = format!("WS connect failed: {e}");
                if crate::sync::carrier::own_setup_fault(&e) {
                    SessionFault::Local(message)
                } else {
                    SessionFault::Remote(message)
                }
            })?;
        Ok((ws_stream, response, binding))
    }
}
