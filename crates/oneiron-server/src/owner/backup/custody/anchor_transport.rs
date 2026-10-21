//! A vault VM's way to its custody anchor door (FIX 6517): the guest has no
//! network, so its bootstrap serves a socket that reaches one URL, the one
//! its host bound the boot to, through the host's anchor proxy
//! (`oneiron_vault_contract::vm_anchor`). The credential the VM was handed
//! carries that route, and the door's client takes it for exactly that URL,
//! as configured: the URL, its TLS and its host checks stay as they are, and
//! only the socket the bytes travel on differs. A credential handed to a
//! node's process carries none, and its calls go out as before.

use std::path::{Path, PathBuf};

use super::CustodyAnchorCredentials;

/// The guest socket that reaches one anchor URL, and no other.
pub(super) struct AnchorRoute {
    url: String,
    socket: PathBuf,
}

impl AnchorRoute {
    pub(super) fn new(url: &str, socket: &Path) -> Self {
        Self {
            url: url.to_owned(),
            socket: socket.to_path_buf(),
        }
    }
}

/// How one door's calls travel.
pub(super) enum AnchorPath {
    /// Over this host's own network, as every native call does.
    Native,
    /// Through a vault VM's guest socket, to the one URL its host bound.
    Routed(PathBuf),
    /// The credential's route reaches another URL than the door's, so no
    /// call is made: it never falls back to a network the guest lacks.
    Elsewhere,
}

impl AnchorPath {
    /// The path calls to the door under `base` take with `credentials`: the
    /// credential's route when `base` is its URL byte for byte, before any
    /// trimming, and the native one when the credential has no route.
    pub(super) fn of(base: &str, credentials: Option<&CustodyAnchorCredentials>) -> Self {
        match credentials.and_then(CustodyAnchorCredentials::route) {
            None => Self::Native,
            Some(route) if route.url == base => Self::Routed(route.socket.clone()),
            Some(_) => Self::Elsewhere,
        }
    }
}
