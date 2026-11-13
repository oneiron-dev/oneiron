//! Cross-device Files search over the mesh (ARCH-0027 #files-world: "Cross-device
//! search over the iroh mesh (OF-535). Each device ranks its own files and
//! returns metadata and snippets. One calibrated merge orders the results
//! across devices.").
//!
//! A device serves [`FILES_SEARCH_ALPN`] with a [`FilesSearchService`]. Each
//! stream carries one search request (a `FilesSourceSearchRequest`, MessagePack)
//! and one reply. The transport admits only a machine whose live
//! `mesh:alpn:oneiron/files-search/1` grant this vault holds, and the engine
//! checks that grant again before the search reads anything
//! (`search_files_sources_for_peer`). The grant is the whole gate: the answer
//! carries the device's metadata and snippets to any machine holding it
//! (ruling L2-16-MESH-SNIPPETS = B).
//!
//! The asking device sends one request to each machine at once and waits for
//! them under one deadline ([`ask_files_search_devices`]); the engine merges
//! the answers with its own (`merge_files_search_answers`). A machine that
//! refused, failed or did not answer in time is listed unreached, never
//! dropped silently.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
pub use oneiron::task_verb::sdk::FILES_SEARCH_ALPN;
use oneiron::task_verb::sdk::{
    FilesDeviceAnswer, FilesSourceSearchAnswer, FilesSourceSearchRequest, FilesUnreachedDevice,
    FilesUnreachedWhy, search_files_sources_for_peer,
};
use serde::{Deserialize, Serialize};

use crate::{MachineId, MeshConnection, MeshError, MeshFuture, MeshService, MeshTransport};

/// How long a cross-device search waits for the owner's other devices, from
/// its dials to their last answer.
pub const FILES_SEARCH_DEADLINE: Duration = Duration::from_secs(8);

/// A device's reply to one search request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reply")]
enum FilesSearchReply {
    /// The device's own ranking of its own Files world.
    Answered { answer: FilesSourceSearchAnswer },
    /// The device did not search: the asking machine holds no live grant
    /// here, the request was unreadable, or the search failed.
    Refused { reason: String },
}

/// This install's side of cross-device Files search: it answers each search
/// an admitted machine of the owner sends with this install's own ranking of
/// its own Files world.
pub struct FilesSearchService {
    vault: Arc<Vault>,
}

impl FilesSearchService {
    #[must_use]
    pub fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }

    /// The reply to one request from `machine`, whose endpoint key the
    /// handshake proved.
    async fn reply(
        &self,
        machine: MachineId,
        endpoint_key: [u8; 32],
        request: &[u8],
    ) -> FilesSearchReply {
        let request: FilesSourceSearchRequest = match rmp_serde::from_slice(request) {
            Ok(request) => request,
            Err(error) => {
                return FilesSearchReply::Refused {
                    reason: format!("unreadable Files search request: {error}"),
                };
            }
        };
        let vault = Arc::clone(&self.vault);
        let searched = tokio::task::spawn_blocking(move || {
            search_files_sources_for_peer(&vault, machine, endpoint_key, request)
        })
        .await;
        match searched {
            Ok(Ok(answer)) => FilesSearchReply::Answered { answer },
            Ok(Err(refusal)) => FilesSearchReply::Refused {
                reason: refusal.to_string(),
            },
            Err(_) => FilesSearchReply::Refused {
                reason: "the Files search stopped before it answered".to_owned(),
            },
        }
    }
}

impl MeshService for FilesSearchService {
    fn serve(&self, connection: Box<dyn MeshConnection>) -> MeshFuture<'_, ()> {
        Box::pin(async move {
            if connection.alpn() != FILES_SEARCH_ALPN {
                connection.close();
                return Ok(());
            }
            let machine = connection.machine();
            let endpoint_key = connection.endpoint_key();
            // One search per stream, until the asking device closes.
            while let Ok(mut stream) = connection.accept_stream().await {
                let Ok(request) = stream.recv().await else {
                    continue;
                };
                let reply = self.reply(machine, endpoint_key, &request).await;
                let Ok(reply) = rmp_serde::to_vec_named(&reply) else {
                    continue;
                };
                if stream.send(&reply).await.is_err() {
                    break;
                }
            }
            Ok(())
        })
    }
}

/// Asks each of `machines` for its own answer to `request` over `transport`,
/// all at once, and waits at most `deadline` for them. Each machine is sent
/// the request without its `devices`: a device answers for its own Files
/// world only. The machines that answered come first; each other one is
/// listed unreached, with why.
pub async fn ask_files_search_devices(
    transport: Arc<dyn MeshTransport>,
    machines: Vec<MachineId>,
    request: &FilesSourceSearchRequest,
    deadline: Duration,
) -> (Vec<FilesDeviceAnswer>, Vec<FilesUnreachedDevice>) {
    let mut asked = request.clone();
    asked.devices = None;
    let mut pending: BTreeSet<MachineId> = machines.iter().copied().collect();
    let mut answered = Vec::new();
    let mut unreached = Vec::new();
    if let Ok(asked) = rmp_serde::to_vec_named(&asked) {
        let asked = Arc::new(asked);
        let mut asks = tokio::task::JoinSet::new();
        for machine in machines {
            let transport = Arc::clone(&transport);
            let asked = Arc::clone(&asked);
            asks.spawn(async move {
                let answer =
                    tokio::time::timeout(deadline, ask_device(transport.as_ref(), machine, &asked))
                        .await
                        .unwrap_or(Err(FilesUnreachedWhy::TimedOut));
                (machine, answer)
            });
        }
        while let Some(joined) = asks.join_next().await {
            let Ok((machine, answer)) = joined else {
                continue;
            };
            pending.remove(&machine);
            match answer {
                Ok(answer) => answered.push(FilesDeviceAnswer { machine, answer }),
                Err(why) => unreached.push(FilesUnreachedDevice { machine, why }),
            }
        }
    }
    // An ask that never returned (it panicked, or the request would not
    // encode) is a failed one.
    unreached.extend(pending.into_iter().map(|machine| FilesUnreachedDevice {
        machine,
        why: FilesUnreachedWhy::Failed,
    }));
    (answered, unreached)
}

/// One machine's answer to the encoded request `asked`.
async fn ask_device(
    transport: &dyn MeshTransport,
    machine: MachineId,
    asked: &[u8],
) -> Result<FilesSourceSearchAnswer, FilesUnreachedWhy> {
    let connection = transport
        .dial(machine, FILES_SEARCH_ALPN)
        .await
        .map_err(unreached_why)?;
    let reply = async {
        let mut stream = connection.open_stream().await?;
        stream.send(asked).await?;
        stream.recv().await
    }
    .await;
    connection.close();
    match rmp_serde::from_slice::<FilesSearchReply>(&reply.map_err(unreached_why)?) {
        Ok(FilesSearchReply::Answered { answer }) => Ok(answer),
        Ok(FilesSearchReply::Refused { .. }) => Err(FilesUnreachedWhy::Refused),
        Err(_) => Err(FilesUnreachedWhy::Failed),
    }
}

/// Why a transport error leaves a machine unreached.
fn unreached_why(error: MeshError) -> FilesUnreachedWhy {
    match error {
        MeshError::Refused => FilesUnreachedWhy::Refused,
        MeshError::Unavailable => FilesUnreachedWhy::Unavailable,
        MeshError::InvalidRoster | MeshError::Io(_) => FilesUnreachedWhy::Failed,
    }
}
