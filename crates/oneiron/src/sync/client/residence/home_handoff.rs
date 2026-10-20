//! The old home's end of a home handoff on the residence RPC lane (FIX 5661
//! C2a). It dials the endpoint captured with the move, never whatever home
//! the route names now, and goes on only while that socket proves the
//! move's target machine. `residence.home_handoff.status` reads where the
//! target stands, `.part` stages one part of at most
//! `HOME_HANDOFF_PART_BYTES` in order, and `.commit` answers the ack the
//! target saved. The source verifies that ack before it keeps it. `.cancel`
//! (FIX 5931) fences a handoff the source takes back, in the target's
//! adopting writer, or answers the ack when the target adopted it first.

use std::time::Duration;

use base64::Engine;
use serde::Deserialize;
use serde_json::json;

use super::{ResidenceRpc, refused, residence_budgets};
use crate::Vault;
use crate::authority::PeerMachine;
use crate::entity_id::EntityId;
use crate::sync::client::{ResidenceHomeRoute, SyncClientConfig};
use crate::sync::home_handoff::{HomeAck, decode_ack};
use crate::sync::residence::sealed_digest_hex;
use crate::sync::transport::TransportError;

/// Where the target says a handoff stands, from its persisted state.
pub(crate) enum TargetStanding {
    /// Adopted there: the ack it saved, still to verify here.
    Adopted(HomeAck),
    /// Not adopted there: how many parts it holds staged, in order.
    Staged(u32),
}

/// What the target answers a cancel with, from its adopting writer.
pub(crate) enum TargetCancel {
    /// Adopted there first: the ack it saved, still to verify here.
    Adopted(HomeAck),
    /// Never adopted there, and fenced now: no commit lands it after.
    Fenced,
}

#[derive(Deserialize)]
struct StatusReply {
    #[serde(default)]
    staged: Option<u32>,
    #[serde(default)]
    ack: Option<String>,
}

#[derive(Deserialize)]
struct PartReply {
    staged: u32,
}

#[derive(Deserialize)]
struct CommitReply {
    ack: String,
}

#[derive(Deserialize)]
struct CancelReply {
    #[serde(default)]
    fenced: Option<bool>,
    #[serde(default)]
    ack: Option<String>,
}

fn ack_from(text: &str) -> Result<HomeAck, TransportError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| refused())?;
    decode_ack(&bytes).map_err(|_| refused())
}

/// One residence socket to a move's target.
pub(crate) struct HandoffLane {
    rpc: ResidenceRpc,
    /// How long a commit waits for its ack: the residence ack budget.
    ack_timeout: Duration,
}

impl HandoffLane {
    /// Dials `endpoint` for a move to `target`. `None` when the endpoint is
    /// out of reach or refuses this machine's socket, or the socket proves a
    /// machine other than `target`.
    pub(crate) async fn open(
        vault: &Vault,
        config: &SyncClientConfig,
        endpoint: &str,
        target: EntityId,
    ) -> Result<Option<Self>, TransportError> {
        let budgets = residence_budgets(vault)?;
        let mut pinned = config.clone();
        pinned.residence_home_route = Some(ResidenceHomeRoute::new(Some(endpoint.to_owned())));
        let rpc = match ResidenceRpc::connect(vault, &pinned, budgets).await {
            Ok(Some(rpc)) => rpc,
            Ok(None) | Err(_) => return Ok(None),
        };
        Ok(match vault.peer_machine_stands(rpc.home) {
            PeerMachine::Proven { machine, .. } if machine == target => Some(Self {
                rpc,
                ack_timeout: Duration::from_millis(budgets.ack_timeout_ms),
            }),
            _ => None,
        })
    }

    /// The target's persisted answer for handoff `id`, sealed to the bytes
    /// `digest` names; `None` when it refused.
    pub(crate) async fn status(
        &mut self,
        id: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<Option<TargetStanding>, TransportError> {
        let params = json!({"id": sealed_digest_hex(id), "digest": sealed_digest_hex(digest)});
        let reply = match self
            .rpc
            .call("residence.home_handoff.status", params)
            .await?
        {
            Ok(reply) => serde_json::from_value::<StatusReply>(reply).map_err(|_| refused())?,
            Err(_) => return Ok(None),
        };
        match (reply.ack, reply.staged) {
            (Some(ack), _) => Ok(Some(TargetStanding::Adopted(ack_from(&ack)?))),
            (None, Some(staged)) => Ok(Some(TargetStanding::Staged(staged))),
            (None, None) => Err(refused()),
        }
    }

    /// Stages part `index` of `count`; the target's staged position after
    /// it, or `None` when it refused.
    pub(crate) async fn part(
        &mut self,
        id: &[u8; 32],
        digest: &[u8; 32],
        index: u32,
        count: u32,
        bytes: &[u8],
    ) -> Result<Option<u32>, TransportError> {
        let params = json!({
            "id": sealed_digest_hex(id),
            "digest": sealed_digest_hex(digest),
            "index": index,
            "count": count,
            "part": base64::engine::general_purpose::STANDARD.encode(bytes),
        });
        match self.rpc.call("residence.home_handoff.part", params).await? {
            Ok(reply) => Ok(Some(
                serde_json::from_value::<PartReply>(reply)
                    .map_err(|_| refused())?
                    .staged,
            )),
            Err(_) => Ok(None),
        }
    }

    /// Commits handoff `id`; the ack the target saved, or `None` when it
    /// refused (not its home yet, stale, or in conflict with rows there).
    pub(crate) async fn commit(
        &mut self,
        id: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<Option<HomeAck>, TransportError> {
        self.rpc.timeout = self.rpc.timeout.max(self.ack_timeout);
        let params = json!({"id": sealed_digest_hex(id), "digest": sealed_digest_hex(digest)});
        match self
            .rpc
            .call("residence.home_handoff.commit", params)
            .await?
        {
            Ok(reply) => {
                let reply = serde_json::from_value::<CommitReply>(reply).map_err(|_| refused())?;
                ack_from(&reply.ack).map(Some)
            }
            Err(_) => Ok(None),
        }
    }

    /// Cancels handoff `id` at the target (FIX 5931): fenced there, or the
    /// ack it saved when it adopted first; `None` when it refused.
    pub(crate) async fn cancel(
        &mut self,
        id: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<Option<TargetCancel>, TransportError> {
        let params = json!({"id": sealed_digest_hex(id), "digest": sealed_digest_hex(digest)});
        let reply = match self
            .rpc
            .call("residence.home_handoff.cancel", params)
            .await?
        {
            Ok(reply) => serde_json::from_value::<CancelReply>(reply).map_err(|_| refused())?,
            Err(_) => return Ok(None),
        };
        match (reply.ack, reply.fenced) {
            (Some(ack), _) => Ok(Some(TargetCancel::Adopted(ack_from(&ack)?))),
            (None, Some(true)) => Ok(Some(TargetCancel::Fenced)),
            (None, _) => Err(refused()),
        }
    }
}
