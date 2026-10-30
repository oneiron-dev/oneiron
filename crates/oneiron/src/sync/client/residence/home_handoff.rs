//! The old home's end of a home handoff on the residence RPC lane (FIX 5661
//! C2a). It dials the endpoint captured with the move, never whatever home
//! the route names now, and goes on only while that socket proves the
//! move's target machine. `residence.home_handoff.status` reads where the
//! target stands, `.part` stages one part of at most
//! `HOME_HANDOFF_PART_BYTES` in order, and `.commit` answers the ack the
//! target saved. The source verifies that ack before it keeps it. `.cancel`
//! (FIX 5931) fences a handoff the source takes back, in the target's
//! adopting writer, or answers the ack when the target adopted it first.
//! A source with no actor session opens the lane as its machine alone (FIX
//! 6458), and a status says when the target fenced the handoff (FIX 6574).
//!
//! FIX 8875 stage 2: `.session` reads the key session the target offers for
//! a handoff and `.keys` sends the handoff's erasable keys sealed to it,
//! before the parts. `.retire` asks a holder of retired keys' copies to
//! retire them, and `.retired` reads which of them it keeps no live copy of.
//! The same lane, dialed to that holder, carries both.

use std::time::Duration;

use base64::Engine;
use serde::Deserialize;
use serde_json::{Value, json};

use super::rpc::HomeRefused;
use super::{ResidenceRpc, refused, residence_budgets};
use crate::Vault;
use crate::authority::PeerMachine;
use crate::entity_id::EntityId;
use crate::sync::client::{ResidenceHomeRoute, SyncClientConfig};
use crate::sync::home_handoff::{HomeAck, KeySessionOffer, SentKey, decode_ack};
use crate::sync::residence::{sealed_digest_from_hex, sealed_digest_hex};
use crate::sync::transport::TransportError;

/// Where the target says a handoff stands, from its persisted state.
pub(crate) enum TargetStanding {
    /// Adopted there: the ack it saved, still to verify here.
    Adopted(HomeAck),
    /// Not adopted there: how many parts it holds staged, in order.
    Staged(u32),
    /// FIX 6574: its source cancelled it there, so it never lands there.
    Fenced,
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
    #[serde(default)]
    fenced: Option<bool>,
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

#[derive(Deserialize)]
struct SessionReply {
    ephemeral: String,
    nonce: String,
}

#[derive(Deserialize)]
struct KeysReply {
    installed: u32,
}

#[derive(Deserialize)]
struct RetireReply {
    staged: u32,
}

#[derive(Deserialize)]
struct RetiredReply {
    retired: Vec<String>,
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
    /// machine other than `target`. With the host's actor session the lane
    /// binds it, as before; without one it opens as this machine alone (FIX
    /// 6458).
    pub(crate) async fn open(
        vault: &Vault,
        config: &SyncClientConfig,
        endpoint: &str,
        target: EntityId,
    ) -> Result<Option<Self>, TransportError> {
        let budgets = residence_budgets(vault)?;
        let mut pinned = config.clone();
        pinned.residence_home_route = Some(ResidenceHomeRoute::new(Some(endpoint.to_owned())));
        let opened = if pinned.note_session.is_some() && pinned.residence_selector.is_some() {
            ResidenceRpc::connect(vault, &pinned, budgets).await
        } else {
            ResidenceRpc::connect_machine(vault, &pinned, budgets).await
        };
        let rpc = match opened {
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
    /// `digest` names; `None` when it refused. Only the target's explicit word
    /// is a fence, never a call that failed.
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
        match (reply.ack, reply.fenced, reply.staged) {
            (Some(ack), _, _) => Ok(Some(TargetStanding::Adopted(ack_from(&ack)?))),
            (None, Some(true), _) => Ok(Some(TargetStanding::Fenced)),
            (None, _, Some(staged)) => Ok(Some(TargetStanding::Staged(staged))),
            (None, _, None) => Err(refused()),
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

    /// FIX 8875: one call whose answer waits on the target's durable writes:
    /// it waits as long as a commit does, and later calls as before.
    async fn durable_call(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Result<Value, HomeRefused>, TransportError> {
        let timeout = self.rpc.timeout;
        self.rpc.timeout = timeout.max(self.ack_timeout);
        let answer = self.rpc.call(method, params).await;
        self.rpc.timeout = timeout;
        answer
    }

    /// FIX 8875: the key session the target offers for handoff `id`, sealed
    /// to the bytes `digest` names: its session-ephemeral public key and
    /// nonce; `None` when it refused.
    pub(crate) async fn session(
        &mut self,
        id: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<Option<KeySessionOffer>, TransportError> {
        let params = json!({"id": sealed_digest_hex(id), "digest": sealed_digest_hex(digest)});
        let reply = match self
            .rpc
            .call("residence.home_handoff.session", params)
            .await?
        {
            Ok(reply) => serde_json::from_value::<SessionReply>(reply).map_err(|_| refused())?,
            Err(_) => return Ok(None),
        };
        let ephemeral = base64::engine::general_purpose::STANDARD
            .decode(&reply.ephemeral)
            .map_err(|_| refused())?;
        let nonce = sealed_digest_from_hex(&reply.nonce).ok_or_else(refused)?;
        Ok(Some(KeySessionOffer { ephemeral, nonce }))
    }

    /// FIX 8875: sends `keys`, sealed to the session the target offered for
    /// handoff `id`; how many of them it holds now, or `None` when it
    /// refused. Each key lands in a writer of its own there: this call waits
    /// as long as a commit does, and the parts after it as before.
    pub(crate) async fn keys(
        &mut self,
        id: &[u8; 32],
        digest: &[u8; 32],
        keys: &[SentKey],
    ) -> Result<Option<u32>, TransportError> {
        let keys: Vec<Value> = keys
            .iter()
            .map(|key| {
                let sealed =
                    base64::engine::general_purpose::STANDARD.encode(key.sealed.as_bytes());
                json!({"key": key.key, "sealed": sealed})
            })
            .collect();
        let params = json!({
            "id": sealed_digest_hex(id),
            "digest": sealed_digest_hex(digest),
            "keys": keys,
        });
        match self
            .durable_call("residence.home_handoff.keys", params)
            .await?
        {
            Ok(reply) => Ok(Some(
                serde_json::from_value::<KeysReply>(reply)
                    .map_err(|_| refused())?
                    .installed,
            )),
            Err(_) => Ok(None),
        }
    }

    /// FIX 8875: asks this lane's machine, a holder of `keys`' copies, to
    /// retire them: this node retired its own for an erase of their actors.
    /// How many it named, or `None` when it refused.
    pub(crate) async fn retire(&mut self, keys: &[String]) -> Result<Option<u32>, TransportError> {
        let params = json!({"keys": keys});
        match self
            .durable_call("residence.home_handoff.retire", params)
            .await?
        {
            Ok(reply) => Ok(Some(
                serde_json::from_value::<RetireReply>(reply)
                    .map_err(|_| refused())?
                    .staged,
            )),
            Err(_) => Ok(None),
        }
    }

    /// FIX 8875: those of `keys` this lane's machine keeps no live copy of,
    /// by its own answer on a socket that proved it; `None` when it refused.
    pub(crate) async fn retired(
        &mut self,
        keys: &[String],
    ) -> Result<Option<Vec<String>>, TransportError> {
        let params = json!({"keys": keys});
        let reply = match self
            .rpc
            .call("residence.home_handoff.retired", params)
            .await?
        {
            Ok(reply) => serde_json::from_value::<RetiredReply>(reply).map_err(|_| refused())?,
            Err(_) => return Ok(None),
        };
        Ok(Some(
            reply
                .retired
                .into_iter()
                .filter(|key| keys.contains(key))
                .collect(),
        ))
    }
}
