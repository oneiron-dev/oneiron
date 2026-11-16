//! Moved from `crates/oneiron/src/policy_model/owner_rows/world_privacy_will/record.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::PolicyRevision;
use oneiron_authority::authority::WorldPrivacy;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What a request asks of its holders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorldPrivacyRequestKind {
    /// An agent's tighten that no Grant line names: any one holder's yes
    /// applies it.
    Proposal,
    /// A widen: an agent's, always, or a holder's own under "widen needs
    /// every owner". It is irreversible in effect, so only a holder's tap
    /// applies it, never a model answer, a remembered reason or silence.
    WidenAsk,
}

/// Where a request stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum WorldPrivacyRequestStatus {
    Pending,
    /// A holder's yes applied it: the settings receipt, and the holder whose
    /// yes it was.
    Applied {
        receipt_id: String,
        holder: String,
    },
    /// A holder declined it, or cancelled it from its notice.
    Declined {
        holder: String,
    },
}

/// One world-privacy request, frozen when it was opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorldPrivacyRequest {
    /// Its id, as hex: the `answer` of the act that settles it.
    pub request_id: String,
    pub kind: WorldPrivacyRequestKind,
    /// The agent that asked, as hex; `None` for a holder's own widen that
    /// waits for the other owners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The credential lineage that opened it, as hex slip ids: neither it
    /// nor a fork of it settles the request (FIX 5064).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub opener_lineage: Vec<String>,
    /// Who opened it, as hex: the agent, or the holder.
    pub author: String,
    /// The WORLD row, as hex.
    pub world: String,
    pub settings: WorldPrivacy,
    /// The world's settings revision it was decided on, as hex.
    pub seen: String,
    /// The holders it went to, as hex.
    pub holders: Vec<String>,
    /// Under "widen needs every owner": every live Owner whose yes it needs,
    /// as hex, as of its last answer: each answer reads the live Owners
    /// again (`unanimity::ask_needs_in_txn`). Empty: any one holder's yes
    /// applies it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    /// The yeses collected so far, as hex.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub yes: Vec<String>,
    /// The decision ask its holders see, for a widen ask, once queued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<u64>,
    pub status: WorldPrivacyRequestStatus,
    pub at: u64,
    /// For an agent's request, why a Grant that named it was passed over:
    /// `pact_standing_lapsed` when, on a shared vault, its pact membership
    /// alone had lapsed (FIX 7548). Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_omitted: Option<String>,
    /// For an agent's ask on a world shared from a connected vault (FIX
    /// 4702): the owning vault, whose holders decide. Its `holders` are this
    /// vault's owners, who carry it there over the pact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owned_by: Option<ForeignWorldPrivacyLink>,
    /// For an ask a connected vault's agent sent here (FIX 4702): that vault,
    /// and its request, which this one's answer settles there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked_from: Option<ForeignWorldPrivacyLink>,
}

/// The other end of a world-settings request carried over a Connect pact
/// (FIX 4702).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignWorldPrivacyLink {
    /// The pact it rides, as 64 hex.
    pub pact: String,
    /// The other vault, as 64 hex.
    pub vault: String,
    /// The world as the other vault names it, as hex: its owned world for
    /// `owned_by`, or its derived foreign copy for `asked_from`.
    pub world: String,
    /// The asking vault's request, as hex: set on the owning vault's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    /// The agent that asked there, as hex: set on the owning vault's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The owning vault's answer, as its holders settled it: set on the
    /// asking vault's once the answer came back, even after a cancel here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<WorldPrivacyRequestStatus>,
}

impl WorldPrivacyRequest {
    /// The request's id.
    pub fn id(&self) -> Result<EntityId> {
        EntityId::from_hex(&self.request_id)
            .map_err(|_| Error::CorruptedIndex("world privacy request id"))
    }

    /// The world it changes.
    pub fn world_id(&self) -> Result<EntityId> {
        EntityId::from_hex(&self.world)
            .map_err(|_| Error::CorruptedIndex("world privacy request world"))
    }

    /// The revision it was decided on.
    pub fn seen_revision(&self) -> Result<PolicyRevision> {
        parse_revision(&self.seen).ok_or(Error::CorruptedIndex("world privacy request seen"))
    }

    /// The agent that asked.
    pub fn agent_id(&self) -> Result<Option<EntityId>> {
        self.agent
            .as_deref()
            .map(|agent| {
                EntityId::from_hex(agent)
                    .map_err(|_| Error::CorruptedIndex("world privacy request agent"))
            })
            .transpose()
    }
}

/// A revision as its 64-hex form reads back; `None` for any other text. A
/// receipt's entry hash reads back the same way.
pub fn parse_revision(hex: &str) -> Option<PolicyRevision> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(PolicyRevision(out))
}
