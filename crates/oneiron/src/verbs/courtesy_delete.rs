//! The inputs and answers of the owner's courtesy delete rows (OF-273,
//! ARCH-0043 #relationship-lifecycle): `vault.courtesy_delete.send`,
//! `.sent`, `.incoming` and `.answer`, each a host door over the engine
//! calls and owner proof `/v1/owner/courtesy-delete/*` takes. A server signs
//! an ask or an answer with its own authority key and delivers it through
//! its courtesy outbox; an embedded handle has neither, so `.send` and
//! `.answer` refuse there ([`courtesy_delete_host_only`]). The two reads are
//! a pure projection of this vault's ledger ([`courtesy_delete_sent`],
//! [`courtesy_delete_incoming`]), so a server and an embedded handle answer
//! them alike (FIX 3139). A former peer's signed ask and answer
//! (`/v1/federation/courtesy-delete*`) are peer HTTP, never a verb.
use serde::{Deserialize, Serialize};

use crate::authority::AuthorityFold;
use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    CooperativeDeletionDispositionKind, CooperativeDeletionNotice, IncomingCooperativeDeletion,
    LegalHoldTarget, parse_hex,
};
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault};

/// `vault.courtesy_delete.send`'s input: the ended pact, the worlds to ask
/// about, and the former peer's host.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CourtesyDeleteSendRequest {
    /// The ended pact, as 64 hex.
    pub pact: String,
    /// The worlds to ask about, as 32 hex; none asks about all the pact
    /// delivered.
    #[serde(default)]
    pub worlds: Vec<String>,
    /// Content up to this pact epoch; by default, the epoch the pact ended at.
    #[serde(default)]
    pub epoch_cutoff: Option<u64>,
    /// The former peer's host origin, `https://host[:port]`.
    pub peer: String,
    /// The ask already signed by the key the peer pinned, base64, when that
    /// key is not this host's. `worlds` and `epoch_cutoff` are then the ask's.
    #[serde(default)]
    pub signed: Option<String>,
}

/// One ask this vault sent, as its outbox holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteSent {
    /// The ask's request id, as 32 hex.
    pub request: String,
    /// Every page's request id of the paged selection, in queue order; the
    /// first is `request` (FIX 11802).
    pub pages: Vec<String>,
    /// The ended pact, as 64 hex.
    pub pact: String,
    pub recipient: String,
    /// Its delivery status.
    pub status: String,
    /// RFC 3339.
    pub created: String,
    /// RFC 3339.
    pub updated: String,
}

/// `vault.courtesy_delete.answer`'s input: the owner's choice on one ask a
/// former peer sent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CourtesyDeleteAnswerRequest {
    /// The pact the ask came under, as 64 hex.
    pub pact: String,
    /// The ask's request id, as 32 hex.
    pub request: String,
    /// `delete`, `redact`, `restrict_pending_review`, `retain_under_basis`,
    /// `legal_hold` or `decline`.
    #[schemars(with = "String")]
    pub choice: CooperativeDeletionDispositionKind,
    /// A short snake_case reason code, for any choice but delete.
    #[serde(default)]
    pub reason_code: Option<String>,
    /// When a choice other than delete comes up for review, unix seconds.
    #[serde(default)]
    pub review_at: Option<u64>,
    /// Under a delete choice, the records to hard-delete, as 32 hex.
    #[serde(default)]
    pub delete: Vec<String>,
    /// Under a legal hold choice, the records to hold, as 32 hex.
    #[serde(default)]
    pub hold: Vec<String>,
    /// The requester's host origin, to send the answer back; without it the
    /// answer stays on this side.
    #[serde(default)]
    pub reply_to: Option<String>,
}

/// One world an incoming ask names, with its stale stamp when the pact's
/// end already stopped its refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteAskedWorld {
    pub world: String,
    pub stale: Option<String>,
    pub stale_epoch: Option<u64>,
}

/// One customer hold a courtesy answer placed, as its row reads now (FIX
/// 2924).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteHold {
    /// The hold, as 32 hex.
    pub hold: String,
    /// `standing`, `lifted`, or `unknown` once its row is gone.
    pub status: String,
    /// The records it names now, or named when lifted, as 32 hex; empty
    /// when unknown.
    pub records: Vec<String>,
    /// RFC 3339, once lifted.
    pub lifted: Option<String>,
}

/// One record of a delete choice, with what became of it (FIX 2926).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteRecordProgress {
    /// The record, as 32 hex.
    pub record: String,
    /// `pending` (not removed yet), `removed`, or `missing` (nothing here).
    pub state: String,
}

/// The owner's recorded choice on an incoming ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteChoice {
    #[schemars(with = "String")]
    pub choice: CooperativeDeletionDispositionKind,
    pub reason_code: Option<String>,
    /// RFC 3339.
    pub review: Option<String>,
    /// The records a delete choice removed.
    pub deleted: Vec<String>,
    /// RFC 3339.
    pub recorded: String,
    /// The customer hold a legal hold choice placed or kept (FIX 2924).
    pub holds: Vec<CourtesyDeleteHold>,
    /// The records a legal hold choice named that are no copy this ask
    /// covers: left out of its hold (FIX 2927).
    pub excluded: Vec<String>,
    /// Each record of a delete choice, in order, and what became of it: one
    /// still pending was not removed (FIX 2926).
    pub progress: Vec<CourtesyDeleteRecordProgress>,
}

/// One ask a former peer sent, filed for the owner's review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CourtesyDeleteIncoming {
    pub request: String,
    pub pact: String,
    /// The pact's state in this vault's log, when it still has one.
    pub pact_status: Option<String>,
    pub requester: String,
    /// The worlds named; empty asks about everything the pact delivered.
    pub worlds: Vec<CourtesyDeleteAskedWorld>,
    pub epoch_cutoff: u64,
    /// The records this vault still holds that the ask covers: delivered by
    /// the pact at or before the cutoff, in a named world, or in any world
    /// when none is named (FIX 321). The owner picks from them; nothing is
    /// deleted on receipt.
    pub candidates: Vec<String>,
    /// RFC 3339.
    pub requested: String,
    /// RFC 3339.
    pub received: String,
    pub answer: Option<CourtesyDeleteChoice>,
    /// The answer's delivery status, once one is sent back.
    pub reply_status: Option<String>,
    /// Every customer hold an answer to this ask placed or kept, an earlier
    /// choice's included (FIX 2924).
    pub holds: Vec<CourtesyDeleteHold>,
}

/// What an embedded handle answers for a courtesy delete row: the asks, the
/// answers and their outbox live with a server's own authority key and
/// delivery, and an embedded vault has neither.
pub fn courtesy_delete_host_only<T, I>(
    _memory: &Memory<'_>,
    verb: &str,
    _input: &I,
) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!(
            "{verb} runs on a server's own authority key and courtesy outbox; an embedded vault has neither"
        ),
        &[super::sdk_host::SERVED_CLIENT_HINT],
    ))
}

/// RFC 3339 with milliseconds and `Z` for a time the ledger keeps in Unix
/// seconds: `2026-10-08T12:34:56.000Z`.
fn rfc3339_secs(unix_seconds: u64) -> String {
    i64::try_from(unix_seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map_or_else(
            || "1970-01-01T00:00:00.000Z".to_owned(),
            |stamp| stamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
}

/// One sent ask, as the ledger holds it.
#[must_use]
pub fn courtesy_delete_sent_ask(notice: CooperativeDeletionNotice) -> CourtesyDeleteSent {
    CourtesyDeleteSent {
        request: notice.request_id.clone(),
        pages: vec![notice.request_id],
        pact: notice.connection_id,
        recipient: notice.recipient_id,
        status: notice.status.as_str().to_owned(),
        created: rfc3339_secs(notice.created_at),
        updated: rfc3339_secs(notice.updated_at),
    }
}

/// Every ask this vault sent (`vault.courtesy_delete.sent`).
pub fn courtesy_delete_sent(vault: &Vault) -> crate::Result<Vec<CourtesyDeleteSent>> {
    Ok(vault
        .cooperative_deletion_notices()?
        .into_iter()
        .map(courtesy_delete_sent_ask)
        .collect())
}

/// Every ask filed here, with each named world's stale stamp and the
/// records the ask covers (`vault.courtesy_delete.incoming`).
pub fn courtesy_delete_incoming(vault: &Vault) -> crate::Result<Vec<CourtesyDeleteIncoming>> {
    let fold = vault.authority_fold()?;
    vault
        .incoming_cooperative_deletions()?
        .into_iter()
        .map(|filed| courtesy_delete_incoming_ask(vault, &fold, filed))
        .collect()
}

const fn hold_status(stands: bool) -> &'static str {
    if stands { "standing" } else { "lifted" }
}

/// The courtesy holds `ids` name, each as its row reads now; `unknown` once
/// it is gone (FIX 2924).
fn courtesy_holds(vault: &Vault, ids: &[EntityId]) -> crate::Result<Vec<CourtesyDeleteHold>> {
    Ok(vault
        .courtesy_holds(ids)?
        .into_iter()
        .map(|(id, hold)| match hold {
            Some(hold) => CourtesyDeleteHold {
                hold: id.to_hex(),
                status: hold_status(hold.stands()).to_owned(),
                records: hold
                    .targets
                    .iter()
                    .filter_map(LegalHoldTarget::id)
                    .map(|record| record.to_hex())
                    .collect(),
                lifted: hold.lifted_at.map(rfc3339_secs),
            },
            None => CourtesyDeleteHold {
                hold: id.to_hex(),
                status: "unknown".to_owned(),
                records: Vec::new(),
                lifted: None,
            },
        })
        .collect())
}

/// One filed ask as the owner reviews it.
pub fn courtesy_delete_incoming_ask(
    vault: &Vault,
    fold: &AuthorityFold,
    filed: IncomingCooperativeDeletion,
) -> crate::Result<CourtesyDeleteIncoming> {
    let pact = parse_hex::<32>(&filed.connection_id);
    let pact_status = pact
        .and_then(|pact| fold.federation_pacts.get(&pact))
        .map(|state| format!("{:?}", state.status));
    // The records the pact delivered that the ask covers (FIX 321). A named
    // world that does not parse matches nothing: it never widens the ask to
    // every world.
    let named: Vec<EntityId> = filed
        .worlds
        .iter()
        .filter_map(|world| EntityId::from_hex(world).ok())
        .collect();
    let candidates = match pact {
        Some(pact) if named.len() == filed.worlds.len() => vault
            .cooperative_deletion_candidates(&pact, &named, filed.epoch_cutoff)?
            .iter()
            .map(EntityId::to_hex)
            .collect(),
        _ => Vec::new(),
    };
    // The ask names the requester's own world ids; a named world's stale stamp
    // is the one on the foreign WORLD it lands in here (FIX 3497). The signed
    // ask is never rewritten.
    let worlds = filed
        .worlds
        .iter()
        .map(|world| {
            let here = match (pact, EntityId::from_hex(world)) {
                (Some(pact), Ok(id)) => crate::federation::pact_foreign_world(fold, &pact, id)?,
                _ => None,
            };
            let stamp = here
                .map(|foreign| {
                    crate::federation::foreign_world_stale_stamp(vault, foreign.entity_id())
                })
                .transpose()?
                .flatten();
            Ok(CourtesyDeleteAskedWorld {
                world: world.clone(),
                stale: stamp.map(|stamp| format!("{:?}", stamp.reason)),
                stale_epoch: stamp.map(|stamp| stamp.disconnect_epoch),
            })
        })
        .collect::<crate::Result<Vec<_>>>()?;
    let holds = courtesy_holds(vault, &filed.courtesy_hold_ids)?;
    let answer = match filed.disposition {
        Some(choice) => Some(CourtesyDeleteChoice {
            choice: choice.kind,
            reason_code: choice.reason_code,
            review: choice.review_at.map(rfc3339_secs),
            deleted: choice.deleted,
            recorded: rfc3339_secs(choice.recorded_at),
            holds: courtesy_holds(vault, &choice.hold_ids)?,
            excluded: choice.excluded,
            progress: choice
                .delete_operation
                .map(|operation| operation.records)
                .unwrap_or_default()
                .into_iter()
                .map(|saved| CourtesyDeleteRecordProgress {
                    record: saved.record.to_hex(),
                    state: saved.state.as_str().to_owned(),
                })
                .collect(),
        }),
        None => None,
    };
    Ok(CourtesyDeleteIncoming {
        request: filed.request_id,
        pact: filed.connection_id,
        pact_status,
        requester: filed.requester_vault_id,
        worlds,
        epoch_cutoff: filed.epoch_cutoff,
        candidates,
        requested: rfc3339_secs(filed.requested_at),
        received: rfc3339_secs(filed.received_at),
        answer,
        reply_status: filed.reply_status.map(|status| status.as_str().to_owned()),
        holds,
    })
}

/// `vault.courtesy_delete.sent` on an embedded handle, for its owner.
pub fn read_courtesy_delete_sent(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<CourtesyDeleteSent>> {
    owner.revalidate(vault)?;
    Ok(courtesy_delete_sent(vault)?)
}

/// `vault.courtesy_delete.incoming` on an embedded handle, for its owner.
pub fn read_courtesy_delete_incoming(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<CourtesyDeleteIncoming>> {
    owner.revalidate(vault)?;
    Ok(courtesy_delete_incoming(vault)?)
}
