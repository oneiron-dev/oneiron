//! The typed world-privacy request (FIX 4480): an agent's proposal of a
//! tighten no Grant line names, or a widen's in-moment ask. A request writes
//! no `WorldPrivacy` op; it freezes the world, the settings and the revision
//! they were decided on, and goes to every holder of the world's settings
//! right. A holder's yes applies it as his own act (`by: Owner`, `answer` =
//! the request), once.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use serde::{Deserialize, Serialize};

use crate::authority::{PolicyRevision, WorldPrivacy};
use crate::error::{Error, Result};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin, WORLD_PRIVACY_ASK_QUEUE,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

use super::super::world_privacy_switch::hex32;

/// The producer of every world-privacy notice.
pub(super) const NOTICE_PRODUCER: &str = "policy.world_privacy";
/// The version of a widen ask's question; bump it with its wording.
const ASK_VERSION: u32 = 1;
const ASK_QUEUE_VERSION: &str = "v1";

/// What a request asks of its holders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub(in crate::policy_model::owner_rows) fn parse_revision(hex: &str) -> Option<PolicyRevision> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(PolicyRevision(out))
}

const REQUESTS: SideTable<EntityId, WorldPrivacyRequest, Named> =
    SideTable::new(&side_table::OWNER_POLICY_WORLD_PRIVACY_REQUEST);

/// What a new request freezes.
pub(super) struct NewRequest {
    pub(super) kind: WorldPrivacyRequestKind,
    pub(super) agent: Option<EntityId>,
    pub(super) opener_lineage: Vec<[u8; 32]>,
    pub(super) author: EntityId,
    pub(super) world: EntityId,
    pub(super) settings: WorldPrivacy,
    pub(super) seen: PolicyRevision,
    pub(super) holders: Vec<EntityId>,
    pub(super) needs: Vec<EntityId>,
    pub(super) yes: Vec<EntityId>,
}

impl Vault {
    /// Opens one request in the caller's writer and tells every holder at
    /// once: a proposal's notice cancels it in one tap; a widen ask's notice
    /// names the request each holder confirms or declines at the
    /// world-privacy door, beside the decision ask its door queues for the
    /// owners after the commit ([`Self::queue_world_privacy_ask`]).
    pub(super) fn open_world_privacy_request_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        new: NewRequest,
    ) -> Result<WorldPrivacyRequest> {
        let id = self.store.clock.entity_id()?;
        let at = self.instant_in_txn(txn)?.secs();
        let hexes = |ids: &[EntityId]| ids.iter().map(EntityId::to_hex).collect::<Vec<_>>();
        let request = WorldPrivacyRequest {
            request_id: id.to_hex(),
            kind: new.kind,
            agent: new.agent.as_ref().map(EntityId::to_hex),
            opener_lineage: new.opener_lineage.iter().map(hex32).collect(),
            author: new.author.to_hex(),
            world: new.world.to_hex(),
            settings: new.settings,
            seen: hex32(&new.seen.0),
            holders: hexes(&new.holders),
            needs: hexes(&new.needs),
            yes: hexes(&new.yes),
            ask: None,
            status: WorldPrivacyRequestStatus::Pending,
            at,
        };
        REQUESTS.put(&self.store, txn, &id, &request)?;
        let (kind, detail) = match new.kind {
            WorldPrivacyRequestKind::Proposal => (
                NotificationKind::WorldPrivacyProposed,
                "an agent proposes stricter settings for this world; any one holder accepts it, \
                 and this notice's tap cancels it",
            ),
            WorldPrivacyRequestKind::WidenAsk => (
                NotificationKind::Ask,
                "a widen of this world's settings waits for a holder's yes: it is irreversible \
                 in effect, so confirm or decline it at the world-privacy door",
            ),
        };
        self.notify_world_holders_in_txn(
            txn,
            kind,
            &request.request_id,
            new.world,
            &new.holders,
            detail,
        )?;
        Ok(request)
    }

    /// One request, in the caller's snapshot. Crate-wide only for the wait
    /// on it (FIX 4706), which admits its asker alone; no door reads it.
    pub(crate) fn world_privacy_request_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
    ) -> Result<Option<WorldPrivacyRequest>> {
        REQUESTS.get(&self.store, txn, &id)
    }

    /// Writes `request` back in the caller's writer.
    pub(super) fn put_world_privacy_request_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: &WorldPrivacyRequest,
    ) -> Result<()> {
        REQUESTS.put(&self.store, txn, &request.id()?, request)
    }

    /// Every world-privacy request, newest first; only the pending ones when
    /// `pending_only`.
    pub fn world_privacy_requests(&self, pending_only: bool) -> Result<Vec<WorldPrivacyRequest>> {
        let txn = self.store.env.read_txn()?;
        let mut requests: Vec<WorldPrivacyRequest> = REQUESTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, request)| request)
            .filter(|request| !pending_only || request.status == WorldPrivacyRequestStatus::Pending)
            .collect();
        requests.sort_by(|left, right| right.at.cmp(&left.at));
        Ok(requests)
    }

    /// [`Self::world_privacy_requests`] as `holder` may see them (FIX 4707),
    /// in one snapshot that revalidates the proof first: a live vault owner
    /// sees every request; anyone else only those on worlds whose settings
    /// right they hold now, by the census the world-privacy doors judge.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds.
    pub fn world_privacy_requests_for(
        &self,
        holder: &crate::consent::AuthenticatedOwner,
        pending_only: bool,
    ) -> Result<Vec<WorldPrivacyRequest>> {
        let txn = self.store.env.read_txn()?;
        let actor = holder.revalidate_person_in_txn(self, &txn)?;
        let every = crate::policy_model::is_live_vault_owner_in_txn(self, &txn, &actor)?;
        let mut held = BTreeMap::new();
        let mut requests = Vec::new();
        for (_, request) in REQUESTS.scan(&self.store, &txn)? {
            if pending_only && request.status != WorldPrivacyRequestStatus::Pending {
                continue;
            }
            if !every {
                let world = request.world_id()?;
                let holds = match held.entry(world) {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        let holders = super::world_holders_in_txn(self, &txn, world)?;
                        *entry.insert(holders.contains(&actor))
                    }
                };
                if !holds {
                    continue;
                }
            }
            requests.push(request);
        }
        requests.sort_by(|left, right| right.at.cmp(&left.at));
        Ok(requests)
    }

    /// Tells each of `holders` about `about` (a settings receipt or a
    /// request) on `world`, in the caller's writer: one NOTIFICATION each,
    /// replay-safe.
    pub(super) fn notify_world_holders_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        kind: NotificationKind,
        about: &str,
        world: EntityId,
        holders: &[EntityId],
        detail: &str,
    ) -> Result<()> {
        self.notify_holders_in_txn(txn, kind, about, &[world], holders, detail)
    }

    /// The same notice path with its subjects named: `subjects` is empty for
    /// a vault-wide setting such as a pending "widen needs every owner"
    /// turn-off.
    pub(super) fn notify_holders_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        kind: NotificationKind,
        about: &str,
        subjects: &[EntityId],
        holders: &[EntityId],
        detail: &str,
    ) -> Result<()> {
        let at = self.instant_in_txn(txn)?.secs();
        for holder in holders {
            self.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind,
                    source: NotificationSource {
                        producer: NOTICE_PRODUCER.to_owned(),
                        event: format!("{about}:{}", holder.to_hex()),
                        result: Some(about.to_owned()),
                        detail: Some(detail.to_owned()),
                        ..NotificationSource::default()
                    },
                    subject_refs: subjects.to_vec(),
                    recipient: Some(*holder),
                    created_at: at,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(())
    }

    /// Queues the in-moment ask a widen request's holders see, once, and
    /// keeps its number on the request. Never inside a writer: the ask queue
    /// opens its own. A request whose ask failed to queue still reached its
    /// holders through the world-privacy door's list, and keeps no number.
    /// A holder who answered before the number was kept settles the ask in
    /// the commit that keeps it, from the request's stored answer, and its
    /// waiters wake after that commit (FIX 4706); nothing is applied again.
    pub(super) fn queue_world_privacy_ask(
        &self,
        mut request: WorldPrivacyRequest,
    ) -> Result<WorldPrivacyRequest> {
        let id = request.id()?;
        let principal = EntityId::from_hex(&request.author)
            .map_err(|_| Error::CorruptedIndex("world privacy request author"))?;
        let Ok(seq) = self.queue_decision_ask(&widen_ask(&request, id, principal)?) else {
            return Ok(request);
        };
        request.ask = Some(seq);
        let settled = self.with_write_txn(|txn| {
            let Some(mut stored) = self.world_privacy_request_in_txn(txn, id)? else {
                return Ok(None);
            };
            stored.ask = Some(seq);
            self.put_world_privacy_request_in_txn(txn, &stored)?;
            let (holder, yes) = match &stored.status {
                WorldPrivacyRequestStatus::Pending => return Ok(None),
                WorldPrivacyRequestStatus::Applied { holder, .. } => (holder, true),
                WorldPrivacyRequestStatus::Declined { holder } => (holder, false),
            };
            let holder = EntityId::from_hex(holder)
                .map_err(|_| Error::CorruptedIndex("world privacy request holder"))?;
            self.settle_world_privacy_ask_in_txn(txn, seq, holder, yes)
        })?;
        if let Some(seq) = settled {
            self.signal_decision_answer(seq);
        }
        Ok(request)
    }
}

/// The widen ask its holders see. The question names the world and the
/// settings asked for, says the widen is irreversible in effect, and that it
/// is confirmed or declined at the world-privacy door: an answer on the ask
/// queue itself applies nothing.
fn widen_ask(
    request: &WorldPrivacyRequest,
    id: EntityId,
    principal: EntityId,
) -> Result<HumanDecisionRequest> {
    let who = match &request.agent {
        Some(agent) => format!("Agent {agent}"),
        None => format!("Holder {}", request.author),
    };
    let settings = serde_json::to_string(&request.settings)
        .map_err(|_| Error::InvariantViolation("world privacy settings encode"))?;
    let every = if request.needs.is_empty() {
        "Any one holder's yes applies it."
    } else {
        "This vault's \"widen needs every owner\" setting is on: it applies once every owner \
         said yes."
    };
    Ok(HumanDecisionRequest {
        question: DecisionQuestion {
            id,
            version: ASK_VERSION,
            text: format!(
                "{who} asks to widen the privacy of world {world} to {settings}. A widen is \
                 irreversible in effect: what reaches a wider place cannot be called back. {every} \
                 Confirm or decline it at the world-privacy door (request {request_id}); an answer \
                 here applies nothing.",
                world = request.world,
                request_id = request.request_id,
            ),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        principal,
        evidence: vec![request.world_id()?],
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: WORLD_PRIVACY_ASK_QUEUE.to_owned(),
            version: ASK_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(id),
    })
}
