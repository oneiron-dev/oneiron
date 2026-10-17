//! Offer cards (OF-530): an agent asks to join a room or one of its threads
//! by a card, never by a turn (ARCH-0006a:237).
//!
//! A card names who asks (the AGENT_DEF), what it would do (one sentence, the
//! artifact attached), the cost as the lease cap of the spend tree the work
//! would run under, and two verbs, join or not now. It sits in the room's
//! audience tier, the GenUI card and the `vault.rooms.offers` read: minting
//! one appends no turn, witnesses nothing and says nothing. A paid card is
//! published only once its payer's consent sits on the scope's root
//! (ARCH-0068:308); the host's admission is then what it asks for, and the
//! vault's membership is read live. One card is current per agent per room
//! or thread: a new one replaces it, which is never a count cap. An open card
//! ages out with its thread, read from the room's own liveness fold; there is
//! no TTL and no close flag. Answering a card is [`super::offer_settle`].

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::offer_settle::{Acceptance, Settled, Step, run_settlement};
use super::{TURNS, invalid};
use crate::agent_dispatch::{AgentDispatcher, SpendScopeId, SpendState};
use crate::claim::{ClaimReadStatus, PointRead};
use crate::error::{Error, Result};
use crate::llm::run_admission::DeclaredMaximum;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::Store;
use crate::workspace_roster::{
    ConsentNeed, JoinDecision, JoinRefusal, JoinRequest, JoinSubject,
    join_subject_for_actor_in_txn, rooms_join_in_txn,
};
use crate::{EntityId, Vault, WriteActor};

/// One offer card and the answer that settled it. Key: the offer id.
pub(super) const OFFERS: SideTable<String, StoredOffer, LegacyJson> =
    SideTable::new(&side_table::ROOMS_OFFER);

/// The card current for one agent in one room or thread. Key:
/// [`current_key`]; value: the offer id.
const OFFER_CURRENT: SideTable<String, String, LegacyJson> =
    SideTable::new(&side_table::ROOMS_OFFER_CURRENT);

const OFFER_ID_DOMAIN: &str = "oneiron.rooms.offer.v1";

/// An agent's ask to join a room or one of its threads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferDraft {
    pub room: EntityId,
    /// The thread's root turn, when the agent asks to join one thread rather
    /// than the room.
    #[serde(default)]
    pub branch: Option<EntityId>,
    /// The AGENT_DEF that asks.
    pub agent: EntityId,
    /// What it would do: one sentence, on one line.
    pub what: String,
    /// The artifact it attaches, by reference.
    #[serde(default)]
    pub artifact_ref: Option<String>,
    /// The open scope paid work would spend under. Its root carries the
    /// payer's consent and the cap the card shows; `None` launches no paid
    /// work. The draft names no payer, cap or paid flag of its own.
    #[serde(default)]
    pub spend_scope: Option<SpendScopeId>,
    /// The caller's idempotency key: the same key replays this card.
    pub intent_key: String,
}

/// Where one card stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OfferState {
    /// Waiting on the parties `needs` names. The host's admission is the one
    /// the card asks for; a payer answers through `rooms.consent`, and
    /// membership is read live.
    Open { needs: Vec<ConsentNeed> },
    /// The join was Ready and the agent's acceptance landed as `turn`, its
    /// own turn in the room or thread.
    Joined { turn: EntityId, receipt_ref: String },
    /// Not now. The decline is in the agent's private diary, or `None` when
    /// the agent's standing refused the note; it settles this card and bars no
    /// later ask.
    NotNow { diary_ref: Option<EntityId> },
    /// A newer card from the same agent for the same room or thread
    /// replaced this one.
    Superseded { by: String },
    /// The card's thread ended before anyone answered it.
    AgedOut,
}

/// One offer card, as the room's audience sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferCard {
    /// 64 lowercase hex: the digest of the room, thread, agent and intent key.
    pub offer_id: String,
    pub room: EntityId,
    pub branch: Option<EntityId>,
    /// Who asks: the AGENT_DEF.
    pub agent: EntityId,
    pub what: String,
    pub artifact_ref: Option<String>,
    /// The cost: the cap the payer accepted on the spend tree's root, in its
    /// unit. `None` for unpaid work.
    pub lease_cap: Option<DeclaredMaximum>,
    /// The PERSON whose funds paid work spends, from the scope's root.
    pub payer: Option<EntityId>,
    /// The scope paid work spends under.
    pub spend_scope: Option<SpendScopeId>,
    /// The join this card filed for the agent, under intent `offer:<offer_id>`.
    pub join_ref: String,
    pub state: OfferState,
    /// Unix seconds.
    pub created_at: u64,
}

/// A card as stored: the card, what it was minted from and by whom, and the
/// host's answer that settled it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredOffer {
    pub(super) card: OfferCard,
    /// The digest of the draft the card was minted from: the same intent asked
    /// with another draft refuses.
    pub(super) draft_digest: String,
    /// The actor that minted it: the agent or its principal.
    pub(super) minted_by: EntityId,
    pub(super) answer: Option<super::offer_settle::RecordedOfferAnswer>,
}

/// A page of the current cards in a room, or in one of its threads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffersRequest {
    pub room: EntityId,
    /// One thread's cards; `None` reads every card in the room.
    #[serde(default)]
    pub branch: Option<EntityId>,
    /// The `next_after` of the previous page.
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffersPage {
    pub rows: Vec<OfferCard>,
    /// Explicit end marker: `None` means no further page.
    pub next_after: Option<String>,
}

/// The current-card key: the room, the thread or `-`, and the agent.
fn current_key(room: EntityId, branch: Option<EntityId>, agent: EntityId) -> String {
    format!(
        "{}/{}/{}",
        room.to_hex(),
        branch.map_or_else(|| "-".to_owned(), |branch| branch.to_hex()),
        agent.to_hex()
    )
}

fn digest<T: Serialize>(value: &T) -> Result<String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| Error::InvariantViolation("offer draft encode"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// An offer id: 64 lowercase hex.
pub(super) fn is_offer_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Deletes every card minted in `room`, whatever its state (a superseded
/// card keeps its row after the new one is current), then the room's
/// current-card pointers.
pub(super) fn delete_room_offers(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
) -> Result<()> {
    delete_offers_where(store, txn, |card| card.room == room)?;
    OFFER_CURRENT.delete_from(store, txn, format!("{}/", room.to_hex()).as_bytes())?;
    Ok(())
}

/// [`delete_room_offers`] for the one thread of `room` rooted at `thread`,
/// when that root is erased: its cards in every state, then its current-card
/// pointers. The room's own cards and every other thread's stay.
pub(super) fn delete_thread_offers(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    thread: EntityId,
) -> Result<()> {
    delete_offers_where(store, txn, |card| {
        card.room == room && card.branch == Some(thread)
    })?;
    OFFER_CURRENT.delete_from(
        store,
        txn,
        format!("{}/{}/", room.to_hex(), thread.to_hex()).as_bytes(),
    )?;
    Ok(())
}

/// Deletes every stored card `doomed` names. OFFERS is keyed by offer id, not
/// by room, so the sweep reads the whole table in keyset pages.
fn delete_offers_where(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    doomed: impl Fn(&OfferCard) -> bool,
) -> Result<()> {
    let page_limit = super::history::PAGE_LIMIT;
    let mut after: Option<String> = None;
    loop {
        let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
        let page: Vec<(String, StoredOffer)> = OFFERS
            .iter_range(store, txn, start, Bound::Unbounded)?
            .take(page_limit)
            .collect::<Result<_>>()?;
        for (offer_id, stored) in &page {
            if doomed(&stored.card) {
                OFFERS.delete(store, txn, offer_id)?;
            }
        }
        if page.len() < page_limit {
            break;
        }
        after = page.last().map(|(offer_id, _)| offer_id.clone());
    }
    Ok(())
}

/// A caller's idempotency key: 1..=128 printable bytes, as a join's.
pub(super) fn valid_intent_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 128 && key.bytes().all(|byte| byte.is_ascii_graphic())
}

/// One sentence on one line: trimmed, not empty, no line break, within the
/// bound a lens text holds.
fn one_line(field: &str, value: &str) -> MemoryResult<String> {
    let value = value.trim();
    if value.is_empty() || value.contains(['\n', '\r']) {
        return Err(MemoryError::bad_request(format!(
            "an offer's {field} is one line of text"
        )));
    }
    crate::lens::LensText::new(value)?;
    Ok(value.to_owned())
}

/// A join refusal, as the refusal of the write that filed or answered it.
pub(super) fn join_refused(refusal: &JoinRefusal) -> MemoryError {
    let typed = serde_json::to_value(refusal)
        .map_or_else(|_| format!("{refusal:?}"), |value| value.to_string());
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("the agent's join is refused: {typed}"),
        &["Once the refused party's standing is fixed, ask or answer again."],
    )
}

/// The cost a paid card shows, read from its scope's root: the cap its payer
/// accepted, and that payer. A card is published only once the payer's
/// consent sits on the root, never on the host's or the vault owner's funds.
fn payer_terms_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: Option<&SpendScopeId>,
) -> MemoryResult<(Option<DeclaredMaximum>, Option<EntityId>)> {
    let Some(scope) = scope else {
        return Ok((None, None));
    };
    let (row, root) = AgentDispatcher::new(vault)
        .scope_with_root_in_txn(txn, scope)?
        .ok_or_else(|| MemoryError::bad_request("no such spend scope"))?;
    let Some(payer) = root.payer else {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the payer's consent precedes the offer",
            &[
                "The PERSON who pays opens the scope with their consent on its root; then the agent asks.",
            ],
        ));
    };
    if row.state != SpendState::Open || root.state != SpendState::Open {
        return Err(MemoryError::bad_request("the spend scope is closed"));
    }
    Ok((
        Some(DeclaredMaximum {
            units: root.cap_units,
            unit: root.unit,
        }),
        Some(payer.party),
    ))
}

/// Mints `draft`'s card in the caller's write: files the agent's join as
/// `caller`, then makes the card current for that agent there, replacing the
/// open one it held. A Ready join lands the agent's acceptance at once.
fn mint_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    draft: &OfferDraft,
    what: &str,
    artifact_ref: Option<&str>,
    caller: WriteActor,
    now: u64,
) -> MemoryResult<Step> {
    let offer_id = digest(&(
        OFFER_ID_DOMAIN,
        draft.room,
        draft.branch,
        draft.agent,
        &draft.intent_key,
    ))?;
    let draft_digest = digest(&(OFFER_ID_DOMAIN, draft))?;
    if let Some(stored) = OFFERS.get(&vault.store, txn, &offer_id)? {
        if stored.draft_digest != draft_digest {
            return Err(MemoryError::bad_request(
                "this intent_key already names a different offer",
            ));
        }
        return Ok(Step::Done(Settled::replayed(vault, txn, stored)?));
    }
    if vault.get_entity_type_in_txn(txn, &draft.agent)? != Some(ENTITY_TYPE_AGENT_DEF) {
        return Err(MemoryError::bad_request(
            "an offer card asks for an AGENT_DEF",
        ));
    }
    // A PERSON-anchored AGENT_DEF is its person's pen and takes part as that
    // person, who joins by writing; only an agent asks by a card.
    if join_subject_for_actor_in_txn(vault, txn, draft.agent, now)?
        != JoinSubject::Agent(draft.agent)
    {
        return Err(MemoryError::bad_request(
            "a person's pen joins by writing as its person, not by an offer card",
        ));
    }
    // A room thread is named by its root turn, as joins and participation
    // name it, never by a reply inside it.
    if let Some(branch) = draft.branch
        && let Some(turn) = TURNS.get(&vault.store, txn, &branch)?
        && !super::liveness::is_thread_root(&turn)
    {
        return Err(MemoryError::bad_request(
            "an offer names its thread by the thread's root turn",
        ));
    }
    let (lease_cap, payer) = payer_terms_in_txn(vault, txn, draft.spend_scope.as_ref())?;
    // The join door files only for the agent's own actor or its principal,
    // and decides the three consents in this write.
    let join = rooms_join_in_txn(
        vault,
        txn,
        &JoinRequest {
            room: draft.room,
            branch: draft.branch,
            subject: JoinSubject::Agent(draft.agent),
            paid: draft.spend_scope.is_some(),
            spend_scope: draft.spend_scope.clone(),
            intent_key: format!("offer:{offer_id}"),
        },
        caller,
        now,
    )?;
    let needs = match &join.decision.state {
        JoinDecision::Refuse(refusal) => return Err(join_refused(refusal)),
        JoinDecision::Hold { needs } => needs.clone(),
        JoinDecision::Ready => Vec::new(),
    };
    // One card per agent per room or thread: the new one replaces it.
    let key = current_key(draft.room, draft.branch, draft.agent);
    if let Some(prior) = OFFER_CURRENT.get(&vault.store, txn, &key)?
        && let Some(mut replaced) = OFFERS.get(&vault.store, txn, &prior)?
        && matches!(replaced.card.state, OfferState::Open { .. })
    {
        replaced.card.state = OfferState::Superseded {
            by: offer_id.clone(),
        };
        OFFERS.put(&vault.store, txn, &prior, &replaced)?;
    }
    OFFER_CURRENT.put(&vault.store, txn, &key, &offer_id)?;
    let card = OfferCard {
        offer_id: offer_id.clone(),
        room: draft.room,
        branch: draft.branch,
        agent: draft.agent,
        what: what.to_owned(),
        artifact_ref: artifact_ref.map(str::to_owned),
        lease_cap,
        payer,
        spend_scope: draft.spend_scope.clone(),
        join_ref: join.join_ref.clone(),
        state: OfferState::Open { needs },
        created_at: now,
    };
    OFFERS.put(
        &vault.store,
        txn,
        &offer_id,
        &StoredOffer {
            card: card.clone(),
            draft_digest,
            minted_by: caller.entity_ref(),
            answer: None,
        },
    )?;
    if matches!(join.decision.state, JoinDecision::Ready) {
        return Ok(Step::Land(Box::new(Acceptance::ready_in_txn(
            vault, txn, card, join,
        )?)));
    }
    Ok(Step::Done(Settled {
        card,
        join: Some(join),
    }))
}

/// Whether `turn` is the acceptance an offer settlement bound, in this write,
/// to `agent` in `room` and its thread `branch`: the card current for that
/// agent there is Joined with exactly this turn. The room speech door takes
/// it in place of a claim on an addressed turn. It is no mention and no
/// claim, and the speaking role and author ceiling still decide the turn.
pub(super) fn accepts_offer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    agent: EntityId,
    turn: EntityId,
) -> Result<bool> {
    let Some(offer) = OFFER_CURRENT.get(&vault.store, txn, &current_key(room, branch, agent))?
    else {
        return Ok(false);
    };
    let Some(stored) = OFFERS.get(&vault.store, txn, &offer)? else {
        return Ok(false);
    };
    let card = stored.card;
    Ok(card.room == room
        && card.branch == branch
        && card.agent == agent
        && matches!(card.state, OfferState::Joined { turn: landed, .. } if landed == turn))
}

impl Memory<'_> {
    /// Publishes an agent's offer card in a room or one of its threads, from
    /// the agent itself or its principal. See the module docs.
    pub fn rooms_offer(&self, draft: &OfferDraft) -> MemoryResult<OfferCard> {
        let what = one_line("what", &draft.what)?;
        let artifact_ref = draft
            .artifact_ref
            .as_deref()
            .map(|artifact| one_line("artifact_ref", artifact))
            .transpose()?;
        if !valid_intent_key(&draft.intent_key) {
            return Err(MemoryError::bad_request(
                "an offer's intent_key is 1..=128 printable bytes",
            ));
        }
        self.require_offer_audience(draft.room, draft.branch)?;
        let caller = WriteActor::new(self.actor(), self.actor_class());
        let vault = self.vault();
        Ok(run_settlement(vault, |txn, now| {
            mint_in_txn(
                vault,
                txn,
                draft,
                &what,
                artifact_ref.as_deref(),
                caller,
                now,
            )
        })?
        .card)
    }

    /// The current offer cards in a room, or in one of its threads, a page at
    /// a time, each one the caller's own reads admit. An open card whose
    /// thread has ended reads as aged out; the read writes nothing.
    pub fn rooms_offers(&self, request: &OffersRequest) -> MemoryResult<OffersPage> {
        let page_limit = super::history::PAGE_LIMIT;
        let limit = request.limit.map_or(page_limit, |limit| {
            usize::try_from(limit).unwrap_or(usize::MAX)
        });
        if limit == 0 || limit > page_limit {
            return Err(MemoryError::from(invalid()));
        }
        self.require_offer_audience(request.room, request.branch)?;
        let prefix = match request.branch {
            Some(branch) => format!("{}/{}/", request.room.to_hex(), branch.to_hex()),
            None => format!("{}/", request.room.to_hex()),
        };
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let mut current = Vec::new();
        for row in OFFER_CURRENT.iter_from(&vault.store, &txn, prefix.as_bytes())? {
            let (key, offer) = row?;
            if request.after.as_ref().is_some_and(|after| key <= *after) {
                continue;
            }
            let stored = OFFERS
                .get(&vault.store, &txn, &offer)?
                .ok_or(Error::CorruptedIndex("current offer has no card"))?;
            current.push((key, stored.card));
        }
        drop(txn);
        let mut rows = Vec::new();
        let mut last = None;
        let mut more = false;
        for (key, card) in current {
            // A thread's card is shown to that thread's audience only.
            if let Some(branch) = card.branch
                && card.branch != request.branch
                && !self.offer_record_readable(branch)?
            {
                continue;
            }
            if rows.len() == limit {
                more = true;
                break;
            }
            rows.push(card);
            last = Some(key);
        }
        let open: BTreeSet<EntityId> = rows
            .iter()
            .filter(|card| matches!(card.state, OfferState::Open { .. }))
            .filter_map(|card| card.branch)
            .collect();
        let ended = self.ended_offer_threads(request.room, &open)?;
        for card in &mut rows {
            if matches!(card.state, OfferState::Open { .. })
                && card.branch.is_some_and(|branch| ended.contains(&branch))
            {
                card.state = OfferState::AgedOut;
            }
        }
        Ok(OffersPage {
            rows,
            next_after: if more { last } else { None },
        })
    }

    /// The threads among `threads` of `room` that have ended, so their open
    /// cards age out (ARCH-0006a:233): the room's own fold, as the caller
    /// reads it, lists them quiet, with no open task, open wait or fresh
    /// message. A card for the room itself, a branch the fold does not hold,
    /// and a room that keeps no thread fold end nothing.
    pub(super) fn ended_offer_threads(
        &self,
        room: EntityId,
        threads: &BTreeSet<EntityId>,
    ) -> MemoryResult<BTreeSet<EntityId>> {
        if threads.is_empty() {
            return Ok(BTreeSet::new());
        }
        let Some(project_room) = self.vault().project_room(room)? else {
            return Ok(BTreeSet::new());
        };
        let turns = self.room_turn_snapshot(room)?;
        let selected: BTreeMap<EntityId, EntityId> = super::liveness::thread_root_map(&turns)?
            .into_iter()
            .filter(|(_, root)| threads.contains(root))
            .collect();
        if selected.is_empty() {
            return Ok(BTreeSet::new());
        }
        let members = project_room.member_ids.into_iter().collect();
        let now = crate::unix_seconds_now();
        // Task and wait reads run inside the room, as the room's own fold
        // reads them.
        let bindings = super::liveness::thread_task_bindings(&turns, &selected)?;
        let tasks = crate::task_verb::room_thread_tasks(
            self.for_room_projection(room)?.memory(),
            &selected,
            &bindings,
            &members,
            now,
        )?;
        let mut ended = BTreeSet::new();
        for thread in threads {
            let held: Vec<_> = tasks
                .iter()
                .filter(|task| task.thread == *thread)
                .cloned()
                .collect();
            if super::liveness::thread_is_live(&turns, &held, room, *thread, now)? == Some(false) {
                ended.insert(*thread);
            }
        }
        Ok(ended)
    }

    /// Whether the caller's own reads admit `id`'s record: a thread root a
    /// card names is shown only to whoever reads it.
    fn offer_record_readable(&self, id: EntityId) -> MemoryResult<bool> {
        let read = self
            .read_lane(ClaimReadStatus::Recorded)?
            .read(&[PointRead::id(id)], None)?;
        Ok(read.value.into_iter().flatten().next().is_some())
    }

    /// Refuses a caller outside a card's audience: one whose own reads do not
    /// admit the room's record or the thread's root. A room turn asks and
    /// reads in its own room only.
    fn require_offer_audience(&self, room: EntityId, branch: Option<EntityId>) -> MemoryResult<()> {
        if let Some(turn) = self.room_turn()
            && turn.room != room
        {
            return Err(MemoryError::bad_request_with(
                "room differs from the bound room turn",
                &[],
            ));
        }
        let readable = self.room_record_readable(room)?
            && match branch {
                Some(branch) => self.offer_record_readable(branch)?,
                None => true,
            };
        if !readable {
            return Err(MemoryError::not_found("no room or thread the caller reads"));
        }
        Ok(())
    }
}
