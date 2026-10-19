//! What an opened device's recall says of its home (FIX 2905, OF-534). A
//! device that syncs only what it opened answers recall from its own items,
//! which are not every window it may read: each recall it answers alone says
//! so ([`RecallResidence`], local-only and incomplete), and the async server
//! door asks the home for the references the device does not hold
//! ([`complete_with_home`]). The home's hits are discovery references, never
//! memory items: they carry no body, and a hit's window opens it.

use serde::{Deserialize, Serialize};

#[cfg(feature = "sync")]
use super::MemoryItem;
use super::MemoryPack;
use crate::Vault;

/// Who answered a recall's [`RecallResidence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecallResidenceSource {
    /// The home answered the query.
    Home,
    /// The home was not asked, was out of reach or refused: the pack holds
    /// this device's own items alone.
    LocalOnly,
}

/// What an opened device's recall says of the windows it does not hold
/// (FIX 2905). The pack's items are this device's own and stay as ranked;
/// the home's discovery hits are separate references the local pack does
/// not hold, and a hit's window opens it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecallResidence {
    /// Who answered.
    pub source: RecallResidenceSource,
    /// The home answered in full. False is this device's answer alone, and
    /// marks the pack `retrieval_meta.partial`.
    pub complete: bool,
    /// The recall's limit was past the residence `search_limit`, so the home
    /// was asked for that many references and no more.
    pub capped: bool,
    /// The home's references the local pack does not hold, in the home's
    /// order, each entity once.
    pub hits: Vec<RecallResidenceHit>,
    /// Whether this stamp is what marked the pack partial, so a later home
    /// answer unmarks only what the stamp marked. Never on the wire.
    #[serde(skip)]
    marked_partial: bool,
}

/// One reference the home holds that the local pack does not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecallResidenceHit {
    /// The entity's full id, 32 lowercase hex.
    pub id: String,
    /// The home's own score: it orders the home's hits, and is never
    /// compared with a local item's.
    pub score: f32,
    /// The month window (`YYYY-MM`) that holds the hit; opening it opens
    /// the hit.
    pub window: String,
}

impl RecallResidence {
    /// The answer of this device alone: the home not asked, out of reach,
    /// or refusing.
    #[must_use]
    pub const fn local_only() -> Self {
        Self {
            source: RecallResidenceSource::LocalOnly,
            complete: false,
            capped: false,
            hits: Vec::new(),
            marked_partial: false,
        }
    }
}

/// How a recall joins the home's references to its own items (FIX 2905).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomeRecallMergeOrder {
    /// The local items stay as they are, first. The home's references
    /// follow apart, in the home's order, each entity once and none the
    /// local pack holds. A local fusion score is never compared with a home
    /// score.
    LocalThenHome,
}

/// The merge order every recall answer takes (FIX 2905): one policy hook.
pub const HOME_RECALL_MERGE_ORDER: HomeRecallMergeOrder = HomeRecallMergeOrder::LocalThenHome;

impl HomeRecallMergeOrder {
    /// The home's `hits` as the pack carries them beside `local`: by full
    /// entity id, none an item holds or quotes, each entity once.
    #[cfg(feature = "sync")]
    fn home_references(
        self,
        local: &[MemoryItem],
        hits: impl IntoIterator<Item = RecallResidenceHit>,
    ) -> Vec<RecallResidenceHit> {
        match self {
            Self::LocalThenHome => {
                let mut held: std::collections::HashSet<String> = local
                    .iter()
                    .flat_map(|item| {
                        item.record.iter().chain(
                            item.cited_messages
                                .iter()
                                .filter_map(|message| message.record.as_ref()),
                        )
                    })
                    .map(|record| record.id.to_ascii_lowercase())
                    .collect();
                hits.into_iter()
                    .filter(|hit| held.insert(hit.id.to_ascii_lowercase()))
                    .collect()
            }
        }
    }
}

impl MemoryPack {
    /// Stamps the recall's residence: an incomplete one marks the pack
    /// partial. A later stamp first unmarks what an earlier one marked, so
    /// a home that completes the answer leaves only the deadline's mark.
    pub(crate) fn stamp_residence(&mut self, residence: Option<RecallResidence>) {
        if self
            .residence
            .take()
            .is_some_and(|earlier| earlier.marked_partial)
        {
            self.retrieval_meta.partial = false;
        }
        if let Some(mut residence) = residence {
            residence.marked_partial = !residence.complete && !self.retrieval_meta.partial;
            self.retrieval_meta.partial |= !residence.complete;
            self.residence = Some(residence);
        }
    }
}

/// The residence a recall answered on this device alone carries (FIX 2905):
/// local-only and incomplete on a device known to run Opened, with a live
/// sync connection or after it dropped; `None` on one that holds every
/// window it may read, or runs no sync.
pub(crate) fn local_residence(vault: &Vault) -> Option<RecallResidence> {
    #[cfg(feature = "sync")]
    let opened = matches!(
        vault.device_residence(),
        crate::sync::DeviceResidence::Opened { .. }
    );
    #[cfg(not(feature = "sync"))]
    let opened = {
        let _ = vault;
        false
    };
    opened.then(RecallResidence::local_only)
}

/// Who a recall asks the home for (FIX 2907): the device's owner, or a
/// narrower caller judged at the home on its own holder proof. A narrower
/// caller with none asks nothing: never the device owner in its place.
#[derive(Debug, Clone)]
pub struct HomeRecallCaller {
    /// The caller is the device's paired owner: the home answers within
    /// this device's own grants.
    pub owner_grade: bool,
    /// A narrower caller's own holder proof, forwarded unchanged; `None`
    /// for an owner-grade caller.
    pub forwarded: Option<crate::authority::ForwardedCallerProof>,
}

impl HomeRecallCaller {
    /// Asks the home for no one: the recall keeps its local answer.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            owner_grade: false,
            forwarded: None,
        }
    }

    /// The device's owner.
    #[must_use]
    pub const fn owner() -> Self {
        Self {
            owner_grade: true,
            forwarded: None,
        }
    }

    /// A caller as its ingress admitted it: owner-grade, or narrower with
    /// the holder proof it presented there, if any. An owner-grade caller
    /// forwards no proof.
    #[must_use]
    pub fn admitted(
        owner_grade: bool,
        forwarded: Option<crate::authority::ForwardedCallerProof>,
    ) -> Self {
        Self {
            owner_grade,
            forwarded: forwarded.filter(|_| !owner_grade),
        }
    }
}

/// What a recall asks its home, read from the request before the request
/// moves to the blocking pool.
#[cfg(feature = "sync")]
#[derive(Debug, Clone)]
pub struct HomeRecallAsk {
    query: String,
    /// The limit the request asked for, or recall's default.
    limit: usize,
    /// Whether the home can answer the request (`home_answers`).
    answerable: bool,
}

#[cfg(feature = "sync")]
impl HomeRecallAsk {
    /// The ask for `request`; `room_turn` says it runs inside a room's turn.
    #[must_use]
    pub fn new(request: &crate::task_verb::sdk::RecallRequest, room_turn: bool) -> Self {
        Self {
            query: request.query.clone(),
            limit: request
                .limit
                .unwrap_or(crate::task_verb::sdk::VAULT_RECALL_LIMIT_DEFAULT),
            answerable: home_answers(request, room_turn),
        }
    }
}

/// Whether the home can answer `request` (FIX 2905, the first slice): its
/// search carries the query and a limit alone, so it answers a recall of
/// every world (`scope.worlds` All) that names no `world_ref`, project,
/// facet or kinds, no `as_of` and no media, outside a room's turn. Every
/// other recall keeps its local answer, marked incomplete, until the home
/// takes the recall's scope.
#[cfg(feature = "sync")]
fn home_answers(request: &crate::task_verb::sdk::RecallRequest, room_turn: bool) -> bool {
    let every_world = request.scope.as_ref().is_some_and(|scope| {
        matches!(scope.worlds, Some(crate::memory::RecallWorlds::All))
            && scope.world_ref.is_none()
            && scope.project_refs.is_empty()
            && scope.facet.is_none()
            && scope.kinds.is_none()
    });
    every_world && request.as_of.is_none() && request.media.is_none() && !room_turn
}

/// Completes a recall answer on a device known to run Opened with its
/// home's references (FIX 2905). The home is asked for `min(limit,
/// search_limit)` under `caller`, within the residence `rpc_timeout_ms` and
/// `due`, the recall's own deadline, whichever comes first; a `Home` answer
/// fills the pack's `residence` with the references the local pack does not
/// hold, in [`HOME_RECALL_MERGE_ORDER`]. No live connection, a request the
/// home cannot answer, a caller with nothing to ask under, a refusal, a
/// timeout, or the device's own fallback answer keeps the pack local-only
/// and incomplete. The local items are never touched. A device not known
/// to run Opened leaves the pack alone.
#[cfg(feature = "sync")]
pub async fn complete_with_home(
    vault: &Vault,
    pack: &mut MemoryPack,
    ask: &HomeRecallAsk,
    caller: &HomeRecallCaller,
    due: Option<std::time::Instant>,
) {
    let crate::sync::DeviceResidence::Opened { search } = vault.device_residence() else {
        return;
    };
    let answer = match search {
        Some(search) if ask.answerable => {
            ask_home(vault, &search, &pack.items, ask, caller, due).await
        }
        _ => None,
    };
    pack.stamp_residence(Some(answer.unwrap_or_else(RecallResidence::local_only)));
}

/// The home's answer to `ask`, or `None` when it gave none this recall can
/// carry: then the pack stays local-only.
#[cfg(feature = "sync")]
async fn ask_home(
    vault: &Vault,
    search: &crate::sync::HomeSearch,
    local: &[MemoryItem],
    ask: &HomeRecallAsk,
    caller: &HomeRecallCaller,
    due: Option<std::time::Instant>,
) -> Option<RecallResidence> {
    let forwarded = match (caller.owner_grade, caller.forwarded.as_ref()) {
        (true, _) => None,
        (false, Some(proof)) => Some(proof),
        (false, None) => return None,
    };
    // A malformed residence policy refuses the ask, as the home search does.
    let budgets = vault.residence_operation_budgets().ok().flatten()?;
    let limit = ask.limit.min(budgets.search_limit);
    let bound =
        std::time::Instant::now() + std::time::Duration::from_millis(budgets.rpc_timeout_ms);
    let bound = due.map_or(bound, |due| due.min(bound));
    let asked = async {
        match forwarded {
            Some(proof) => search.search_for(&ask.query, limit, proof).await,
            None => search.search(&ask.query, limit).await,
        }
    };
    let found = tokio::time::timeout_at(bound.into(), asked)
        .await
        .ok()?
        .ok()?;
    // The device's own fallback ranks rows the local recall already read.
    if found.source != crate::sync::SearchSource::Home {
        return None;
    }
    let hits = found.hits.into_iter().map(|hit| RecallResidenceHit {
        id: hit.entity_id,
        score: hit.score,
        window: hit.window.to_string(),
    });
    Some(RecallResidence {
        source: RecallResidenceSource::Home,
        complete: found.complete,
        capped: ask.limit > budgets.search_limit,
        hits: HOME_RECALL_MERGE_ORDER.home_references(local, hits),
        marked_partial: false,
    })
}
