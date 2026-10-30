//! What an opened device's recall says of its home (FIX 2905, OF-534). A
//! device that syncs only what it opened answers recall from its own items,
//! which are not every window it may read: each recall it answers alone says
//! so ([`RecallResidence`], local-only and incomplete), and the async server
//! door asks the home for the references the device does not hold
//! ([`complete_with_home`]). The home's hits are discovery references, never
//! memory items: they carry no body, and a hit's window opens it. The home
//! narrows its search by the scope the device's recall resolved, before its
//! candidate cut, and returns the unit recall returns.

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
    /// The home's answer stopped short of the recall's limit: a page ran
    /// past its time, or the home's list went on past the pages the limit
    /// asks (FIX 9256). The references it gave stand, and `complete` is
    /// false.
    pub capped: bool,
    /// The home's references the local pack does not hold, in the home's
    /// order, each entity once.
    pub hits: Vec<RecallResidenceHit>,
    /// Whether this stamp is what marked the pack partial, so a later home
    /// answer unmarks only what the stamp marked. Never on the wire.
    #[serde(skip)]
    marked_partial: bool,
    /// What the recall that stamped this narrowed by, as it resolved it:
    /// the scope its home narrows by. Never on the wire.
    #[cfg(feature = "sync")]
    #[serde(skip)]
    #[schemars(skip)]
    selection: Option<crate::sync::residence::ResolvedRecallSelection>,
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
            #[cfg(feature = "sync")]
            selection: None,
        }
    }

    /// The home's answer to a text search (FIX 3876, `vault.search.bm25`):
    /// its `hits` in its order, each entity once and none of `held`, the
    /// full ids the device's own page holds; `complete` as the home said;
    /// `capped` when its answer stopped short of the search's limit.
    #[must_use]
    pub fn home_text(
        hits: impl IntoIterator<Item = RecallResidenceHit>,
        complete: bool,
        capped: bool,
        held: &[String],
    ) -> Self {
        let mut held: std::collections::HashSet<String> =
            held.iter().map(|id| id.to_ascii_lowercase()).collect();
        Self {
            source: RecallResidenceSource::Home,
            complete,
            capped,
            hits: hits
                .into_iter()
                .filter(|hit| held.insert(hit.id.to_ascii_lowercase()))
                .collect(),
            marked_partial: false,
            #[cfg(feature = "sync")]
            selection: None,
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

    /// Marks the pack partial for its own retrieval (a cut at the deadline),
    /// not for its residence.
    pub(crate) fn mark_cut(&mut self) {
        self.retrieval_meta.partial = true;
        if let Some(residence) = self.residence.as_mut() {
            residence.marked_partial = false;
        }
    }

    /// Whether the pack is partial for its own retrieval: the deadline cut a
    /// stage. The residence stamp's mark is not that.
    pub(crate) fn cut_short(&self) -> bool {
        self.retrieval_meta.partial
            && !self
                .residence
                .as_ref()
                .is_some_and(|residence| residence.marked_partial)
    }
}

/// The residence a recall answered on this device alone carries (FIX 2905):
/// local-only and incomplete on a device known to run Opened, with a live
/// sync connection or after it dropped; `None` on one that holds every
/// window it may read, or runs no sync. It keeps `selection`, what the
/// recall narrowed by, for the home step; a pack with none asks no home.
pub(crate) fn local_residence(
    vault: &Vault,
    selection: Option<&super::selection::RecallSelection>,
) -> Option<RecallResidence> {
    #[cfg(feature = "sync")]
    let opened = matches!(
        vault.device_residence(),
        crate::sync::DeviceResidence::Opened { .. }
    );
    #[cfg(not(feature = "sync"))]
    let opened = {
        let _ = (vault, selection);
        false
    };
    opened.then(|| RecallResidence {
        #[cfg(feature = "sync")]
        selection: selection.map(super::selection::RecallSelection::resolved),
        ..RecallResidence::local_only()
    })
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
    /// Where that caller sits relative to this device, as its ingress
    /// placed it: signed into the forwarded search, so the home reads for
    /// a caller off this device as off it (FIX 3550). Unread when nothing
    /// is forwarded.
    pub locality: crate::claim::CallerLocality,
}

impl HomeRecallCaller {
    /// Asks the home for no one: the recall keeps its local answer.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            owner_grade: false,
            forwarded: None,
            locality: crate::claim::CallerLocality::OffDevice,
        }
    }

    /// The device's owner.
    #[must_use]
    pub const fn owner() -> Self {
        Self {
            owner_grade: true,
            forwarded: None,
            locality: crate::claim::CallerLocality::OffDevice,
        }
    }

    /// A caller as its ingress admitted it at `locality`: owner-grade, or
    /// narrower with the holder proof it presented there, if any. An
    /// owner-grade caller forwards no proof.
    #[must_use]
    pub fn admitted(
        owner_grade: bool,
        forwarded: Option<crate::authority::ForwardedCallerProof>,
        locality: crate::claim::CallerLocality,
    ) -> Self {
        Self {
            owner_grade,
            forwarded: forwarded.filter(|_| !owner_grade),
            locality,
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
    /// Whether the home can take the request (`home_answers`).
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

/// Whether the home can take `request` (FIX 2905): its search carries the
/// query, a limit and the recall's resolved scope (worlds, the actor's
/// default included, projects, facet and kinds), but no `as_of`, no media
/// and no room's turn. A recall naming any of those keeps its local answer,
/// marked incomplete.
#[cfg(feature = "sync")]
fn home_answers(request: &crate::task_verb::sdk::RecallRequest, room_turn: bool) -> bool {
    request.as_of.is_none() && request.media.is_none() && !room_turn
}

/// Completes a recall answer on a device known to run Opened with its
/// home's references (FIX 2905). The home is asked for the recall's whole
/// `limit` under `caller`, narrowed by the scope the recall resolved (the
/// one its stamp keeps), a page of `search_limit` at a time (FIX 9256, L02
/// 07:06), each page under that same scope and caller, within the residence
/// `rpc_timeout_ms` and `due`, the recall's own deadline, whichever comes
/// first; a `Home` answer fills the pack's `residence` with the references
/// the local pack does not hold, in [`HOME_RECALL_MERGE_ORDER`]. One that
/// stopped short keeps the pages it got, `capped` and incomplete. No live
/// connection, a request the home cannot take, a pack whose recall kept no
/// scope, a caller with nothing to ask under, a refusal (a scope axis the
/// home cannot evaluate included) or a timeout before the home's first page
/// keeps the pack local-only and incomplete. The local items are never
/// touched. A device not known to run Opened leaves the pack alone.
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
    let selection = pack
        .residence
        .as_ref()
        .and_then(|residence| residence.selection.clone());
    let answer = match (search, selection) {
        (Some(search), Some(selection)) if ask.answerable => {
            ask_home(&search, &selection, &pack.items, ask, caller, due).await
        }
        _ => None,
    };
    pack.stamp_residence(Some(answer.unwrap_or_else(RecallResidence::local_only)));
}

/// The home's answer to `ask`, narrowed by `selection`, the scope the
/// recall resolved, or `None` when it gave none this recall can carry: then
/// the pack stays local-only.
#[cfg(feature = "sync")]
async fn ask_home(
    search: &crate::sync::HomeSearch,
    selection: &crate::sync::residence::ResolvedRecallSelection,
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
    let forwarded = forwarded.map(|proof| (proof, caller.locality));
    // The search takes the whole limit in pages, each within its own RPC
    // timeout and `due`; one that stops short keeps what it got. A
    // malformed residence policy refuses the ask there.
    let found = search
        .search_recall(&ask.query, ask.limit, selection, forwarded, due)
        .await
        .ok()?;
    // A scoped search takes no local fallback; only the home's answer counts.
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
        // A home answer is incomplete only when its pages stopped short.
        capped: !found.complete,
        hits: HOME_RECALL_MERGE_ORDER.home_references(local, hits),
        marked_partial: false,
        selection: None,
    })
}
