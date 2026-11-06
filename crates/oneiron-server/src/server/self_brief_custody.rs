//! The one owner of installed self briefs (FIX 17594 delivery, slice D1).
//!
//! A trusted host installs a run's resolved brief state under the agent and
//! a session key. Every later step goes through [`InstalledBriefs`]: prepare
//! stages the prefix of the boundary the session has yet to deliver,
//! acknowledge promotes a staged candidate once its host delivered it, tail
//! answers a mid-run `describe(self)`, and close removes the installation.
//! HTTP hydration is the first host to prepare and acknowledge; the native,
//! MCP and code-mode hosts use the same operations. Nothing here renders on
//! its own or installs anything.

use std::collections::{BTreeMap, BTreeSet};

use oneiron::EntityId;
use oneiron::context_board::{
    People, PlacedSelfBrief, SelfBriefSession, SelfBriefState, SessionReadSet,
};
use tokio::sync::{Mutex, MutexGuard};

/// An installed brief's key: the authenticated agent and its session.
pub(crate) type BriefKey = (EntityId, String);

/// One installation under a key. A key installed again after a close gets a
/// new owner, so a holder of the old one can be told apart: its
/// acknowledgment or close never acts on the newer installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BriefOwner(u64);

/// The boundary a brief's prefix is rendered at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BriefBoundary {
    /// Turn one: the run's first prefix.
    Birth,
    /// A completed fold, named by the epoch the host installed for it. HTTP
    /// hydration names a fold by that epoch for now.
    Fold { epoch: u64 },
}

/// The prefix a session delivered: the boundary it was rendered at and the
/// installed epoch it covers, a fold's own or the epoch turn one rendered at.
#[derive(Debug, Clone, Copy)]
struct AcknowledgedPrefix {
    boundary: BriefBoundary,
    epoch: u64,
}

/// One host-resolved agent run and the prefix this session actually emitted.
/// The host advances the epoch only after a real fold; an HTTP request cannot.
struct HostSelfBriefSession {
    state: SelfBriefState,
    render: SelfBriefSession,
    epoch: u64,
    acknowledged: Option<AcknowledgedPrefix>,
    owner: BriefOwner,
}

impl HostSelfBriefSession {
    /// The boundary whose prefix this session has yet to acknowledge: turn
    /// one before any, then a fold at each epoch the host installs past the
    /// acknowledged one. `None` while the acknowledged prefix covers the
    /// installed epoch.
    fn pending_boundary(&self) -> Option<BriefBoundary> {
        match self.acknowledged {
            None => Some(BriefBoundary::Birth),
            Some(acknowledged) if acknowledged.epoch == self.epoch => None,
            Some(_) => Some(BriefBoundary::Fold { epoch: self.epoch }),
        }
    }
}

/// A prefix staged for one boundary of one installation, and what it is
/// derived from. It changes no custody until [`InstalledBriefs::acknowledge`]
/// promotes it.
pub(crate) struct BriefCandidate {
    key: BriefKey,
    owner: BriefOwner,
    boundary: BriefBoundary,
    /// The installed epoch the candidate's prefix covers.
    epoch: u64,
    /// The session's prefix custody with the candidate's prefix bytes and
    /// resident PEOPLE in place.
    render: SelfBriefSession,
    /// The rows the prefix is derived from
    /// ([`oneiron::context_board::SelfBrief::sources`]).
    sources: Vec<EntityId>,
}

#[expect(
    dead_code,
    reason = "the native, MCP and code-mode hosts of later FIX 17594 slices read a candidate"
)]
impl BriefCandidate {
    /// The prefix bytes the candidate delivers.
    pub(crate) fn prefix(&self) -> &str {
        self.render.cached_prefix().unwrap_or_default()
    }

    /// The persons the candidate prefix's `people` roster holds.
    pub(crate) fn resident_people(&self) -> &BTreeSet<EntityId> {
        self.render.resident_people()
    }

    /// The rows the candidate prefix is derived from.
    pub(crate) fn sources(&self) -> &[EntityId] {
        &self.sources
    }

    /// The installation the candidate was staged for.
    pub(crate) fn owner(&self) -> BriefOwner {
        self.owner
    }

    /// The boundary the candidate was staged for.
    pub(crate) fn boundary(&self) -> BriefBoundary {
        self.boundary
    }
}

/// What [`InstalledBriefs::prepare`] found for an installed key.
pub(crate) enum BriefPreparation<'a> {
    /// A boundary the session has yet to acknowledge: the prefix as placed
    /// for the reply, and the candidate to acknowledge once it is delivered.
    Staged {
        placed: PlacedSelfBrief,
        candidate: BriefCandidate,
    },
    /// The installed epoch's prefix is acknowledged: its cached bytes,
    /// unchanged.
    Emitted {
        #[expect(
            dead_code,
            reason = "the native hosts of later FIX 17594 slices deliver these bytes on every request"
        )]
        prefix: &'a str,
    },
}

/// What [`InstalledBriefs::acknowledge`] did with a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum BriefAcknowledgment {
    /// The candidate's prefix and roster are the session's custody now, and
    /// its boundary is recorded as emitted.
    Committed,
    /// The key was closed, installed again under a new owner, or moved past
    /// the candidate's boundary: nothing changed.
    Stale,
}

/// The persons an installed brief's prefix roster holds, as a board reads
/// them.
pub(crate) enum BriefResidence {
    /// No brief is installed under the key.
    Absent,
    /// The acknowledged prefix's roster.
    Acknowledged(BTreeSet<EntityId>),
    /// A boundary is still to be delivered: the persons its brief pins, from
    /// which a board predicts the roster that boundary lays out.
    Pending { pinned: Vec<EntityId> },
}

/// The installed briefs and the owner each key's installation has.
#[derive(Default)]
pub(crate) struct InstalledBriefs {
    runs: BTreeMap<BriefKey, HostSelfBriefSession>,
    /// The last owner an installation was given.
    last_owner: u64,
}

impl InstalledBriefs {
    /// Install an already resolved run snapshot from the trusted host. The
    /// HTTP request never supplies scope, class verdicts, or budget. Advancing
    /// `epoch` happens only when the host has completed a real fold. A key
    /// with no installation gets a new owner; installing again under a held
    /// key keeps its owner and its acknowledged prefix.
    ///
    /// # Errors
    ///
    /// The state is not `actor`'s, the session id is empty, or `epoch` is
    /// below the installed one.
    pub(crate) fn install(
        &mut self,
        actor: EntityId,
        session_id: String,
        epoch: u64,
        state: SelfBriefState,
    ) -> oneiron::Result<BriefOwner> {
        if state.self_ref != actor || session_id.is_empty() {
            return Err(oneiron::Error::InvariantViolation(
                "self brief actor or session mismatch",
            ));
        }
        let Self { runs, last_owner } = self;
        let entry = runs.entry((actor, session_id)).or_insert_with(|| {
            *last_owner = last_owner.wrapping_add(1);
            HostSelfBriefSession {
                state: state.clone(),
                render: SelfBriefSession::default(),
                epoch,
                acknowledged: None,
                owner: BriefOwner(*last_owner),
            }
        });
        if epoch < entry.epoch {
            return Err(oneiron::Error::InvariantViolation("stale self brief epoch"));
        }
        entry.state = state;
        entry.epoch = epoch;
        Ok(entry.owner)
    }

    /// Stages the prefix of the boundary `key`'s session has yet to
    /// acknowledge, from its installed state: turn one, or a fold, rendered
    /// with its roster under `people_budget_tok` (the `people` share of the
    /// agent's layout). The installed custody does not move. With the
    /// installed epoch acknowledged, the cached prefix comes back unchanged.
    /// `None` when nothing is installed under `key`.
    ///
    /// # Errors
    ///
    /// The brief does not render.
    pub(crate) fn prepare(
        &self,
        key: &BriefKey,
        vault: &oneiron::Vault,
        read_set: &SessionReadSet,
        people: Option<&People>,
        people_budget_tok: Option<usize>,
    ) -> oneiron::Result<Option<BriefPreparation<'_>>> {
        let Some(run) = self.runs.get(key) else {
            return Ok(None);
        };
        let Some(boundary) = run.pending_boundary() else {
            // The turn one or fold an acknowledgment promoted cached its
            // prefix.
            return Ok(run
                .render
                .cached_prefix()
                .map(|prefix| BriefPreparation::Emitted { prefix }));
        };
        let mut render = run.render.clone();
        render.set_people_budget_tok(people_budget_tok);
        let (placed, sources) = match boundary {
            BriefBoundary::Birth => render.turn_one_listing(vault, &run.state, read_set, people)?,
            BriefBoundary::Fold { .. } => {
                render.fold_listing(vault, &run.state, read_set, people)?
            }
        };
        Ok(Some(BriefPreparation::Staged {
            placed,
            candidate: BriefCandidate {
                key: key.clone(),
                owner: run.owner,
                boundary,
                epoch: run.epoch,
                render,
                sources,
            },
        }))
    }

    /// Promotes `candidate`'s prefix and roster to its session's custody and
    /// records its boundary as emitted, only while its key is held by the
    /// owner it was staged for and that boundary is still the one to
    /// deliver. Otherwise nothing changes.
    pub(crate) fn acknowledge(&mut self, candidate: BriefCandidate) -> BriefAcknowledgment {
        let Some(run) = self.runs.get_mut(&candidate.key) else {
            return BriefAcknowledgment::Stale;
        };
        if run.owner != candidate.owner || run.pending_boundary() != Some(candidate.boundary) {
            return BriefAcknowledgment::Stale;
        }
        run.render = candidate.render;
        run.acknowledged = Some(AcknowledgedPrefix {
            boundary: candidate.boundary,
            epoch: candidate.epoch,
        });
        BriefAcknowledgment::Committed
    }

    /// The boundary `key`'s delivered prefix was rendered at; `None` before
    /// turn one is acknowledged or when nothing is installed.
    #[expect(
        dead_code,
        reason = "the resident and MCP hosts of later FIX 17594 slices read what was delivered"
    )]
    pub(crate) fn acknowledged(&self, key: &BriefKey) -> Option<BriefBoundary> {
        self.runs
            .get(key)?
            .acknowledged
            .map(|acknowledged| acknowledged.boundary)
    }

    /// A mid-run `describe(self)` of `key`'s installed brief: a tail card,
    /// the cached prefix untouched. `None` when nothing is installed.
    pub(crate) fn tail(
        &self,
        key: &BriefKey,
        vault: &oneiron::Vault,
        read_set: &SessionReadSet,
        people: Option<&People>,
    ) -> Option<oneiron::Result<PlacedSelfBrief>> {
        self.runs.get(key).map(|run| {
            run.render
                .describe_self(vault, &run.state, read_set, people)
        })
    }

    /// [`Self::tail`], beside the rows the tail is derived from.
    pub(crate) fn tail_listing(
        &self,
        key: &BriefKey,
        vault: &oneiron::Vault,
        read_set: &SessionReadSet,
        people: Option<&People>,
    ) -> Option<oneiron::Result<(PlacedSelfBrief, Vec<EntityId>)>> {
        self.runs.get(key).map(|run| {
            run.render
                .describe_self_listing(vault, &run.state, read_set, people)
        })
    }

    /// The brief state installed under `key`.
    pub(crate) fn state(&self, key: &BriefKey) -> Option<&SelfBriefState> {
        self.runs.get(key).map(|run| &run.state)
    }

    /// The persons `key`'s prefix roster holds: the acknowledged prefix's
    /// while it covers the installed epoch, else the persons the brief pins
    /// for the boundary still to be delivered.
    pub(crate) fn residence(&self, key: &BriefKey) -> BriefResidence {
        match self.runs.get(key) {
            None => BriefResidence::Absent,
            Some(run) if run.pending_boundary().is_none() => {
                BriefResidence::Acknowledged(run.render.resident_people().clone())
            }
            Some(run) => BriefResidence::Pending {
                pinned: run.state.pinned_people(),
            },
        }
    }

    /// Removes `key`'s installation only while `owner` holds it, and says
    /// whether it did: a late close never removes a newer owner's.
    #[expect(
        dead_code,
        reason = "the resident and MCP hosts of later FIX 17594 slices close what they installed"
    )]
    pub(crate) fn close(&mut self, key: &BriefKey, owner: BriefOwner) -> bool {
        let held = self.runs.get(key).is_some_and(|run| run.owner == owner);
        if held {
            self.runs.remove(key);
        }
        held
    }

    /// Removes `key`'s installation, whichever owner holds it.
    pub(crate) fn close_any_owner(&mut self, key: &BriefKey) {
        self.runs.remove(key);
    }
}

/// The installed briefs behind one lock. A host holds the lock from prepare
/// through acknowledge when it must commit with nothing in between, as HTTP
/// hydration does.
#[derive(Default)]
pub(crate) struct SelfBriefCustody {
    briefs: Mutex<InstalledBriefs>,
}

impl SelfBriefCustody {
    /// Locks the installed briefs for one or more operations.
    pub(crate) async fn lock(&self) -> MutexGuard<'_, InstalledBriefs> {
        self.briefs.lock().await
    }
}
