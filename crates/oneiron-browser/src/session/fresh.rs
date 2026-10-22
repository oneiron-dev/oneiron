//! The fresh guest a proposal's replay runs on (CUA E1): admission's second
//! check runs on a browser of its own, never on the page the solved run
//! left, so a program that worked only on that page's state does not join
//! the library.
//!
//! The host gives the session a [`FreshGuest`]: its own start path for the
//! run, so the fresh guest gets its own proved fence, the run's egress door,
//! the proposing session's request custody, its own live-handle charge, and
//! its own decider and keeper of receipt screenshots. The session carries
//! its sign-ins into it (`fresh_guest_state_policy`), the replay runs there
//! with no model and its checks are read on its page, and then it goes. Its
//! replay is answered whole: no cursor pages a guest that is gone.
//!
//! The fresh guest holds the run's secret custody (FIX 8028): the host's
//! own, where its start gave it one, else the proposing session's, with the
//! kinds of the handles its reads took.
//!
//! The run's press policy goes with the replay and comes back spent: one
//! budget, never copied and never refilled. No fresh guest is the
//! proposal's refusal, at the stage it failed; the replay never falls back
//! to the proposing page, nor to another engine.

use super::BrowserSession;
use super::storage::OriginSnapshots;
use super::switch::{Halt, hold, seed_state};
use crate::library::{check_solved, no_fresh_guest, replay_and_file};
use crate::request::BrowserRequestHandler;
use crate::{
    BrowserEngine, BrowserError, HandleRetention, NoDecider, ProposeInput, ProposeOutput,
    ReplayGuest, StoragePhase, SwitchComponent, SwitchStage, WorkflowLibrary,
};
use std::sync::Arc;

/// How the host starts the fresh browser a proposal's replay runs on: on
/// the path the run's own browser started on, for the same run.
pub trait FreshGuest: Send {
    /// Starts a session for the run on `engine`, attached as every guest is,
    /// its requests in `requests`' custody (the proposing session's: the
    /// host's handler, where it gave one), with its own decider and keeper
    /// of receipt screenshots. It holds nothing of any page yet.
    fn start(
        &mut self,
        engine: BrowserEngine,
        requests: Option<Arc<dyn BrowserRequestHandler>>,
    ) -> Result<BrowserSession, BrowserError>;

    /// A charge on the host's retained line, holding nothing yet, for the
    /// sign-ins a session holds while it carries them into a fresh guest.
    fn state_charge(&self) -> Box<dyn HandleRetention>;

    /// Hears, once, that a fresh guest's replay ended with that guest's
    /// sandbox abandoned, with its manifest (FIX 7879): the host lands its
    /// abandon receipt as it does its run's own guest's. Its own observer,
    /// apart from any demonstration's close. The default hears nothing.
    fn abandoned(&mut self, manifest: &oneiron_container::SessionManifest) {
        let _ = manifest;
    }
}

/// What a fresh admission guest takes of the proposing session
/// (`fresh_guest_state_policy`, CUA E1 fresh-guest state, CALLS row; Engine
/// 10-21 23:4x): its sign-ins, not its page. Its cookies, and the local and
/// session stores of every origin its front tab visited, go in as an engine
/// switch carries them, the current origin's read fresh (`switch_export`);
/// its page, URL, scroll and other tabs stay behind, as the program's first
/// step opens its own page. A fresh guest with no cookies would fail every
/// signed-in program's admission. Cookies the guest refuses fail it; any
/// other part not carried is listed, and the replay runs.
fn fresh_guest_state_policy(
    from: &mut BrowserSession,
    to: &BrowserSession,
    charge: &mut dyn HandleRetention,
) -> Result<ReplayGuest, Halt> {
    let mut guest = ReplayGuest {
        engine: to.engine(),
        carried: Vec::new(),
        not_carried: Vec::new(),
    };
    let (_, mut state) = from.read_state(false, &mut guest.not_carried);
    hold(&mut state, charge, &mut guest.not_carried);
    let (kept, losses) = (&mut guest.carried, &mut guest.not_carried);
    seed_state(&to.driver, guest.engine, &state, kept, losses)?;
    fresh_records(&mut guest);
    Ok(guest)
}

/// The fresh carry's records as its own (FIX 7877): a store read at the
/// carry names `fresh_export`, not a switch's, and the URL, which the
/// carry never takes, is no loss of it.
fn fresh_records(guest: &mut ReplayGuest) {
    let fresh = |phase: &mut Option<StoragePhase>| {
        if *phase == Some(StoragePhase::SwitchExport) {
            *phase = Some(StoragePhase::FreshExport);
        }
    };
    guest
        .not_carried
        .retain(|lost| lost.component != SwitchComponent::Url);
    for lost in &mut guest.not_carried {
        fresh(&mut lost.phase);
    }
    for kept in &mut guest.carried {
        fresh(&mut kept.phase);
    }
}

impl BrowserSession {
    /// Gives the session the host's start path for a proposal's fresh
    /// guest. A session that kept no storage snapshots (its host gave it no
    /// engine-switch starter) keeps them from now on, charged to the fresh
    /// guest's line, so an admission carries its visited origins' stores as
    /// a switch would; `switch_engine` still needs the starter.
    pub fn set_fresh_guest(&mut self, fresh: Box<dyn FreshGuest>) {
        if self.snapshots.is_none() {
            let collector = OriginSnapshots::collector(fresh.state_charge());
            OriginSnapshots::landed(&collector, self.landed_seq());
            self.driver.collect(OriginSnapshots::sink(&collector));
            self.snapshots = Some(collector);
        }
        self.fresh = Some(fresh);
    }

    /// `library.propose` into `library`: the solved page checked on this
    /// session, then the replay on a fresh guest, which goes after.
    pub(super) fn propose(
        &mut self,
        library: &mut dyn WorkflowLibrary,
        input: ProposeInput,
    ) -> Result<ProposeOutput, BrowserError> {
        let solved = match check_solved(self, input)? {
            Ok(solved) => solved,
            Err(refused) => return Ok(refused),
        };
        let (mut fresh, guest) = match self.fresh_replay_guest() {
            Ok(started) => started,
            Err(Halt { stage, error }) => return Ok(no_fresh_guest(stage, &error)),
        };
        fresh.policy = std::mem::take(&mut self.policy);
        let mut decider = fresh.decider.take();
        let output = match decider.as_deref_mut() {
            Some(decider) => replay_and_file(&mut fresh, decider, library, solved, guest),
            None => replay_and_file(&mut fresh, &mut NoDecider, library, solved, guest),
        };
        self.policy = std::mem::take(&mut fresh.policy);
        // A fresh guest abandoned under its replay lands its own receipt,
        // however the replay ended.
        if fresh.abandoned()
            && let Some(factory) = self.fresh.as_mut()
        {
            factory.abandoned(fresh.manifest());
        }
        let mut output = output?;
        if let Some(replay) = output.replay.as_mut() {
            self.page_replay(replay);
        }
        Ok(output)
    }

    /// Pages a replay's observations, its failed step's too, through this
    /// session, which outlives the fresh guest they were read on (FIX 7881):
    /// their cursors read on here.
    fn page_replay(&mut self, replay: &mut crate::BatchOutput) {
        if let Some(observation) = replay.observation.take() {
            let page = self.driver.adopt_page(observation);
            replay.observation = Some(page.observation);
            replay.next = page.next;
        }
        if let Some(failed) = replay.failed_receipt.as_mut()
            && let Some(observation) = failed.observation.take()
        {
            let page = self.driver.adopt_page(observation);
            failed.observation = Some(page.observation);
            failed.next = page.next;
        }
    }

    /// The fresh guest for this session's replay, on the engine this session
    /// runs now and in its request custody, its sign-ins carried in; or the
    /// stage at which there was none.
    fn fresh_replay_guest(&mut self) -> Result<(Self, ReplayGuest), Halt> {
        let Some(mut factory) = self.fresh.take() else {
            return Err(Halt {
                stage: SwitchStage::Start,
                error: BrowserError::Unsupported("a proposal's fresh guest".to_owned()),
            });
        };
        let requests = self.custody.handler().cloned();
        let carried = match factory.start(self.engine(), requests) {
            Ok(fresh) => {
                // The replay is the same run: its secrets are the run's.
                fresh.secrets.adopt(&self.secrets);
                fresh.driver.book_inbound(factory.state_charge());
                let mut charge = factory.state_charge();
                let guest = fresh_guest_state_policy(self, &fresh, charge.as_mut());
                guest.map(|guest| (fresh, guest))
            }
            Err(error) => Err(Halt {
                stage: SwitchStage::Start,
                error,
            }),
        };
        self.fresh = Some(factory);
        carried
    }
}
