//! A backend read live on its spend scope (FIX 11457): for a run outside
//! the step pump that spends on a meter its scope bounds, each call first
//! takes the lease's look ([`LiveLease::book_and_revise`]), as the pump's
//! own calls do, so it is admitted against what the scope has left then,
//! its siblings' spend included. The lease is the one ledger: this backend
//! books nothing itself. A run's planner runner, which spends on its entry's
//! meter through a backend of its own, takes the same look before each start
//! ([`LiveLeaseRunner`], FIX 11747).

use std::sync::Arc;

use oneiron::agent_dispatch::{SpawnNeed, TeamPlan};
use oneiron::skill::LoadedSkillPack;
use oneiron::team::{PatternLaunchRunner, PatternLaunchSpec};
use oneiron::{
    BudgetLease, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest, LlmStreamResult,
    ModelId, Result, Vault, WriteActor,
};

use crate::ai_host::live_lease::{LeaseLine, LiveLease};

/// `inner` on `live`'s meter, each call after the lease's look: a call the
/// revised limit no longer fits is refused by `inner`'s own admission on
/// that meter, as a spent meter refuses it.
pub(crate) struct LiveLeaseBackend<'l> {
    live: &'l LiveLease<'l>,
    inner: &'l dyn LlmBackend,
}

impl<'l> LiveLeaseBackend<'l> {
    /// `inner`, a backend whose calls spend on `live`'s meter.
    pub(crate) fn new(live: &'l LiveLease<'l>, inner: &'l dyn LlmBackend) -> Self {
        Self { live, inner }
    }
}

impl LlmBackend for LiveLeaseBackend<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.inner.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.live.book_and_revise();
        self.inner.generate(request, lease)
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.live.book_and_revise();
        self.inner.stream(request, lease)
    }
}

/// A planner runner whose start spends on an entry's meter, each start after
/// the entry's lease's look (FIX 11747): the start makes one model call, the
/// capture, and a scope its siblings spent down refuses it as a spent meter
/// does. The lease books the start's spend; this runner books nothing.
pub(crate) struct LiveLeaseRunner {
    inner: Arc<dyn PatternLaunchRunner>,
    vault: Arc<Vault>,
    lease: LeaseLine,
}

impl LiveLeaseRunner {
    /// `inner`, looking on `lease` first when the entry spends under a
    /// scope; else `inner` as it is.
    pub(crate) fn lend(
        inner: Arc<dyn PatternLaunchRunner>,
        vault: &Arc<Vault>,
        lease: Option<&LeaseLine>,
    ) -> Arc<dyn PatternLaunchRunner> {
        match lease {
            Some(lease) => Arc::new(Self {
                inner,
                vault: Arc::clone(vault),
                lease: lease.clone(),
            }),
            None => inner,
        }
    }
}

impl PatternLaunchRunner for LiveLeaseRunner {
    fn run(
        &self,
        skill: &LoadedSkillPack,
        asked: &SpawnNeed,
        prompt: &str,
        plan: &TeamPlan,
        payer: &WriteActor,
    ) -> Result<PatternLaunchSpec> {
        self.lease.on(&self.vault).book_and_revise();
        self.inner.run(skill, asked, prompt, plan, payer)
    }
}
