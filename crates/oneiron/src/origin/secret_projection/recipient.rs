//! Core half of `origin::secret_projection::recipient`: its store-layer items live in `oneiron_store::origin::secret_projection::recipient` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: inert until 2b-ii-B binds a proven recipient at the MCP and run hosts"
)]

pub use oneiron_store::origin::secret_projection::recipient::*;

pub(crate) use self::binding::RepoProjectionRevealBinding;
use crate::entity_id::EntityId;
use crate::secret_custody::RevealAsker;

mod binding;

/// The agent a host proved receives a repo read's bytes: its registered
/// actor, the model provider the host served it from, the project and the
/// run it works in. A trusted-host contract like `GitPushCaller`, not a
/// grant: it holds no credential and is never decoded from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRevealRecipient {
    agent: EntityId,
    provider: Option<String>,
    project: Option<EntityId>,
    run: Option<String>,
}

impl RepoRevealRecipient {
    /// The agent `agent`, as the host's authenticated transport proved it:
    /// a registered agent actor, never the owner's own identity.
    #[must_use]
    pub const fn proven_agent(agent: EntityId) -> Self {
        Self {
            agent,
            provider: None,
            project: None,
            run: None,
        }
    }

    /// This recipient with the model provider its host named, if any.
    #[must_use]
    pub fn with_provider(mut self, provider: Option<&str>) -> Self {
        self.provider = provider.map(str::to_owned);
        self
    }

    /// This recipient working in `project`, as its host bound it.
    #[must_use]
    pub fn in_project(mut self, project: Option<EntityId>) -> Self {
        self.project = project;
        self
    }

    /// This recipient working for `run`, as its host bound it.
    #[must_use]
    pub fn for_run(mut self, run: Option<String>) -> Self {
        self.run = run;
        self
    }

    /// The agent the host proved.
    #[must_use]
    pub const fn agent(&self) -> &EntityId {
        &self.agent
    }

    /// The project its host bound it to, if any.
    pub(crate) const fn project(&self) -> Option<EntityId> {
        self.project
    }

    /// The reveal asker a per-file read of this recipient asks as.
    pub(crate) fn asker(&self) -> RevealAsker {
        RevealAsker::new(self.agent, self.project, self.run.clone())
            .with_provider(self.provider.as_deref())
    }
}

/// What a Memory handle carries about its repo reads' recipient: whether
/// the host bound it to a tool or run (mask-only, FIX 8961), and the actual
/// recipient it proved, when it proved one. Off on every other handle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RepoToolRecipient {
    masked: bool,
    actual: Option<RepoRevealRecipient>,
}

impl RepoToolRecipient {
    /// No binding: the handle's own credential decides.
    pub(crate) const OFF: Self = Self {
        masked: false,
        actual: None,
    };

    /// Whether the host bound the handle to a tool call or run.
    pub(crate) const fn masked(&self) -> bool {
        self.masked
    }

    /// Binds the handle to a tool call: masked, recipient unknown.
    pub(crate) fn mask(&mut self) {
        self.masked = true;
    }

    /// Binds the handle to the proven `actual` recipient, which masks it too.
    pub(crate) fn bind(&mut self, actual: RepoRevealRecipient) {
        self.masked = true;
        self.actual = Some(actual);
    }

    /// The recipient the host proved, when it proved one.
    pub(crate) const fn actual(&self) -> Option<&RepoRevealRecipient> {
        self.actual.as_ref()
    }
}
