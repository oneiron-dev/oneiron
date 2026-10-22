//! Who actually receives a repo read's bytes, as its host proved it (FIX
//! 7608 slice 2b-ii-A, ASK 1 addition).
//!
//! A Memory handle the host bound to an MCP tool call or a run reads repo
//! bytes masked (FIX 8961). When the host also proves who the receiving
//! agent is (its registered actor, never the credential's owner standing in
//! for one), it binds that agent here, and a per-file read that says why
//! may then ask the owner for the file's real bytes through the shipped
//! file reveal. The binding admits nothing: the engine still revalidates
//! the agent, its scope and the live grant at every read, and an unknown
//! recipient reads masked.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: inert until 2b-ii-B binds a proven recipient at the MCP and run hosts"
)]

use crate::entity_id::EntityId;
use crate::secret_custody::RevealAsker;

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
