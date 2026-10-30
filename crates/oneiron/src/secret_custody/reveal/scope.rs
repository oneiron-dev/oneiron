//! The reach of the owner's standing grant on a reveal (FIX 2354): this
//! project, every project, this task or this run. Each reach is its own
//! envelope selector, so a grant covers only the reach it names: a task's
//! grant never covers its project, and no grant is a wildcard.

use super::{
    RevealAsker, RevealGrantScope, RevealRow, covering_grant, project_selector, reveal_class,
};
use crate::AttemptId;
use crate::consent::{
    AudienceBound, DisclosureClass, DisclosureEnvelope, GrantBound, StandingConsentGrant,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The selector a project's grant names beside its project, so no other
/// grant that names the project (a repo file's, FIX 9236) covers a reveal.
const PROJECT_SCOPE_SELECTOR: &str = "reveal_scope:project";

/// The one selector a grant of every project names: an explicit reach of its
/// own, never a wildcard over project selectors.
const EVERY_PROJECT_SELECTOR: &str = "reveal_scope:every_project";

const TASK_SCOPE_DOMAIN: &[u8] = b"oneiron.secret_reveal.task_scope.v1";
const RUN_SCOPE_DOMAIN: &[u8] = b"oneiron.secret_reveal.run_scope.v1";

impl RevealGrantScope {
    /// Every scope, the narrowest first: the order a reveal's cover is tried
    /// and the owner's choices are listed.
    pub(crate) const ALL: [Self; 4] = [Self::Run, Self::Task, Self::Project, Self::EveryProject];
}

/// What a reveal's reach is read from, as its host bound it: the project,
/// the task its run works and the leased try that asked.
#[derive(Debug, Clone, Copy)]
pub(super) struct RevealReach<'a> {
    project: Option<&'a EntityId>,
    task: Option<&'a str>,
    attempt: Option<&'a AttemptId>,
}

impl RevealReach<'_> {
    /// The envelope a grant of `scope` names at this reach; `None` for a task
    /// or run scope when the reveal names no task or run.
    fn selectors(&self, scope: RevealGrantScope) -> Option<Vec<String>> {
        Some(match scope {
            RevealGrantScope::Project => vec![
                project_selector(self.project),
                PROJECT_SCOPE_SELECTOR.to_owned(),
            ],
            RevealGrantScope::EveryProject => vec![EVERY_PROJECT_SELECTOR.to_owned()],
            RevealGrantScope::Task => vec![format!(
                "reveal_task:{}",
                scope_hex(TASK_SCOPE_DOMAIN, self.task?.as_bytes())
            )],
            RevealGrantScope::Run => vec![format!(
                "reveal_run:{}",
                scope_hex(RUN_SCOPE_DOMAIN, self.attempt?.as_bytes())
            )],
        })
    }

    /// The scopes a standing answer may pick for a reveal at this reach, the
    /// narrowest first.
    pub(super) fn scopes(&self) -> Vec<RevealGrantScope> {
        RevealGrantScope::ALL
            .into_iter()
            .filter(|scope| self.selectors(*scope).is_some())
            .collect()
    }

    /// The bound a grant of `scope` covers: `connection` × `class` × the
    /// scope's envelope; `None` when this reach names no task or run for it.
    ///
    /// # Errors
    /// A selector the consent bound refuses.
    pub(super) fn bound(
        &self,
        connection: &str,
        class: &str,
        scope: RevealGrantScope,
    ) -> Result<Option<GrantBound>> {
        let Some(selectors) = self.selectors(scope) else {
            return Ok(None);
        };
        GrantBound::disclosure(
            AudienceBound::singleton(connection)?,
            DisclosureClass::new(class)?,
            DisclosureEnvelope::new(selectors)?,
        )
        .map(Some)
    }

    /// The standing grant that covers a reveal of `class` to `connection` at
    /// this reach now, under any scope, the narrowest first: the scope and
    /// the grant's registry ref; `None` when none does.
    ///
    /// # Errors
    /// As [`Self::bound`].
    pub(super) fn covering_grant(
        &self,
        connection: &str,
        class: &str,
        grants: &[StandingConsentGrant],
    ) -> Result<Option<(RevealGrantScope, String)>> {
        for scope in RevealGrantScope::ALL {
            let Some(bound) = self.bound(connection, class, scope)? else {
                continue;
            };
            if let Some(grant_ref) = covering_grant(&bound, self.project.copied(), grants)? {
                return Ok(Some((scope, grant_ref)));
            }
        }
        Ok(None)
    }
}

/// This project's reach, the default: what `reveal_bound` and every grant a
/// found key's owner gives name.
pub(super) const fn project_reach(project: Option<&EntityId>) -> RevealReach<'_> {
    RevealReach {
        project,
        task: None,
        attempt: None,
    }
}

impl RevealAsker {
    /// This asker's reach, as its host bound it.
    pub(super) fn reach(&self) -> RevealReach<'_> {
        RevealReach {
            project: self.project.as_ref(),
            task: self.task.as_deref(),
            attempt: self.attempt.as_ref(),
        }
    }
}

impl RevealRow {
    /// The reach this reveal was asked at.
    pub(super) fn reach(&self) -> RevealReach<'_> {
        RevealReach {
            project: self.project.as_ref(),
            task: self.task.as_deref(),
            attempt: self.attempt.as_ref(),
        }
    }

    /// The disclosure class a grant on this reveal names: a PERSON claim's
    /// `names`, or the record's custody class.
    fn grant_class(&self) -> Result<String> {
        Ok(match &self.person {
            Some(_) => "names".to_owned(),
            None => reveal_class(self.class()?),
        })
    }

    fn grant_connection(&self) -> Result<&str> {
        self.connection
            .as_deref()
            .ok_or(Error::CorruptedIndex("secret reveal connection"))
    }

    /// The standing grant that covers this reveal now, under any scope: the
    /// scope and the grant's registry ref (FIX 2354).
    ///
    /// # Errors
    /// A row with no connection or class; a selector the bound refuses.
    pub(super) fn covering(
        &self,
        grants: &[StandingConsentGrant],
    ) -> Result<Option<(RevealGrantScope, String)>> {
        self.reach()
            .covering_grant(self.grant_connection()?, &self.grant_class()?, grants)
    }

    /// The bound a standing answer of `scope` to this reveal mints; `None`
    /// for a task or run scope when the reveal names no task or run.
    ///
    /// # Errors
    /// As [`Self::covering`].
    pub(super) fn standing_bound(&self, scope: RevealGrantScope) -> Result<Option<GrantBound>> {
        self.reach()
            .bound(self.grant_connection()?, &self.grant_class()?, scope)
    }
}

/// `bytes` hashed under `domain`, lower hex: a task ref or a leased try as a
/// selector, so no guest text reaches the consent registry.
fn scope_hex(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}
