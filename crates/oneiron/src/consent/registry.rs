use super::bound::{BoundEnvelope, BoundSubject, ConsentDomain};
use super::grant::{ConsentGrantRow, ConsentGrantStatus};

// ---------------------------------------------------------------------------
// The registry surface (invariant 9 surface (b))
// ---------------------------------------------------------------------------

/// Query for the unified consent registry — surface (b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentRegistryQuery {
    /// Maximum rows returned.
    pub limit: usize,
    /// Include revoked rows (audit view) as well as active ones.
    pub include_revoked: bool,
}

impl ConsentRegistryQuery {
    /// Builds a registry query.
    #[must_use]
    pub const fn new(limit: usize, include_revoked: bool) -> Self {
        Self {
            limit,
            include_revoked,
        }
    }
}

/// One registry row: who-can-see-what / what-can-run, with a one-tap revoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRegistryRow {
    /// The stable row reference (the bound digest hex).
    pub grant_ref: String,
    /// Which domain this row governs.
    pub domain: ConsentDomain,
    /// The subject, rendered for display.
    pub subject: String,
    /// The class, rendered for display.
    pub class: String,
    /// The envelope selectors, rendered for display.
    pub selectors: Vec<String>,
    /// Lifecycle state.
    pub status: ConsentGrantStatus,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// The one-tap revoke command the host interprets.
    pub revoke_action: ConsentRevokeAction,
}

/// The one-tap revoke command carried by every registry row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRevokeAction {
    /// Pinned command name.
    pub command: String,
    /// The row this command revokes.
    pub grant_ref: String,
}

/// Pinned one-tap revoke command for a consent registry row.
pub const CONSENT_REVOKE_COMMAND: &str = "consent.revoke_grant";

/// The unified consent registry projection — surface (b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRegistry {
    /// The rows, newest first.
    pub rows: Vec<ConsentRegistryRow>,
}

impl ConsentRegistryRow {
    pub(super) fn from_row(row: &ConsentGrantRow) -> Self {
        let bound = row.grant.bound();
        let grant_ref = row.grant_ref();
        Self {
            domain: bound.domain(),
            subject: render_subject(bound.subject()),
            class: bound.class().as_str().to_owned(),
            selectors: render_selectors(bound.envelope()),
            status: row.status,
            created_at: row.created_at,
            revoke_action: ConsentRevokeAction {
                command: CONSENT_REVOKE_COMMAND.to_owned(),
                grant_ref: grant_ref.clone(),
            },
            grant_ref,
        }
    }
}

fn render_subject(subject: &BoundSubject) -> String {
    match subject {
        BoundSubject::Actor(actor) => match actor.actor_class() {
            Some(class) => format!("{}/{}", actor.actor_ref(), class),
            None => actor.actor_ref().to_owned(),
        },
        BoundSubject::Audience(audience) => audience.members().join(", "),
    }
}

fn render_selectors(envelope: &BoundEnvelope) -> Vec<String> {
    match envelope {
        BoundEnvelope::Disclosure(envelope) => envelope.selectors().to_vec(),
        BoundEnvelope::Action(envelope) => {
            let mut selectors = envelope.selectors().to_vec();
            if let Some(target) = envelope.target() {
                selectors.push(format!("target:{target}"));
            }
            if let Some(budget) = envelope.budget() {
                selectors.push(format!("budget:{budget}"));
            }
            selectors
        }
    }
}
