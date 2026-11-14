use super::bound::{BoundEnvelope, BoundSubject, ConsentDomain};
use super::contact_clearance::{
    CONTACT_CLEARANCE_CLASS, CONTACT_CLEARANCE_REVOKE_COMMAND, contact_clearance_ref,
};
use super::grant::{ConsentGrantRow, ConsentGrantStatus};
use crate::disclosure::{DisclosureScope, DisclosureScopeStatus};
use crate::entity_id::EntityId;
use oneiron_authority::federation::{
    RepoAccessBounds, Scope, ScopeAxis, Sensitivity, SensitivityCeiling,
};

#[doc(hidden)]
pub use oneiron_verb_wire::consent::registry::{
    AGENT_GRANT_CLASS, CONSENT_REVOKE_COMMAND, ConsentRegistryAgentGrant,
    ConsentRegistryDelegation, ConsentRegistryQuery, ConsentRegrantAction, ConsentRevokeAction,
    GrantlessAgentConvertAction, GrantlessAgentRow, SUPPORT_GRANT_CLASS,
};
#[doc(hidden)]
use oneiron_verb_wire::consent::registry::{
    render_axis, render_scope, render_selectors, render_subject,
};

/// One registry row: who-can-see-what / what-can-run, with a one-tap revoke.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ConsentRegistryRow {
    /// The stable row reference (the bound digest hex).
    pub grant_ref: String,
    /// Which domain this row governs.
    pub domain: ConsentDomain,
    /// The subject, rendered for display.
    pub subject: String,
    /// The class, rendered for display.
    pub class: String,
    /// The envelope's authorization axes, rendered for display.
    pub selectors: Vec<String>,
    /// Typed contact clearance, when present. Hosts can inspect the complete
    /// Scope before choosing which standing grant to revoke; facet is a mask.
    pub scope: Option<Scope>,
    /// Lifecycle state.
    pub status: ConsentGrantStatus,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// The one-tap revoke command the host interprets.
    pub revoke_action: ConsentRevokeAction,
    /// A revoked witness-read grant's owner re-grant command and its exact
    /// arguments; absent on every other row. This is a projection, not authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regrant_action: Option<ConsentRegrantAction>,
    /// Where a scoped catastrophe bypass grant applies; `None` for an
    /// ordinary standing grant.
    pub bypass: Option<super::bypass::BypassExtent>,
    /// A support grant's delegation (OF-606), projected from its logged
    /// mint; `None` for every other row. Projection only: no grant row
    /// stores or edits it.
    pub delegation: Option<ConsentRegistryDelegation>,
    /// An owner's agent grant (FIX 5628), projected from its live row or
    /// signed revoked mint; absent on every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_grant: Option<ConsentRegistryAgentGrant>,
}

/// The unified consent registry projection — surface (b).
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ConsentRegistry {
    /// The rows, newest first.
    pub rows: Vec<ConsentRegistryRow>,
    /// The live slips of named agents that no Grant has ever named, newest
    /// issued first (FIX AGENT-GRANTLESS-VISIBLE); absent when there are
    /// none. Each reads as its Scope allows until the owner converts it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grantless_agents: Vec<GrantlessAgentRow>,
}

impl ConsentRegistryRow {
    pub(super) fn from_row(row: &ConsentGrantRow) -> Self {
        let bound = row.grant.bound();
        let grant_ref = crate::consent::consent_grant_row_grant_ref(&row);
        Self {
            domain: bound.domain(),
            subject: render_subject(bound.subject()),
            class: bound.class().as_str().to_owned(),
            selectors: render_selectors(bound.envelope()),
            scope: match bound.envelope() {
                BoundEnvelope::Disclosure(envelope) => envelope.scope().cloned(),
                BoundEnvelope::Action(_) => None,
            },
            status: row.status,
            created_at: row.created_at,
            revoke_action: ConsentRevokeAction {
                command: CONSENT_REVOKE_COMMAND.to_owned(),
                grant_ref: grant_ref.clone(),
            },
            regrant_action: None,
            grant_ref,
            bypass: row.bypass,
            delegation: None,
            agent_grant: None,
        }
    }

    /// One contact's clearance row. Its revoke is the contact clearance
    /// door's (`consent.revoke_contact_disclosure`), not the grant revoke.
    pub(super) fn from_contact_clearance(contact: &EntityId, clearance: &DisclosureScope) -> Self {
        let grant_ref = contact_clearance_ref(contact);
        Self {
            domain: ConsentDomain::Disclosure,
            subject: contact.to_hex(),
            class: CONTACT_CLEARANCE_CLASS.to_owned(),
            selectors: render_scope(&clearance.scope),
            scope: Some(clearance.scope.clone()),
            status: match clearance.status {
                DisclosureScopeStatus::Active => ConsentGrantStatus::Active,
                DisclosureScopeStatus::Revoked => ConsentGrantStatus::Revoked,
            },
            created_at: clearance.created_at,
            revoke_action: ConsentRevokeAction {
                command: CONTACT_CLEARANCE_REVOKE_COMMAND.to_owned(),
                grant_ref: grant_ref.clone(),
            },
            regrant_action: None,
            grant_ref,
            bypass: None,
            delegation: None,
            agent_grant: None,
        }
    }

    /// One support grant (OF-606), from its logged mint. Its one-tap revoke
    /// is the support revoke door's, never the consent grant revoke; it is
    /// Active only while the grant admits its holder.
    pub(super) fn from_support_grant(grant: &crate::authority::SupportGrantRow) -> Self {
        use crate::authority::{SUPPORT_GRANT_REVOKE_COMMAND, SupportGrantStatus};
        let grant_ref = crate::entity_id::bytes_to_hex_lower(&grant.slip_id);
        let mut selectors = render_scope(&grant.scope);
        if !grant.records.is_empty() {
            selectors.push(format!(
                "records:{}",
                grant.records.iter().cloned().collect::<Vec<_>>().join(",")
            ));
        }
        selectors.push(format!("comm:{}", grant.comm.as_str()));
        Self {
            domain: ConsentDomain::Action,
            subject: format!("{}/{}", grant.holder.to_hex(), grant.holder_class),
            class: SUPPORT_GRANT_CLASS.to_owned(),
            selectors,
            scope: Some(grant.scope.clone()),
            status: if grant.status == SupportGrantStatus::Active {
                ConsentGrantStatus::Active
            } else {
                ConsentGrantStatus::Revoked
            },
            created_at: grant.delegation.approved_at,
            revoke_action: ConsentRevokeAction {
                command: SUPPORT_GRANT_REVOKE_COMMAND.to_owned(),
                grant_ref: grant_ref.clone(),
            },
            regrant_action: None,
            grant_ref,
            bypass: None,
            delegation: Some(ConsentRegistryDelegation {
                purpose: grant.delegation.purpose.clone(),
                ticket_ref: grant.delegation.ticket_ref.clone(),
                approved_by: grant.delegation.owner_ref.clone(),
                wall_expires_at: grant.delegation.wall_expires_at,
                status: grant.status,
                comm: grant.comm,
            }),
            agent_grant: None,
        }
    }

    /// One owner's agent grant (FIX 5628), from its live grant row. Its
    /// one-tap revoke is the agent grant revoke door's, never the consent
    /// grant revoke; it is Active until its expiry, and always when it has
    /// none. A grant with repo bounds shows them whole, and its repo among
    /// the selectors as a GitPush row shows its repos (FIX 6894).
    pub(crate) fn from_agent_grant(
        standing: &crate::federation::AgentGrantStanding,
        now: u64,
        classes: &crate::federation::AgentVerbClasses,
    ) -> Self {
        let grant = &standing.grant;
        Self::from_agent_grant_fields(
            standing.id,
            &grant.authority_scope,
            ConsentRegistryAgentGrant {
                agent: grant.member_ref,
                delegated_by: standing.delegated_by,
                expires_at: grant.expires_at,
                repo_bounds: grant.repo_bounds.clone(),
                verb_classes: grant.verb_classes.clone(),
                wallet_ref: grant.wallet_ref.clone(),
                working_view_bounds: grant.working_view_bounds,
                confers: grant.confers_with_classes_at(now, classes),
            },
            if standing.stands_at(now) {
                ConsentGrantStatus::Active
            } else {
                ConsentGrantStatus::Revoked
            },
            standing.created_at,
        )
    }

    /// Projects live row fields or a revoked grant's signed mint, without
    /// constructing a grant with a made-up residence scope.
    pub(crate) fn from_agent_grant_fields(
        id: EntityId,
        scope: &Scope,
        agent_grant: ConsentRegistryAgentGrant,
        status: ConsentGrantStatus,
        created_at: u64,
    ) -> Self {
        let grant_ref = id.to_hex();
        let mut selectors = render_scope(scope);
        if let Some(bounds) = &agent_grant.repo_bounds {
            selectors.push(format!(
                "repo:{}@project:{}",
                bounds.repo.to_hex(),
                bounds.project.to_hex()
            ));
        }
        selectors.push(format!(
            "delegated_by:{}",
            agent_grant.delegated_by.to_hex()
        ));
        selectors.push(agent_grant.expires_at.map_or_else(
            || "expiry:durable".to_owned(),
            |expires_at| format!("expiry:{expires_at}"),
        ));
        Self {
            domain: ConsentDomain::Action,
            subject: format!("{}/agent", agent_grant.agent.to_hex()),
            class: AGENT_GRANT_CLASS.to_owned(),
            selectors,
            scope: Some(scope.clone()),
            status,
            created_at,
            revoke_action: ConsentRevokeAction {
                command: crate::federation::AGENT_GRANT_REVOKE_COMMAND.to_owned(),
                grant_ref: grant_ref.clone(),
            },
            regrant_action: None,
            grant_ref,
            bypass: None,
            delegation: None,
            agent_grant: Some(agent_grant),
        }
    }
}
