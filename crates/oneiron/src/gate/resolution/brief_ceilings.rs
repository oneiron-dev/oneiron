//! The self brief's CLASSES producer (FIX 17594, Engine ruling 21:47 CLASSES
//! = B): the concrete class ceilings the resolved policy holds, each a dated
//! description of its configured row, beside the actor's live definition
//! ceiling. It evaluates no Gate and gives no verdict on any act: class
//! verdicts stay unavailable.
//!
//! The rows come from the policy fold, which takes them from trusted packs
//! only: a quarantined or untrusted pack adds none. Each row keeps its own
//! keys. No holder, subject class or effect is taken from the caller: the
//! actor binding is read only where the row itself binds an actor. The read
//! writes nothing; like every fold, it may park a scan check in memory,
//! which the vault's next write keeps.

use crate::Vault;
use crate::context_board::{
    BriefActPosture, BriefCeiling, BriefCeilingPosture, BriefCeilingTarget, BriefClassPrecedence,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::gate::ceiling::PolicyApprovalCeiling;
use crate::gate::class_policy::{ActPosture, ClassPolicyPrecedence};
use crate::policy_manifest_doors::{PolicyCeiling, PolicyScopedGrantRow};
use crate::write_envelope::WriteActor;

use super::manifest_types::PolicyManifestResolution;

impl PolicyManifestResolution {
    /// The class ceilings this resolved policy holds for `actor`, beside the
    /// live definition ceiling `definition` read for it in the same
    /// snapshot, each dated `as_of_secs` and this policy's frontier hash. In
    /// order:
    ///
    /// 1. each actor-ceiling row that matches the actor's class and ref, the
    ///    way [`Self::actor_ceiling`] matches them, then, when one matched,
    ///    the ceiling those rows resolve to;
    /// 2. the definition ceiling, when the definition bounds the actor;
    /// 3. every act-policy row and every wait-policy row, vault and holder
    ///    rows alike, as configured;
    /// 4. every scoped policy grant row whose own actor binding admits the
    ///    actor's class and ref.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] when a loaded manifest holds the policy
    /// fail-closed, so its rows do not govern; a frontier hash that does not
    /// compute; a scoped grant value that does not encode.
    pub(crate) fn brief_ceiling_rows(
        &self,
        actor: WriteActor,
        as_of_secs: u64,
        definition: Option<PolicyApprovalCeiling>,
    ) -> Result<Vec<BriefCeiling>> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return Err(Error::InvalidConfig(
                "the policy is held fail-closed; its class rows do not govern".into(),
            ));
        }
        let policy_frontier = bytes_to_hex_lower(&self.read_frontier_hash()?);
        let dated = |class_or_effect, posture| BriefCeiling {
            class_or_effect,
            posture,
            as_of_secs,
            policy_frontier: policy_frontier.clone(),
        };
        let actor_class = actor.actor_class().gate_actor_class();
        let actor_ref = actor.entity_ref().to_hex();
        let mut rows = Vec::new();
        for row in self.actor_ceilings.iter().filter(|row| {
            row.actor_class == actor_class
                && row
                    .actor_ref
                    .as_deref()
                    .is_none_or(|bound| bound == actor_ref)
        }) {
            rows.push(dated(
                BriefCeilingTarget::Actor {
                    actor_class: row.actor_class.clone(),
                    actor_ref: row.actor_ref.clone(),
                },
                approval(row.ceiling),
            ));
        }
        if !rows.is_empty() {
            let resolved = self.actor_ceiling(actor_class, Some(actor_ref.as_str()));
            rows.push(dated(
                BriefCeilingTarget::ResolvedActor {
                    actor_class: actor_class.to_owned(),
                    actor_ref: actor_ref.clone(),
                },
                approval(resolved),
            ));
        }
        if let Some(definition) = definition {
            rows.push(dated(
                BriefCeilingTarget::Definition {
                    actor: actor.entity_ref(),
                },
                approval(definition),
            ));
        }
        // A holder row governs only its holder's acts: the agent's brief
        // shows the vault rows and its own holder rows, never another
        // holder's.
        let own_or_vault = |holder: Option<crate::entity_id::EntityId>| {
            holder.is_none_or(|holder| holder == actor.entity_ref())
        };
        for row in self
            .act_policy
            .rows()
            .iter()
            .filter(|row| own_or_vault(row.holder_ref))
        {
            rows.push(dated(
                BriefCeilingTarget::Act {
                    act_class: row.act_class.clone(),
                    subject_class: row.subject_class.clone(),
                    holder: row.holder_ref,
                },
                BriefCeilingPosture::Act {
                    posture: match row.posture {
                        ActPosture::Deny => BriefActPosture::Deny,
                        ActPosture::RequireCapability => BriefActPosture::RequireCapability,
                    },
                    precedence: row
                        .holder_ref
                        .is_none()
                        .then_some(class_precedence(row.precedence)),
                },
            ));
        }
        for row in self
            .wait_policy
            .rows()
            .iter()
            .filter(|row| own_or_vault(row.holder_ref))
        {
            rows.push(dated(
                BriefCeilingTarget::Wait {
                    wait_class: row.wait_class.clone(),
                    holder: row.holder_ref,
                },
                BriefCeilingPosture::Wait {
                    min_secs: row.min_secs,
                    max_secs: row.max_secs,
                    precedence: row
                        .holder_ref
                        .is_none()
                        .then_some(class_precedence(row.precedence)),
                },
            ));
        }
        for grant in self.scoped_grants().iter().filter(|grant| {
            grant
                .actor_class
                .as_deref()
                .is_none_or(|bound| bound == actor_class)
                && grant
                    .actor_ref
                    .as_deref()
                    .is_none_or(|bound| bound == actor_ref)
        }) {
            let row = PolicyScopedGrantRow::of_decoded(grant)?;
            rows.push(dated(
                BriefCeilingTarget::Effector {
                    effector: row.effector,
                    actor_class: row.actor_class,
                    actor_ref: row.actor_ref,
                },
                BriefCeilingPosture::ConfiguredScopedGrant {
                    scope: row.scope,
                    selectors: row.selectors,
                    budget: row.budget,
                    receipt_required: row.receipt_required,
                },
            ));
        }
        Ok(rows)
    }
}

impl Vault {
    /// The concrete class ceilings that bound the host-bound agent `actor`,
    /// for its self brief, read in one snapshot: the vault's authority
    /// instant, the policy resolved once, its rows (`brief_ceiling_rows`)
    /// and the live definition ceiling (`agent_definition_ceiling_for_actor`).
    /// Each is a dated description; none is a verdict on an act.
    ///
    /// # Errors
    /// A store, fold or clock failure, or a policy a loaded manifest holds
    /// fail-closed.
    pub fn self_brief_ceilings(&self, actor: WriteActor) -> Result<Vec<BriefCeiling>> {
        let txn = self.store.env.read_txn()?;
        let as_of_secs = self.instant_in_txn(&txn)?.secs();
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        let definition = crate::gate::agent_definition_ceiling_for_actor(&self.store, &txn, actor);
        policy.brief_ceiling_rows(actor, as_of_secs, definition)
    }
}

/// The approval posture of the Gate's ceiling `ceiling`.
fn approval(ceiling: PolicyApprovalCeiling) -> BriefCeilingPosture {
    BriefCeilingPosture::Approval {
        approval: PolicyCeiling::of_approval(ceiling),
    }
}

/// The public name of a class's holder-row precedence.
fn class_precedence(precedence: ClassPolicyPrecedence) -> BriefClassPrecedence {
    match precedence {
        ClassPolicyPrecedence::NestedNarrowing => BriefClassPrecedence::NestedNarrowing,
        ClassPolicyPrecedence::VaultOnly => BriefClassPrecedence::VaultOnly,
    }
}
