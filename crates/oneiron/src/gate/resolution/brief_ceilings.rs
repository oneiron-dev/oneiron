//! The self brief's CLASSES producer (FIX 17594, Engine ruling 21:47 CLASSES
//! = B): the concrete class ceilings the resolved policy holds, each a dated
//! description of its configured row, beside the actor's live definition
//! ceiling. Beside them, in the same snapshot, the per-class verdicts (FIX
//! 20734, Engine ruling 11:16): one line for each class the actor's standing
//! outbound and consent grants, its effector policy rows, governing connector
//! keys and act-policy rows name, and DEC-0006 invariant 1's default lines,
//! each word classed as
//! `can(effect)` classes it, from the checks the actor meets for any target.
//! It evaluates no Gate and judges no one act.
//!
//! The rows come from the policy fold, which takes them from trusted packs
//! only: a quarantined or untrusted pack adds none. Each row keeps its own
//! keys. No holder, subject class or effect is taken from the caller: the
//! actor binding is read only where the row itself binds an actor. The read
//! writes nothing; like every fold, it may park a scan check in memory,
//! which the vault's next write keeps.

use std::collections::BTreeSet;

use crate::Vault;
use crate::connector_key::{ConnectorKeyStatus, SlateCapability, SlateDisposition};
use crate::consent::BoundEnvelope;
use crate::context_board::{
    BriefActPosture, BriefActionEnvelope, BriefCeiling, BriefCeilingPosture, BriefCeilingTarget,
    BriefClassPrecedence, BriefClassReads, BriefClassSource, BriefClassVerdict, BriefClassVerdicts,
    BriefDefaultRule, BriefOutboundScope, BriefPerActCheck,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::gate::GateReasonCode;
use crate::gate::ceiling::PolicyApprovalCeiling;
use crate::gate::class_policy::{ActPosture, ClassPolicyPrecedence};
use crate::gate::constants::{
    EXTERNAL_EFFECT_EFFECTOR_LONG_PREFIX, EXTERNAL_EFFECT_EFFECTOR_PREFIX,
};
use crate::gate::grants::{PolicyScopedGrant, external_effect_grant_admits_effect};
use crate::memory::CanEffectVerdict;
use crate::outbound_grant::StandingOutboundGrantScope;
use crate::policy_manifest_doors::{PolicyCeiling, PolicyScopedGrantRow};
use crate::store::Store;
use crate::write_envelope::WriteActor;

use super::manifest_types::PolicyManifestResolution;

/// The actor class a scoped connector call's Gate input names, whoever the
/// actor is (`outbound_consent::execution::scoped_mcp_gate_input`).
const SCOPED_MCP_ACTOR_CLASS: &str = "first_party";

/// The class an artifact-publish grant covers: the verb its effect names.
const ARTIFACT_PUBLISH_CLASS: &str = "publish";

/// The checks every send inside a grant's or a row's bound still meets.
const SEND_CHECKS: [BriefPerActCheck; 5] = [
    BriefPerActCheck::CounterpartyOptOut,
    BriefPerActCheck::CampaignCompliance,
    BriefPerActCheck::EnvelopeWindow,
    BriefPerActCheck::Budget,
    BriefPerActCheck::Permission,
];

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
        self.refuse_fail_closed_class_rows()?;
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
        for row in self
            .act_policy
            .rows()
            .iter()
            .filter(|row| vault_or_own(row.holder_ref, actor))
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
            .filter(|row| vault_or_own(row.holder_ref, actor))
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
        for grant in self
            .scoped_grants()
            .iter()
            .filter(|grant| scoped_grant_admits(grant, actor_class, &actor_ref))
        {
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

    /// The per-class verdicts this resolved policy gives `actor`, read on
    /// `txn` beside the two ceilings `ceilings` read for it in the same
    /// snapshot (its definition's own and a foreign introduction's), dated
    /// `as_of_secs` and this policy's frontier
    /// hash. One line for:
    ///
    /// 1. each standing outbound grant whose principal is the actor and that
    ///    is active under this policy: the class its scope dial covers;
    /// 2. each active standing consent grant whose actor subject contains the
    ///    actor and whose envelope is an action envelope;
    /// 3. each scoped policy grant row whose own actor binding admits the
    ///    actor, that has no budget row and whose Scope admits an external
    ///    effect: the effector it covers;
    /// 4. the actor's governing connector keys: non-Active status, charter
    ///    drift or compiled never-list entries, and each non-Auto slate tool;
    /// 5. each act-policy pairing a vault row or the actor's own holder row
    ///    names, whose posture resolves to deny for the actor;
    /// 6. each default rule of DEC-0006 invariant 1.
    ///
    /// The consent grants and connector census are read on that same `txn`.
    ///
    /// Inside its bound, a grant line or an effector line gets the words of
    /// the checks the actor meets for any target, classed as `can(effect)`
    /// classes them with no press (`crate::gate::preflight_words`). The
    /// checks are an actor ceiling below auto, a foreign agent held at
    /// Proposed and, on every line except a scoped connector call's, a
    /// Proposed definition ceiling, which also withholds the external-effect
    /// authority. A scoped connector call's Gate input names the actor class
    /// `first_party`, and a verified scoped grant dissolves a Proposed
    /// definition ceiling and the actor ceiling with it, never a foreign
    /// agent's clamp. Beyond its bound, an act meets the same walls and the
    /// consent ask an uncovered act raises (`beyond_bound`). The lines are sorted by
    /// class, then by source kind, then by grant.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] when a loaded manifest holds the policy
    /// fail-closed, so its rows do not govern; a frontier hash that does not
    /// compute; an outbound, consent or connector read that fails or does not
    /// decode; an invalid actor bound or charter policy; a selector value that
    /// does not encode.
    pub(crate) fn brief_class_verdicts(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        actor: WriteActor,
        as_of_secs: u64,
        ceilings: BriefActorCeilings,
    ) -> Result<BriefClassVerdicts> {
        self.refuse_fail_closed_class_rows()?;
        let BriefActorCeilings {
            definition,
            foreign,
        } = ceilings;
        let frontier = self.read_frontier_hash()?;
        let actor_class = actor.actor_class().gate_actor_class();
        let actor_ref = actor.entity_ref().to_hex();
        let below_auto = |class: &str| {
            self.actor_ceiling(class, Some(actor_ref.as_str())) != PolicyApprovalCeiling::Auto
        };
        let proposed = definition == Some(PolicyApprovalCeiling::Proposed);
        // A foreign agent held at Proposed is clamped on every effect, a
        // scoped MCP call's too: a scoped grant dissolves only the
        // definition's fork (evaluation.rs, the foreign-agent clamp).
        let foreign_proposed = foreign == Some(PolicyApprovalCeiling::Proposed);
        let mut target_free_codes = Vec::new();
        let mut scoped_mcp_codes = Vec::new();
        if self.is_fail_closed() {
            // A policy held fail-closed (no manifest at all) holds every
            // external effect on its missing authority alone, before any
            // ceiling is read, as the Gate's evaluation does.
            target_free_codes.push(GateReasonCode::PendingExternalEffectAuthority);
            scoped_mcp_codes.push(GateReasonCode::PendingExternalEffectAuthority);
        } else {
            if proposed || foreign_proposed || below_auto(actor_class) {
                target_free_codes.push(GateReasonCode::PendingActorCeiling);
            }
            if proposed {
                target_free_codes.push(GateReasonCode::PendingExternalEffectAuthority);
            }
            if foreign_proposed || (!proposed && below_auto(SCOPED_MCP_ACTOR_CLASS)) {
                scoped_mcp_codes.push(GateReasonCode::PendingActorCeiling);
            }
        }
        let mut verdicts = Vec::new();
        // The actor's standing outbound grants are consent rows (FIX 11874);
        // a revoked row is no line.
        for grant in crate::outbound_grant::standing_outbound_grants_for_principal_in_txn(
            store, txn, &actor_ref,
        )? {
            if !grant.is_active_under_policy(&frontier) {
                continue;
            }
            let (class, per_act) = outbound_class(&grant.scope);
            let line_codes = if matches!(grant.scope, StandingOutboundGrantScope::ScopedMcp { .. })
            {
                &scoped_mcp_codes
            } else {
                &target_free_codes
            };
            verdicts.push(worded_line(
                class,
                BriefClassSource::OutboundGrant {
                    grant: grant.id,
                    scope: BriefOutboundScope::of_grant_scope(&grant.scope),
                },
                line_codes,
                Some(beyond_bound(line_codes)),
                per_act,
            ));
        }
        for grant in self.scoped_grants().iter().filter(|grant| {
            scoped_grant_admits(grant, actor_class, &actor_ref)
                && grant.budget.is_none()
                && external_effect_grant_admits_effect(grant)
        }) {
            let row = PolicyScopedGrantRow::of_decoded(grant)?;
            verdicts.push(worded_line(
                effector_class(&row.effector).to_owned(),
                BriefClassSource::Effector {
                    effector: row.effector,
                    selectors: row.selectors,
                    receipt_required: row.receipt_required,
                },
                &target_free_codes,
                Some(beyond_bound(&target_free_codes)),
                SEND_CHECKS.to_vec(),
            ));
        }
        let candidate =
            crate::consent::ActorBound::new(actor_ref.clone())?.with_actor_class(actor_class)?;
        for row in crate::consent::active_standing_grant_rows_in_txn(store, txn)? {
            let bound = row.grant.bound();
            if !bound
                .actor()
                .is_some_and(|subject| subject.contains(&candidate))
            {
                continue;
            }
            let BoundEnvelope::Action(envelope) = bound.envelope() else {
                continue;
            };
            verdicts.push(worded_line(
                bound.class().as_str().to_owned(),
                BriefClassSource::ConsentGrant {
                    grant: crate::consent::consent_grant_row_grant_ref(&row),
                    envelope: BriefActionEnvelope {
                        selectors: envelope.selectors().to_vec(),
                        target: envelope.target().map(str::to_owned),
                        budget: envelope.budget(),
                        receipt_required: envelope.receipt_required(),
                    },
                    external_effects: bound
                        .actor()
                        .is_some_and(|subject| subject.actor_class().is_none()),
                },
                &target_free_codes,
                Some(beyond_bound(&target_free_codes)),
                vec![
                    BriefPerActCheck::BoundContainment,
                    BriefPerActCheck::ExternalAuthority,
                ],
            ));
        }
        for (key_id, key) in
            crate::connector_key::governing_keys_for_actor_in_txn(store, txn, &actor.entity_ref())?
        {
            let Some(server) = crate::connector_key::brief_server_name(&key) else {
                continue;
            };
            if key.status != ConnectorKeyStatus::Active {
                let class = format!("mcp:{server}/*");
                let source = BriefClassSource::ConnectorKey {
                    key: key_id,
                    server,
                    status: key.status.as_str().to_owned(),
                };
                let verdict = match key.status {
                    ConnectorKeyStatus::Suspended | ConnectorKeyStatus::Pending => {
                        // The connector driver stops these statuses before the
                        // Gate; its administrative hold is not a Gate denial.
                        let hold = if key.status == ConnectorKeyStatus::Suspended {
                            "connector_key_suspended"
                        } else {
                            "connector_key_pending"
                        };
                        BriefClassVerdict {
                            class,
                            source,
                            inside: CanEffectVerdict::Held,
                            reasons: vec![hold.to_owned()],
                            holds: vec![hold.to_owned()],
                            outside: None,
                            per_act: vec![],
                        }
                    }
                    ConnectorKeyStatus::Revoked => worded_line(
                        class,
                        source,
                        &[GateReasonCode::DenyConnectorKeySuspended],
                        None,
                        vec![],
                    ),
                    ConnectorKeyStatus::Active => unreachable!("guarded above"),
                };
                verdicts.push(verdict);
                continue;
            }
            let catalog_charter = crate::connector_key::catalog_charter_in_txn(store, txn, &key)?;
            for (block, is_catalog_charter) in [
                (key.charter.as_ref(), false),
                (catalog_charter.as_ref(), true),
            ] {
                let Some(block) = block else {
                    continue;
                };
                if crate::connector_key::charter_block_drifted(block)? {
                    verdicts.push(worded_line(
                        format!("mcp:{server}/*"),
                        BriefClassSource::CharterDrift {
                            key: key_id,
                            server: server.clone(),
                            catalog_charter: is_catalog_charter,
                        },
                        &[GateReasonCode::PendingCharterDrift],
                        None,
                        vec![],
                    ));
                    continue;
                }
                for entry in &block.compiled.never_list {
                    verdicts.push(worded_line(
                        entry.clone(),
                        BriefClassSource::NeverListEntry {
                            key: key_id,
                            server: server.clone(),
                            entry: entry.clone(),
                            catalog_charter: is_catalog_charter,
                        },
                        &[GateReasonCode::DenyCharterNeverList],
                        None,
                        vec![],
                    ));
                }
            }
            if let Some((_, slate)) =
                crate::connector_key::governing_slate_in_txn(store, txn, &key)?
            {
                for row in slate.rows() {
                    let SlateCapability::Tool(tool) = row.draft.capability() else {
                        continue;
                    };
                    let setting = crate::connector_key::connector_tool_setting_in_txn(
                        store, txn, &key_id, &key, tool,
                    )?;
                    let mut codes = scoped_mcp_codes.clone();
                    let per_act = match setting {
                        SlateDisposition::NeverAllow => {
                            codes.push(GateReasonCode::DenyCharterNeverList);
                            vec![]
                        }
                        SlateDisposition::AlwaysAsk => {
                            codes.push(GateReasonCode::PendingConsentIrreversibleEffect);
                            vec![]
                        }
                        SlateDisposition::AlwaysAllow => vec![
                            BriefPerActCheck::ExternalAuthority,
                            BriefPerActCheck::DataClassAndEndpoint,
                            BriefPerActCheck::ManifestBinding,
                            BriefPerActCheck::Budget,
                        ],
                        SlateDisposition::Auto => continue,
                    };
                    verdicts.push(worded_line(
                        format!("mcp:{server}/{tool}"),
                        BriefClassSource::SlateTool {
                            key: key_id,
                            server: server.clone(),
                            tool: tool.to_owned(),
                            setting,
                        },
                        &codes,
                        None,
                        per_act,
                    ));
                }
            }
        }
        let pairings: BTreeSet<(&str, &str)> = self
            .act_policy
            .rows()
            .iter()
            .filter(|row| vault_or_own(row.holder_ref, actor))
            .map(|row| (row.act_class.as_str(), row.subject_class.as_str()))
            .collect();
        for (act_class, subject_class) in pairings {
            if self
                .act_policy
                .resolve(act_class, subject_class, Some(actor.entity_ref()))
                == Some(ActPosture::Deny)
            {
                verdicts.push(BriefClassVerdict {
                    class: act_class.to_owned(),
                    source: BriefClassSource::Act {
                        act_class: act_class.to_owned(),
                        subject_class: subject_class.to_owned(),
                    },
                    inside: CanEffectVerdict::Deny,
                    reasons: Vec::new(),
                    holds: Vec::new(),
                    outside: None,
                    per_act: Vec::new(),
                });
            }
        }
        for rule in BriefDefaultRule::ALL {
            let (codes, per_act) = default_rule_words(rule);
            verdicts.push(worded_line(
                rule.as_str().to_owned(),
                BriefClassSource::Default { rule },
                codes,
                None,
                per_act,
            ));
        }
        verdicts.sort_by(|left, right| {
            left.class
                .cmp(&right.class)
                .then_with(|| source_rank(&left.source).cmp(&source_rank(&right.source)))
                .then_with(|| source_grant(&left.source).cmp(&source_grant(&right.source)))
        });
        Ok(BriefClassVerdicts {
            as_of_secs,
            policy_frontier: bytes_to_hex_lower(&frontier),
            verdicts,
        })
    }

    /// Refuses to describe the class rows of a policy a loaded manifest
    /// holds fail-closed: its rows do not govern.
    fn refuse_fail_closed_class_rows(&self) -> Result<()> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            return Err(Error::InvalidConfig(
                "the policy is held fail-closed; its class rows do not govern".into(),
            ));
        }
        Ok(())
    }
}

/// The two ceilings a class verdict meets, read apart as the Gate reads
/// them: the live definition's own ceiling, and the ceiling of a foreign
/// agent's introduction.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BriefActorCeilings {
    pub(crate) definition: Option<PolicyApprovalCeiling>,
    pub(crate) foreign: Option<PolicyApprovalCeiling>,
}

impl Vault {
    /// The class reads of the host-bound agent `actor`'s self brief, read in
    /// one snapshot: the vault's authority instant, the policy resolved
    /// once, the live definition ceiling
    /// (`agent_definition_ceiling_for_actor`), and from them the concrete
    /// class ceilings (`brief_ceiling_rows`) and the per-class verdicts
    /// (`brief_class_verdicts`), each dated with that instant and the
    /// policy's frontier. Each ceiling is a dated description, and each
    /// verdict is a class's, never one act's.
    ///
    /// # Errors
    /// A store, fold or clock failure, a grant that does not decode, or a
    /// policy a loaded manifest holds fail-closed.
    pub fn self_brief_class_reads(&self, actor: WriteActor) -> Result<BriefClassReads> {
        let txn = self.store.env.read_txn()?;
        let as_of_secs = self.instant_in_txn(&txn)?.secs();
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        let definition = crate::gate::agent_definition_ceiling_for_actor(&self.store, &txn, actor);
        // The verdicts meet the two ceilings apart, as the Gate does: the
        // definition's own, and a foreign agent's introduction.
        let verdict_ceilings = BriefActorCeilings {
            definition: crate::gate::definition_only_ceiling_for_actor(&self.store, &txn, actor),
            foreign: crate::gate::resolve_foreign_agent_ceiling(&self.store, &txn, actor)?,
        };
        Ok(BriefClassReads {
            ceilings: policy.brief_ceiling_rows(actor, as_of_secs, definition)?,
            class_verdicts: policy.brief_class_verdicts(
                &self.store,
                &txn,
                actor,
                as_of_secs,
                verdict_ceilings,
            )?,
        })
    }
}

/// Whether a row held by `holder` governs `actor`'s acts: a vault row, or
/// the actor's own holder row.
fn vault_or_own(holder: Option<EntityId>, actor: WriteActor) -> bool {
    holder.is_none_or(|holder| holder == actor.entity_ref())
}

/// Whether scoped policy grant row `grant`'s own actor binding admits the
/// actor of class `actor_class` and ref `actor_ref`.
fn scoped_grant_admits(grant: &PolicyScopedGrant, actor_class: &str, actor_ref: &str) -> bool {
    grant
        .actor_class
        .as_deref()
        .is_none_or(|bound| bound == actor_class)
        && grant
            .actor_ref
            .as_deref()
            .is_none_or(|bound| bound == actor_ref)
}

/// The class standing outbound grant dial `scope` covers, and the checks
/// every act inside it still meets.
fn outbound_class(scope: &StandingOutboundGrantScope) -> (String, Vec<BriefPerActCheck>) {
    match scope {
        StandingOutboundGrantScope::Contact { .. } | StandingOutboundGrantScope::Channel { .. } => {
            (
                crate::store::consent_bound::SEND_VERB_CLASS.to_owned(),
                SEND_CHECKS.to_vec(),
            )
        }
        StandingOutboundGrantScope::VerbClass { verb_class }
        | StandingOutboundGrantScope::BriefVerbClass { verb_class, .. } => {
            (verb_class.clone(), SEND_CHECKS.to_vec())
        }
        StandingOutboundGrantScope::ArtifactPublish { .. } => (
            ARTIFACT_PUBLISH_CLASS.to_owned(),
            vec![BriefPerActCheck::Budget],
        ),
        StandingOutboundGrantScope::ScopedMcp { server, tool, .. } => (
            format!("mcp:{server}/{tool}"),
            vec![
                BriefPerActCheck::DataClassAndEndpoint,
                BriefPerActCheck::ManifestBinding,
                BriefPerActCheck::ToolSetting,
                BriefPerActCheck::Budget,
            ],
        ),
        StandingOutboundGrantScope::BookingPageInvites { .. } => (
            crate::calendar::CALENDAR_INVITE_VERB.to_owned(),
            vec![BriefPerActCheck::BoundContainment, BriefPerActCheck::Budget],
        ),
    }
}

/// The class a scoped policy grant row's effector covers: the verb, without
/// its `external:` or `external_effect:` prefix; `*` stays `*`.
fn effector_class(effector: &str) -> &str {
    let effector = effector.trim();
    effector
        .strip_prefix(EXTERNAL_EFFECT_EFFECTOR_PREFIX)
        .or_else(|| effector.strip_prefix(EXTERNAL_EFFECT_EFFECTOR_LONG_PREFIX))
        .unwrap_or(effector)
}

/// The reason codes behind default rule `rule`'s word, and the checks every
/// act under it still meets: a reversible vault effect proceeds; a
/// destructive, outbound or critical one asks unless a standing grant
/// covers it, which the act's own bound decides; the catastrophe floor
/// asks.
fn default_rule_words(
    rule: BriefDefaultRule,
) -> (&'static [GateReasonCode], Vec<BriefPerActCheck>) {
    match rule {
        BriefDefaultRule::ReversibleVaultEffect => (&[], Vec::new()),
        BriefDefaultRule::DestructiveOutboundOrCritical => (
            &[GateReasonCode::PendingConsentIrreversibleEffect],
            vec![BriefPerActCheck::BoundContainment],
        ),
        BriefDefaultRule::CatastropheFloor => (
            &[GateReasonCode::PendingConsentCatastropheFloor],
            Vec::new(),
        ),
    }
}

/// The line for `class` from `source`: inside its bound, the words reason
/// codes `codes` give, classed with no press; beyond it, `outside`.
/// The word for an act beyond a grant's bound: the same target-free walls
/// `codes`, plus the consent ask an uncovered irreversible act raises. It
/// asks unless a wall holds or denies the act anyway, so an administrative
/// hold stays held past the bound, as inside it.
fn beyond_bound(codes: &[GateReasonCode]) -> CanEffectVerdict {
    let mut beyond = codes.to_vec();
    beyond.push(GateReasonCode::PendingConsentIrreversibleEffect);
    CanEffectVerdict::of_preflight(crate::gate::preflight_words(&beyond, false).verdict)
}

fn worded_line(
    class: String,
    source: BriefClassSource,
    codes: &[GateReasonCode],
    outside: Option<CanEffectVerdict>,
    per_act: Vec<BriefPerActCheck>,
) -> BriefClassVerdict {
    let words = crate::gate::preflight_words(codes, false);
    BriefClassVerdict {
        class,
        source,
        inside: CanEffectVerdict::of_preflight(words.verdict),
        reasons: words.reasons.into_iter().map(str::to_owned).collect(),
        holds: words.holds.into_iter().map(str::to_owned).collect(),
        outside,
        per_act,
    }
}

/// A line source's place among the lines of one class.
fn source_rank(source: &BriefClassSource) -> u8 {
    match source {
        BriefClassSource::OutboundGrant { .. } => 0,
        BriefClassSource::ConsentGrant { .. } => 1,
        BriefClassSource::ConnectorKey { .. } => 2,
        BriefClassSource::CharterDrift { .. } => 3,
        BriefClassSource::NeverListEntry { .. } => 4,
        BriefClassSource::SlateTool { .. } => 5,
        BriefClassSource::Effector { .. } => 6,
        BriefClassSource::Act { .. } => 7,
        BriefClassSource::Default { .. } => 8,
    }
}

/// The standing outbound grant a line comes from, if any.
fn source_grant(source: &BriefClassSource) -> Option<EntityId> {
    match source {
        BriefClassSource::OutboundGrant { grant, .. } => Some(*grant),
        BriefClassSource::ConsentGrant { .. }
        | BriefClassSource::ConnectorKey { .. }
        | BriefClassSource::CharterDrift { .. }
        | BriefClassSource::NeverListEntry { .. }
        | BriefClassSource::SlateTool { .. }
        | BriefClassSource::Effector { .. }
        | BriefClassSource::Act { .. }
        | BriefClassSource::Default { .. } => None,
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
