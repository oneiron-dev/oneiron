//! The read context an attempt's admission keeps (FIX 11001): the rows its
//! input names, decoded with each kind's own decoder. A kind whose input is
//! Nil, a sweep, or names no entity row keeps none, and a decode that fails
//! keeps none and logs nothing: the admission never fails or changes because
//! of this. `record` is the one row the job is about when it names exactly
//! one, else `None`; `about` is every entity row the input names, and only
//! those. An id the input names that is no entity row (an attempt id, a
//! change cursor, a side-table key, a hash) is left out, never converted.

use std::collections::BTreeSet;

use crate::EntityId;
use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::dreamer_consolidation;
use crate::dreamer_runner::{self, maintenance};
use crate::feedback;
use crate::scope_summary::{ScopeSummaryTarget, decode_target};
use crate::store::GateDecisionReadContext;

/// The read context of one attempt's admission: the entity rows its `input`
/// names under its `attempt_type`. `None` when the kind keeps none.
pub(crate) fn attempt_read_context(
    attempt_type: &str,
    input: &rmpv::Value,
) -> Option<GateDecisionReadContext> {
    // The consolidation lanes' payload discriminator is the scope's own
    // `micro`/`meso`/`macro` string (`DreamerConsolidationScope::as_str`),
    // matched literally as the roster does.
    let about: Vec<EntityId> = match attempt_type {
        "micro" | "meso" | "macro" | dreamer_consolidation::DREAMER_GAP_SCAN_ATTEMPT_TYPE => {
            let branch = dreamer_consolidation::decode_partition_payload(input).ok()?;
            let mut about = Vec::new();
            about.extend(branch.world_ref);
            about.extend(branch.facet_ref);
            if let Some(thing) = branch.thing {
                about.extend(thing.entity);
                about.extend(thing.audience);
            }
            for part in &branch.parts {
                about.push(part.conversation_ref);
                about.extend(part.turns.iter().copied());
            }
            about
        }
        dreamer_consolidation::DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE => {
            vec![crate::edit_distance::miner::miner_session_from_input(input).ok()?]
        }
        dreamer_consolidation::DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE => {
            match decode_target(input).ok()? {
                ScopeSummaryTarget::Scope { scope, land_on, .. } => {
                    let mut about = scope_ids(&scope);
                    about.extend(land_on);
                    about
                }
                ScopeSummaryTarget::Thread { trunk } => vec![trunk],
                ScopeSummaryTarget::Sources { scope, sources } => {
                    let mut about = scope.map(|scope| scope_ids(&scope)).unwrap_or_default();
                    about.extend(sources);
                    about
                }
                ScopeSummaryTarget::Session { session } => vec![session],
                ScopeSummaryTarget::Arc { scope } => scope_ids(&scope),
            }
        }
        dreamer_consolidation::DREAMER_PERSON_ABOUT_ATTEMPT_TYPE => {
            vec![dreamer_consolidation::person_of_about_input(input).ok()?]
        }
        dreamer_runner::DREAMER_WEAVE_RECIPE_ATTEMPT_KIND => {
            let pin = dreamer_runner::WeaveRecipePin::decode(input).ok()?;
            vec![pin.skill, pin.subject, pin.evidence]
        }
        dreamer_runner::DREAMER_WEAVE_LENS_ATTEMPT_KIND => {
            let (reader, _, _) = crate::claim::weave_lens_attempt_period(input).ok()?;
            vec![reader.id()]
        }
        dreamer_runner::connector_event::CONNECTOR_EVENT_FACET => {
            vec![dreamer_runner::connector_event::ConnectorEventWake::agent_of_input(input).ok()?]
        }
        dreamer_runner::DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND => {
            let resident = maintenance::optimize::resident(input).ok()??;
            vec![resident]
        }
        maintenance::action_mode::ACTION_MODE_FACET => {
            vec![EntityId::from_hex(input.as_str()?).ok()?]
        }
        maintenance::representation::REPRESENTATION_FACET => {
            maintenance::representation::packet_claims(input).ok()?
        }
        maintenance::digest::DIGEST_ASSESS_FACET => {
            let candidate = maintenance::digest::json_field::<
                maintenance::digest::DigestHarmCandidate,
            >(input, maintenance::digest::CANDIDATE_KEY)
            .ok()?;
            digest_candidate_about(&candidate)
        }
        maintenance::digest::DIGEST_URGENT_FACET => {
            let assessment = maintenance::digest::json_field::<
                maintenance::digest::UrgentDigestAssessment,
            >(input, maintenance::digest::ASSESSMENT_KEY)
            .ok()?;
            digest_candidate_about(&assessment.candidate)
        }
        maintenance::compaction_check::COMPACTION_CHECK_FACET => {
            if let Some(declaration) =
                maintenance::compaction_check::ConversationCheckDeclaration::from_input(input)
                    .ok()?
            {
                declaration.cited(true)
            } else {
                maintenance::compaction_check::CompactionCheckDeclaration::from_input(input)
                    .ok()?
                    .cited(true)
            }
        }
        feedback::COACH_FEEDBACK_TRIAGE_FACET => {
            let (_, evidence) = feedback::job_target(input).ok()?;
            vec![evidence]
        }
        feedback::COACH_FEEDBACK_TRIAGE_PART_FACET
        | feedback::COACH_FEEDBACK_TRIAGE_SYNTHESIS_FACET => {
            vec![feedback::node_target(input).ok()?.evidence]
        }
        maintenance::agent_health::COACH_AGENT_HEALTH_ASK_FACET => {
            let (subject, _, task) = maintenance::agent_health::parse_card_ref(input.as_str()?)?;
            let mut about = vec![EntityId::from_bytes(subject).ok()?];
            // An all-zero task is the handle's no-task marker, not a row.
            if task != [0; 16] {
                about.push(EntityId::from_bytes(task).ok()?);
            }
            about
        }
        _ => return None,
    };
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::with_capacity(about.len());
    for id in about {
        if seen.insert(id) {
            deduped.push(id);
        }
    }
    let record = (deduped.len() == 1).then(|| deduped[0]);
    GateDecisionReadContext::about(record, deduped)
}

/// Every entity id a scope selector names: its conversation, session and
/// path rows.
fn scope_ids(scope: &ScopeSelector) -> Vec<EntityId> {
    let mut ids = vec![scope.conversation];
    ids.extend(scope.session);
    match scope.path {
        ScopePath::Canonical => {}
        ScopePath::Branch(id) | ScopePath::SubSession(id) => ids.push(id),
        ScopePath::BranchSpan { after, through } => ids.extend([after, through]),
    }
    ids
}

/// Every entity row a harm candidate names: its recipient owner, its intent
/// and result claims, and its due record when it names one.
fn digest_candidate_about(candidate: &maintenance::digest::DigestHarmCandidate) -> Vec<EntityId> {
    let mut about = vec![
        candidate.recipient,
        candidate.intent.claim_ref,
        candidate.result.claim_ref,
    ];
    about.extend(candidate.needed_before.map(|needed| needed.source_ref));
    about
}
