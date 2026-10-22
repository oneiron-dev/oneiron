//! Tradeoff ladder planning, application and authenticated settlement.
//! Entry function: `plan`.
//! Preference and ask definitions remain in `super`.

use super::*;

/// What the ladder decided outside the write transaction.
pub(in crate::skill_optimize::gate) enum TradeoffPlan {
    /// Not a pending tradeoff.
    None,
    /// A preference rule, or a confident bound Jev verdict, answered.
    Decided {
        question: SkillTradeoffQuestion,
        choice: TradeoffChoice,
        rung: TradeoffRung,
        authentication: String,
        jev: Option<JevTradeoffVerdict>,
    },
    /// Nothing answered; the responsible person is asked.
    Ask {
        question: SkillTradeoffQuestion,
        jev: Option<JevTradeoffVerdict>,
    },
    /// A person's approval of this exact question, kept on the row a spent
    /// cycle or the judge's cadence deferred, answers it again (FIX 8848).
    Carried(TradeoffResolution),
}

/// Climb the ladder for a scored vector, OUTSIDE any write transaction. A
/// person's kept approval of this exact question answers first. A rule hit
/// never calls Jev. A Jev choice rules only when it echoes the exact question
/// digest with a choice confidence at or above the band's high edge; anything
/// lower asks the person, whatever the learning policy's limit.
pub(in crate::skill_optimize::gate) fn plan(
    vault: &Vault,
    proposal: &EntityId,
    basis: &ScoredBasis,
    definition: &GoalDefinition,
    axes: &BTreeMap<String, GoalAxisScore>,
    scorer: &dyn HeldOutReplayNotes,
) -> Result<TradeoffPlan> {
    if floor_regressed(axes) || !is_tradeoff(axes) {
        return Ok(TradeoffPlan::None);
    }
    let txn = vault.store.env.read_txn()?;
    if let Some(carried) =
        deferred_approval::deferred_approval_in_txn(vault, &txn, proposal, basis, axes)?
    {
        return Ok(TradeoffPlan::Carried(carried));
    }
    let preferences = preferences_in_txn(vault, &txn, &basis.goal_id)?;
    let prior: Option<SkillTradeoffAsk> = load(vault, &txn, &key(ASK_PREFIX, proposal))?;
    let roles = responsible_roles_in_txn(
        vault,
        &txn,
        definition.project.as_ref(),
        preferences
            .as_ref()
            .map(|preferences| preferences.responsible),
    )?;
    drop(txn);
    let project = definition
        .project
        .as_ref()
        .map(|join| project_rules(join, &definition.axes))
        .unwrap_or_default();
    let moved = |keep: fn(&GoalAxisScore) -> bool| -> BTreeSet<String> {
        axes.iter()
            .filter(|(_, axis)| keep(axis))
            .map(|(name, _)| name.clone())
            .collect()
    };
    let question = SkillTradeoffQuestion {
        goal_id: basis.goal_id,
        goal_revision: basis.goal_revision.clone(),
        project: definition.project.as_ref().map(|join| join.project),
        roles,
        proposal: *proposal,
        proposal_digest: basis.proposal_digest.clone(),
        target_digest: basis.target_digest.clone(),
        evidence_digest: basis.evidence_digest.clone(),
        world_digest: basis.world_digest.clone(),
        axes: axes.clone(),
        gains: moved(|axis| axis.after > axis.before),
        losses: moved(|axis| axis.after < axis.before),
    };
    if let Some((choice, authentication)) = matching_rule(
        preferences.as_ref(),
        &project,
        &question.gains,
        &question.losses,
    ) {
        return Ok(TradeoffPlan::Decided {
            question,
            choice,
            rung: TradeoffRung::Preference,
            authentication,
            jev: None,
        });
    }
    // Reuse a measurement only for this exact question. Every fresh answer
    // comes from the shared typed-decision ladder, never a supplied scalar.
    let band = preferences
        .as_ref()
        .and_then(|preferences| preferences.jev_band);
    let jev = match (prior.filter(|prior| prior.question == question), band) {
        (Some(prior), _) => prior.jev,
        // No band was authored, so no judgment can rule: ask the role.
        (None, None) => None,
        (None, Some(band)) => {
            if let Some(decision) = scorer.tradeoff_decision(&question, band)? {
                let choice = match &decision.answer {
                    DecisionAnswer::Choice(value) if value == "approve" => {
                        Some(TradeoffChoice::Approve)
                    }
                    DecisionAnswer::Choice(value) if value == "reject" => {
                        Some(TradeoffChoice::Reject)
                    }
                    _ => None,
                };
                // Choice probability is confidence in the chosen option, not
                // P(yes): the lower tail is uncertainty, never a confident no.
                if let (Some(choice), Some(probability), Some(pin)) = (
                    choice,
                    decision.probability,
                    decision.receipt.providers.last(),
                ) && decision.human_ask.is_none()
                    && probability >= band.high
                {
                    let verdict = JevTradeoffVerdict {
                        question_digest: question.digest()?,
                        choice,
                        probability,
                        pin: pin.clone(),
                    };
                    verdict.validate()?;
                    return Ok(TradeoffPlan::Decided {
                        authentication: format!("{}@{}", pin.model, pin.version),
                        question,
                        choice,
                        rung: TradeoffRung::Judgment,
                        jev: Some(verdict),
                    });
                }
            }
            None
        }
    };
    Ok(TradeoffPlan::Ask { question, jev })
}

/// Settle or park a pending ruling inside the gate's committing transaction,
/// after the tier checks. That transaction re-checked the goal revision
/// against the scored basis, so the preferences the plan read are still in
/// force. Returns the resolution the decision door writes after the pending
/// row. An approval under a spent cycle cap defers like a dominating win.
pub(in crate::skill_optimize::gate) fn apply_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cycle: &SkillEditCycle,
    verdict: &mut HeldOutVerdict,
    plan: &TradeoffPlan,
) -> Result<Option<(TradeoffChoice, TradeoffResolution)>> {
    if verdict.disposition != SkillEditDisposition::NeedsTradeoffDecision {
        // Any other ruling answers or voids an earlier question.
        clear_ask_in_txn(vault, txn, &verdict.proposal)?;
        return Ok(None);
    }
    match plan {
        TradeoffPlan::None => Ok(None),
        TradeoffPlan::Decided {
            question,
            choice,
            rung,
            authentication,
            jev,
        } => {
            verdict.tradeoff_jev.clone_from(jev);
            let resolution = TradeoffResolution {
                pending: verdict.id,
                owner: question
                    .accountable()
                    .ok_or(Error::CorruptedIndex("tradeoff question without a role"))?,
                authentication: authentication.clone(),
                evidence: question.digest()?,
                rung: *rung,
            };
            decided_in_txn(vault, txn, cycle, verdict, *choice, resolution)
        }
        TradeoffPlan::Carried(carried) => {
            let resolution = TradeoffResolution {
                pending: verdict.id,
                ..carried.clone()
            };
            decided_in_txn(
                vault,
                txn,
                cycle,
                verdict,
                TradeoffChoice::Approve,
                resolution,
            )
        }
        TradeoffPlan::Ask { question, jev } => {
            verdict.tradeoff_jev.clone_from(jev);
            // Re-ruling the same question keeps the rung its ask climbed to.
            let rung = load::<SkillTradeoffAsk>(vault, txn, &key(ASK_PREFIX, &verdict.proposal))?
                .filter(|prior| prior.question == *question)
                .map_or(0, |prior| prior.rung);
            save(
                vault,
                txn,
                &key(ASK_PREFIX, &verdict.proposal),
                &SkillTradeoffAsk {
                    pending: verdict.id,
                    question: question.clone(),
                    jev: jev.clone(),
                    rung,
                },
            )?;
            Ok(None)
        }
    }
}

/// A ladder rung decided the pending row: its ask is answered, and an approval
/// the cycle cannot admit yet is kept on the row it defers, so the answer it
/// gave to this exact question stays known.
fn decided_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    cycle: &SkillEditCycle,
    verdict: &mut HeldOutVerdict,
    choice: TradeoffChoice,
    resolution: TradeoffResolution,
) -> Result<Option<(TradeoffChoice, TradeoffResolution)>> {
    clear_ask_in_txn(vault, txn, &verdict.proposal)?;
    if choice == TradeoffChoice::Approve
        && let Some(deferred) =
            approval_deferral_in_txn(vault, txn, cycle, &verdict.proposal, &verdict.skill)?
    {
        verdict.disposition = deferred;
        verdict.tradeoff_resolution = Some(resolution);
        return Ok(None);
    }
    Ok(Some((choice, resolution)))
}

/// The responsible role's answer to the pending A/B question. The digest
/// must name the exact question the person saw, so an older reply cannot
/// answer a replacement question on the same proposal. Any live person
/// holding a role the ask has reached may pick. The pick is learned as a
/// preference for the axis signature and settles the pending tradeoff
/// through the decision door in the same transaction; no model callback can
/// write it or impersonate the person. For a project-bound goal the pick is
/// also proposed for the project's goal record, which only its interview
/// revises. An approval under a spent cycle cap is still learned and defers
/// the proposal: a later cycle re-rules it through the new preference. A pick
/// past the learning policy's limit is still learned, with an advisory.
/// # Errors
/// No pending ask, a digest for another question, a person holding no role the
/// ask has reached, a question stale against the goal, bodies, tier or
/// evidence, or storage errors. An error writes nothing.
pub fn settle_skill_tradeoff_ask(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    vault.with_write_txn_grouped(|txn| {
        settle_skill_tradeoff_ask_in_txn(
            vault,
            txn,
            owner,
            proposal,
            expected_question_digest,
            choice,
            at,
        )
    })
}

/// [`settle_skill_tradeoff_ask`] in the caller's write transaction, so a
/// host commits the pick with its own writes (a project ask's answer and its
/// route) or not at all.
/// # Errors
/// As [`settle_skill_tradeoff_ask`].
pub(crate) fn settle_skill_tradeoff_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    let actor = owner.revalidate_person_in_txn(vault, txn)?;
    settle_ask_in_txn(
        vault,
        txn,
        actor,
        format!("{:?}", owner.decision_id()),
        TradeoffRung::Person,
        proposal,
        expected_question_digest,
        choice,
        at,
    )
}

/// [`settle_skill_tradeoff_ask`] for a live person or a bound agent, owner
/// or not, that holds a responsible role the ask has reached
/// (ROLES-EVERYWHERE): a board member answers on their own behalf. The role
/// check is the authorization; a person's pick is learned at the person
/// rung, an agent's at the role rung.
/// # Errors
/// A writer that is no live person or bound agent, plus every error of
/// [`settle_skill_tradeoff_ask`]. An error writes nothing.
pub fn settle_skill_tradeoff_ask_as(
    vault: &Vault,
    by: &crate::write_envelope::WriteActor,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    vault.with_write_txn_grouped(|txn| {
        settle_skill_tradeoff_ask_as_in_txn(
            vault,
            txn,
            by,
            proposal,
            expected_question_digest,
            choice,
            at,
        )
    })
}

/// [`settle_skill_tradeoff_ask_as`] in the caller's write transaction.
/// # Errors
/// As [`settle_skill_tradeoff_ask_as`].
pub(crate) fn settle_skill_tradeoff_ask_as_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    by: &crate::write_envelope::WriteActor,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    vault.verify_write_actor_in_txn(txn, by)?;
    let actor = by.entity_ref();
    let (authentication, rung) = match by.actor_class() {
        crate::edge::EdgeActorClass::Human => {
            if !crate::consent::person_is_live_in_txn(vault, txn, &actor)? {
                return Err(invalid("a person's tradeoff pick requires a live person"));
            }
            (format!("person:{}", actor.to_hex()), TradeoffRung::Person)
        }
        crate::edge::EdgeActorClass::Agent => {
            (format!("agent:{}", actor.to_hex()), TradeoffRung::Role)
        }
        _ => return Err(invalid("a tradeoff pick comes from a person or an agent")),
    };
    settle_ask_in_txn(
        vault,
        txn,
        actor,
        authentication,
        rung,
        proposal,
        expected_question_digest,
        choice,
        at,
    )
}

/// [`settle_skill_tradeoff_ask`] for an agent that holds a responsible role
/// the ask has reached (ROLES-EVERYWHERE). The agent must be a live, bound
/// writer in the settling transaction; the role check is the authorization,
/// and its pick is learned as the role's preference like a person's.
/// # Errors
/// A writer that is not a live agent, plus every error of
/// [`settle_skill_tradeoff_ask`]. An error writes nothing.
pub fn settle_skill_tradeoff_ask_as_agent(
    vault: &Vault,
    agent: &crate::write_envelope::WriteActor,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    if agent.actor_class() != crate::edge::EdgeActorClass::Agent {
        return Err(invalid("an agent tradeoff pick requires an agent actor"));
    }
    settle_skill_tradeoff_ask_as(vault, agent, proposal, expected_question_digest, choice, at)
}

#[allow(clippy::too_many_arguments)]
fn settle_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    authentication: String,
    rung: TradeoffRung,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    {
        let ask: SkillTradeoffAsk = load(vault, txn, &key(ASK_PREFIX, proposal))?
            .ok_or(invalid("no pending skill tradeoff ask"))?;
        let question = &ask.question;
        if question.digest()? != expected_question_digest {
            return Err(invalid("tradeoff reply does not bind the pending question"));
        }
        let latest = standing_verdict_in_txn(vault, txn, proposal)?.ok_or(invalid(
            "no scored tradeoff verdict stands for this proposal",
        ))?;
        let pending = open_pending_tradeoff_in_txn(vault, txn, proposal, ask.pending, latest, at)?;
        if pending.goal_revision != question.goal_revision {
            return Err(invalid("tradeoff goal changed before the pick"));
        }
        let previous = preferences_in_txn(vault, txn, &question.goal_id)?;
        let project = project_goal_in_txn(vault, txn, &question.goal_id)?;
        if project.as_ref().map(|join| join.project) != question.project {
            return Err(invalid("tradeoff goal changed before the pick"));
        }
        // The current holders of the reached roles, read in this txn, decide
        // (FIX 5967): the plan-time snapshot no longer authorizes.
        if !may_answer_in_txn(
            vault,
            txn,
            &ask,
            project.as_ref(),
            previous.as_ref(),
            &actor,
        )? {
            return Err(invalid(
                "tradeoff pick must come from a responsible role the ask has reached",
            ));
        }
        let mut preferences = match previous {
            Some(previous) => previous,
            None => SkillTradeoffPreferences {
                revision: vault.store.clock.entity_id()?,
                responsible: actor,
                rules: Vec::new(),
                learned: Vec::new(),
                jev_band: None,
            },
        };
        if let Some(join) = &project {
            propose_learned_preference_in_txn(vault, txn, join, question, choice, actor, at)?;
        }
        preferences.learned.push(TradeoffRule {
            gains: question.gains.clone(),
            losses: question.losses.clone(),
            choice,
        });
        tradeoff_capacity::advise_in_txn(vault, txn, &question.goal_id, &preferences);
        save(
            vault,
            txn,
            &key(PREFERENCES_PREFIX, &question.goal_id),
            &preferences,
        )?;
        let cycle = SkillEditCycle::new(pending.cycle.clone())?;
        let resolution = TradeoffResolution {
            pending: pending.id,
            owner: actor,
            authentication,
            evidence: expected_question_digest.to_owned(),
            rung,
        };
        if choice == TradeoffChoice::Approve
            && let Some(disposition) =
                approval_deferral_in_txn(vault, txn, &cycle, proposal, &pending.skill)?
        {
            // The deferred row keeps the person's approval, so the outcome of
            // the question they answered stays known.
            return deferred_approval::record_deferred_approval_in_txn(
                vault,
                txn,
                pending,
                resolution,
                disposition,
                &cycle,
                at,
            );
        }
        record_tradeoff_resolution_in_txn(vault, txn, pending, resolution, choice, &cycle, at)
    }
}
