//! Authenticated A/B picks and upward role escalation; no model call runs here.
use super::*;

/// The responsible role's answer to the pending A/B question. The digest
/// must name the exact question the person saw, so an older reply cannot
/// answer a replacement question on the same proposal. The pick is learned as
/// a preference for the axis signature and settles the pending tradeoff
/// through the decision door in the same transaction; no model callback can
/// write it or impersonate the person. An approval under a spent cycle cap is
/// still learned and defers the proposal: a later cycle re-rules it through
/// the new preference.
/// # Errors
/// No pending ask, a digest for another question, a person other than the
/// responsible one, a question stale against the goal, bodies, tier or
/// evidence, no capacity to learn, or storage errors. An error writes nothing.
pub fn settle_skill_tradeoff_ask(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_person_in_txn(vault, txn)?;
        settle_in_txn(
            vault,
            txn,
            actor,
            &format!("{:?}", owner.decision_id()),
            proposal,
            expected_question_digest,
            choice,
            at,
        )
    })
}

/// A role holder may be an agent or a person. Only the host's authority
/// service authenticates it; a typed model answer is never a credential.
pub fn settle_skill_tradeoff_role_ask(
    vault: &Vault,
    authentication: &str,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    vault.with_write_txn_grouped(|txn| {
        let authenticated = roles::service()?.authenticate_in_txn(vault, txn, authentication)?;
        settle_in_txn(
            vault,
            txn,
            authenticated.actor,
            &authenticated.receipt,
            proposal,
            expected_question_digest,
            choice,
            at,
        )
    })
}

fn settle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    authentication: &str,
    proposal: &EntityId,
    expected_question_digest: &str,
    choice: TradeoffChoice,
    at: u64,
) -> Result<HeldOutVerdict> {
    if authentication.trim().is_empty() {
        return Err(invalid("tradeoff pick requires an authority receipt"));
    }
    let ask: SkillTradeoffAsk = load(vault, txn, &key(ASK_PREFIX, proposal))?
        .ok_or(invalid("no pending skill tradeoff ask"))?;
    let question = &ask.question;
    if ask.digest()? != expected_question_digest {
        return Err(invalid("tradeoff reply does not bind the pending question"));
    }
    if roles::current_actor_in_txn(vault, txn, &ask)? != actor {
        return Err(invalid("tradeoff pick must come from the responsible role"));
    }
    let latest = standing_verdict_in_txn(vault, txn, proposal)?.ok_or(invalid(
        "no scored tradeoff verdict stands for this proposal",
    ))?;
    let pending = open_pending_tradeoff_in_txn(vault, txn, proposal, ask.pending, latest, at)?;
    let mut preferences = preferences_in_txn(vault, txn, &question.goal_id)?
        .filter(|preferences| preferences.responsible == question.responsible)
        .ok_or(invalid("tradeoff goal changed before the pick"))?;
    if pending.goal_revision != question.goal_revision {
        return Err(invalid("tradeoff goal changed before the pick"));
    }
    if preferences.learning_full(skill_tradeoff_limits_in_txn(&vault.store, txn, &actor)?) {
        return Err(invalid(CAPACITY_EXHAUSTED));
    }
    preferences.learned.push(TradeoffRule {
        gains: question.gains.clone(),
        losses: question.losses.clone(),
        choice,
    });
    save(
        vault,
        txn,
        &key(PREFERENCES_PREFIX, &question.goal_id),
        &preferences,
    )?;
    let cycle = SkillEditCycle::new(pending.cycle.clone())?;
    if choice == TradeoffChoice::Approve
        && accepted_in_cycle_in_txn(vault, txn, &cycle, proposal)? >= cycle_cap_in_txn(vault, txn)?
    {
        let deferred = HeldOutVerdict {
            id: vault.store.clock.entity_id()?,
            disposition: SkillEditDisposition::DeferredCycleCap,
            accepted: false,
            goal_revision: goal_definition_in_txn(vault, txn, &pending.skill)?.revision,
            at,
            ..pending
        };
        record_verdict_in_txn(vault, txn, &deferred)?;
        clear_ask_in_txn(vault, txn, proposal)?;
        return Ok(deferred);
    }
    let resolution = TradeoffResolution {
        pending: pending.id,
        owner: actor,
        authentication: authentication.to_owned(),
        evidence: expected_question_digest.to_owned(),
        rung: TradeoffRung::Role,
    };
    record_tradeoff_resolution_in_txn(vault, txn, pending, resolution, choice, &cycle, at)
}

/// Ask the next authorised role without learning a preference or admitting
/// anything. At the owner role the chain stops; it never wraps or invents a holder.
pub fn escalate_skill_tradeoff_ask(
    vault: &Vault,
    authentication: &str,
    proposal: &EntityId,
    expected_question_digest: &str,
) -> Result<SkillTradeoffAsk> {
    vault.with_write_txn_grouped(|txn| {
        let authenticated = roles::service()?.authenticate_in_txn(vault, txn, authentication)?;
        let actor = authenticated.actor;
        let pending = standing_verdict_in_txn(vault, txn, proposal)?
            .ok_or(invalid("no pending tradeoff verdict"))?;
        let (mut ask, _) =
            bound_ask_in_txn(vault, txn, &pending)?.ok_or(invalid("no current tradeoff ask"))?;
        if roles::current_actor_in_txn(vault, txn, &ask)? != actor
            || ask.digest()? != expected_question_digest
        {
            return Err(invalid("role escalation does not bind the current ask"));
        }
        if ask.role_index + 1 >= ask.roles.len() {
            return Err(invalid("tradeoff ask is already at the vault owner role"));
        }
        ask.role_index += 1;
        save(vault, txn, &key(ASK_PREFIX, proposal), &ask)?;
        Ok(ask)
    })
}

/// The authenticated goal author assigns the responsible role. Its chain is
/// resolved now and again at settlement; changing it invalidates old asks.
pub fn set_skill_tradeoff_responsible_role(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    skill: &EntityId,
    responsible: EntityId,
) -> Result<String> {
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        roles::chain_in_txn(vault, txn, responsible)?;
        let goal = goal_definition_in_txn(vault, txn, skill)?;
        let mut preferences = preferences_in_txn(vault, txn, &goal.goal_id)?.ok_or(invalid(
            "configure tradeoff preferences before assigning a role",
        ))?;
        preferences.responsible = responsible;
        preferences.revision = vault.store.clock.entity_id()?;
        save(
            vault,
            txn,
            &key(PREFERENCES_PREFIX, &goal.goal_id),
            &preferences,
        )?;
        Ok(goal_definition_in_txn(vault, txn, skill)?.revision)
    })
}
