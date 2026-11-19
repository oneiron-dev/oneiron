//! An agent's change that asks: the check-in it opens, and the spend of the yes that answers it.

use oneiron_authority::authority::Permitted;
use oneiron_contracts::fingerprint::{Fingerprinter, purposes};

use super::super::SettingScope;
use super::actor_reading::person_reading_in_txn;
use super::{Change, SET_VERB, SetSettingOutcome, Spend};
use crate::Vault;
use crate::check_in::{
    CheckInMode, CheckInScope, HolderAnswer, NoAgentVerdict, OpenPendingCheckIn, PendingState,
    VerifiedChain, WaitReason, consume_pending_check_in_in_txn, open_keyed_pending_check_in_in_txn,
    pending_check_in_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The check-in scope of a row: its world or project, else the whole vault.
fn check_in_scope(scope: &SettingScope) -> CheckInScope {
    match scope {
        SettingScope::World(world) => CheckInScope {
            world_ref: Some(world.to_hex()),
            project_ref: None,
        },
        SettingScope::Project(project) => CheckInScope {
            world_ref: None,
            project_ref: Some(project.to_hex()),
        },
        _ => CheckInScope::default(),
    }
}

/// The digest a proposal binds and its yes names (DESIGN 1.5, "A proposal binds what it will
/// write"): the row's key, the value it would hold, a seed's weight, and the stored bytes of the
/// row it replaces, so an approval spends only over the row it was asked over. A fingerprint
/// under [`purposes::setting::SET_EFFECT_V2`]; each optional part writes its presence first.
fn effect_digest(change: &Change<'_>, replaced: Option<&[u8]>) -> [u8; 32] {
    let mut digest = Fingerprinter::new(purposes::setting::SET_EFFECT_V2);
    digest.part(&change.key.encode());
    match change.value {
        None => digest.flag(false),
        Some(value) => digest.flag(true).part(&value.0),
    };
    match change.weight_runs {
        None => digest.flag(false),
        Some(weight) => digest.flag(true).u64(weight.to_bits()),
    };
    match replaced {
        None => digest.flag(false),
        Some(bytes) => digest.flag(true).part(bytes),
    };
    digest.finish().into_bytes()
}

/// Opens, or finds, the check-in `agent`'s change waits on, under its own live owner Grant that
/// lists `vault.settings.set`.
pub(super) fn open_request_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &Change<'_>,
    replaced: Option<&[u8]>,
    agent: EntityId,
    now: u64,
) -> Result<SetSettingOutcome> {
    let grant = crate::authority::principal_standing_in_txn(
        vault,
        txn,
        agent,
        EdgeActorClass::Agent,
        SET_VERB,
    )?
    .and_then(|standing| standing.grant)
    .ok_or_else(|| {
        Error::InvalidConfig(format!(
            "an agent asks for a setting change under its own live owner Grant that lists {SET_VERB}"
        ))
    })?;
    let (row, _) = open_keyed_pending_check_in_in_txn(
        vault,
        txn,
        OpenPendingCheckIn {
            asker: agent,
            grant_ref: grant.to_hex(),
            verb: SET_VERB.to_owned(),
            act: change.spec.act,
            scope: check_in_scope(&change.key.scope),
            effect_digest: effect_digest(change, replaced),
            mode: CheckInMode::AlwaysAsk,
            reason: WaitReason::AlwaysAsk,
            asker_wait_secs: None,
            until: None,
            undo_plan: None,
            delay_window: None,
        },
        None,
        &VerifiedChain::new(&NoAgentVerdict),
        now,
    )?;
    super::super::ask::keep_ask_in_txn(vault, txn, &row.id, agent, change.key, change.value)?;
    Ok(SetSettingOutcome::Pending {
        check_in: row.id.to_hex(),
    })
}

/// Spends the approved check-in `id` for `agent`'s change, in the door's writer: the ask must be
/// this agent's for this change over the row it replaces, and its yes must come from someone who
/// could make the change themselves ([`approver_may_make_in_txn`]).
pub(super) fn spend_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spend: &Spend<'_, '_>,
    agent: EntityId,
    id: &EntityId,
    now: u64,
) -> Result<()> {
    let change = spend.change;
    let row = pending_check_in_in_txn(&vault.store, txn, id)?.ok_or(Error::EntityNotFound)?;
    if row.asker != agent
        || row.verb != SET_VERB
        || row.act != change.spec.act
        || row.scope != check_in_scope(&change.key.scope)
    {
        return Err(Error::InvalidConfig(
            "the check-in is not this agent's ask for this setting change".into(),
        ));
    }
    if row.eligible_basis().is_some() && !approver_may_make_in_txn(vault, txn, &row.state, spend)? {
        return Err(Error::InvalidConfig(format!(
            "the yes on this check-in came from someone who cannot make this change of `{}`: an \
             agent's change spends the yes of the vault's owner, or of a live person who may make \
             it on their own row, read now",
            change.spec.name
        )));
    }
    consume_pending_check_in_in_txn(vault, txn, id, &effect_digest(change, spend.replaced), now)?;
    super::super::ask::drop_ask_in_txn(vault, txn, id)
}

/// Whether the yes in `state` came from someone who could make `spend`'s change themselves, read
/// live in this write. ARCH-0082 `#ladder`: a holder answers only what it could do itself without
/// asking; DESIGN 1.2 step 3: "when a holder answers, the same door runs under the holder's
/// proof". The ladder rechecks only a holder's grant and own check-in for the verb, and the ask
/// keeps only the effect's digest, so the setting door's own rule is read here: a live owner of
/// the vault now makes any change; another live person makes what their own reading admits
/// ([`person_reading_in_txn`]), inside the owner's row as every non-owner is. Any other yes does
/// not spend: a person who is not, or is no longer, an owner on an owner-set key, a pin or the
/// owner's row; a yes whose answerer was erased; and any eligibility that is no one's yes.
fn approver_may_make_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    state: &PendingState,
    spend: &Spend<'_, '_>,
) -> Result<bool> {
    let PendingState::Answered {
        answer: HolderAnswer::Approve,
        by: Some(by),
        ..
    } = state
    else {
        return Ok(false);
    };
    if crate::policy_model::owners_in_txn(vault, txn)?.contains(by) {
        return Ok(true);
    }
    if !crate::consent::person_is_live_in_txn(vault, txn, by)? {
        return Ok(false);
    }
    Ok(
        person_reading_in_txn(vault, txn, spend.change, *by)?.is_some_and(|(_, permitted)| {
            let permitted = if spend.over_owners_row {
                permitted.limited_by(Permitted::NoWidening)
            } else {
                permitted
            };
            permitted.admit(spend.moved).is_some()
        }),
    )
}
