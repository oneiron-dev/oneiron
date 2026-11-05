//! Who an answer names, and the erase that forgets it (FIX 3520): an ask's
//! answerer, and the owner whose reason on that answer wrote a rule row. An
//! ask's principal, the responsible actor its route names and the holders it
//! was put to are forgotten with it (FIX 4588).

use super::asks::{ASKS, DecisionAsk};
use super::ladder::{AskConsent, AskRole};
use crate::vault_shape::ShapeGrantBound;
use crate::{EntityId, Result, Vault};

/// Makes a responsible role name no one when it named `actor`; whether it
/// did. Its project and rank stay, so the chain still walks that project's
/// boards up to the ask's ceiling; no other actor takes its place.
fn forget_role(role: &mut AskRole, actor: EntityId) -> bool {
    match role {
        AskRole::Responsible { actor: named, .. } => named.forget(actor),
        AskRole::Board { .. } | AskRole::Owner => false,
    }
}

/// Whether a consent attachment names `actor` as an action subject or an
/// audience member, including the effect's requirements and its draft bound.
fn consent_names_actor(consent: &AskConsent, actor: EntityId) -> bool {
    std::iter::once(&consent.bound)
        .chain(consent.effect.action.iter())
        .chain(consent.effect.disclosure.iter())
        .any(|bound| match bound {
            ShapeGrantBound::Action { actor: named, .. } => {
                EntityId::from_hex(named).is_ok_and(|named| named == actor)
            }
            ShapeGrantBound::Disclosure { audience, .. } => audience
                .iter()
                .any(|named| EntityId::from_hex(named).is_ok_and(|named| named == actor)),
        })
}

/// Takes `actor` out of `ask` (FIX 3520, 4588): its principal, the
/// responsible role it was routed to, is at and was answered as, the live
/// holders it was put to, and its answerer. A role left with no holder is
/// none, as an ask no role held. Whether `ask` named `actor`.
fn forget_in_ask(ask: &mut DecisionAsk, actor: EntityId) -> bool {
    let mut named = ask.principal.forget(actor);
    named |= forget_role(&mut ask.to.role, actor);
    let unheld = ask.role.as_mut().is_some_and(|at| {
        named |= forget_role(&mut at.role, actor);
        let held = at.holders.len();
        at.holders.retain(|holder| holder.actor != actor);
        named |= at.holders.len() != held;
        at.holders.is_empty()
    });
    if unheld {
        ask.role = None;
    }
    if let Some(answer) = &mut ask.answer {
        named |= answer.by.forget(actor);
        named |= forget_role(&mut answer.role, actor);
    }
    if ask
        .consent
        .as_ref()
        .is_some_and(|consent| consent_names_actor(consent, actor))
    {
        ask.consent = None;
        named = true;
    }
    named
}

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the decision rows.
use crate::deletion::names_no_actor;

/// Erasing `actor` from the asks (FIX 3520): each answer it gave keeps its
/// value, time, role, kind, reason and rule, and names no one. The ask stays
/// answered, since clearing the answer would reopen it. A consent attachment
/// naming the erased actor is cleared, not rewritten into a different bound;
/// the question, answer and withdrawal state stay intact. A use of the answer
/// still to run takes a live answerer: the e-sign hold refuses an erased
/// one. An ask for it, or routed or put to it, keeps its question, evidence,
/// times and answer and names no one (FIX 4588): an ask for no one rebuilds
/// no request, so a late answer to it is refused, and one routed to no one
/// climbs past that role. One-way, in the erase's own transaction. An id
/// whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or an ask row that cannot be read.
pub(crate) fn erase_ask_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut asks = Vec::new();
    for (seq, mut ask) in ASKS.scan(&vault.store, wtxn)? {
        if forget_in_ask(&mut ask, *actor) {
            asks.push((seq, ask));
        }
    }
    for (seq, ask) in asks {
        ASKS.put(&vault.store, wtxn, &seq, &ask)?;
    }
    Ok(())
}

pub use crate::model_decision::AnswerActor;
