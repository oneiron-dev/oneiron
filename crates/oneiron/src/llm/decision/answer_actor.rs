//! Who an answer names, and the erase that forgets it (FIX 3520): an ask's
//! answerer, and the owner whose reason on that answer wrote a rule row. An
//! ask's principal, the responsible actor its route names and the holders it
//! was put to are forgotten with it (FIX 4588).

use super::asks::{ASKS, DecisionAsk};
use super::ladder::AskRole;
use super::rules::RULES;
use super::types::invalid;
use crate::{EntityId, Result, Vault};

/// The actor an answer names (an ask's answerer, a rule row's writer, an
/// ask's principal or responsible actor), or no one once that actor was
/// erased (FIX 3520, 4588). It reads and writes as the actor's hex id, or as
/// [`crate::receipt::ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerActor {
    Actor(EntityId),
    Erased,
}

impl schemars::JsonSchema for AnswerActor {
    fn schema_name() -> String {
        "AnswerActor".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

impl AnswerActor {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// The actor, while it is not erased.
    #[must_use]
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// The actor, refused once it was erased: no live request is rebuilt
    /// for no one.
    pub(super) fn live(self) -> Result<EntityId> {
        self.id()
            .ok_or_else(|| invalid("the decision ask names an erased actor"))
    }

    /// Makes this no one when it is `actor`; whether it was.
    fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

/// Makes a responsible role name no one when it named `actor`; whether it
/// did. Its project and rank stay, so the chain still walks that project's
/// boards up to the ask's ceiling; no other actor takes its place.
fn forget_role(role: &mut AskRole, actor: EntityId) -> bool {
    match role {
        AskRole::Responsible { actor: named, .. } => named.forget(actor),
        AskRole::Board { .. } | AskRole::Owner => false,
    }
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
    named
}

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the decision rows.
use crate::deletion::names_no_actor;

/// Erasing `actor` from the asks (FIX 3520): each answer it gave keeps its
/// value, time, role, kind, reason and rule, and names no one. The ask stays
/// answered, since clearing the answer would reopen it. A use of the answer
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

/// Erasing `actor` from the rule rows (FIX 3520): every revision it wrote
/// keeps its question, evidence, answer, reason and times, and names no one.
/// A standing row still answers its question, as a row is advice and never a
/// grant; the owner's revoke still stops it. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a rule row that cannot be read.
pub(crate) fn erase_rule_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut rows = Vec::new();
    for (key, mut row) in RULES.scan(&vault.store, wtxn)? {
        if row.by.forget(*actor) {
            rows.push((key, row));
        }
    }
    for (key, row) in rows {
        RULES.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}
