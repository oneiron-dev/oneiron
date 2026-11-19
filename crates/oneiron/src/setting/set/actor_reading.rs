//! What a non-owner may do to a change's row: an agent's and a person's reading of the actor,
//! and the bounds the owner's rows put on it.

use oneiron_authority::authority::Permitted;
use oneiron_setting_contract::Order;

use super::super::pack::layer_default_in_txn;
use super::super::read::{key_line_grant_in_txn, load_in_txn, names_subject};
use super::super::{
    SetBy, Setter, SettingMode, SettingScope, set_line, widen_line, widen_line_at, widen_scope_line,
};
use super::{Change, is_slot, slot_chain};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// What `agent` may do to `change`'s row, and in which capacity: A0's reading of the actor, or
/// `None` when it may do nothing without asking. This is the one place the agent-holder rule
/// lives.
/// - With the owner's standing approval for the key or the row's scope
///   ([`standing_grant_in_txn`]): any move, so its widening lands without asking (owner
///   principle, 16 Nov 00:44: the ask is the default, and standing approval the owner's opt-out).
/// - A holder of the key (its own Grant line `settings.set:<key>`, a live `engine.controls`
///   Grant for the key's class, or its own row of a key its subject sets) makes no widening: its
///   loose move asks the user (AUTH-1 = A).
/// - The row's own subject, on a key whose rows meet, narrows only.
/// - Neither, or a pin: nothing. On a key that reads one row every agent keeps clear of the
///   owner's pin, and one without standing approval of the owner's rows too
///   ([`one_row_bounds_in_txn`]).
pub(super) fn agent_reading_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &Change<'_>,
    agent: EntityId,
) -> Result<Option<(Setter, Permitted)>> {
    let spec = change.spec;
    if change.key.mode == SettingMode::Pin {
        return Ok(None);
    }
    if let Some(grant) = standing_grant_in_txn(vault, txn, agent, change)? {
        return Ok(
            one_row_bounds_in_txn(vault, txn, change, StandingApproval::Given)?
                .then_some((Setter::Standing { grant }, Permitted::AnyMove)),
        );
    }
    let holder = match key_line_grant_in_txn(vault, txn, agent, &set_line(spec.name))? {
        Some(grant) => Some(Setter::KeyGrant { grant }),
        None => match spec.set_by {
            SetBy::Class(class) => vault
                .engine_controls_grant_in(txn, agent, class)?
                .map(|grant| Setter::Holder { grant }),
            SetBy::Subject if names_subject(&change.key.scope, agent) => Some(Setter::Subject),
            SetBy::Owner | SetBy::Subject => None,
        },
    };
    let reading = match holder {
        Some(setter) => (setter, Permitted::NoWidening),
        None if spec.reads_met() && names_subject(&change.key.scope, agent) => {
            (Setter::Subject, Permitted::NarrowingOnly)
        }
        None => return Ok(None),
    };
    Ok(one_row_bounds_in_txn(vault, txn, change, StandingApproval::Absent)?.then_some(reading))
}

/// The live owner Grant through which `agent` holds the owner's standing approval for
/// `change`'s row: the key's line ([`widen_line`]), the key's line at the row's scope
/// ([`widen_line_at`]), or the line of every key at that scope ([`widen_scope_line`]), the
/// first found in that order. Each is the vault-wide line rule of [`key_line_grant_in_txn`],
/// checked live in this write, so a revoked Grant ends it at once.
fn standing_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    change: &Change<'_>,
) -> Result<Option<EntityId>> {
    let name = change.spec.name;
    let scope = &change.key.scope;
    let lines = [
        Some(widen_line(name)),
        widen_line_at(name, scope),
        widen_scope_line(scope),
    ];
    for line in lines.into_iter().flatten() {
        if let Some(grant) = key_line_grant_in_txn(vault, txn, agent, &line)? {
            return Ok(Some(grant));
        }
    }
    Ok(None)
}

/// Whether a non-owner's change carries the owner's standing approval, for the bounds of a key
/// that reads one row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StandingApproval {
    /// No standing approval: the owner's rows and a learned key's cap bind it.
    Absent,
    /// The owner's standing approval: only the owner's pin binds it.
    Given,
}

/// What `person` may do to `change`'s row: only a value row at their own `Person` scope. On a
/// key set by its subject the row is their own choice, so they make any move on it (authority
/// pass 26, section 1.2); on another key whose rows meet they narrow it only; else nothing.
pub(super) fn person_reading_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &Change<'_>,
    person: EntityId,
) -> Result<Option<(Setter, Permitted)>> {
    if change.key.mode == SettingMode::Pin || change.key.scope != SettingScope::Person(person) {
        return Ok(None);
    }
    let permitted = match change.spec.set_by {
        SetBy::Subject => Permitted::AnyMove,
        SetBy::Owner | SetBy::Class(_) if change.spec.reads_met() => Permitted::NarrowingOnly,
        SetBy::Owner | SetBy::Class(_) => return Ok(None),
    };
    Ok(
        one_row_bounds_in_txn(vault, txn, change, StandingApproval::Absent)?
            .then_some((Setter::Subject, permitted)),
    )
}

/// Whether a non-owner's `change` stays clear of the owner's rows where the move rule cannot
/// judge it (DESIGN 1.2 step 4). On a key whose rows meet, always: a value row there only
/// narrows what it meets, and the rule judges every move. On a key that reads one row: no owner's
/// pin on the chain; and without the owner's standing approval, no row the owner set in the slot,
/// and on a learned key with an order a value inside the owner's nearest value row at that scope
/// or wider, else inside the default the vault accepted (stage 3's holder rule).
fn one_row_bounds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &Change<'_>,
    standing: StandingApproval,
) -> Result<bool> {
    let spec = change.spec;
    if spec.reads_met() {
        return Ok(true);
    }
    let chain = slot_chain(change)?;
    let item = change.key.item.as_deref();
    let loaded = load_in_txn(&vault.store, txn, spec, &chain, item)?;
    if loaded
        .iter()
        .any(|row| row.found.by_owner && row.found.mode == SettingMode::Pin)
    {
        return Ok(false);
    }
    if standing == StandingApproval::Given {
        return Ok(true);
    }
    if loaded
        .iter()
        .any(|row| row.found.by_owner && is_slot(row, change))
    {
        return Ok(false);
    }
    let Some(value) = change
        .value
        .filter(|_| spec.is_learned() && spec.kind.order() != Order::None)
    else {
        return Ok(true);
    };
    let cap = loaded
        .iter()
        .filter(|row| row.found.mode == SettingMode::Value && row.found.by_owner)
        .min_by_key(|row| (row.found.at, !row.found.item));
    Ok(match cap {
        Some(cap) => cap
            .found
            .value
            .as_ref()
            .and_then(|cap| spec.kind.no_wider(value, cap))
            .unwrap_or(false),
        None => spec
            .kind
            .no_wider(value, &layer_default_in_txn(&vault.store, txn, spec)?.value)
            .unwrap_or(false),
    })
}
