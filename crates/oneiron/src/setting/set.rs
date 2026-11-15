//! The one door that changes a setting row: [`Vault::set_setting`].

use serde::{Deserialize, Serialize};

use oneiron_authority::authority::{ActSurface, Direction, Permitted};
use oneiron_setting_contract::{ChangeDirection, FoundRow, Order, Quorum, RowKey};

use super::change::record_change_in_txn;
use super::learned::{checked_weight, fits_in_txn};
use super::pack::layer_default_in_txn;
use super::read::{
    Loaded, StoredRow, in_force_of, key_line_grant_in_txn, load_in_txn, names_subject, table_of,
};
use super::signed_act::sign_owner_change_in_txn;
use super::{
    EncodedValue, Restore, SetBy, Setter, SettingChange, SettingMode, SettingScope, SettingSpec,
    set_line, spec_named, widen_line, widen_line_at, widen_scope_line,
};
use crate::Vault;
use crate::batch::secret_scan::admit_typed;
use crate::check_in::{
    CheckInMode, CheckInScope, NoAgentVerdict, OpenPendingCheckIn, VerifiedChain, WaitReason,
    consume_pending_check_in_in_txn, open_keyed_pending_check_in_in_txn, pending_check_in_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The verb whose act a waiting change is.
pub(crate) const SET_VERB: &str = "vault.settings.set";

/// The longest reason a change may carry, in bytes.
const WHY_MAX_BYTES: usize = 1_000;

/// Who asks for a change.
#[derive(Debug, Clone, Copy)]
pub enum SettingCaller<'a> {
    /// The owner, by a proof the door revalidates in its write.
    Owner(&'a AuthenticatedOwner),
    /// An agent whose binding the caller verified.
    Agent(EntityId),
    /// A live person on their own row of a key set by its subject, by a proof the door
    /// revalidates in its write as a person's (owner of the vault or not).
    Person(&'a AuthenticatedOwner),
    /// The engine's own path; only this crate builds one.
    Engine(EngineSetting),
}

/// The engine's own change. Only this crate builds one, so no host and no verb can name it. It
/// writes a value row with no check-in and no holder's bound, as the engine's direct writes did,
/// and never a pin.
#[derive(Debug, Clone, Copy)]
pub struct EngineSetting {
    ask: Option<EntityId>,
}

impl EngineSetting {
    /// The engine applies the owner's answer to the ask `check_in` (a model fallback chosen in a
    /// question, DESIGN 1.2 step 3).
    #[must_use]
    #[cfg_attr(
        not(all(oneiron_test_support, feature = "test-support")),
        allow(dead_code)
    )]
    pub(crate) const fn answer(check_in: EntityId) -> Self {
        Self {
            ask: Some(check_in),
        }
    }

    /// An engine path's own change, such as a retired model pack's successor or the residence
    /// switch; the change's reason names the path.
    #[must_use]
    #[cfg_attr(
        not(all(oneiron_test_support, feature = "test-support")),
        allow(dead_code)
    )]
    pub(crate) const fn own() -> Self {
        Self { ask: None }
    }
}

/// One change a caller asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct SetSetting {
    pub key: String,
    pub item: Option<String>,
    pub scope: SettingScope,
    pub mode: SettingMode,
    /// The new value as JSON; `None` clears the row. For a key whose value is an `Option`,
    /// `Some(Value::Null)` stores `None` (the verb reads a `null` value as a clear).
    pub value: Option<serde_json::Value>,
    /// The row's revision the caller saw; the change is refused when the row has moved since.
    pub expected_revision: Option<u64>,
    pub why: Option<String>,
    /// The settled check-in this change waited on, to spend.
    pub check_in_ref: Option<EntityId>,
    /// A learned key's seed: its weight in runs, finite and above zero (ARCH-0003
    /// `#learning-settings`). Only a value row of a learned key carries one, and it must.
    pub weight_runs: Option<f64>,
    /// Where the owner said so (DESIGN 1.2 "The change stream"): an owner's applied change that
    /// names it is signed as one `PolicySettingSet` in the same write, last and best effort
    /// (stage 7a-1). Only the owner's change names one. The host names it from where the
    /// owner's request reached it, never from the request's input.
    pub surface: Option<ActSurface>,
}

impl SetSetting {
    /// A value row of `key` at the vault scope, with no item, expected revision, reason or
    /// check-in: the common change of one value.
    #[must_use]
    pub fn vault_value(key: &str, value: serde_json::Value) -> Self {
        Self {
            key: key.to_owned(),
            item: None,
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(value),
            expected_revision: None,
            why: None,
            check_in_ref: None,
            weight_runs: None,
            surface: None,
        }
    }
}

/// What a change answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SetSettingOutcome {
    /// The row is as asked.
    Applied {
        /// The change's sequence in the stream; none when the row already held the value and
        /// nothing was written.
        sequence: Option<u64>,
        /// The row's revision now; 0 when no row stands.
        revision: u64,
        /// The row's value now, as JSON; null when it was cleared.
        value: serde_json::Value,
    },
    /// The change waits on this pending check-in (32 hex). Once the holders approve it, the same
    /// change again with `check_in_ref` applies it.
    Pending { check_in: String },
}

impl Vault {
    /// Changes one setting row in one write: the catalogue, the side-row wall on the value, the
    /// value's check, the move rule (DESIGN 1.5, stage 6.0) judged live in this write, the change
    /// row with the move's direction, and the key's hook. Once the write commits, an applied
    /// change runs the key's `after_commit`.
    ///
    /// The move rule. The key's order gives the move's direction against the rows this write
    /// sees: on a key whose rows meet, a value row below the vault is judged against the row it
    /// replaces (an added row narrows, a clear widens); every other slot on what its readers read
    /// before and after; a key with no order has no safe move, and a neutral key's moves guard
    /// nothing. The caller's capacity says what it may do (the authority rule's reading):
    /// - the owner, any move, a pin included; the engine, any move of a value row, never a pin;
    /// - an agent holder of the key (its own Grant line `settings.set:<key>`, a live
    ///   `engine.controls` grant for its class, or its own row of a key its subject sets): no
    ///   widening, so it tightens at once and its loosening asks the user (AUTH-1 = A);
    /// - an agent with the owner's standing approval for the key or the row's scope (its own
    ///   Grant line [`super::widen_line`], [`super::widen_line_at`] or
    ///   [`super::widen_scope_line`]): any move of a value row, so its widening lands without
    ///   asking, receipted [`Setter::Standing`] (owner principle, 16 Nov 00:44);
    /// - a person, on their own row of a key their subject sets, any move; on another key whose
    ///   rows meet, a narrowing of their own row;
    /// - an agent that is the subject of a row of a key whose rows meet: a narrowing of that row.
    ///
    /// Over a row the owner (or the engine) set, a non-owner other than one with standing
    /// approval makes no widening: it tightens the owner's row and asks to loosen it. On a key
    /// that reads one row a non-owner also stays clear of the owner's pin and, without standing
    /// approval, of the owner's row, and a learned key's holder keeps inside the owner's cap. A
    /// move the rule does not admit waits for an agent on a check-in under its own live owner
    /// Grant that lists
    /// `vault.settings.set`: the door opens it and answers [`SetSettingOutcome::Pending`]; the
    /// same change again, naming the approved check-in, applies once over the row it was asked
    /// over. A person's is refused.
    ///
    /// The value passes the side-row wall before it is checked and stored, as an authored row
    /// does: a secret goes to custody and the row keeps its handle; any other hit refuses the
    /// change. A value equal to the row's writes nothing.
    ///
    /// An owner's change that names its act surface is signed: last in the write, after the key's
    /// hook, one `PolicySettingSet` on the key's target, best effort, and the change row names the
    /// entry (stage 7a-1, [`super::signed_act`]).
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an unknown key, an item or scope the key does not admit, a value of
    /// another shape or one its check refuses, a moved row, a reason over 1,000 bytes, a
    /// check-in that is not this change's or that was asked over another row, an agent with no
    /// Grant listing the verb, a person's move the rule does not admit, an engine pin, a loose
    /// move of a key whose quorum is all, or an act surface named by a caller other than the
    /// owner; an owner or person proof that no longer holds; the side-row wall's refusal; storage
    /// errors.
    pub fn set_setting(
        &self,
        caller: SettingCaller<'_>,
        request: SetSetting,
    ) -> Result<SetSettingOutcome> {
        self.with_write_txn_grouped_after_commit(
            |txn| self.set_setting_in_txn(txn, caller, &request),
            |outcome| {
                run_after_commit(self, &[(&request, &outcome)]);
                Ok(outcome)
            },
        )
    }

    /// [`Self::set_setting`] in the caller's write: the same wall, checks, power, change row and
    /// hook, so the change commits with the caller's other writes or not at all. Several changes
    /// in one write take consecutive sequences. A [`SetSettingOutcome::Pending`] answer opened
    /// its check-in in this write too; a caller whose other writes need the change applied fails
    /// its write on it. The caller runs [`run_after_commit`] over its changes once its write has
    /// committed.
    ///
    /// # Errors
    ///
    /// As [`Self::set_setting`].
    pub(crate) fn set_setting_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        caller: SettingCaller<'_>,
        request: &SetSetting,
    ) -> Result<SetSettingOutcome> {
        let spec = spec_named(&request.key)?;
        spec.check_item(request.item.as_deref())?;
        if !spec.admits_scope(request.scope.kind()) {
            return Err(Error::InvalidConfig(format!(
                "`{}` has no rows at a {} scope",
                spec.name,
                request.scope.kind().as_str()
            )));
        }
        if request
            .why
            .as_ref()
            .is_some_and(|why| why.len() > WHY_MAX_BYTES)
        {
            return Err(Error::InvalidConfig(
                "a setting change's reason is at most 1,000 bytes".into(),
            ));
        }
        let key = RowKey {
            name: spec.name.to_owned(),
            item: request.item.clone(),
            mode: request.mode,
            scope: request.scope.clone(),
        };
        let value = match request.value.clone() {
            Some(mut json) => {
                // The side-row wall reads the value before it is encoded (SETTING-ROWS-SIDE-ROW-
                // WALL = A): a secret goes to custody and the value keeps its handle.
                admit_typed(
                    self,
                    txn,
                    (wall_place(spec), key.encode().as_slice()),
                    &mut json,
                )?;
                Some(spec.kind.from_json(json)?)
            }
            None => None,
        };
        let change = Change {
            spec,
            key: &key,
            value: value.as_ref(),
            weight_runs: checked_weight(spec, request)?,
        };
        set_in_txn(self, txn, &change, caller, request)
    }
}

/// Where the side-row wall says it found a secret in a setting value (OF-067).
const fn wall_place(spec: &SettingSpec) -> &'static str {
    match spec.restore {
        Restore::Live => "side:SETTING",
        Restore::Content => "side:SETTING_CONTENT",
    }
}

/// Runs the `after_commit` of each key whose change applied with a sequence, once per change,
/// after the write that made them committed. [`Vault::set_setting`] runs it itself; a caller of
/// [`Vault::set_setting_in_txn`] runs it over its changes once its own write has committed. A
/// change that wrote nothing (an equal value) or waits on a check-in runs nothing.
pub(crate) fn run_after_commit(vault: &Vault, changes: &[(&SetSetting, &SetSettingOutcome)]) {
    for (request, outcome) in changes {
        if !matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ) {
            continue;
        }
        if let Some(after_commit) = spec_named(&request.key)
            .ok()
            .and_then(|spec| spec.after_commit)
        {
            after_commit(vault);
        }
    }
}

/// One asked change, checked against the catalogue.
struct Change<'a> {
    spec: &'static SettingSpec,
    key: &'a RowKey,
    value: Option<&'a EncodedValue>,
    /// A learned key's seed weight ([`checked_weight`]).
    weight_runs: Option<f64>,
}

fn set_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &Change<'_>,
    caller: SettingCaller<'_>,
    request: &SetSetting,
) -> Result<SetSettingOutcome> {
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    if request.surface.is_some() && !matches!(caller, SettingCaller::Owner(_)) {
        return Err(Error::InvalidConfig(
            "only the owner's change names where the owner said so: an act surface is the owner's"
                .into(),
        ));
    }
    if change.key.mode == SettingMode::Carried && change.value.is_some() {
        return Err(Error::InvalidConfig(
            "only a move writes a carried row; a set may only clear one".into(),
        ));
    }
    if change.key.mode == SettingMode::Pin && matches!(caller, SettingCaller::Engine(_)) {
        return Err(Error::InvalidConfig(
            "the engine sets a value row, never a pin: a pin is the owner's".into(),
        ));
    }
    // Who asks, and what it may do: A0's reading of the actor, its proof checked in this write.
    let (by, reading) = match caller {
        SettingCaller::Owner(owner) => (
            Some(owner.revalidate_in_txn(vault, txn)?),
            Some((Setter::Owner, Permitted::AnyMove)),
        ),
        SettingCaller::Engine(engine) => (
            None,
            Some((Setter::Engine { ask: engine.ask }, Permitted::AnyMove)),
        ),
        SettingCaller::Person(person) => {
            let person = person.revalidate_person_in_txn(vault, txn)?;
            (
                Some(person),
                person_reading_in_txn(vault, txn, change, person)?,
            )
        }
        SettingCaller::Agent(agent) => (
            Some(agent),
            agent_reading_in_txn(vault, txn, change, agent)?,
        ),
    };
    let table = table_of(change.spec);
    let key_bytes = change.key.encode();
    let prior_bytes = table.get_bytes(&vault.store, txn, &key_bytes)?;
    let prior = prior_bytes
        .as_deref()
        .map(|bytes| rmp_serde::from_slice::<StoredRow>(bytes).ok());
    let revision = prior
        .as_ref()
        .map_or(0, |row| row.as_ref().map_or(0, |row| row.change));
    if let Some(expected) = request.expected_revision
        && expected != revision
    {
        return Err(Error::InvalidConfig(format!(
            "the row's revision is {revision}, not {expected}: read it again"
        )));
    }
    // A row that does not decode is never "the same value": a clear removes it, a set replaces it.
    let readable = !matches!(prior, Some(None));
    let prior_row = prior.flatten();
    let prior_row_by_owner = prior_row.as_ref().is_some_and(StoredRow::by_owner);
    let prior_weight = prior_row.as_ref().and_then(|row| row.weight_runs);
    let prior_value = prior_row.map(|row| row.value);
    let unchanged =
        readable && prior_value.as_ref() == change.value && prior_weight == change.weight_runs;
    let by_owner = matches!(caller, SettingCaller::Owner(_) | SettingCaller::Engine(_));
    // Which way the change moves its row, against the rows this write sees (A3: the key's
    // comparator gives the direction). A change that leaves the row as it is moves nothing.
    let direction = if unchanged {
        ChangeDirection::Tighter
    } else if readable {
        direction_in_txn(vault, txn, change, prior_value.as_ref(), by_owner)?
    } else {
        ChangeDirection::Unordered
    };
    // Over a row the owner set, a non-owner makes no widening (DESIGN 1.2 step 4: its value
    // stays inside the owner's row): it tightens the owner's row, and asks to loosen it. The
    // owner's standing approval for the key or the scope is the owner's yes to that widening.
    let owners_row = prior_row_by_owner && !by_owner;
    let reading = reading.map(|(setter, permitted)| {
        if owners_row && !matches!(setter, Setter::Standing { .. }) {
            (setter, permitted.limited_by(Permitted::NoWidening))
        } else {
            (setter, permitted)
        }
    });
    let moved = authority_direction(direction);
    let admitted = reading
        .and_then(|(setter, permitted)| permitted.admit(moved).map(|admitted| (setter, admitted)));
    let setter = match (admitted, caller) {
        (Some((setter, _)), _) => setter,
        (None, SettingCaller::Agent(agent)) => match request.check_in_ref {
            Some(check_in) => {
                spend_in_txn(
                    vault,
                    txn,
                    change,
                    prior_bytes.as_deref(),
                    agent,
                    &check_in,
                    now,
                )?;
                Setter::Approved { check_in }
            }
            None => {
                return open_request_in_txn(vault, txn, change, prior_bytes.as_deref(), agent, now);
            }
        },
        (None, _) => {
            return Err(Error::InvalidConfig(format!(
                "a person sets only a value row about themselves: on a key set by its subject, \
                 any value, and on a key whose rows meet, only one that narrows; never under the \
                 owner's pin or over the owner's row on a key that reads one row: `{}`",
                change.spec.name
            )));
        }
    };
    let json = |value: Option<&EncodedValue>| {
        value
            .and_then(|value| change.spec.kind.to_json(value))
            .unwrap_or(serde_json::Value::Null)
    };
    if unchanged {
        return Ok(SetSettingOutcome::Applied {
            sequence: None,
            revision,
            value: json(change.value),
        });
    }
    if change.spec.quorum == Quorum::All && moved == Direction::Widens {
        return Err(Error::InvalidConfig(format!(
            "`{}` takes the yes of every holder for a loose move, and that count lands with the \
             Grant of a person's setting class (stage 6d-1)",
            change.spec.name
        )));
    }
    let recorded = record_change_in_txn(
        &vault.store,
        txn,
        SettingChange {
            id: vault.store.clock.entity_id()?,
            sequence: 0,
            key: change.spec.name.to_owned(),
            item: change.key.item.clone(),
            scope: change.key.scope.clone(),
            mode: change.key.mode,
            by,
            setter,
            prior: prior_value,
            value: change.value.cloned(),
            at: now,
            why: request.why.clone(),
            weight_runs: change.weight_runs,
            direction: Some(direction),
            surface: request.surface,
            signed: None,
        },
    )?;
    let revision = match change.value {
        Some(value) => {
            let row = StoredRow {
                value: value.clone(),
                by,
                setter,
                set_at: now,
                change: recorded.sequence,
                weight_runs: change.weight_runs,
            };
            table.put(&vault.store, txn, &key_bytes, &row)?;
            recorded.sequence
        }
        None => {
            table.delete(&vault.store, txn, &key_bytes)?;
            0
        }
    };
    if let Some(on_change) = change.spec.on_change {
        on_change(vault, txn, &recorded)?;
    }
    // The signed record goes last, best effort, after every mandatory write (FIX 4624).
    if let (SettingCaller::Owner(_), Some(owner), Some(surface)) = (caller, by, request.surface) {
        sign_owner_change_in_txn(vault, txn, change.spec, owner, surface, &recorded);
    }
    Ok(SetSettingOutcome::Applied {
        sequence: Some(recorded.sequence),
        revision,
        value: json(change.value),
    })
}

/// The authority rule's direction of a change: a tighter move narrows, a neutral key's move is
/// neutral, and a looser move or "cannot tell" widens.
const fn authority_direction(direction: ChangeDirection) -> Direction {
    match direction {
        ChangeDirection::Tighter => Direction::Narrows,
        ChangeDirection::Neutral => Direction::Neutral,
        ChangeDirection::Looser | ChangeDirection::Unordered => Direction::Widens,
    }
}

/// Which way `change` moves its row (DESIGN 1.5, "The rule"), against the rows `txn` sees;
/// `prior` is the slot's readable value before it, and `by_owner` whether the row the change
/// leaves counts as the owner's.
/// - A neutral key's every move is neutral; a key with no order has no safe move.
/// - On a key whose rows meet, a value row below the vault, or a row a move carried, is a bound,
///   judged against the row it replaces: an added row only narrows, a changed one is compared
///   with its prior value, and a clear drops a bound.
/// - Any other slot (a vault value row, a pin, every row of a key that reads one row) is judged on
///   what its readers read: the walk at the slot's scope before the change against the walk with
///   the slot as the change leaves it.
fn direction_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &Change<'_>,
    prior: Option<&EncodedValue>,
    by_owner: bool,
) -> Result<ChangeDirection> {
    let spec = change.spec;
    match spec.kind.order() {
        Order::Neutral => return Ok(ChangeDirection::Neutral),
        Order::None => return Ok(ChangeDirection::Unordered),
        _ => {}
    }
    let no_wider = |a: &EncodedValue, b: &EncodedValue| spec.kind.no_wider(a, b).unwrap_or(false);
    if spec.reads_met()
        && matches!(change.key.mode, SettingMode::Value | SettingMode::Carried)
        && change.key.scope != SettingScope::Vault
    {
        return Ok(match (change.value, prior) {
            (Some(_), None) => ChangeDirection::Tighter,
            (Some(left), Some(replaced)) => ChangeDirection::of(left, replaced, no_wider),
            (None, _) => ChangeDirection::Looser,
        });
    }
    let chain = slot_chain(change)?;
    let item = change.key.item.as_deref();
    let loaded = load_in_txn(&vault.store, txn, spec, &chain, item)?;
    let fits = fits_in_txn(&vault.store, txn, spec, &chain)?;
    let mut after: Vec<Loaded> = loaded
        .iter()
        .filter(|row| !is_slot(row, change))
        .cloned()
        .collect();
    if let Some(value) = change.value {
        after.push(Loaded {
            scope: change.key.scope.clone(),
            found: FoundRow {
                at: 0,
                item: item.is_some(),
                mode: change.key.mode,
                by_owner,
                value: Some(value.clone()),
            },
            revision: 0,
        });
    }
    let layer = layer_default_in_txn(&vault.store, txn, spec)?;
    let (before, _, _) = in_force_of(spec, &loaded, &fits, &chain, &layer)?;
    let (after, _, _) = in_force_of(spec, &after, &fits, &chain, &layer)?;
    Ok(ChangeDirection::of(&after, &before, no_wider))
}

/// The scopes the readers of `change`'s slot read through: its scope and every wider one the key
/// admits, narrowest first.
fn slot_chain(change: &Change<'_>) -> Result<Vec<SettingScope>> {
    match &change.key.scope {
        SettingScope::Vault => Ok(vec![SettingScope::Vault]),
        scope => SettingScope::chain(std::slice::from_ref(scope), change.spec.scopes),
    }
}

/// Whether the loaded row `row` is `change`'s own slot.
fn is_slot(row: &Loaded, change: &Change<'_>) -> bool {
    row.found.at == 0
        && row.found.item == change.key.item.is_some()
        && row.found.mode == change.key.mode
}

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
fn agent_reading_in_txn(
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
fn person_reading_in_txn(
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
/// row it replaces, so an approval spends only over the row it was asked over. BLAKE3, key
/// derived from `oneiron setting set v2`.
fn effect_digest(change: &Change<'_>, replaced: Option<&[u8]>) -> [u8; 32] {
    let key = change.key.encode();
    let mut hasher = blake3::Hasher::new_derive_key("oneiron setting set v2");
    hasher.update(&(key.len() as u64).to_be_bytes());
    hasher.update(&key);
    match change.value {
        None => hasher.update(&[0]),
        Some(value) => hasher
            .update(&[1])
            .update(&(value.0.len() as u64).to_be_bytes())
            .update(&value.0),
    };
    if let Some(weight) = change.weight_runs {
        hasher.update(&[2]).update(&weight.to_bits().to_be_bytes());
    }
    match replaced {
        None => hasher.update(&[3, 0]),
        Some(bytes) => hasher
            .update(&[3, 1])
            .update(&(bytes.len() as u64).to_be_bytes())
            .update(bytes),
    };
    *hasher.finalize().as_bytes()
}

/// Opens, or finds, the check-in `agent`'s change waits on, under its own live owner Grant that
/// lists `vault.settings.set`.
fn open_request_in_txn(
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
    Ok(SetSettingOutcome::Pending {
        check_in: row.id.to_hex(),
    })
}

/// Spends the approved check-in `id` for `agent`'s `change` over the row `replaced`, in the
/// door's writer.
fn spend_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &Change<'_>,
    replaced: Option<&[u8]>,
    agent: EntityId,
    id: &EntityId,
    now: u64,
) -> Result<()> {
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
    consume_pending_check_in_in_txn(vault, txn, id, &effect_digest(change, replaced), now)?;
    Ok(())
}
