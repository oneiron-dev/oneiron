//! The one door that changes a setting row: [`Vault::set_setting`].

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::RowKey;

use super::change::record_change_in_txn;
use super::learned::checked_weight;
use super::read::{
    StoredRow, in_force_in_txn, key_line_grant_in_txn, load_in_txn, names_subject, table_of,
};
use super::{
    EncodedValue, Restore, SetBy, Setter, SettingChange, SettingMode, SettingScope, SettingSpec,
    set_line, spec_named,
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
    /// value's check, the caller's power checked live in this write, the change row, and the
    /// key's hook. Once the write commits, an applied change runs the key's `after_commit`.
    ///
    /// - The owner sets every key, a pin included.
    /// - An agent sets a value row of a key whose own line (`settings.set:<key>`) its live owner
    ///   Grant lists, vault-wide; of a key of class `c` while it holds a live `engine.controls`
    ///   grant for `c`; and about itself on a key set by its subject. It never
    ///   replaces a row the owner set. On a key that names its tighter direction, a holder's value
    ///   stays inside the owner's nearest row at that scope or wider, or inside the catalogue
    ///   default where the owner set none, and a subject's is no looser than the value in force.
    /// - Any other change by an agent, a pin or a change under an owner's pin among them, waits
    ///   on a check-in under the agent's own live owner Grant that lists `vault.settings.set`:
    ///   the door opens it and answers [`SetSettingOutcome::Pending`]; the same change again,
    ///   naming the approved check-in, applies once.
    /// - A live person sets a value row about themselves (scope `Person(them)`) on a key set by
    ///   its subject, and on a key that names its tighter direction only a value no looser than
    ///   the one in force; never a row the owner set. Anything else is refused, with no ask.
    /// - The engine sets a value row of any key, with no ask and no bound; never a pin.
    ///
    /// The value passes the side-row wall before it is checked and stored, as an authored row
    /// does: a secret goes to custody and the row keeps its handle; any other hit refuses the
    /// change. A value equal to the row's writes nothing.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an unknown key, an item or scope the key does not admit, a value of
    /// another shape or one its check refuses, a moved row, a reason over 1,000 bytes, a
    /// check-in that is not this change's, an agent with no Grant listing the verb, a person's
    /// change outside their own row, or an engine pin; an owner or person proof that no longer
    /// holds; the side-row wall's refusal; storage errors.
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
    let (by, setter) = match caller {
        SettingCaller::Owner(owner) => (Some(owner.revalidate_in_txn(vault, txn)?), Setter::Owner),
        SettingCaller::Agent(agent) => match agent_power_in_txn(vault, txn, change, agent)? {
            Some(setter) => (Some(agent), setter),
            None => match request.check_in_ref {
                Some(check_in) => {
                    spend_in_txn(vault, txn, change, agent, &check_in, now)?;
                    (Some(agent), Setter::Approved { check_in })
                }
                None => return open_request_in_txn(vault, txn, change, agent, now),
            },
        },
        SettingCaller::Person(person) => {
            let person = person.revalidate_person_in_txn(vault, txn)?;
            let setter = person_power_in_txn(vault, txn, change, person)?.ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "a person sets only a value row about themselves on a key set by its \
                     subject, never one the owner set, and on a key with a tighter direction no \
                     looser than the value in force: `{}`",
                    change.spec.name
                ))
            })?;
            (Some(person), setter)
        }
        SettingCaller::Engine(engine) => {
            if change.key.mode == SettingMode::Pin {
                return Err(Error::InvalidConfig(
                    "the engine sets a value row, never a pin: a pin is the owner's".into(),
                ));
            }
            (None, Setter::Engine { ask: engine.ask })
        }
    };
    let table = table_of(change.spec);
    let key_bytes = change.key.encode();
    let prior = match table.get_bytes(&vault.store, txn, &key_bytes)? {
        Some(bytes) => Some(rmp_serde::from_slice::<StoredRow>(&bytes).ok()),
        None => None,
    };
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
    let prior_weight = prior_row.as_ref().and_then(|row| row.weight_runs);
    let prior_value = prior_row.map(|row| row.value);
    let json = |value: Option<&EncodedValue>| {
        value
            .and_then(|value| change.spec.kind.to_json(value))
            .unwrap_or(serde_json::Value::Null)
    };
    if readable && prior_value.as_ref() == change.value && prior_weight == change.weight_runs {
        return Ok(SetSettingOutcome::Applied {
            sequence: None,
            revision,
            value: json(change.value),
        });
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
    Ok(SetSettingOutcome::Applied {
        sequence: Some(recorded.sequence),
        revision,
        value: json(change.value),
    })
}

/// The capacity in which `agent` may make `change` without asking, in `txn`, or `None` when it
/// must ask.
fn agent_power_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &Change<'_>,
    agent: EntityId,
) -> Result<Option<Setter>> {
    let spec = change.spec;
    if change.key.mode == SettingMode::Pin {
        return Ok(None);
    }
    // The key's own Grant line makes the agent a holder of that one key (AUTH-1 = A: its
    // widening still asks the user).
    let setter = match key_line_grant_in_txn(vault, txn, agent, &set_line(spec.name))? {
        Some(grant) => Some(Setter::KeyGrant { grant }),
        None => match spec.set_by {
            SetBy::Class(class) => vault
                .engine_controls_grant_in(txn, agent, class)?
                .map(|grant| Setter::Holder { grant }),
            SetBy::Subject if names_subject(&change.key.scope, agent) => Some(Setter::Subject),
            SetBy::Owner | SetBy::Subject => None,
        },
    };
    let Some(setter) = setter else {
        return Ok(None);
    };
    bounded_power_in_txn(vault, txn, change, setter)
}

/// The capacity in which `person` may make `change`, in `txn`, or `None` when they may not: a
/// value row at their own `Person` scope on a key set by its subject.
fn person_power_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &Change<'_>,
    person: EntityId,
) -> Result<Option<Setter>> {
    if change.key.mode == SettingMode::Pin
        || change.spec.set_by != SetBy::Subject
        || change.key.scope != SettingScope::Person(person)
    {
        return Ok(None);
    }
    bounded_power_in_txn(vault, txn, change, Setter::Subject)
}

/// `setter` when the rows in force leave it room for `change`, else `None`: no owner's pin on
/// the chain, no row the owner set in its place, and on a key that names its tighter direction a
/// holder's value inside the owner's nearest row, or inside the catalogue default where the owner
/// set none (a holder never raises a key past it), a subject's no looser than the value in force.
fn bounded_power_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    change: &Change<'_>,
    setter: Setter,
) -> Result<Option<Setter>> {
    let spec = change.spec;
    // The scope and every wider one the key admits, narrowest first.
    let chain = match &change.key.scope {
        SettingScope::Vault => vec![SettingScope::Vault],
        scope => SettingScope::chain(std::slice::from_ref(scope), spec.scopes)?,
    };
    let item = change.key.item.as_deref();
    let loaded = load_in_txn(&vault.store, txn, spec, &chain, item)?;
    if loaded
        .iter()
        .any(|row| row.found.mode == SettingMode::Pin && row.found.by_owner)
    {
        // Under the owner's pin a holder's row would never be read: the owner decides.
        return Ok(None);
    }
    if loaded.iter().any(|row| {
        row.found.at == 0
            && row.found.item == item.is_some()
            && row.found.mode == change.key.mode
            && row.found.by_owner
    }) {
        // The row is the owner's: only the owner, or an approved ask, replaces it.
        return Ok(None);
    }
    let Some(value) = change.value.filter(|_| spec.kind.has_direction()) else {
        return Ok(Some(setter));
    };
    let within = match setter {
        Setter::Subject => {
            let (in_force, _, _) = in_force_in_txn(&vault.store, txn, spec, &chain, item)?;
            spec.kind.is_tighter(value, &in_force).unwrap_or(false)
        }
        _ => {
            let cap = loaded
                .iter()
                .filter(|row| row.found.mode == SettingMode::Value && row.found.by_owner)
                .min_by_key(|row| (row.found.at, !row.found.item));
            match cap {
                Some(cap) => cap
                    .found
                    .value
                    .as_ref()
                    .and_then(|cap| spec.kind.is_tighter(value, cap))
                    .unwrap_or(false),
                None => spec
                    .kind
                    .is_tighter(value, &spec.kind.default_value()?)
                    .unwrap_or(false),
            }
        }
    };
    Ok(within.then_some(setter))
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

/// The digest of one change: the row's key, the value it would hold and a seed's weight. BLAKE3,
/// key derived from `oneiron setting set v1`. A change with no weight hashes as before weights
/// existed, so a check-in opened for it still matches.
fn effect_digest(change: &Change<'_>) -> [u8; 32] {
    let key = change.key.encode();
    let mut hasher = blake3::Hasher::new_derive_key("oneiron setting set v1");
    hasher.update(&(key.len() as u64).to_be_bytes());
    hasher.update(&key);
    match change.value {
        None => hasher.update(&[0]),
        Some(value) => hasher.update(&[1]).update(&value.0),
    };
    if let Some(weight) = change.weight_runs {
        hasher.update(&[2]).update(&weight.to_bits().to_be_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Opens, or finds, the check-in `agent`'s change waits on, under its own live owner Grant that
/// lists `vault.settings.set`.
fn open_request_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &Change<'_>,
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
            effect_digest: effect_digest(change),
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

/// Spends the approved check-in `id` for `agent`'s `change`, in the door's writer.
fn spend_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &Change<'_>,
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
    consume_pending_check_in_in_txn(vault, txn, id, &effect_digest(change), now)?;
    Ok(())
}
