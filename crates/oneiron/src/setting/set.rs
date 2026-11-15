//! The one door that changes a setting row: [`Vault::set_setting`].

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::RowKey;

use super::change::record_change_in_txn;
use super::read::{StoredRow, in_force_in_txn, load_in_txn, names_subject, table_of};
use super::{
    EncodedValue, SetBy, Setter, SettingChange, SettingMode, SettingScope, SettingSpec, spec_named,
};
use crate::Vault;
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
}

/// One change a caller asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct SetSetting {
    pub key: String,
    pub item: Option<String>,
    pub scope: SettingScope,
    pub mode: SettingMode,
    /// The new value as JSON; `None` clears the row.
    pub value: Option<serde_json::Value>,
    /// The row's revision the caller saw; the change is refused when the row has moved since.
    pub expected_revision: Option<u64>,
    pub why: Option<String>,
    /// The settled check-in this change waited on, to spend.
    pub check_in_ref: Option<EntityId>,
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
    /// Changes one setting row in one write: the catalogue, the value's check, the caller's power
    /// checked live in this write, the change row, and the key's hook.
    ///
    /// - The owner sets every key, a pin included.
    /// - An agent sets a value row of a key of class `c` while it holds a live `engine.controls`
    ///   grant for `c`, and a value row about itself on a key set by its subject. It never
    ///   replaces a row the owner set. On a key that names its tighter direction, a holder's value
    ///   stays inside the owner's nearest row at that scope or wider, and a subject's is no looser
    ///   than the value in force.
    /// - Any other change by an agent, a pin or a change under an owner's pin among them, waits
    ///   on a check-in under the agent's own live owner Grant that lists `vault.settings.set`:
    ///   the door opens it and answers [`SetSettingOutcome::Pending`]; the same change again,
    ///   naming the approved check-in, applies once.
    ///
    /// A value equal to the row's writes nothing.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an unknown key, an item or scope the key does not admit, a value of
    /// another shape or one its check refuses, a moved row, a reason over 1,000 bytes, a
    /// check-in that is not this change's, or an agent with no Grant listing the verb; an owner
    /// proof that no longer holds; storage errors.
    pub fn set_setting(
        &self,
        caller: SettingCaller<'_>,
        request: SetSetting,
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
        let value = request
            .value
            .clone()
            .map(|json| spec.kind.from_json(json))
            .transpose()?;
        let key = RowKey {
            name: spec.name.to_owned(),
            item: request.item.clone(),
            mode: request.mode,
            scope: request.scope.clone(),
        };
        self.with_write_txn_grouped(|txn| {
            let change = Change {
                spec,
                key: &key,
                value: value.as_ref(),
            };
            set_in_txn(self, txn, &change, caller, &request)
        })
    }
}

/// One asked change, checked against the catalogue.
struct Change<'a> {
    spec: &'static SettingSpec,
    key: &'a RowKey,
    value: Option<&'a EncodedValue>,
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
        SettingCaller::Owner(owner) => (owner.revalidate_in_txn(vault, txn)?, Setter::Owner),
        SettingCaller::Agent(agent) => match agent_power_in_txn(vault, txn, change, agent)? {
            Some(setter) => (agent, setter),
            None => match request.check_in_ref {
                Some(check_in) => {
                    spend_in_txn(vault, txn, change, agent, &check_in, now)?;
                    (agent, Setter::Approved { check_in })
                }
                None => return open_request_in_txn(vault, txn, change, agent, now),
            },
        },
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
    let prior_value = prior.flatten().map(|row| row.value);
    let json = |value: Option<&EncodedValue>| {
        value
            .and_then(|value| change.spec.kind.to_json(value))
            .unwrap_or(serde_json::Value::Null)
    };
    if readable && prior_value.as_ref() == change.value {
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
            by: Some(by),
            setter,
            prior: prior_value,
            value: change.value.cloned(),
            at: now,
            why: request.why.clone(),
        },
    )?;
    let revision = match change.value {
        Some(value) => {
            let row = StoredRow {
                value: value.clone(),
                by: Some(by),
                setter,
                set_at: now,
                change: recorded.sequence,
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
    let setter = match spec.set_by {
        SetBy::Class(class) => vault
            .engine_controls_grant_in(txn, agent, class)?
            .map(|grant| Setter::Holder { grant }),
        SetBy::Subject if names_subject(&change.key.scope, agent) => Some(Setter::Subject),
        SetBy::Owner | SetBy::Subject => None,
    };
    let Some(setter) = setter else {
        return Ok(None);
    };
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
        _ => loaded
            .iter()
            .filter(|row| row.found.mode == SettingMode::Value && row.found.by_owner)
            .min_by_key(|row| (row.found.at, !row.found.item))
            .is_none_or(|cap| {
                cap.found
                    .value
                    .as_ref()
                    .and_then(|cap| spec.kind.is_tighter(value, cap))
                    .unwrap_or(false)
            }),
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

/// The digest of one change: the row's key and the value it would hold. BLAKE3, key derived from
/// `oneiron setting set v1`.
fn effect_digest(change: &Change<'_>) -> [u8; 32] {
    let key = change.key.encode();
    let mut hasher = blake3::Hasher::new_derive_key("oneiron setting set v1");
    hasher.update(&(key.len() as u64).to_be_bytes());
    hasher.update(&key);
    match change.value {
        None => hasher.update(&[0]),
        Some(value) => hasher.update(&[1]).update(&value.0),
    };
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
