//! The app's policy actions as host verbs (OF-181). The action table holds
//! three policy actions no SDK row named: `dreamer.wake_policy.set`,
//! `inference.defaults.read` and `inference.defaults.replace`. The host verbs
//! `vault.settings.wake_policy.set`, `vault.settings.inference_defaults` and
//! `.replace` run them, so code mode, MCP and the SDK clients reach the same
//! actions the app's buttons do. Each door runs the table's own action under
//! the caller's credential: the wake policy still needs the host's owner
//! proof, and the inference defaults the caller's Auto ceiling. Nothing here
//! writes a policy itself.
//!
//! The owner's act on either setting is recorded in the commit that changes
//! it (WILL-PLAN L13 row 01, Engine 10-19 02:4x): an [`OwnerAct`] of kind
//! [`OwnerActKind::PolicySetting`], on the setting's reserved target
//! ([`owner_act_target`]), with where the owner said so (audit only), the
//! setting's live acts as its revision, and the setting as it stood. This
//! install keeps it as its local index ([`Vault::policy_setting_acts`]), and
//! the same commit signs it as a `PolicySettingSet` every machine the owner
//! admits folds and checks (FIX 4624), best effort: a record that cannot be
//! signed leaves the setting and this index as before.

use serde::{Deserialize, Serialize};

use crate::authority::{ActSurface, OwnerAct, OwnerActKind, PolicySettingAct};
use crate::claim::ScopedReadActorKey;
use crate::code_run::actions::{
    ActionArgument, ActionDispatch, ActionHostBinding, ActionRegistry, AgentActionCall,
};
use crate::consent::AuthenticatedOwner;
use crate::lens::{LensPrincipalBinding, LensText, SelfUiActionId};
use crate::memory::{Memory, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId, Error, Result, Vault, WriteActor};

/// `vault.settings.wake_policy.set`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakePolicySetRequest {
    /// The dreamer wake policy row, as `dreamer.wake_policy.set` takes it.
    pub policy: serde_json::Value,
    /// The call's idempotency key, at most 256 bytes: a retry with the same
    /// key and policy gets the first call's answer.
    pub idempotency_key: String,
}

/// `vault.settings.inference_defaults.replace`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InferenceDefaultsReplaceRequest {
    /// The whole per-purpose default table, as `inference.defaults.replace`
    /// takes it.
    pub defaults: serde_json::Value,
    /// The call's idempotency key, at most 256 bytes.
    pub idempotency_key: String,
}

/// A policy action's answer: its outcome as the action's replay record
/// spells it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PolicyActionOutcome {
    pub outcome: serde_json::Value,
}

impl PolicyActionOutcome {
    /// # Errors
    /// An outcome that does not encode.
    pub fn from_dispatch(dispatch: &ActionDispatch) -> Result<Self> {
        Ok(Self {
            outcome: dispatch.outcome_value()?,
        })
    }
}

fn action(id: &str, args: Vec<ActionArgument>, idempotency_key: String) -> Result<AgentActionCall> {
    Ok(AgentActionCall {
        verb_id: SelfUiActionId::new(id)?,
        args,
        idempotency_key,
    })
}

fn json_text(value: &serde_json::Value) -> Result<ActionArgument> {
    let text = serde_json::to_string(value)
        .map_err(|_| Error::InvalidConfig("policy action input does not encode".to_owned()))?;
    Ok(ActionArgument::Text(LensText::new(text)?))
}

impl WakePolicySetRequest {
    /// The table's `dreamer.wake_policy.set` call.
    /// # Errors
    /// A policy past the action's text bound.
    pub fn into_action(self) -> Result<AgentActionCall> {
        action(
            "dreamer.wake_policy.set",
            vec![json_text(&self.policy)?],
            self.idempotency_key,
        )
    }
}

impl InferenceDefaultsReplaceRequest {
    /// The table's `inference.defaults.replace` call.
    /// # Errors
    /// A table past the action's text bound.
    pub fn into_action(self) -> Result<AgentActionCall> {
        action(
            "inference.defaults.replace",
            vec![json_text(&self.defaults)?],
            self.idempotency_key,
        )
    }
}

/// The table's `inference.defaults.read` call. A read takes no key from its
/// caller: each read gets a fresh one, so it never answers from an earlier
/// read's record.
/// # Errors
/// None in practice; the action id is fixed.
pub fn inference_defaults_read_action() -> Result<AgentActionCall> {
    action(
        "inference.defaults.read",
        Vec::new(),
        format!("read/{}", EntityId::now().to_hex()),
    )
}

/// The principal an action call runs as: `actor` itself, reading under its
/// credential's `key`, as a human view, an agent task or a system job by
/// its class.
/// # Errors
/// A key that does not belong to `actor`.
pub fn action_principal(
    actor: WriteActor,
    key: ScopedReadActorKey,
) -> Result<LensPrincipalBinding> {
    let id = actor.entity_ref().to_hex();
    match actor.actor_class() {
        EdgeActorClass::Agent => LensPrincipalBinding::agent_task(id, key.clone(), vec![key]),
        EdgeActorClass::System => LensPrincipalBinding::system_job(id, key.clone(), vec![key]),
        EdgeActorClass::Human => LensPrincipalBinding::human_view(id, key.clone(), vec![key]),
    }
}

/// An embedded call: the handle's own actor and read key, and the owner's
/// proof when the action needs it.
fn run_embedded(
    memory: &Memory<'_>,
    call: AgentActionCall,
    owner: Option<&AuthenticatedOwner>,
) -> MemoryResult<PolicyActionOutcome> {
    let actor = WriteActor::new(memory.actor(), memory.actor_class());
    let principal = action_principal(actor, memory.read_key()?)?;
    let dispatch = ActionRegistry::app()?.execute_call(
        memory.vault(),
        actor,
        &principal,
        &call,
        ActionHostBinding {
            verb_door: None,
            owner,
            // An embedded handle's call is this install's own.
            owner_surface: owner.map(|_| ActSurface::ThisInstall),
            live_run: None,
            planner: None,
        },
    )?;
    Ok(PolicyActionOutcome::from_dispatch(&dispatch)?)
}

/// `vault.settings.wake_policy.set` on an embedded handle: the owner's own.
/// # Errors
/// A handle that is not the owner's, or the action's refusal.
pub fn wake_policy_set_embedded(
    memory: &Memory<'_>,
    input: WakePolicySetRequest,
) -> MemoryResult<PolicyActionOutcome> {
    let owner = memory.embedded_owner("vault.settings.wake_policy.set")?;
    run_embedded(memory, input.into_action()?, Some(&owner))
}

/// `vault.settings.inference_defaults` on an embedded handle.
/// # Errors
/// The action's refusal: the handle's actor needs an Auto ceiling.
pub fn inference_defaults_embedded(memory: &Memory<'_>) -> MemoryResult<PolicyActionOutcome> {
    run_embedded(memory, inference_defaults_read_action()?, None)
}

/// `vault.settings.inference_defaults.replace` on an embedded handle.
/// # Errors
/// The action's refusal: the handle's actor needs an Auto ceiling, and the
/// table must validate.
pub fn inference_defaults_replace_embedded(
    memory: &Memory<'_>,
    input: InferenceDefaultsReplaceRequest,
) -> MemoryResult<PolicyActionOutcome> {
    run_embedded(memory, input.into_action()?, None)
}

// The setting an owner act changes and the reserved target of a vault-wide
// one live beside the signed op that carries them (FIX 4624).
pub use oneiron_authority::authority::{PolicySetting, owner_act_target};

/// One owner act on a vault-wide setting, as this install recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySettingActReceipt {
    pub setting: PolicySetting,
    pub act: OwnerAct,
    /// BLAKE3 over the setting as it stood, as JSON.
    pub prior: [u8; 32],
    /// Vault clock seconds.
    pub at: u64,
}

const ACTS: SideTable<u64, PolicySettingActReceipt, Named> =
    SideTable::new(&side_table::POLICY_SETTING_ACT);

/// Records, in the caller's write transaction, the act of the owner `owner`
/// (the person the caller revalidated in that transaction) on `setting`,
/// whose value before the write was `prior` and after it `value`. The act's
/// `seen` is the setting's live acts (zero where the fold does not read);
/// `prior` is kept as BLAKE3 over it as JSON. The act is also signed as a
/// `PolicySettingSet` in this transaction, best effort (FIX 4624). With no
/// `surface`, the host named none, so nothing is recorded and the write
/// stands as it is.
pub(crate) fn record_policy_setting_act_in_txn<T: Serialize>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    setting: PolicySetting,
    owner: EntityId,
    surface: Option<ActSurface>,
    prior: &T,
    value: &T,
) -> Result<()> {
    let Some(surface) = surface else {
        return Ok(());
    };
    let prior = serde_json::to_vec(prior)
        .map_err(|_| Error::InvariantViolation("policy setting act encoding"))?;
    let prior = *blake3::hash(&prior).as_bytes();
    let target = owner_act_target(setting.as_str())?;
    // A fold or a value that does not read leaves the act unsigned and this
    // index as before (rubric 1).
    let signable = match (
        vault.policy_setting_revision_in_txn(txn, target),
        serde_json::to_vec(value),
    ) {
        (Ok(seen), Ok(value)) => Some((seen, *blake3::hash(&value).as_bytes())),
        (Err(error), _) => {
            tracing::warn!(%error, "policy setting act: the setting's revision did not read");
            None
        }
        (_, Err(error)) => {
            tracing::warn!(%error, "policy setting act: the new value did not encode");
            None
        }
    };
    let act = OwnerAct::by_owner(
        owner,
        OwnerActKind::PolicySetting,
        target,
        surface,
        signable.map_or([0; 32], |(seen, _)| seen),
    );
    if let Some((_, value)) = signable {
        vault.record_policy_setting_op_in_txn(
            txn,
            PolicySettingAct {
                act,
                setting,
                prior,
                value: Some(value),
            },
        );
    }
    let sequence = match ACTS.iter_rev_from(&vault.store, txn, &[])?.next() {
        None => 0,
        Some(row) => row?
            .0
            .checked_add(1)
            .ok_or(Error::IndexOverflow("policy setting act sequence"))?,
    };
    let at = vault.instant_in_txn(txn)?.secs();
    ACTS.put(
        &vault.store,
        txn,
        &sequence,
        &PolicySettingActReceipt {
            setting,
            act,
            prior,
            at,
        },
    )
}

impl Vault {
    /// Every owner act on a vault-wide setting this install recorded, oldest
    /// first.
    ///
    /// # Errors
    /// A store read that fails.
    pub fn policy_setting_acts(&self) -> Result<Vec<PolicySettingActReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(ACTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect())
    }
}
