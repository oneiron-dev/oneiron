//! The owner's pick of his vault's home node (DOOR-101 PR2a; ARCH-0026: "The
//! owner picks the home node in settings; the always-on machine is the
//! default"), and its wire codec.
//!
//! The owner picks the node that runs his vault's MACRO consolidation from
//! any surface where he is authenticated, on any host. The install that
//! served him, a live machine of the vault in any role, signs the pick with
//! its install key; the pick carries his act ([`OwnerAct`], kind
//! `home_node_pick`, target the vault: [`home_pick_target`]) and its `seen`
//! is the vault's live picks as the deciding surface showed them, under
//! [`HOME_PICK_REVISION_CONTEXT`]. It is a main-log entry, so every machine
//! the owner admits folds it.
//!
//! The record is shape only: a nonzero node id, or none for a clear. Whether
//! the node is a live candidate is each machine's election to judge; a pick
//! of a node this machine does not know is recorded all the same. The home
//! pick is the owner's: no Grant action names it, so an agent's act never
//! makes it.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_HOME_NODE_PICK: &str = "home_node_pick";
const HOME_NODE_PICK_KEYS: [&str; 4] = [OP_KEY_KIND, OP_KEY_ACT, "machine", "node_id"];
/// The domain of a home pick act's `seen`, beside the checkpoint policy's
/// ([`CHECKPOINT_POLICY_REVISION_CONTEXT`]): BLAKE3 over it and the vault's
/// sorted live pick hashes, in the `PolicyRevision` shape.
pub const HOME_PICK_REVISION_CONTEXT: &[u8] = b"oneiron/home-pick-revision/v1";

/// The target a home pick act names: the vault itself, as the
/// content-addressed id of its genesis row, so every install names the same
/// target.
pub fn home_pick_target(vault_id: &AuthorityVaultId) -> Result<EntityId> {
    authority_log_entity_id_from_hash(vault_id)
}

/// One owner pick of the vault's home node, signed by the install key of
/// `machine`, a live machine of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeNodePick {
    /// The owner's act: who decided, from which surface, on which of the
    /// vault's pick revisions. Its kind is `home_node_pick` and its target
    /// the vault ([`home_pick_target`]).
    pub act: OwnerAct,
    /// The carrier: the machine whose install key signed the pick.
    pub machine: EntityId,
    /// The node the owner picked, never zero. `None` clears his pick: the
    /// default election order holds again.
    pub node_id: Option<u64>,
}

impl HomeNodePick {
    pub fn validate(&self) -> Result<()> {
        // The home pick is the owner's own: no Grant action names it, and no
        // ask answers it, so only his say-so makes it.
        if self.node_id == Some(0)
            || self.act.act != OwnerActKind::HomeNodePick
            || self.act.by != ActBy::Owner
            || self.act.answer.is_some()
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// The act names the entry's own vault.
    pub fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        let vault_id = entry.vault_id.ok_or_else(invalid_authority)?;
        self.act
            .validate_carried(OwnerActKind::HomeNodePick, home_pick_target(&vault_id)?)
    }
}

pub(super) fn home_node_pick_value(pick: &HomeNodePick) -> Value {
    let node_id = pick.node_id.map_or(Value::Nil, Value::from);
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_HOME_NODE_PICK),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&pick.act),
        ),
        (Value::from("machine"), Value::from(pick.machine.to_hex())),
        (Value::from("node_id"), node_id),
    ])
}

/// A u64 or nil; the op's shape check then refuses zero.
pub(super) fn decode_home_node_pick(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &HOME_NODE_PICK_KEYS)?;
    let node_id = match required(entries, "node_id")? {
        Value::Nil => None,
        value => Some(value.as_u64().ok_or_else(invalid_authority)?),
    };
    Ok(AuthorityOp::HomeNodePick(HomeNodePick {
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        machine: decode_canonical_id(required(entries, "machine")?)?,
        node_id,
    }))
}
