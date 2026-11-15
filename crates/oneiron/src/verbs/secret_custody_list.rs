//! `vault.secrets.list` as a typed row (FIX [SECRETS-OWNER-LIST-READ],
//! [SECRETS-HOLDER-LIST-READ]): every secret in custody, value-free, one
//! item per value, each with the machines that hold it. It runs the engine
//! read its `GET /v1/owner/secrets` route runs
//! ([`Vault::secret_custody_list`]) under the owner's proof, with the same
//! reply fields.
//!
//! Ids are 32 hex, as `GET /v1/owner/secrets/custody` names a record
//! (`secret_id`) and a machine. Two records are one item only when this
//! install proves they hold one value (RULING SECRETS-LIST-DUP-GROUPING =
//! A); `maybe_same_as` is a hint, never a merge.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{MachineOwnership, MachineRole};
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;
use crate::secret_custody::{
    SecretCustodyHolder, SecretCustodyList, SecretCustodyListItem, SecretCustodyListRecord,
};

/// `vault.secrets.list`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretListReply {
    /// One item per secret value, newest first.
    pub items: Vec<SecretListItemReply>,
}

/// One secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretListItemReply {
    /// The record the item's acts name (`secret_id`): the first of
    /// `records`.
    pub secret_id: String,
    /// The primary record's handle, such as `sc12`.
    pub handle: Option<String>,
    /// What the item is called.
    pub display_name: String,
    /// `label` (the owner's), `service` (a binding opens it), `kind` (what
    /// a scan found it as) or `name` (its custody name).
    pub display_name_source: String,
    /// What it is for, in the owner's words: the first record that says.
    pub purpose: Option<String>,
    /// Every record's binding effectors, each once (`connector:gmail`).
    pub uses: Vec<String>,
    /// The primary record's payment mark.
    pub payment: SecretListPayment,
    /// Where a mask on write found the primary record, when one did here.
    pub origin: Option<SecretListOrigin>,
    /// The primary record's times, Unix seconds.
    pub registered_at: Option<u64>,
    pub rotated_at: Option<u64>,
    /// Every machine that holds one of its records, the primary's first.
    pub holders: Vec<SecretListHolder>,
    /// The item's records, the primary first.
    pub records: Vec<SecretListRecordReply>,
    /// The `secret_id` of the one other item that may hold the same value
    /// (same source, kind and place, not proven different): a hint to show,
    /// never a merge, and no act on this item reaches it.
    pub maybe_same_as: Option<String>,
}

/// A record's payment mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretListPayment {
    /// The owner's answer; `null` while unanswered.
    pub marked: Option<bool>,
    /// What its label hint says: a key a scan found as a Stripe key pays.
    pub suggested: bool,
    /// The owner's answer, else the hint.
    pub payment: bool,
}

/// Where a mask on write found a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretListOrigin {
    /// The record whose text or field held it, 32 hex.
    pub source: String,
    /// The scan's kind code (`openai_key`).
    pub kind: String,
    /// Where in the record: `body`, `claim`, `text:<field>`, `file`, ...
    pub place: String,
}

/// One machine that holds a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretListHolder {
    /// 32 hex.
    pub machine: String,
    /// `phone` or `computer`; `null` for a machine the fold names no
    /// revision of.
    pub class: Option<String>,
    /// `yours`, `work_school`, `rented`, `hosted_node`, `execution_node`,
    /// `removed` or `unanswered`; `null` as `class` is.
    pub role: Option<String>,
    pub this_install: bool,
}

/// One custody record of an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretListRecordReply {
    pub secret_id: String,
    pub handle: Option<String>,
    /// Its custody name; `null` for a secret another machine holds that
    /// this vault keeps no transition of.
    pub name: Option<String>,
    /// `custody-portable`, `custody-device-bound` or `cross-vault`; `null`
    /// as `name` is.
    pub class: Option<String>,
    pub generation: u32,
    /// This install holds the record.
    pub held_here: bool,
    pub label: Option<String>,
    pub registered_at: Option<u64>,
    pub rotated_at: Option<u64>,
    /// The machines that hold its value, 32 hex each.
    pub holders: Vec<String>,
    /// For a record of an item with several, held on one machine alone and
    /// not the primary: that machine, which holds its own copy.
    pub own_copy: Option<String>,
}

/// `vault.secrets.list`: every secret in custody, value-free.
///
/// # Errors
/// Every refusal of [`Vault::secret_custody_list`].
pub fn list_secrets_as(vault: &Vault, owner: &AuthenticatedOwner) -> MemoryResult<SecretListReply> {
    Ok(vault.secret_custody_list(owner)?.into())
}

impl From<SecretCustodyList> for SecretListReply {
    fn from(list: SecretCustodyList) -> Self {
        Self {
            items: list
                .items
                .into_iter()
                .map(SecretListItemReply::from)
                .collect(),
        }
    }
}

impl From<SecretCustodyListItem> for SecretListItemReply {
    fn from(item: SecretCustodyListItem) -> Self {
        let primary = &item.records[0];
        let mut uses: Vec<String> = Vec::new();
        for record in &item.records {
            for effector in &record.uses {
                if !uses.contains(effector) {
                    uses.push(effector.clone());
                }
            }
        }
        Self {
            secret_id: item.primary.to_hex(),
            handle: primary.handle.clone(),
            display_name: item.display_name,
            display_name_source: item.display_name_source.as_str().to_owned(),
            purpose: item
                .records
                .iter()
                .find_map(|record| record.purpose.clone()),
            uses,
            payment: SecretListPayment {
                marked: primary.payment_marked,
                suggested: primary.payment_suggested,
                payment: primary.payment_marked.unwrap_or(primary.payment_suggested),
            },
            origin: primary.origin.as_ref().map(|origin| SecretListOrigin {
                source: origin.source.to_hex(),
                kind: origin.kind.clone(),
                place: origin.place.clone(),
            }),
            registered_at: primary.registered_at,
            rotated_at: primary.rotated_at,
            holders: item
                .holders
                .into_iter()
                .map(SecretListHolder::from)
                .collect(),
            records: item
                .records
                .into_iter()
                .map(SecretListRecordReply::from)
                .collect(),
            maybe_same_as: item.maybe_same_as.map(|id| id.to_hex()),
        }
    }
}

impl From<SecretCustodyHolder> for SecretListHolder {
    fn from(holder: SecretCustodyHolder) -> Self {
        Self {
            machine: holder.machine.to_hex(),
            class: holder.class.map(|class| class.wire().to_owned()),
            role: holder.role.map(|role| role_name(role).to_owned()),
            this_install: holder.this_install,
        }
    }
}

impl From<SecretCustodyListRecord> for SecretListRecordReply {
    fn from(record: SecretCustodyListRecord) -> Self {
        Self {
            secret_id: record.id.to_hex(),
            handle: record.handle,
            name: record.name,
            class: record.class.map(|class| class.as_str().to_owned()),
            generation: record.generation,
            held_here: record.held_here,
            label: record.label,
            registered_at: record.registered_at,
            rotated_at: record.rotated_at,
            holders: record
                .holders
                .iter()
                .map(|machine| machine.to_hex())
                .collect(),
            own_copy: record.own_copy.map(|machine| machine.to_hex()),
        }
    }
}

/// A machine role's wire string, as `GET /v1/owner/machines/answer` spells
/// it.
fn role_name(role: MachineRole) -> &'static str {
    match role {
        MachineRole::Owned(MachineOwnership::Yours) => "yours",
        MachineRole::Owned(MachineOwnership::WorkSchool) => "work_school",
        MachineRole::Owned(MachineOwnership::Rented) => "rented",
        MachineRole::HostedNode => "hosted_node",
        MachineRole::ExecutionNode => "execution_node",
        MachineRole::Removed => "removed",
        MachineRole::Unanswered => "unanswered",
    }
}
