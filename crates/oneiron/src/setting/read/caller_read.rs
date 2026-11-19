//! Reads for a caller: who reads, what each reader may read, and the doors that read a key or the
//! catalogue for a caller.

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::{Order, Quorum};

use super::super::pack::{ProposedDefaultView, layer_default_in_txn, proposed_defaults_in_txn};
use super::super::{LearnedRange, ReadBy, ScopeKind, SetBy, SettingScope, SettingSpec};
use super::{
    SettingRowView, SettingView, key_line_grant_in_txn, names_subject, rows_in_txn, view_in_txn,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::SubstrateRead;

/// Who reads: the owner (already proved), or an actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingReader {
    Owner,
    Actor(EntityId),
}

/// Who asks a door for a read, as [`super::super::SettingCaller`] asks for a change.
#[derive(Debug, Clone)]
pub(crate) enum SettingReadCaller {
    /// The owner, by a proof the read revalidates in the snapshot it reads: a proof that no
    /// longer holds there (a co-owner's slip revoked since the door took it) reads nothing.
    Owner(AuthenticatedOwner),
    /// An agent whose binding the caller verified.
    Agent(EntityId),
}

impl SettingReadCaller {
    /// Who reads in `txn`: the owner only while its proof holds in `txn`.
    fn reader_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<SettingReader> {
        Ok(match self {
            Self::Owner(owner) => {
                owner.revalidate_in_txn(vault, txn)?;
                SettingReader::Owner
            }
            Self::Agent(agent) => SettingReader::Actor(*agent),
        })
    }
}

/// Whether `reader` may read `spec`'s rows at `scope` (all its rows when `None`), in `txn`: the
/// owner always; a member of the vault for a key read by members; a live holder of the key's
/// `engine.controls` class; for a dials key, a live whole-vault Steward grant naming any
/// `engine.controls` class; an agent whose live owner Grant lists the key's read line
/// ([`super::super::get_line`]), vault-wide; the agent or person a row's scope names, for that row.
pub(crate) fn reader_reads_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reader: SettingReader,
    spec: &SettingSpec,
    scope: Option<&SettingScope>,
) -> Result<bool> {
    let actor = match reader {
        SettingReader::Owner => return Ok(true),
        SettingReader::Actor(actor) => actor,
    };
    if spec.read_by == ReadBy::Members {
        return Ok(true);
    }
    if let SetBy::Class(class) = spec.set_by
        && vault.engine_controls_grant_in(txn, actor, class)?.is_some()
    {
        return Ok(true);
    }
    if spec.read_by == ReadBy::Dials
        && vault.substrate_read_granted_in_txn(txn, actor, SubstrateRead::Dials)?
    {
        return Ok(true);
    }
    if scope.is_some_and(|scope| names_subject(scope, actor)) {
        return Ok(true);
    }
    Ok(key_line_grant_in_txn(vault, txn, actor, &super::super::get_line(spec.name))?.is_some())
}

/// One catalogue key as `vault.settings.list` shows it: the row, its schema and default, the
/// value in force, and the stored rows the reader may read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettingCatalogueEntry {
    pub key: String,
    /// What the key chooses.
    pub doc: String,
    /// The value's JSON Schema.
    pub schema: serde_json::Value,
    /// The build's default, as JSON: what the `engine` pack proposes for the key.
    pub default: serde_json::Value,
    /// The default the vault accepted (the default layer, DESIGN 1.5), as JSON: what a read with
    /// no deciding row starts from. `null` when the accepted row is lost: the key then reads
    /// strictest.
    pub accepted_default: serde_json::Value,
    /// A pack's default for the key that waits on the owner's yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_default: Option<ProposedDefaultView>,
    /// Who sets it without asking: `owner`, `subject`, or the `engine.controls` grant verb of
    /// its class.
    pub set_by: String,
    /// The key's order: which side of a change is safe.
    pub order: Order,
    /// How many holders must say yes to a loose move.
    pub quorum: Quorum,
    /// The check-in act class of a change.
    pub act_class: String,
    pub read_by: ReadBy,
    pub restore: super::super::Restore,
    pub sync: super::super::SettingSync,
    /// The kinds of scope its rows may sit at.
    pub scopes: Vec<ScopeKind>,
    /// For a family key, what its items name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// For a learned key, the range its rows and its fits stay in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned: Option<LearnedRange>,
    /// The value in force at the vault (or at the places the request named), when the reader
    /// reads the whole key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SettingView>,
    pub rows: Vec<SettingRowView>,
}

/// What `vault.settings.list` narrows to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SettingListFilter {
    /// Keys whose name starts with it.
    pub(crate) prefix: Option<String>,
    /// Keys a holder of this `engine.controls` class sets.
    pub(crate) class: Option<crate::federation::EngineControlClass>,
    /// The places the value in force is read at.
    pub(crate) at: Vec<SettingScope>,
}

impl Vault {
    /// The value in force for `key` (and `item`) at the places `at`, when `caller` may read it.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an unknown key, a place or item it does not admit, or a reader who may
    /// not read it; a gate error for an owner proof that does not hold in this read; storage
    /// errors.
    pub(crate) fn setting_view_for(
        &self,
        caller: &SettingReadCaller,
        key: &str,
        item: Option<&str>,
        at: &[SettingScope],
    ) -> Result<SettingView> {
        let spec = super::super::spec_named(key)?;
        let txn = self.store.env.read_txn()?;
        let reader = caller.reader_in_txn(self, &txn)?;
        let own = match reader {
            SettingReader::Owner => None,
            SettingReader::Actor(actor) => at.iter().find(|scope| names_subject(scope, actor)),
        };
        if !reader_reads_key_in_txn(self, &txn, reader, spec, own)? {
            return Err(Error::InvalidConfig(format!(
                "reading `{key}` needs the owner, a holder of its class, its Grant line, or its \
                 subject"
            )));
        }
        view_in_txn(&self.store, &txn, spec, at, item)
    }

    /// Every catalogue key `filter` takes that `caller` may read, wholly or for its own rows.
    ///
    /// # Errors
    ///
    /// A place no key admits only skips that key's value; a gate error for an owner proof that
    /// does not hold in this read; storage errors.
    pub(crate) fn setting_catalogue_for(
        &self,
        caller: &SettingReadCaller,
        filter: &SettingListFilter,
    ) -> Result<Vec<SettingCatalogueEntry>> {
        let txn = self.store.env.read_txn()?;
        let reader = caller.reader_in_txn(self, &txn)?;
        let mut proposed = proposed_defaults_in_txn(&self.store, &txn)?;
        let mut entries = Vec::new();
        for spec in super::super::catalogue() {
            if filter
                .prefix
                .as_deref()
                .is_some_and(|prefix| !spec.name.starts_with(prefix))
                || filter
                    .class
                    .is_some_and(|class| spec.set_by != SetBy::Class(class))
            {
                continue;
            }
            let whole = reader_reads_key_in_txn(self, &txn, reader, spec, None)?;
            let mut rows = rows_in_txn(&self.store, &txn, spec)?;
            if let SettingReader::Actor(actor) = reader
                && !whole
            {
                rows.retain(|row| names_subject(&row.scope, actor));
                if rows.is_empty() {
                    continue;
                }
            }
            let value = if whole {
                let at: Vec<SettingScope> = filter
                    .at
                    .iter()
                    .filter(|scope| spec.admits_scope(scope.kind()))
                    .cloned()
                    .collect();
                Some(view_in_txn(&self.store, &txn, spec, &at, None)?)
            } else {
                None
            };
            // A lost accepted default (or one whose key names no strictest value) shows null.
            let accepted_default = layer_default_in_txn(&self.store, &txn, spec)
                .ok()
                .filter(|layer| layer.lost.is_none())
                .and_then(|layer| spec.kind.to_json(&layer.value))
                .unwrap_or(serde_json::Value::Null);
            let proposed_default = proposed
                .iter()
                .position(|(key, _)| key == spec.name)
                .map(|at| proposed.swap_remove(at).1);
            entries.push(SettingCatalogueEntry {
                key: spec.name.to_owned(),
                doc: spec.doc.trim().to_owned(),
                schema: spec.kind.schema(),
                default: spec
                    .kind
                    .default_value()
                    .ok()
                    .and_then(|value| spec.kind.to_json(&value))
                    .unwrap_or(serde_json::Value::Null),
                accepted_default,
                proposed_default,
                set_by: match spec.set_by {
                    SetBy::Owner => "owner".to_owned(),
                    SetBy::Subject => "subject".to_owned(),
                    SetBy::Class(class) => class.grant_verb().to_owned(),
                },
                order: spec.kind.order(),
                quorum: spec.quorum,
                act_class: spec.act.as_str().to_owned(),
                read_by: spec.read_by,
                restore: spec.restore,
                sync: spec.sync,
                scopes: ScopeKind::NARROWEST_FIRST
                    .into_iter()
                    .filter(|kind| spec.admits_scope(*kind))
                    .collect(),
                item: spec.item.map(|domain| domain.name.to_owned()),
                learned: spec.kind.learned_range(),
                value,
                rows,
            });
        }
        Ok(entries)
    }
}
