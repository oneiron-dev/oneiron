//! The owner's verb-class rows for his agents' Grants (FIX 8735, Engine
//! 18:26 = A), in the existing trusted default policy manifest.
//!
//! A row is a class name and its member verbs, each an exact verb string.
//! An owner's agent Grant that names the class admits each member verb as
//! if its exact verbs listed it (`federation::AgentVerbClasses`). There is
//! no built-in set: a vault holds only the rows its owner wrote, through
//! this family's owner door (the owner's manifest writer and its receipt
//! ledger), and an untrusted, absent or malformed table holds none. A
//! member is a verb, never another row's class (no nested classes), and
//! never the `git_push` verb: only the owner's `git_push` mint grants raw
//! push.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{body_in_txn, decode_fields, invalid, rewrite_default_manifest_field_as_owner_in_txn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::federation::GIT_PUSH_VERB;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::{Error, Result, Vault};

/// The default manifest's field that holds the owner's verb-class rows.
pub(crate) const AGENT_VERB_CLASSES_KEY: &str = "agent_verb_classes";

/// One owner verb-class row: a class an agent Grant may name, and the exact
/// verbs it admits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentVerbClassRow {
    /// The class name a Grant's `verb_classes` names: nonempty, no
    /// surrounding whitespace, never `git_push`.
    pub name: String,
    /// Its member verbs, exact verb strings: nonempty, never `git_push`,
    /// never another row's class.
    pub verbs: BTreeSet<String>,
}

/// `vault.agents.verb_classes.configure`'s input: the whole table, against
/// the manifest the owner read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentVerbClassesConfigureRequest {
    pub expected_body_hash: String,
    /// Every row the table holds after the edit, one per class; empty
    /// clears it.
    pub classes: Vec<AgentVerbClassRow>,
}

/// The owner's verb-class rows and the default manifest's edit precondition.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentVerbClassesView {
    pub manifest_ref: String,
    pub body_hash: String,
    /// The rows, in class order.
    pub classes: Vec<AgentVerbClassRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentVerbClassesReceipt {
    pub configuration: AgentVerbClassesView,
    pub receipt_ref: String,
}

/// The rows as one map from class to member verbs, refused whole when one
/// row breaks the shape.
fn validate_rows(rows: &[AgentVerbClassRow]) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut table = BTreeMap::new();
    for row in rows {
        if !oneiron_authority::federation::verb_class_name_is_valid(&row.name) {
            return Err(invalid(
                "a verb class name is nonempty, unpadded and never git_push",
            ));
        }
        if row.verbs.is_empty()
            || row.verbs.iter().any(|verb| {
                verb.is_empty() || verb.trim() != verb.as_str() || verb == GIT_PUSH_VERB
            })
        {
            return Err(invalid(
                "a verb class lists nonempty, unpadded exact verbs and never git_push",
            ));
        }
        if table.insert(row.name.clone(), row.verbs.clone()).is_some() {
            return Err(invalid("a verb class appears once"));
        }
    }
    for (class, verbs) in &table {
        if verbs
            .iter()
            .any(|verb| verb != class && table.contains_key(verb))
        {
            return Err(invalid("a verb class lists verbs, never another class"));
        }
    }
    Ok(table)
}

/// The rows in class order.
fn rows_of(table: &BTreeMap<String, BTreeSet<String>>) -> Vec<AgentVerbClassRow> {
    table
        .iter()
        .map(|(name, verbs)| AgentVerbClassRow {
            name: name.clone(),
            verbs: verbs.clone(),
        })
        .collect()
}

/// The verb-class table `fields` holds; `None` when the field is absent. A
/// malformed table refuses the manifest.
pub(crate) fn decode_agent_verb_classes(
    fields: &[(rmpv::Value, rmpv::Value)],
) -> Result<Option<BTreeMap<String, BTreeSet<String>>>> {
    let mut tables = fields
        .iter()
        .filter(|(key, _)| key.as_str() == Some(AGENT_VERB_CLASSES_KEY));
    let Some((_, value)) = tables.next() else {
        return Ok(None);
    };
    if tables.next().is_some() {
        return Err(invalid("duplicate agent_verb_classes"));
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| invalid("agent verb classes encoding"))?;
    let rows: Vec<AgentVerbClassRow> =
        rmp_serde::from_slice(&bytes).map_err(|_| invalid("invalid agent verb classes"))?;
    validate_rows(&rows).map(Some)
}

/// The owner's verb-class rows as `txn` holds them, through `store`: the
/// default manifest's table when that manifest is owner-trusted and not
/// quarantined. An absent, untrusted or quarantined manifest, or a table that does not decode, holds none (a
/// classed Grant then admits only its classes' own spellings and the
/// built-in outbound classes). A judgment reads this once and passes it in.
///
/// # Errors
/// A store read failure.
pub(crate) fn agent_verb_class_rows_for_store_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let id = crate::gate::default_policy_manifest_id()?;
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
        return Ok(BTreeMap::new());
    };
    if EntityMetadataHeader::parse(&raw)
        .is_none_or(|header| header.entity_type != ENTITY_TYPE_POLICY_MANIFEST)
    {
        return Ok(BTreeMap::new());
    }
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(BTreeMap::new());
    };
    // A quarantined manifest keeps its body and trust stamp, but its rows
    // count for nothing, as the manifest fold reads it (FIX 8735 review).
    if !crate::gate::manifest_authenticity::manifest_is_trusted(store, txn, &id, body)?
        || crate::gate::manifest_authenticity::manifest_is_quarantined(store, txn, &id, body)?
    {
        return Ok(BTreeMap::new());
    }
    match decode_fields(body).and_then(|fields| decode_agent_verb_classes(&fields)) {
        Ok(table) => Ok(table.unwrap_or_default()),
        Err(error) => {
            tracing::warn!(
                error_kind = ?error.kind(),
                "the owner's agent verb classes do not decode; no class row admits a verb"
            );
            Ok(BTreeMap::new())
        }
    }
}

/// The verb-class table a stored default-manifest `body` declares, whether
/// or not it is trusted yet; none when it declares none or does not decode.
/// A shape plan's projection reads the table a manifest would install with.
pub(crate) fn agent_verb_class_rows_of_body(body: &[u8]) -> BTreeMap<String, BTreeSet<String>> {
    decode_fields(body)
        .and_then(|fields| decode_agent_verb_classes(&fields))
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Whether the verb-class table `after` confers no verb that `before` did
/// not: every class it names was in `before`, with no verb added. A class
/// row is part of every agent Grant naming it, so a new class or an added
/// verb is a widening, which waits for the owner's word like any other
/// (FIX 8735 review); removing a class or a verb narrows.
pub(crate) fn verb_classes_narrow(
    before: &BTreeMap<String, BTreeSet<String>>,
    after: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    after
        .iter()
        .all(|(class, verbs)| before.get(class).is_some_and(|had| verbs.is_subset(had)))
}

fn view(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<AgentVerbClassesView> {
    let id = crate::gate::default_policy_manifest_id()?;
    let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
    if !crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, &id, &body)? {
        return Err(invalid(
            "agent verb classes require an owner-trusted manifest",
        ));
    }
    let table = decode_agent_verb_classes(&decode_fields(&body)?)?.unwrap_or_default();
    Ok(AgentVerbClassesView {
        manifest_ref: id.to_hex(),
        body_hash: blake3::hash(&body).to_hex().to_string(),
        classes: rows_of(&table),
    })
}

/// `vault.agents.verb_classes.get`: the owner's verb-class rows and the
/// default manifest's edit precondition.
pub fn agent_verb_classes_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<AgentVerbClassesView> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    view(vault, &txn)
}

/// `vault.agents.verb_classes.configure`: replaces the owner's whole
/// verb-class table through the native owner writer and receipt ledger.
/// Each agent Grant that names a class admits its new members from the next
/// judgment on; a Grant that names none is untouched.
pub fn configure_agent_verb_classes_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: AgentVerbClassesConfigureRequest,
) -> Result<AgentVerbClassesReceipt> {
    let table = validate_rows(&input.classes)?;
    let receipt = vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        if view(vault, txn)?.body_hash != input.expected_body_hash {
            return Err(invalid(
                "expected_body_hash must match the current policy manifest",
            ));
        }
        let replacement = rmp_serde::to_vec_named(&rows_of(&table))
            .map_err(|_| invalid("agent verb classes encoding"))?;
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(replacement))
            .map_err(|_| invalid("agent verb classes encoding"))?;
        let receipt_ref = rewrite_default_manifest_field_as_owner_in_txn(
            vault,
            owner,
            txn,
            AGENT_VERB_CLASSES_KEY,
            |_| Ok(value),
            "gate.allow.owner_agent_verb_classes",
        )?;
        Ok(AgentVerbClassesReceipt {
            configuration: view(vault, txn)?,
            receipt_ref,
        })
    })?;
    vault.apply_pending_rebinds_after_commit();
    Ok(receipt)
}
