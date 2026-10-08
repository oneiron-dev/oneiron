//! A historical restore gives content as it stood, never authority as it stood.
//!
//! ARCH-0038 (RD-20, amended 2026-09-26): a checkpoint never resets the current
//! authority root or freshness pins and never restores a destroyed identity
//! key. Restoring over a live vault therefore splits the image's rows into
//! three planes by family:
//!
//! - **carried**: the live vault's rows replace the image's, and a family the
//!   live vault no longer holds stays absent. This is the root, device and
//!   slip plane, its freshness pins and clocks, exterior key custody, and
//!   one-shot approvals, so nothing spent or revoked comes back.
//! - **guarded**: grants, policy, consent, custody and machine identities.
//!   Their history is entangled with content, so a restore that would roll
//!   one of them back is refused rather than half-applied.
//!
//! Membership is checked on the result: a restore may not make anyone an
//! owner or member who is not one now, whether by reviving a deleted or
//! merged PERSON or a removed shared member (`refuse_new_members`).
//! - everything else is content and comes from the image.
use super::CanonicalRows;
use crate::batch::EntityMetadataHeader;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CHANNEL_IDENTITY,
    ENTITY_TYPE_CONNECTOR_KEY, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SECRET_CUSTODY,
};
use crate::{Error, Result, Vault};
use heed::types::Bytes;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Plane {
    Carried,
    Guarded(&'static str),
}

#[derive(Clone, Copy)]
enum Select {
    Prefix(&'static [u8]),
    Kind(u8),
}

use Plane::{Carried, Guarded};
use Select::{Kind, Prefix};

/// The `vault_meta` row holding a store's random id (`vault::identity`).
const VAULT_STORE_ID: &[u8] = b"vault_identity:local:v1";

/// `(database, rows, plane)`. The first matching row family wins.
const FAMILIES: &[(&str, Select, Plane)] = &[
    // Root, devices, keys, slips, revocations, pacts and their observation.
    ("entities", Kind(ENTITY_TYPE_AUTHORITY_LOG), Carried),
    ("sync_state", Prefix(b"auth:"), Carried),
    ("sync_state", Prefix(b"authlog:"), Carried),
    ("sync_state", Prefix(b"authority:"), Carried),
    ("sync_state", Prefix(b"peerauth:"), Carried),
    // Device identity and the device lease registry, with the root document
    // that mirrors the leases.
    ("sync_state", Prefix(b"m:client_id"), Carried),
    ("sync_state", Prefix(b"m:device_sk"), Carried),
    ("sync_state", Prefix(b"m:device_pk"), Carried),
    ("sync_state", Prefix(b"ls:"), Carried),
    ("sync_state", Prefix(b"d:root"), Carried),
    ("sync_state", Prefix(b"u:root:"), Carried),
    ("sync_state", Prefix(b"managed:"), Carried),
    // Freshness pins, clocks, local identity and exterior key custody.
    ("vault_meta", Prefix(b"authority.checkpoint."), Carried),
    ("vault_meta", Prefix(b"ports:clock_floor:v1"), Carried),
    ("vault_meta", Prefix(b"ports:id_floor:v1"), Carried),
    ("vault_meta", Prefix(VAULT_STORE_ID), Carried),
    ("vault_meta", Prefix(b"derivation:owner:v1"), Carried),
    (
        "vault_meta",
        Prefix(b"gate_decision:custody_root:v1"),
        Carried,
    ),
    ("vault_meta", Prefix(b"tasks.ask.link_signer.v1:"), Carried),
    // One-shot approvals: a spent approve-once never comes back available.
    ("vault_meta", Prefix(b"consent.once.v1:"), Carried),
    // Grants, policy, consent, custody and machine identities.
    (
        "entities",
        Kind(ENTITY_TYPE_POLICY_MANIFEST),
        Guarded("policy manifests"),
    ),
    (
        "entities",
        Kind(ENTITY_TYPE_FEDERATION_GRANT),
        Guarded("federation grants"),
    ),
    (
        "entities",
        Kind(ENTITY_TYPE_ACCESS_GRANT),
        Guarded("access grants"),
    ),
    (
        "entities",
        Kind(ENTITY_TYPE_SECRET_CUSTODY),
        Guarded("secret custody"),
    ),
    (
        "entities",
        Kind(ENTITY_TYPE_CONNECTOR_KEY),
        Guarded("connector keys"),
    ),
    (
        "entities",
        Kind(ENTITY_TYPE_CHANNEL_IDENTITY),
        Guarded("channel identities"),
    ),
    (
        "entities",
        Kind(ENTITY_TYPE_OUTBOUND_GRANT),
        Guarded("outbound grants"),
    ),
    (
        "entities",
        Kind(ENTITY_TYPE_MACHINE),
        Guarded("machine identities"),
    ),
    (
        "vault_meta",
        Prefix(b"consent.grant.v1:"),
        Guarded("standing consent grants"),
    ),
    (
        "vault_meta",
        Prefix(b"standing.block.v1:"),
        Guarded("standing blocks"),
    ),
    (
        "vault_meta",
        Prefix(b"disclosure.scope.v1:"),
        Guarded("disclosure scopes"),
    ),
    (
        "vault_meta",
        Prefix(b"disclosure.tier_a.v1:"),
        Guarded("disclosure scopes"),
    ),
    (
        "vault_meta",
        Prefix(b"org.admin.v1."),
        Guarded("org admin grants"),
    ),
    (
        "vault_meta",
        Prefix(b"shared-vault:creation:v1"),
        Guarded("shared vault membership"),
    ),
    (
        "vault_meta",
        Prefix(b"secret_custody:name:v1:"),
        Guarded("secret custody"),
    ),
    (
        "vault_meta",
        Prefix(b"secret_lease:v1:"),
        Guarded("secret custody"),
    ),
    (
        "vault_meta",
        Prefix(b"secret_local:v1:"),
        Guarded("secret custody"),
    ),
    (
        "vault_meta",
        Prefix(b"connector_key/"),
        Guarded("connector keys"),
    ),
    (
        "vault_meta",
        Prefix(b"connector.grant_slate"),
        Guarded("connector keys"),
    ),
    (
        "vault_meta",
        Prefix(b"outbound_grant:channel_identity_usage:v1:"),
        Guarded("outbound grants"),
    ),
    (
        "vault_meta",
        Prefix(b"esign.principal.v1/"),
        Guarded("e-sign capabilities"),
    ),
    (
        "vault_meta",
        Prefix(b"esign.capability.v1/"),
        Guarded("e-sign capabilities"),
    ),
    (
        "vault_meta",
        Prefix(b"esign.recipient_capability.v1/"),
        Guarded("e-sign capabilities"),
    ),
    (
        "vault_meta",
        Prefix(b"share:brief:admission:v1:"),
        Guarded("share admissions"),
    ),
    (
        "vault_meta",
        Prefix(b"origin:authority"),
        Guarded("repository origin authority"),
    ),
];

fn plane_of(database: &str, key: &[u8], value: &[u8]) -> Option<Plane> {
    FAMILIES
        .iter()
        .find(|(db, select, _)| {
            *db == database
                && match select {
                    Prefix(prefix) => key.starts_with(prefix),
                    Kind(kind) => EntityMetadataHeader::parse(value)
                        .is_some_and(|header| header.entity_type == *kind),
                }
        })
        .map(|(_, _, plane)| *plane)
}

fn planed_databases() -> BTreeSet<&'static str> {
    FAMILIES.iter().map(|(db, _, _)| *db).collect()
}

/// Rewrites `databases` so its authority plane is `current`'s.
pub(super) fn carry_current_authority(
    databases: &mut BTreeMap<String, CanonicalRows>,
    current: &Vault,
) -> Result<()> {
    let live = current_planed_rows(current)?;
    // A store's random id, minted at its first open, names the vault even
    // before it has an authority log. Every image carries one; a missing or
    // different id is another vault.
    let store_id = |rows: &CanonicalRows| {
        rows.iter()
            .find(|(key, _)| key.as_slice() == VAULT_STORE_ID)
            .map(|(_, value)| value.clone())
    };
    let image_id = store_id(&databases["vault_meta"]);
    if image_id.is_none() || image_id != store_id(&live["vault_meta"]) {
        return Err(Error::InvalidConfig(
            "this checkpoint belongs to another vault".into(),
        ));
    }
    // The log only grows. An image entry the live vault never saw means the
    // image is another vault's, or this one's history was rewritten.
    let log = |rows: &CanonicalRows| -> BTreeSet<Vec<u8>> {
        rows.iter()
            .filter(|(_, value)| {
                EntityMetadataHeader::parse(value)
                    .is_some_and(|header| header.entity_type == ENTITY_TYPE_AUTHORITY_LOG)
            })
            .map(|(key, _)| key.clone())
            .collect()
    };
    if !log(&databases["entities"]).is_subset(&log(&live["entities"])) {
        return Err(Error::InvalidConfig(
            "this checkpoint's authority log is not a prefix of this vault's; it belongs to another vault"
                .into(),
        ));
    }
    let mut moved = BTreeSet::new();
    for database in planed_databases() {
        let guarded = |rows: &CanonicalRows| -> BTreeMap<&'static str, CanonicalRows> {
            let mut families: BTreeMap<_, CanonicalRows> = BTreeMap::new();
            for (key, value) in rows {
                if let Some(Guarded(name)) = plane_of(database, key, value) {
                    families
                        .entry(name)
                        .or_default()
                        .push((key.clone(), value.clone()));
                }
            }
            families
        };
        let image = guarded(&databases[database]);
        let current = guarded(&live[database]);
        for name in image.keys().chain(current.keys()) {
            if image.get(name) != current.get(name) {
                moved.insert(*name);
            }
        }
    }
    if !moved.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "restoring this checkpoint would roll back {} changed since it was taken; restore it beside the vault instead",
            moved.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    for database in planed_databases() {
        let rows = databases.get_mut(database).ok_or_else(super::codec_error)?;
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = std::mem::take(rows)
            .into_iter()
            .filter(|(key, value)| plane_of(database, key, value) != Some(Carried))
            .collect();
        merged.extend(
            live[database]
                .iter()
                .filter(|(key, value)| plane_of(database, key, value) == Some(Carried))
                .cloned(),
        );
        *rows = merged.into_iter().collect();
    }
    Ok(())
}

/// The live vault's canonical rows in any carried or guarded family.
fn current_planed_rows(current: &Vault) -> Result<BTreeMap<&'static str, CanonicalRows>> {
    let txn = current.store.env.read_txn()?;
    let mut planed = BTreeMap::new();
    for database in planed_databases() {
        let db = current
            .store
            .env
            .open_database::<Bytes, Bytes>(&txn, Some(database))?
            .ok_or_else(super::codec_error)?;
        let mut rows = Vec::new();
        for row in db.iter(&txn)? {
            let (key, value) = row?;
            if super::storage_tier(database, key) == super::StorageTier::Canonical
                && plane_of(database, key, value).is_some()
            {
                rows.push((key.to_vec(), value.to_vec()));
            }
        }
        planed.insert(database, rows);
    }
    Ok(planed)
}

/// Refuses a restored vault in which someone is a member who is not a member
/// of `current` now (the owner of a personal vault; any role of a shared one).
/// Membership rides content (PERSON rows, lifecycle, shared grants), so it is
/// checked on the result rather than by row: a person deleted or merged away
/// since the checkpoint does not regain the authority their unchanged grants
/// would confer.
pub(super) fn refuse_new_members(current: &Vault, restored: &Vault) -> Result<()> {
    if restored
        .live_member_ids()?
        .is_subset(&current.live_member_ids()?)
    {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "restoring this checkpoint would make someone a vault owner or member who is not one now; restore it beside the vault instead"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests;
