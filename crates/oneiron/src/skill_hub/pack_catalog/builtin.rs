//! Engine-embedded connector source and local first-open installation.
//! A bootstrap receipt describes requested powers; it never mints a grant or a wake.

use super::{PackAdapter, PackInstallReceipt, PackInstallStatus, PackKind, PackSource, admission};
use crate::skill_hub::HubFile;
use crate::{EntityId, TimeRange, Vault, error::Result};

const SEED_KEY: &[u8] = b"pack.builtin.seeded.v1";
const PACKS: [(&str, &str); 4] = [
    (
        "slack",
        include_str!("../../../../../packs/builtin/slack/PACK.md"),
    ),
    (
        "line",
        include_str!("../../../../../packs/builtin/line/PACK.md"),
    ),
    (
        "email",
        include_str!("../../../../../packs/builtin/email/PACK.md"),
    ),
    (
        "linkedin",
        include_str!("../../../../../packs/builtin/linkedin/PACK.md"),
    ),
];

fn engine_hub_id() -> Result<EntityId> {
    let hash = blake3::hash(b"oneiron/built-in-connector-packs/v1");
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_bytes(bytes)
}

pub(crate) fn seed_builtin_packs(vault: &Vault) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    if vault.store.vault_meta.get(&rtxn, SEED_KEY)?.is_some() {
        return Ok(());
    }
    drop(rtxn);
    // Match the bootstrap skills: malformed policy remains open for owner repair.
    if crate::gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn()?)?
        .diagnostics()
        .loaded_manifest_forces_fail_closed()
    {
        return Ok(());
    }
    let mut txn = vault.store.env.write_txn()?;
    if vault.store.vault_meta.get(&txn, SEED_KEY)?.is_some() {
        return Ok(());
    }
    for (name, markdown) in PACKS {
        let source = PackSource::from_files(vec![HubFile::new("PACK.md", markdown.as_bytes())])?;
        if source.manifest.name != format!("oneiron.{name}")
            || source.manifest.kind != PackKind::Connector
            || source.manifest.adapter != Some(PackAdapter::Builtin(name.to_owned()))
        {
            return Err(super::invalid(
                "embedded adapter manifest disagrees with build",
            ));
        }
        // A prior locally installed pack owns its name. Never overwrite an owner's
        // installation (including one imported before this bootstrap pass).
        if vault
            .store
            .vault_meta
            .get(&txn, &admission::install_key(&source.manifest.name))?
            .is_some()
        {
            continue;
        }
        // A prior source or tombstone at the deterministic hash owns this ID.
        // Do not relabel a foreign import as engine-born or resurrect erasure.
        let source_id = source.entity_id()?;
        let deletion =
            crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &txn, &source_id)?;
        if vault
            .store
            .entities
            .get(&txn, source_id.as_bytes())?
            .is_some()
            || deletion.deleted
            || deletion.stale
        {
            continue;
        }
        vault.stage_pack_source_in_txn(&mut txn, &source, TimeRange { start: 0, end: 0 }, 0)?;
        let receipt = PackInstallReceipt {
            source_id: source_id.to_hex(),
            pack_name: source.manifest.name.clone(),
            content_hash: source.content_hash().to_hex(),
            kind: source.manifest.kind,
            adapter: source.manifest.adapter.clone(),
            engine_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            status: PackInstallStatus::Active,
            candidate_reason: None,
            hub_id: engine_hub_id()?.to_hex(),
            hub_ref: format!("built-in:{name}"),
            pin_type: "engine_version".to_owned(),
            pin_value: env!("CARGO_PKG_VERSION").to_owned(),
            publisher: "oneiron-engine".to_owned(),
            permissions: admission::pack_permissions(&source, None)?,
            sections: source.sections().to_vec(),
            predicates: source.manifest.predicates.iter().cloned().collect(),
            kinds: source.manifest.kinds.iter().cloned().collect(),
            skills: Vec::new(),
            installed_at: 0,
        };
        let bytes = serde_json::to_vec(&receipt)
            .map_err(|_| super::invalid("built-in receipt encoding"))?;
        vault.store.vault_meta.put(
            &mut txn,
            &admission::install_key(&receipt.pack_name),
            &bytes,
        )?;
    }
    vault
        .store
        .vault_meta
        .put(&mut txn, SEED_KEY, env!("CARGO_PKG_VERSION").as_bytes())?;
    txn.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests;
