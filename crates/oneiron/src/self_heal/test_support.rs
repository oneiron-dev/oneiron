//! Shared policy fixtures; never a production policy installation door.
pub(super) fn replace_default_manifest(vault: &crate::Vault, body: &[u8]) {
    let id = crate::gate::default_policy_manifest_id().unwrap();
    vault
        .with_write_txn(|txn| {
            let old = vault.store.entities.get(txn, id.as_bytes())?.unwrap();
            let mut raw = old[..crate::batch::ENTITY_METADATA_HEADER_LEN].to_vec();
            raw.extend_from_slice(body);
            vault.store.entities.put(txn, id.as_bytes(), &raw)?;
            Ok(())
        })
        .unwrap();
}
