//! The vault data key's boot steps (moved out of `state_serve`): the page
//! seal a managed vault opens with, its escrow wraps, and the escrow
//! capsules spooled to the supervisor's outbox.

use std::collections::BTreeSet;

use super::super::args::ManagedArgs;

/// Seals the vault's held data key to the node's managed escrow recipient
/// and the owner's break-glass recipient, each named by the supervisor.
/// A wrap is labelled by its recipient's fingerprint, so a restart adds
/// nothing, and a recipient of a new epoch gets a wrap of its own.
pub(super) fn escrow_vault_key(
    vault: &oneiron::Vault,
    managed: &ManagedArgs,
) -> anyhow::Result<()> {
    let present = vault.vault_key_wraps()?;
    for (role, path) in [
        ("managed", &managed.escrow_recipient),
        ("break-glass", &managed.break_glass_recipient),
    ] {
        let Some(path) = path else {
            continue;
        };
        let bytes = std::fs::read(path)
            .map_err(|error| anyhow::anyhow!("{role} escrow recipient unreadable: {error}"))?;
        let recipient = oneiron::world_keys::HybridPublicKey::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("{role} escrow recipient is not a hybrid public key"))?;
        let fingerprint = blake3::hash(&bytes);
        let label = format!("{role}.{}", &fingerprint.to_hex()[..16]);
        let sealed = present.iter().any(|wrap| {
            matches!(&wrap.kind, oneiron::world_keys::VaultKeyWrapKind::Escrow { label: held } if *held == label)
        });
        if !sealed {
            // A key released and retired under another label still seals,
            // with a warning (FIX 2857).
            let added = vault.add_vault_key_escrow(&label, &recipient)?;
            for warning in &added.warnings {
                tracing::warn!(role, %label, ?warning, "an escrow recipient was retired before");
            }
        }
    }
    Ok(())
}

/// The page seal a managed vault opens with (OF-570 maximum tier), from the
/// data key its supervisor delivered: a sealed vault's, reopened from the
/// mirror beside it; a new one where no vault is yet and `maximum_tier`
/// (`--maximum-tier`, else the settings file's) opted in; none for a plain
/// vault, which stays plain (no converter).
pub(super) fn managed_page_seal(
    managed: &ManagedArgs,
    maximum_tier: bool,
    dek: &[u8; 32],
) -> anyhow::Result<Option<oneiron::VaultPageSeal>> {
    let path = &managed.data_dir;
    if oneiron::world_keys::vault_is_sealed(path)? {
        return Ok(Some(oneiron::world_keys::reopen_delivered_page_seal(
            path, dek,
        )?));
    }
    if !maximum_tier {
        return Ok(None);
    }
    if path.join("data.mdb").exists() {
        tracing::warn!(
            "the maximum tier is chosen when a vault is created; this plain vault opens plain"
        );
        return Ok(None);
    }
    Ok(Some(oneiron::world_keys::new_delivered_page_seal(
        path, dek,
    )?))
}

/// Hands each escrow capsule the outbox does not hold yet to the outbox the
/// supervisor named (CROSS-ARCH-0022 #ov-custody, invariant 03): the report
/// is written durably first and marked in the vault after, so a crash
/// between the two writes the same report again. The node ships it and
/// removes it only after the registry's durable acknowledgement. A capsule
/// that cannot be spooled waits for the next start; the vault still serves,
/// since the node holds the key it runs on.
///
/// Returns the report ids the outbox holds once this pass ends, spooled now
/// or before (a cold restore's receipt names each added recipient's), or
/// `None` without an outbox.
pub(super) fn spool_vault_key_escrow(
    vault: &oneiron::Vault,
    managed: &ManagedArgs,
) -> Option<BTreeSet<String>> {
    let outbox = managed.escrow_outbox.as_ref()?;
    let mut spooled = BTreeSet::new();
    let mut spool = || -> anyhow::Result<()> {
        for capsule in vault.vault_key_escrow_capsules()? {
            let Some((role @ ("managed" | "break-glass"), _)) = capsule.label.split_once('.')
            else {
                continue;
            };
            let report_id = blake3::hash(&capsule.capsule).to_hex().to_string();
            if capsule.spooled {
                spooled.insert(report_id);
                continue;
            }
            let report = oneiron_vault_contract::escrow::EscrowCapsuleReport {
                schema_version: oneiron_vault_contract::escrow::ESCROW_REPORT_SCHEMA_VERSION,
                report_type: oneiron_vault_contract::escrow::ESCROW_REPORT_TYPE.to_owned(),
                report_id: report_id.clone(),
                vault_name: managed.vault_name.clone(),
                vault_id: oneiron_vault_contract::hex(&capsule.vault_id),
                role: role.to_owned(),
                label: capsule.label.clone(),
                wrap_id: capsule.wrap_id.clone(),
                key_commitment: oneiron_vault_contract::hex(&capsule.commitment),
                capsule: oneiron_vault_contract::hex(&capsule.capsule),
                sealed_at: capsule.created_at,
            };
            oneiron_vault_contract::escrow::spool_escrow_report(outbox, &report)?;
            vault.mark_vault_key_escrow_spooled(&capsule.wrap_id, &capsule.capsule)?;
            spooled.insert(report_id);
        }
        Ok(())
    };
    if let Err(error) = spool() {
        tracing::warn!(%error, "an escrow capsule was not spooled; the next start spools it");
    }
    Some(spooled)
}
