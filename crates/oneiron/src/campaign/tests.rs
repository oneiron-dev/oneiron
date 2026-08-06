use super::*;
use crate::config::VaultConfig;
use crate::error::{Error, ErrorKind};
use crate::registry::{
    TYPE_BYTE_BAND_COMPANION_START, TYPE_BYTE_BAND_CRM_END, TYPE_BYTE_BAND_CRM_START, band_of,
    entity_type_registry_entry,
};
use crate::temporal::TimeRange;
use crate::vault::Vault;

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

/// A free CRM-band byte, derived from the band constants rather than written as
/// a literal. `nth` indexes forward from the band start so a test can ask for a
/// second, distinct byte without either test carrying an inline number — the
/// property this ticket's static-byte oracle enforces.
///
/// Panics if the requested slot leaves the band or is already claimed by a
/// static registry row, so a future band or registry change fails loudly here
/// instead of silently retargeting an oracle.
fn crm_band_byte(nth: u8) -> u8 {
    let byte = TYPE_BYTE_BAND_CRM_START
        .checked_add(nth)
        .expect("CRM band offset must not wrap");
    assert!(
        byte <= TYPE_BYTE_BAND_CRM_END,
        "offset {nth} leaves the CRM band"
    );
    assert!(
        entity_type_registry_entry(byte).is_none(),
        "CRM-band byte {byte} is statically registered; pick another free slot"
    );
    byte
}

#[test]
fn campaign_kind_registers_runtime_assigned_crm_byte() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault();
    let assigned = crm_band_byte(0);

    let registration = register_campaign_kind(&vault, assigned)?;

    assert_eq!(registration.type_byte, assigned);
    assert_eq!(registration.band, TypeByteBand::Crm);
    assert_eq!(registration.short_id_prefix, CAMPAIGN_SHORT_ID_PREFIX);
    assert_eq!(registration.pack, CRM_PACK_ID);

    let persisted = vault
        .structural_kind_registration(assigned)
        .expect("registration must be readable from the vault registry");
    assert_eq!(persisted, registration);
    Ok(())
}

#[test]
fn campaign_kind_registration_persists_across_reopen() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let assigned = crm_band_byte(0);

    let registered = {
        let vault = Vault::open(dir.path(), VaultConfig::device())?;
        register_campaign_kind(&vault, assigned)?
    };

    let reopened = Vault::open(dir.path(), VaultConfig::device())?;
    let persisted = reopened
        .structural_kind_registration(assigned)
        .expect("registration must load from vault_meta on reopen");

    assert_eq!(
        persisted, registered,
        "reopen must recover the registration verbatim without re-registering"
    );
    assert_eq!(
        reopened.structural_kind_registrations(),
        vec![registered],
        "reopen must surface exactly one dynamic row for the CRM pack"
    );
    Ok(())
}

#[test]
fn campaign_kind_rejects_non_crm_assignment() {
    let (_dir, vault) = open_test_vault();
    // Companion band: a valid byte for some pack, but not for CAMPAIGN's
    // declared `Crm` band.
    let out_of_band = TYPE_BYTE_BAND_COMPANION_START;
    assert_ne!(band_of(out_of_band), TypeByteBand::Crm);

    let error = register_campaign_kind(&vault, out_of_band)
        .expect_err("a byte outside the CRM band must be refused");

    assert_eq!(error.kind(), ErrorKind::StructuralKindBandViolation);
    match error {
        Error::StructuralKindBandViolation {
            type_byte,
            declared_band,
            actual_band,
            ..
        } => {
            assert_eq!(type_byte, out_of_band);
            assert_eq!(declared_band, TypeByteBand::Crm);
            assert_eq!(actual_band, band_of(out_of_band));
        }
        other => panic!("expected a band violation, got {other:?}"),
    }
    assert!(
        vault.structural_kind_registrations().is_empty(),
        "a refused registration must leave no row behind"
    );
}

#[test]
fn campaign_kind_rejects_prefix_or_byte_collision() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault();
    let campaign_byte = crm_band_byte(0);
    let free_byte = crm_band_byte(1);

    // Byte collision: something else already holds CAMPAIGN's assigned byte.
    vault.register_structural_kind(campaign_byte, "cq", TypeByteBand::Crm, "other-pack")?;
    let byte_error = register_campaign_kind(&vault, campaign_byte)
        .expect_err("a taken byte must be refused by the existing registration path");
    assert_eq!(byte_error.kind(), ErrorKind::StructuralKindCollision);
    assert!(
        matches!(byte_error, Error::StructuralKindTypeByteCollision(byte) if byte == campaign_byte),
        "byte collision must surface the existing type-byte variant"
    );

    // Prefix collision: `ca` is already claimed on a different free byte.
    let (_prefix_dir, prefix_vault) = open_test_vault();
    prefix_vault.register_structural_kind(
        campaign_byte,
        CAMPAIGN_SHORT_ID_PREFIX,
        TypeByteBand::Crm,
        "other-pack",
    )?;
    let prefix_error = register_campaign_kind(&prefix_vault, free_byte)
        .expect_err("a taken short-id prefix must be refused");
    assert_eq!(prefix_error.kind(), ErrorKind::StructuralKindCollision);
    assert!(
        matches!(
            prefix_error,
            Error::StructuralKindPrefixCollision(ref prefix) if prefix == CAMPAIGN_SHORT_ID_PREFIX
        ),
        "prefix collision must surface the existing prefix variant"
    );
    Ok(())
}

#[test]
fn campaign_short_id_uses_ca_prefix() -> crate::Result<()> {
    let (_dir, vault) = open_test_vault();
    let assigned = crm_band_byte(0);
    register_campaign_kind(&vault, assigned)?;

    let id = crate::test_util::entity(0x5C);
    vault.put_entity(
        &id,
        assigned,
        TimeRange { start: 1, end: 1 },
        2,
        b"campaign",
    )?;

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .short_ids_reverse
        .get(&rtxn, id.as_bytes())?
        .expect("a registered kind must mint a short id on write");
    let (short_id, _content_hash) = crate::batch::parse_short_id_value(&raw)?;

    assert!(
        short_id.starts_with(CAMPAIGN_SHORT_ID_PREFIX),
        "short id {short_id:?} must resolve through the persisted `ca` registration"
    );
    assert_eq!(
        short_id,
        format!("{CAMPAIGN_SHORT_ID_PREFIX}1"),
        "the first CAMPAIGN entity must take counter 1 in the `ca` namespace"
    );
    Ok(())
}
