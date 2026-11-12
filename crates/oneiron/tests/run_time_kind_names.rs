//! Each compiled-in product kind a vault registers at run time reads by its
//! name through `Vault::entity_kind_name`, the one spelling every read of a
//! stored row's kind uses (FIX PROJECT-KIND-READS-TYPE-103): PROJECT and
//! PROJECT_REVISION, registered when the vault opens, and the CRM pack's
//! CAMPAIGN and SAVED_QUERY once registered. A byte no registration names
//! still reads as `TYPE_<byte>`. `project_kind_reads_by_name.rs` proves the
//! PROJECT spelling through the read verbs; no public door births a
//! PROJECT_REVISION row without the owner's signing ceremony.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_time_kind_names`

use oneiron::campaign::{CRM_PACK_ID, register_crm_pack};
use oneiron::registry::TypeByteFamily;
use oneiron::registry::pack_namespaces::{
    CAMPAIGN_SHORT_ID_PREFIX, PROJECT_PACK, PROJECT_REVISION_SHORT_ID_PREFIX,
    PROJECT_SHORT_ID_PREFIX, SAVED_QUERY_SHORT_ID_PREFIX,
};
use oneiron::{Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The kind name `vault` spells for its run-time registration of `pack` and
/// `short_id_prefix`.
fn spelled(vault: &Vault, pack: &str, short_id_prefix: &str) -> String {
    let registration = vault
        .structural_kind_registrations()
        .into_iter()
        .find(|row| row.pack == pack && row.short_id_prefix == short_id_prefix)
        .unwrap_or_else(|| panic!("the vault registers no {pack} kind under {short_id_prefix}"));
    vault.entity_kind_name(registration.type_byte)
}

#[test]
fn every_compiled_in_product_kind_reads_by_its_name() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(
        spelled(&vault, PROJECT_PACK, PROJECT_SHORT_ID_PREFIX),
        "PROJECT"
    );
    assert_eq!(
        spelled(&vault, PROJECT_PACK, PROJECT_REVISION_SHORT_ID_PREFIX),
        "PROJECT_REVISION"
    );
    register_crm_pack(&vault, 107, 108, TypeByteFamily::Productivity)?;
    assert_eq!(
        spelled(&vault, CRM_PACK_ID, CAMPAIGN_SHORT_ID_PREFIX),
        "CAMPAIGN"
    );
    assert_eq!(
        spelled(&vault, CRM_PACK_ID, SAVED_QUERY_SHORT_ID_PREFIX),
        "SAVED_QUERY"
    );
    Ok(())
}

#[test]
fn a_byte_no_registration_names_reads_as_its_number() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let named: Vec<u8> = vault
        .structural_kind_registrations()
        .iter()
        .map(|row| row.type_byte)
        .collect();
    let unnamed = (100..=127)
        .find(|byte| {
            !named.contains(byte) && oneiron::registry::entity_type_registry_entry(*byte).is_none()
        })
        .expect("a compiled-product byte neither the static registry nor this vault names");
    assert_eq!(vault.entity_kind_name(unnamed), format!("TYPE_{unnamed}"));
    Ok(())
}
