//! Managed vault open gates: credentials, the canary marker, and the DEK MAC.

use std::os::fd::{FromRawFd, RawFd};
use std::path::Path;

use oneiron_vault_contract::{Credentials, DEK_LEN, read_credentials};
use subtle::ConstantTimeEq;

use super::args::ManagedError;

/// Marks a vault as a synthetic canary: the only thing a contract-v1 managed
/// open will accept in place of the (unimplemented) hardened-tenant
/// preconditions.
pub const CANARY_MARKER_KEY: &str = "managed:canary:v1";

/// Value the canary marker row must carry, so a blank or truncated row is not
/// mistaken for consent.
pub const CANARY_MARKER_VALUE: &[u8] = b"managed:canary:v1";

/// Keyed MAC of the vault's `vault_meta` head page under the delivered DEK.
pub const DEK_MAC_KEY: &str = "managed:dek_mac:v1";

/// Domain separator for the DEK MAC, so the same DEK over the same bytes in
/// another role cannot collide with this one.
const DEK_MAC_CONTEXT: &[u8] = b"oneiron:managed:dek_mac:v1";

/// Reads the 64-byte DEK ‖ spawn-token frame from the inherited fd.
///
/// Fail-closed: a short, long or unreadable frame is a typed refusal, never a
/// fallback to some other credential source. Called before the data directory
/// is opened, as the contract requires.
pub fn read_managed_credentials(fd: RawFd) -> Result<Credentials, ManagedError> {
    // SAFETY: `fd` arrives on argv (`--credentials-fd`) through the
    // supervisor's spawn contract and is this process's to own. The `File`
    // takes it over exactly once and closes it on drop, which is also what
    // lets the contract's EOF check terminate once the supervisor's write end
    // is gone.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    read_credentials(file).map_err(|error| ManagedError::CredentialsRejected {
        reason: error.to_string(),
    })
}

/// Canonical bytes of the vault's `vault_meta` head page: the identity rows
/// the storage layer stamps at open (storage ABI, schema, text-index
/// identity), read back through the vault's own integrity report.
///
/// This is what the DEK MAC covers. It is stable across content writes and
/// changes only when the vault's storage identity does, so a wrong DEK is
/// caught by a MAC over metadata rather than by decrypting user content.
fn vault_meta_head_page(vault: &oneiron::Vault) -> Result<Vec<u8>, ManagedError> {
    let report = vault
        .doctor()
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    let abi = report.storage_abi_version;
    let schema = report.storage_schema_version;
    let analyzer = report.analyzer_manifest_hash.as_deref().unwrap_or_default();
    let bm25 = report.bm25_field_schema_hash.as_deref().unwrap_or_default();
    let text_schema = report.text_index_schema_version;
    let page = format!(
        "oneiron:vault_meta:head:v1\nstorage_abi_version={abi:?}\nstorage_schema_version={schema:?}\nanalyzer_manifest_hash={analyzer}\nbm25_field_schema_hash={bm25}\ntext_index_schema_version={text_schema:?}\n"
    );
    Ok(page.into_bytes())
}

fn canary_marker_present(vault: &oneiron::Vault) -> Result<bool, ManagedError> {
    let row = vault
        .sync_state_get(CANARY_MARKER_KEY)
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    Ok(row.is_some_and(|raw| raw.as_slice() == CANARY_MARKER_VALUE))
}

/// The waiver's other half: an fscrypt policy on the data directory AND a
/// dedicated per-vault UID owning it.
///
/// Neither is implemented in contract v1 and neither can be probed here, so
/// this is a constant `false` on purpose. Making it a named function rather
/// than an inline `false` is what keeps the missing work addressable: when the
/// preconditions land, this is the one place that learns to say yes, and the
/// canary marker stops being the only way through.
fn hardened_tenant_preconditions_present(_vault: &oneiron::Vault) -> bool {
    false
}

/// Verifies the delivered DEK against the vault's sealed MAC, or seals it on
/// a vault that has never been opened in managed mode.
///
/// Runs before any content is read: a supervisor that hands over the wrong DEK
/// finds out from a metadata MAC, not from garbled user data.
fn verify_or_seal_dek_mac(
    vault: &oneiron::Vault,
    vault_name: &str,
    dek: &[u8; DEK_LEN],
) -> Result<(), ManagedError> {
    let head = vault_meta_head_page(vault)?;
    let mut covered = Vec::with_capacity(DEK_MAC_CONTEXT.len() + head.len());
    covered.extend_from_slice(DEK_MAC_CONTEXT);
    covered.extend_from_slice(&head);
    let mac = blake3::keyed_hash(dek, &covered);

    let stored = vault
        .sync_state_get(DEK_MAC_KEY)
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    match stored {
        Some(stored) => {
            // Constant time: a supervisor probing DEKs must not learn how many
            // leading MAC bytes it got right.
            if bool::from(stored.as_slice().ct_eq(mac.as_bytes().as_slice())) {
                Ok(())
            } else {
                Err(ManagedError::DekMacMismatch {
                    vault: vault_name.to_owned(),
                    key: DEK_MAC_KEY,
                })
            }
        }
        None => {
            vault
                .sync_state_put(DEK_MAC_KEY, mac.as_bytes())
                .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
            Ok(())
        }
    }
}

/// The managed open gates, in fail-closed order: the waiver gate first, then
/// the DEK MAC. Both run before any content is read.
///
/// The credential gate has already passed by the time a caller holds
/// `credentials` — [`read_managed_credentials`] is the only way to get one.
pub fn check_managed_open_gates(
    vault: &oneiron::Vault,
    vault_name: &str,
    credentials: &Credentials,
) -> Result<(), ManagedError> {
    if !canary_marker_present(vault)? && !hardened_tenant_preconditions_present(vault) {
        return Err(ManagedError::ManagedRealTenantRefused {
            vault: vault_name.to_owned(),
            marker: CANARY_MARKER_KEY,
        });
    }
    verify_or_seal_dek_mac(vault, vault_name, &credentials.dek)
}

/// Opens the vault for managed mode and runs the open gates over it.
pub fn open_managed_vault(
    data_dir: &Path,
    vault_config: oneiron::VaultConfig,
    vault_name: &str,
    credentials: &Credentials,
) -> Result<oneiron::Vault, ManagedError> {
    let vault = oneiron::Vault::open(data_dir, vault_config)
        .map_err(|error| ManagedError::VaultMeta(error.to_string()))?;
    check_managed_open_gates(&vault, vault_name, credentials)?;
    Ok(vault)
}
