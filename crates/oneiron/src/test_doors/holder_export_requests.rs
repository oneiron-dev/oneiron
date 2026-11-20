//! The owner's export secret request (FIX 4624(b)) for a custody secret the
//! fold proves an install holds, recorded by this install as an owner
//! export's audit write records one, for the tests of the owner's supplement
//! import mark (`authority_log_owner_reserve_import_mark`). No export here
//! met the secret unopened, so the test names the secret, its generation and
//! the recipient machine itself; the request carries the owner's own export
//! act, and the fold names its holder as every export secret request's.

use crate::authority::{
    ActSurface, AuthorityEntryHash, EXPORT_ACT_SEEN, EXPORT_ACT_TARGET_NAME, ExportSecretWork,
    OwnerWorkBody,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// Records, carried by this install, the owner's export secret request for
/// the secret `secret` at custody generation `generation`, its sealed copy
/// for the machine `recipient`, by the owner `owner` revalidated in the
/// writer, as the owner export's own door records it. Returns the request's
/// entry.
///
/// # Errors
/// The recipient is no linked install with a permit here, no install holds
/// the secret at that generation (nothing is written), or the write's own.
pub fn record_export_secret_request(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    secret: EntityId,
    generation: u32,
    recipient: EntityId,
) -> Result<AuthorityEntryHash> {
    vault.with_write_txn(|txn| {
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        let permit = crate::secret_custody::holder_export::recipient_permit(&fold, recipient)
            .ok_or_else(|| {
                Error::InvalidConfig("the recipient has no custody permit here".to_owned())
            })?;
        drop(fold);
        let work = OwnerWorkBody::ExportSecret(ExportSecretWork {
            secret,
            generation,
            export: EntityId::now(),
            digest: None,
            export_act: None,
            recipient: permit,
        });
        let receipt = vault.record_owner_work_in_txn(
            txn,
            owner,
            ActSurface::ThisInstall,
            crate::policy_setting_doors::owner_act_target(EXPORT_ACT_TARGET_NAME)?,
            EXPORT_ACT_SEEN,
            work,
        )?;
        receipt
            .request
            .as_deref()
            .and_then(oneiron_verb_wire::authority::export_secret_work::entry_of_hex)
            .ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "no install holds the secret: {:?}",
                    receipt.unassigned
                ))
            })
    })
}
