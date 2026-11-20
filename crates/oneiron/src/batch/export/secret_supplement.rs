//! The owner's import of one export secret supplement (FIX 4624(b)): the
//! custody secret an owner export carried as its handle, its holder having
//! sealed it to the recipient the owner chose and that recipient having
//! opened it (`crate::secret_custody::holder_export`).
//!
//! The opened supplement is the archive row the export would have carried
//! with its value, so it takes the archive import's own custody restore: the
//! row's name, metadata and body must agree; a record already here under its
//! id, the same as the supplement's, is unchanged; one the comparison cannot
//! read stays as it is, skipped; any other is a collision, refused, never
//! overwritten. A record an admitted revoke ended is skipped.
//!
//! Once its secret is restored, or found here already the same, the import
//! marks the request imported in its own writer (FIX 12062), so no install
//! relays the sealed copy any more. A skipped or refused import marks
//! nothing. A mark this install cannot sign there stays owed, value-free,
//! and a later pass signs it (FIX 12291); only a failure to file that intent
//! refuses the import. The owner's own import, his undelegated, unnarrowed
//! proof revalidated in that writer as his own write, lends the mark that
//! write, so the mark carries the owner key's proof this install holds (row
//! OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS); a narrowed or delegated
//! proof, or one bound to a request's slip, marks it unproven, as before.

use base64::Engine as _;
use zeroize::Zeroizing;

use super::document_import::parse_id;
use crate::Vault;
use crate::batch::export::secret_supplement_record::{
    OpenedSecretSupplement, SecretSupplementImport,
};
use crate::consent::{AuthenticatedOwner, OwnerAuthoredWrite};
use crate::error::{Error, Result};
use crate::secret_custody::archive_same_custody_in_txn;
use crate::secret_record::ArchiveSameId;
use oneiron_authority::authority::ActSurface;

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("secret supplement import: {reason}"))
}

/// The owner's own write of this import, his proof `owner` revalidated in
/// the import's writer `txn` ([`AuthenticatedOwner::owner_answer_in_txn`]):
/// the import mark then carries the owner key's proof. A narrowed or
/// delegated proof, or one that does not read (logged), marks it unproven;
/// the import stands either way.
fn owner_authored_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> Option<OwnerAuthoredWrite> {
    owner
        .owner_answer_in_txn(vault, txn)
        .unwrap_or_else(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "secret supplement import: the owner's proof did not read; its mark is carried unproven"
            );
            None
        })
}

impl Vault {
    /// Restores the custody secret `supplement` carries into this vault,
    /// for `owner`, revalidated as a live vault owner in the import's own
    /// writer, through the archive import's custody restore, his act made
    /// from `surface`. Its value is wiped once the write is done, whatever
    /// it came to.
    pub fn import_secret_supplement(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        supplement: &OpenedSecretSupplement,
    ) -> Result<SecretSupplementImport> {
        let row = &supplement.row;
        let id = parse_id(&row.id)?;
        if row.metadata.name != row.name {
            return Err(invalid("its name disagrees with its metadata"));
        }
        let Some(body) = &row.body else {
            return Err(invalid("it carries no value"));
        };
        let body = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .map_err(|_| invalid("its body is not base64"))?,
        );
        let mut record = crate::secret_record::decode_secret_custody_body(&body)?;
        if record.metadata() != row.metadata {
            zeroize::Zeroize::zeroize(&mut record.value_bytes);
            return Err(invalid("its body disagrees with its metadata"));
        }
        // The install key that signs the import mark loads before the writer
        // opens; without it the mark stays owed, and the import stands.
        let _ = self.load_install_signing_if_minted();
        let imported = self.with_write_txn(|wtxn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, wtxn)?;
            let outcome = if let Some(existing) =
                crate::ports::EntityStoreRead::port_entity_raw(&self.store, wtxn, &id)?
            {
                match archive_same_custody_in_txn(&self.store, &id, &existing, &record) {
                    ArchiveSameId::Same => SecretSupplementImport::Unchanged,
                    ArchiveSameId::Pending => SecretSupplementImport::Skipped,
                    ArchiveSameId::Different => {
                        return Err(invalid(
                            "its id collides with a different custody record here; nothing was \
                             overwritten",
                        ));
                    }
                }
            } else if crate::secret_custody::restore_secret_custody_in_txn(
                self,
                wtxn,
                &id,
                &mut record,
            )? {
                SecretSupplementImport::Restored
            } else {
                SecretSupplementImport::Skipped
            };
            let marked = if matches!(
                outcome,
                SecretSupplementImport::Restored | SecretSupplementImport::Unchanged
            ) {
                let owner_authored = owner_authored_in_txn(self, wtxn, owner);
                self.mark_supplement_imported_in_txn(
                    wtxn,
                    actor,
                    surface,
                    supplement.request,
                    owner_authored.as_ref(),
                )?
            } else {
                false
            };
            Ok((outcome, marked))
        });
        zeroize::Zeroize::zeroize(&mut record.value_bytes);
        let (outcome, marked) = imported?;
        // A mark this writer signed rides the live windows now, so their
        // relayed copies leave (FIX 12291).
        #[cfg(feature = "sync")]
        if marked {
            self.refresh_custody_in_live_windows();
        }
        #[cfg(not(feature = "sync"))]
        let _ = marked;
        Ok(outcome)
    }
}
