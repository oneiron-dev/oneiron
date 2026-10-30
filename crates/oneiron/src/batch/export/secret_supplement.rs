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
//! nothing, and a mark that fails leaves the import standing.

use base64::Engine as _;
use zeroize::Zeroizing;

use super::document_import::parse_id;
use crate::Vault;
use crate::authority::{ActSurface, OpenedSecretSupplement, SecretSupplementImport};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::secret_custody::{ArchiveSameId, archive_same_custody_in_txn};

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("secret supplement import: {reason}"))
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
        let mut record = crate::secret_custody::decode_secret_custody_body(&body)?;
        if record.metadata() != row.metadata {
            zeroize::Zeroize::zeroize(&mut record.value_bytes);
            return Err(invalid("its body disagrees with its metadata"));
        }
        // The install key that signs the import mark loads before the writer
        // opens; without it the mark is not signed, and the import stands.
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
            if matches!(
                outcome,
                SecretSupplementImport::Restored | SecretSupplementImport::Unchanged
            ) {
                self.mark_supplement_imported_in_txn(wtxn, actor, surface, supplement.request);
            }
            Ok(outcome)
        });
        zeroize::Zeroize::zeroize(&mut record.value_bytes);
        imported
    }
}
