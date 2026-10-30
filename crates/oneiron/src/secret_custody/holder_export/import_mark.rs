//! The owner's mark that he imported one export secret supplement (FIX
//! 12062), signed in the import's own writer: once its secret is restored
//! here, or found here already the same, this install, the recipient
//! machine the export named, carries his act to every install. Each stops
//! relaying the request's sealed copy on the window plane once it folds the
//! mark; every kept copy, and the owner's read of it, stay.

use crate::Vault;
use crate::authority::{
    ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityOp, EXPORT_ACT_TARGET_NAME,
    ExportSupplementImported, FrontierSigner, MAX_PARENTS, OwnerAct, OwnerActKind,
    invalid_authority, next_sequence, sign_side_entry,
};
use crate::error::{Error, Result};
use crate::policy_setting_doors::owner_act_target;
use crate::{EntityId, TimeRange};

impl Vault {
    /// Marks the supplement of the export secret request signed as entry
    /// `request` imported, in a savepoint of the import's writer `txn`,
    /// carried by this install for `actor`, the owner the import revalidated
    /// in it, from `surface`. Best effort: a fault is logged and leaves `txn`
    /// as it was, the import standing, and the request's rows ride on as
    /// before. A request already marked takes no second mark.
    pub(crate) fn mark_supplement_imported_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        request: AuthorityEntryHash,
    ) {
        let marked = self
            .store
            .env
            .nested_write_txn(txn)
            .map_err(Error::from)
            .and_then(|mut savepoint| {
                self.sign_import_mark_in_txn(&mut savepoint, actor, surface, request)?;
                savepoint.commit().map_err(Error::from)
            });
        if let Err(error) = marked {
            tracing::warn!(
                kind = ?error.kind(),
                "an imported export secret supplement was not marked; its rows ride on"
            );
        }
    }

    /// Signs and lands the mark in `txn`. Its parents are the main-log heads
    /// alone, which carry the request (FIX 4987). The fold is the judge: a
    /// mark it does not take refuses the savepoint.
    fn sign_import_mark_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        request: AuthorityEntryHash,
    ) -> Result<()> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.export_supplement_imported(&request) {
            return Ok(());
        }
        // Key possession: this install carries the act with its own install
        // key, under a live profile of any role (mesh contract §3).
        let (machine, signing) = self.owner_work_carrier_in_txn(txn, &fold)?.ok_or_else(|| {
            Error::InvalidConfig(
                "this install has no live machine profile to carry the owner's import mark"
                    .to_owned(),
            )
        })?;
        let public_key = signing.verifying_key().to_bytes();
        let act = OwnerAct::by_owner(
            actor,
            OwnerActKind::Export,
            owner_act_target(EXPORT_ACT_TARGET_NAME)?,
            surface,
            ExportSupplementImported::seen_for(request),
        );
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Install(machine, &signing);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let parents = fold.owner_work_parents();
        if parents.len() > MAX_PARENTS {
            return Err(invalid_authority());
        }
        let mark = ExportSupplementImported {
            carrier: machine,
            act,
            request,
        };
        let seq = next_sequence(&fold, &AuthorityKey::Ed25519(public_key))?;
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &signing,
            seq,
            parents,
            AuthorityOp::ExportSupplementImported(mark),
            now,
        )?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        if !self
            .authority_view_readonly_in_txn(txn)?
            .export_supplement_imported(&request)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}
