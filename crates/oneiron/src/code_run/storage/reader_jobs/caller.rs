//! The latest actual parent entry's destination (FIX 1837), not its first
//! spawn's destination. These are recipient data, never credentials.

use super::*;
use crate::code_run::ReaderActor;
use crate::settings::ReadDestination;

#[derive(serde::Serialize, serde::Deserialize)]
struct ParentCaller {
    actor: ReaderActor,
    host: Option<EntityId>,
    route: ReaderRoute,
    destination: ReadDestination,
}

impl RawValue for ParentCaller {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex("code-run parent caller").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("code-run parent caller").into())
    }
}

const CALLERS: SideTable<EntityId, ParentCaller, Raw> =
    SideTable::new(&side_table::CODE_RUN_READER_CALLER);

impl ReaderJobs<'_> {
    /// The route this run's reader rows actually use.
    #[must_use]
    pub fn route(&self) -> ReaderRoute {
        ReaderRoute {
            vault: crate::code_run::vault_ref(self.storage.vault_id()),
            session_ref: self.storage.session_ref().map(str::to_owned),
            participant: self.storage.participant(),
        }
    }

    /// Overwrites the actual last entry, even when this install cannot
    /// qualify a host. Hosts serialize this commit with their live update.
    /// No keystore is loaded or identity minted here.
    pub fn note_parent_caller(
        &self,
        run: EntityId,
        actor: ReaderActor,
        destination: &ReadDestination,
    ) -> Result<()> {
        self.storage.reader_txn(|tx| {
            let vault = tx.spend.0;
            if crate::code_run::actor_gone_in_txn(vault, tx.txn, &actor.entity) {
                CALLERS.delete(&tx.write, tx.txn, &run)?;
                return Ok(());
            }
            let host = crate::store::install_identity::loaded_signer_in_txn(vault, tx.txn)
                .ok()
                .map(|signer| signer.machine);
            tx.put_row(
                &CALLERS,
                &run,
                &ParentCaller {
                    actor,
                    host,
                    route: self.route(),
                    destination: destination.clone(),
                },
            )
        })
    }

    /// The last destination only on its actual route, for its actual actor,
    /// on the same loaded install. Every read still rejudges its peer keys
    /// and worlds through the existing recipient judge.
    pub fn parent_caller(
        &self,
        run: EntityId,
        actor: ReaderActor,
    ) -> Result<Option<ReadDestination>> {
        self.storage.reader_read(|txn, dbs| {
            let vault = self.storage.spend_book().0;
            if crate::code_run::actor_gone_in_txn(vault, txn, &actor.entity) {
                return Ok(None);
            }
            let Some(note) = CALLERS.get(&dbs, txn, &run)? else {
                return Ok(None);
            };
            let host = crate::store::install_identity::loaded_signer_in_txn(vault, txn)
                .ok()
                .map(|signer| signer.machine);
            Ok((host.is_some()
                && host == note.host
                && note.actor == actor
                && note.route == self.route())
            .then_some(note.destination))
        })
    }
}

pub(crate) fn erase_reader_caller_actor_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for (run, note) in CALLERS.scan(&vault.store, txn)? {
        if note.actor.entity == *actor {
            retire_reader_caller_in_txn(vault, txn, run)?;
        }
    }
    Ok(())
}

fn retire_reader_caller_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, run: EntityId) -> Result<()> {
    let place = format!("side:{}", CALLERS.decl().name);
    let origin = crate::batch::secret_scan::side_row_origin(&place, &CALLERS.key_bytes(&run))?;
    crate::secret_custody::revoke_side_row_custody_in_txn(vault, txn, &origin, None)?;
    CALLERS.delete(&vault.store, txn, &run)?;
    Ok(())
}
