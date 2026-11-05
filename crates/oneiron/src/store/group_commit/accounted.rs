//! A native-accounted opaque writer on the ordinary arrival queue.

use super::*;

/// Declared before the native transaction so unwinding aborts it first. Settled
/// prefix vault handles stay here until this attempt finally passes the writer.
struct AccountedLeader<'s, 'v> {
    core: &'s Arc<StoreCore>,
    limits: Option<Limits>,
    preceding: Option<DetachedGroup<'v>>,
    detached: Option<DetachedGroup<'v>>,
}

impl Drop for AccountedLeader<'_, '_> {
    fn drop(&mut self) {
        self.core
            .group_commit
            .hand_off(self.limits.as_ref().map(|limits| (self.core, limits)));
        if let Some(detached) = self.detached.take() {
            detached.release();
        }
        if let Some(preceding) = self.preceding.take() {
            preceding.release();
        }
    }
}

impl Store {
    pub(super) fn solo_write_accounted<T, E>(
        &self,
        attempt: &NativeWriteAttempt,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        let mut txn = self.env.write_txn()?;
        txn.set_page_account(attempt.account())
            .map_err(Error::from)?;
        let rows = {
            let _known_index = crate::store::known_value_index::known_index_scope();
            write(&mut txn)
        };
        match rows {
            Rows::Commit(value) => {
                txn.commit().map_err(Error::from)?;
                attempt.mark_committed();
                Ok(value)
            }
            Rows::Refuse(error) => {
                txn.commit().map_err(Error::from)?;
                attempt.mark_committed();
                Err(error)
            }
            Rows::Discard(answer) => answer,
        }
    }

    pub(super) fn lead_accounted<T, E>(
        &self,
        attempt: &NativeWriteAttempt,
        write: impl FnOnce(&mut RwTxn<'_>) -> Rows<T, E>,
        closing: Option<&Vault>,
    ) -> std::result::Result<T, E>
    where
        E: From<Error>,
    {
        let mut leader = AccountedLeader {
            core: &self.core,
            limits: None,
            preceding: None,
            detached: Some(DetachedGroup::new(closing)),
        };
        let mut shared = self.env.write_txn()?;
        leader.limits = Some(Limits::read(self, &shared));
        let mut opened = Instant::now();
        self.core
            .run_queued_detached(&mut shared, leader.detached.as_mut().unwrap());
        if leader.detached.as_ref().unwrap().ran() > 0 {
            // These working writes precede ours. Commit them unaccounted without
            // handing off or releasing their held Vaults, then take a fresh root.
            self.core
                .settle_group(
                    shared,
                    leader.limits.as_ref().unwrap(),
                    opened,
                    (0, 0),
                    true,
                    None,
                    leader.detached.as_mut().unwrap(),
                    None,
                )
                .map_err(Error::from)?;
            leader.preceding = leader.detached.take();
            shared = self.env.write_txn()?;
            leader.limits = Some(Limits::read(self, &shared));
            leader.detached = Some(DetachedGroup::new(closing));
            opened = Instant::now();
        }
        shared
            .set_page_account(attempt.account())
            .map_err(Error::from)?;
        let (staged, mut refusals) = self.stage(&mut shared, write);
        match staged {
            Staged::Kept(answer) => {
                refusals.write_in(&mut shared);
                self.core
                    .settle_group(
                        shared,
                        leader.limits.as_ref().unwrap(),
                        opened,
                        (1, 1),
                        true,
                        Some(refusals),
                        leader.detached.as_mut().unwrap(),
                        Some(attempt),
                    )
                    .map_err(Error::from)?;
                answer
            }
            Staged::Dropped(answer) => {
                if refusals.write_in(&mut shared) {
                    refusals.landed(shared.commit().is_ok());
                } else {
                    drop(shared);
                }
                answer
            }
            Staged::Panicked(panic) => {
                drop(shared);
                resume_unwind(panic);
            }
        }
    }
}
