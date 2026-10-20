//! A world's keys and its ensure step on their executor, through the
//! holder's own read checks and the writer's own read-only plan (FIX 4686,
//! 5552): an owner's read that recomputes everything from this install's
//! durable state, so a restart changes no answer. Nothing is minted,
//! wrapped, written or raised.
//!
//! The writer appends each key's wraps in id order, each later record naming
//! the one before it; the ensure step's records follow. So a key's first
//! record names the signer's previous row of the world this snapshot holds
//! until some earlier key appends, and from then on a row the door writes
//! first ([`ChainHead::Planned`]), one more parent.

use super::super::super::MachineSecret;
use super::super::super::doors::ChainHead;
use super::super::super::reassert::{HeldKey, HolderRead};
use super::{
    EnsureDiagnostics, EnsureView, REASSERT_DIAGNOSTICS_PAGE, ReassertDiagnostics, ReassertKey,
    ReassertKeyState, ReassertUnread,
};
use crate::authority::{AuthorityEntryHash, WorldKeyId};
use crate::error::Result;
use crate::{EntityId, Vault};

/// Why a diagnostics read has no holder read: the world reads everywhere
/// (`None`), or the read checks could not run.
type NoHolderRead = Option<ReassertUnread>;

impl Vault {
    /// One page of `world`'s keys from `offset` for the re-assertion signed
    /// as entry `request`: the ids its records name, then the fold's other
    /// keys of the world as unknown history, ascending by id; and the ensure
    /// step that follows.
    pub(super) fn reassert_diagnostics(
        &self,
        request: AuthorityEntryHash,
        world: EntityId,
        offset: usize,
    ) -> Result<ReassertDiagnostics> {
        let mut out = ReassertDiagnostics::empty(world, self.world_keys.frontier_raised(world));
        let Ok(secret) = self.machine_secret_outside_txn() else {
            out.unread = Some(ReassertUnread::NoMachineSecret);
            return Ok(out);
        };
        let txn = self.store.env.read_txn()?;
        let read = match self.diagnostics_holder_read(&txn, world, &secret)? {
            Ok(read) => read,
            Err(None) => {
                out.reads_everywhere = true;
                return Ok(out);
            }
            Err(unread) => {
                out.unread = unread;
                return Ok(out);
            }
        };
        let mut every: Vec<WorldKeyId> = read
            .fold
            .all_world_keys()
            .map(|key| key.id)
            .filter(|id| id.world == world)
            .chain(read.ids.iter().copied())
            .collect();
        every.sort_unstable();
        every.dedup();
        let head = read.chain_head();
        let mut first_append = None;
        for id in &read.ids {
            let state = self.planned_key_state(&read, &txn, &secret, (*id, request), head)?;
            if matches!(state, ReassertKeyState::WrapsPending { .. }) {
                first_append = Some(*id);
                break;
            }
        }
        let chain = |id: &WorldKeyId| match first_append {
            Some(first) if first < *id => ChainHead::Planned,
            Some(_) | None => head,
        };
        for id in every.iter().skip(offset).take(REASSERT_DIAGNOSTICS_PAGE) {
            let state = if read.ids.contains(id) {
                self.planned_key_state(&read, &txn, &secret, (*id, request), chain(id))?
            } else {
                ReassertKeyState::UnknownHistory
            };
            out.keys.push(ReassertKey { key: *id, state });
        }
        let end = offset.saturating_add(REASSERT_DIAGNOSTICS_PAGE);
        out.next_offset = (end < every.len()).then_some(end);
        let after = if first_append.is_some() {
            ChainHead::Planned
        } else {
            head
        };
        out.ensure = Some(self.ensure_view(&read, &txn, &secret, (world, request), after)?);
        Ok(out)
    }

    /// The ensure step of the Ensure request signed as entry `request` for
    /// `world`.
    pub(super) fn ensure_diagnostics(
        &self,
        request: AuthorityEntryHash,
        world: EntityId,
    ) -> Result<EnsureDiagnostics> {
        let mut out = EnsureDiagnostics {
            world,
            unread: None,
            reads_everywhere: false,
            question_raised: self.world_keys.frontier_raised(world),
            ensure: None,
        };
        let Ok(secret) = self.machine_secret_outside_txn() else {
            out.unread = Some(ReassertUnread::NoMachineSecret);
            return Ok(out);
        };
        let txn = self.store.env.read_txn()?;
        match self.diagnostics_holder_read(&txn, world, &secret)? {
            Ok(read) => {
                let head = read.chain_head();
                out.ensure =
                    Some(self.ensure_view(&read, &txn, &secret, (world, request), head)?);
            }
            Err(None) => out.reads_everywhere = true,
            Err(unread) => out.unread = unread,
        }
        Ok(out)
    }

    /// This install's holder read of `world`, or why there is none.
    fn diagnostics_holder_read(
        &self,
        txn: &heed::RoTxn<'_>,
        world: EntityId,
        secret: &MachineSecret,
    ) -> Result<std::result::Result<HolderRead, NoHolderRead>> {
        match self.holder_read_in_txn(txn, world, secret) {
            Ok(Some(read)) => Ok(Ok(read)),
            Ok(None) => Ok(Err(None)),
            Err(crate::Error::Secret(crate::error::SecretError::WorldKeyRefused(_))) => {
                Ok(Err(Some(ReassertUnread::NotMineReader)))
            }
            Err(error) => Err(error),
        }
    }

    /// The key `id`'s state on `read`, the wraps it lacks planned for
    /// `request` as the writer plans them, its first record naming `chain`.
    fn planned_key_state(
        &self,
        read: &HolderRead,
        txn: &heed::RoTxn<'_>,
        secret: &MachineSecret,
        (id, request): (WorldKeyId, AuthorityEntryHash),
        chain: ChainHead,
    ) -> Result<ReassertKeyState> {
        Ok(match read.check(&self.store, txn, id, secret)? {
            HeldKey::Conflicted => ReassertKeyState::Conflicted,
            HeldKey::MissingPad => ReassertKeyState::MissingPad,
            HeldKey::NoOpening => ReassertKeyState::NoOpeningRecordOrWrap,
            HeldKey::Opened { missing, .. } if missing.is_empty() => ReassertKeyState::Wrapped,
            HeldKey::Opened { missing, .. } => {
                let asked = (secret.machine, Some(request));
                if read.wraps_wide(self, txn, asked, &missing, chain)? {
                    ReassertKeyState::FrontierNeedsSplit
                } else {
                    ReassertKeyState::WrapsPending {
                        missing: missing.len(),
                    }
                }
            }
        })
    }

    /// The ensure step on `read` for `request`: the world's current key as
    /// [`Self::planned_key_state`] finds it, or, with none here, the first key
    /// it would mint, wrapped to every recipient the settings allow.
    fn ensure_view(
        &self,
        read: &HolderRead,
        txn: &heed::RoTxn<'_>,
        secret: &MachineSecret,
        (world, request): (EntityId, AuthorityEntryHash),
        chain: ChainHead,
    ) -> Result<EnsureView> {
        let Some(id) = read.fold.current_world_key(world).map(|current| current.id) else {
            let allowed = read.allowed();
            let asked = (secret.machine, Some(request));
            let state = if read.wraps_wide(self, txn, asked, &allowed, chain)? {
                ReassertKeyState::FrontierNeedsSplit
            } else {
                ReassertKeyState::WrapsPending {
                    missing: allowed.len(),
                }
            };
            return Ok(EnsureView { key: None, state });
        };
        let state = self.planned_key_state(read, txn, secret, (id, request), chain)?;
        Ok(EnsureView {
            key: Some(id),
            state,
        })
    }
}
