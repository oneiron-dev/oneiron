//! The weave Admin's digest namespace (OF-499 A3): its key, its saved and
//! newest period read, its kept live render, and the person binding a hard
//! delete finds it by. Also the per-reader namespace helpers the Admin's
//! `d` tag joins: a reader's whole namespace erased by its stem, and its
//! newest period found by its keys.
//!
//! The namespace keys on the exact membership grant, so two Admin grants
//! never share a period or a live render, and the same human's Person,
//! Owner and Admin rows never overwrite each other. Its person rides beside
//! the grant as the policy holder, recipient, label author and budget
//! subject. Foreground only: no Admin schedule, background render or
//! attempt exists, and a stored Admin tag never stands in for its proof.
use super::super::weave_report::admin::{WeaveAdminFrame, weave_admin_read_txn};
use super::super::{ScopedRead, WeaveReader, WeaveReport};
use super::{
    DIGEST_PREFIX, KeptLiveLens, LIVE_PREFIX, SCHEDULE_PREFIX, StoredWeaveDigest,
    WeaveDigestReader, WeaveLensRender, digest_row_in, erase_weave_digest_in_txn,
    index_source_in_txn, invalid, put_digest_row_in_txn, settle_live_weave_lens,
};
use crate::authority::AuthenticatedWeaveAdmin;
use crate::error::Result;
use crate::store::Store;
use crate::{EntityId, Vault};

/// The Admin namespace's tag (CALLS `OF-499 A3 admin key`): `d`, beside a
/// person's `p`, an owner's `o` and an agent's `a`. Its keys carry the
/// exact membership grant where the others carry the reader.
pub(super) const ADMIN_TAG: &str = "d";

/// A weave Admin's digest identity (OF-499 A3): its person and its exact
/// Admin membership grant, taken from a proof its read checked. The grant
/// keys the Admin's namespace; the person is its policy holder, recipient,
/// label author and budget subject. Identity only: it reads nothing and
/// authenticates no one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeaveAdminKey {
    actor: EntityId,
    membership_grant: EntityId,
}

impl WeaveAdminKey {
    /// The key of `admin`'s proof. Every use of it sits behind that proof's
    /// revalidation in the same transaction.
    pub(in crate::claim::scoped_read) fn of(admin: &AuthenticatedWeaveAdmin) -> Self {
        Self {
            actor: admin.actor(),
            membership_grant: admin.membership_grant(),
        }
    }

    /// The Admin's person.
    #[must_use]
    pub fn actor(self) -> EntityId {
        self.actor
    }

    /// The exact Admin membership grant its namespace keys on.
    #[must_use]
    pub fn membership_grant(self) -> EntityId {
        self.membership_grant
    }
}

impl WeaveDigestReader {
    /// The Admin membership grant this reader's labels and evidence file
    /// under: an Admin's own; `None` for every other reader, whose labels
    /// name none.
    pub(in crate::claim::scoped_read) fn admin_grant(self) -> Option<EntityId> {
        match self {
            Self::Admin(key) => Some(key.membership_grant),
            Self::Person(_) | Self::Owner(_) | Self::Agent(_) => None,
        }
    }
}

/// The stem of `grant`'s Admin namespace: a hard delete of the grant takes
/// it whole.
pub(super) fn grant_stem(grant: &EntityId) -> Vec<u8> {
    [ADMIN_TAG.as_bytes(), grant.as_bytes()].concat()
}

/// The Admin namespace a person's binding entry names, when `indexed` is
/// one: the Admin's live key, given as its stem (tag and grant). Every
/// other entry names a saved period.
pub(super) fn bound_admin_stem(indexed: &[u8]) -> Option<&[u8]> {
    indexed
        .strip_prefix(LIVE_PREFIX)
        .filter(|stem| stem.len() == 1 + 16 && stem.starts_with(ADMIN_TAG.as_bytes()))
}

/// Deletes one reader's saved periods, schedule and kept live render, by
/// `stem`, its tag byte and the id its namespace keys on.
pub(super) fn erase_reader_rows_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    stem: &[u8],
) -> Result<()> {
    let periods = store
        .vault_meta
        .prefix_iter(&*txn, &[DIGEST_PREFIX, stem].concat())?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    for digest_key in periods {
        erase_weave_digest_in_txn(store, txn, &digest_key)?;
    }
    store
        .vault_meta
        .delete(txn, &[SCHEDULE_PREFIX, stem].concat())?;
    store
        .vault_meta
        .delete(txn, &[LIVE_PREFIX, stem].concat())?;
    Ok(())
}

/// `reader`'s newest saved period in `txn`, by its keys alone: no row is
/// read.
pub(super) fn latest_period_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    reader: WeaveDigestReader,
) -> Result<Option<u64>> {
    let prefix = reader.key(DIGEST_PREFIX);
    let mut latest = None;
    for row in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (key, _) = row?;
        if let Some(at) = key
            .strip_prefix(prefix.as_slice())
            .and_then(|at| <[u8; 8]>::try_from(at).ok())
        {
            latest = Some(u64::from_be_bytes(at));
        }
    }
    Ok(latest)
}

impl Vault {
    /// `admin`'s saved period at `scheduled_for`, else its newest, under
    /// the current read policy and its own lane, built in the reading
    /// snapshot; the newest one's lookup revalidates the proof in its own
    /// snapshot even when it finds none. No Admin schedule writes a period
    /// yet, so this answers `None` until one does (FIX-LIST).
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof does not
    /// hold; the saved read's own refusals otherwise.
    pub(in crate::claim::scoped_read) fn read_weave_admin_digest(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        frame: &WeaveAdminFrame,
        scheduled_for: Option<u64>,
    ) -> Result<Option<StoredWeaveDigest>> {
        let reader_key = WeaveDigestReader::Admin(WeaveAdminKey::of(admin));
        let scheduled_for = match scheduled_for {
            Some(at) => at,
            None => {
                let txn = weave_admin_read_txn(self)?;
                admin.read_scope_in_txn(self, &txn)?;
                match latest_period_in(&self.store, &txn, reader_key)? {
                    Some(at) => at,
                    None => return Ok(None),
                }
            }
        };
        let txn = weave_admin_read_txn(self)?;
        let lane = ScopedRead::weave_admin_lane_in(self, &txn, admin, frame)?;
        lane.saved_weave_digest_in_txn(
            &txn,
            reader_key,
            scheduled_for,
            Some(WeaveReader::Admin(admin)),
        )
    }

    /// Keep an Admin's live lens render as its grant's newest, its proof
    /// revalidated in the writer that keeps it, with the person's binding
    /// beside it so a hard delete of the person takes the namespace too.
    /// Then the render it replaces settles on the skill's corrections axis,
    /// counting only the labels filed under this grant. The axis is
    /// evidence, never a gate on the render.
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof does not
    /// hold in the writer; a storage fault as itself.
    pub(in crate::claim::scoped_read) fn keep_weave_admin_live_lens(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        report: &WeaveReport,
        render: &WeaveLensRender,
    ) -> Result<()> {
        let reader = WeaveDigestReader::Admin(WeaveAdminKey::of(admin));
        let key = reader.key(LIVE_PREFIX);
        let bytes = serde_json::to_vec(&KeptLiveLens::of(report, render)).map_err(|_| invalid())?;
        let previous = self.with_write_txn_grouped(|txn| {
            admin.read_scope_in_txn(self, txn)?;
            let previous = digest_row_in(&self.store, txn, &key)?
                .map(|bytes| serde_json::from_slice::<KeptLiveLens>(&bytes))
                .transpose()
                .map_err(|_| invalid())?;
            put_digest_row_in_txn(&self.store, txn, &key, &bytes)?;
            index_source_in_txn(&self.store, txn, &admin.actor(), &key, true)?;
            Ok(previous)
        })?;
        if let Some(previous) = previous.filter(|kept| kept.rendered_at() < render.rendered_at)
            && let Err(error) = settle_live_weave_lens(self, reader, &previous, render.rendered_at)
        {
            tracing::warn!(
                error_kind = ?error.kind(),
                "an admin's live weave lens axis did not settle"
            );
        }
        Ok(())
    }
}
