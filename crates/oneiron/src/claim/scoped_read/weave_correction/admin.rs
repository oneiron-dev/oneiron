//! A weave Admin's wrong labels (OF-499 A3): the one-tap wrong on a link,
//! claim, project, budget or sieve audit row its own Admin report shows,
//! filed under its current proof. The label names the person as its actor
//! and the exact membership grant it was filed under, so two Admin grants
//! keep apart, a person's or owner's labels never count toward it, and a
//! hard delete of either the person or the grant takes it. No verb files it
//! yet (L13 binds one); the Person and Owner doors are unchanged.
use super::super::weave_report::admin::WeaveAdminFrame;
use super::super::{ScopedRead, WeaveReader};
use super::{
    ITEM_LABELS, LABELS, StoredCorrection, StoredItemCorrection, WeaveItemCorrection,
    WeaveItemTarget, WeaveLinkCorrection,
};
use crate::authority::AuthenticatedWeaveAdmin;
use crate::error::{Error, Result};
use crate::provenance::EdgeRef;
use crate::{EntityId, Vault};

impl Vault {
    /// File `admin`'s wrong-link tap on `link`, a link its own live Admin
    /// report shows in the writer's snapshot. A caller-chosen edge ref alone
    /// grants no write authority; the label is not an edge retraction.
    ///
    /// # Errors
    /// `AuthorityRefused(WEAVE_ADMIN_NOT_CURRENT)` when the proof does not
    /// hold in the writer; `EntityNotFound` when its report does not show
    /// the link.
    pub(in crate::claim::scoped_read) fn file_weave_admin_link_label(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        frame: &WeaveAdminFrame,
        link: EdgeRef,
    ) -> Result<WeaveLinkCorrection> {
        self.file_weave_admin_label(
            admin,
            frame,
            |lane, txn| lane.require_visible_weave_link_in(txn, WeaveReader::Admin(admin), link),
            |txn, actor, grant| {
                Ok(self
                    .weave_link_correction_labels_in_txn(txn, link)?
                    .iter()
                    .filter(|label| label.actor == actor && label.admin_grant == Some(grant))
                    .count())
            },
            |txn, actor, grant, now| {
                let correction = WeaveLinkCorrection {
                    id: EntityId::now(),
                    link,
                    actor,
                    recorded_at: now,
                    admin_grant: Some(grant),
                };
                LABELS.put(
                    &self.store,
                    txn,
                    &(link.encode(), correction.id),
                    &StoredCorrection {
                        id: correction.id,
                        link: link.encode().to_vec(),
                        actor,
                        recorded_at: now,
                        admin_grant: Some(grant),
                    },
                )?;
                Ok(correction)
            },
        )
    }

    /// File `admin`'s wrong-item tap on `item`, a row its own live Admin
    /// report shows in the writer's snapshot, under the same bound as a
    /// link's. A caller-chosen id alone grants no write authority; the
    /// label changes no record.
    ///
    /// # Errors
    /// As [`Self::file_weave_admin_link_label`].
    pub(in crate::claim::scoped_read) fn file_weave_admin_item_label(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        frame: &WeaveAdminFrame,
        item: WeaveItemTarget,
    ) -> Result<WeaveItemCorrection> {
        self.file_weave_admin_label(
            admin,
            frame,
            |lane, txn| lane.require_visible_weave_item_in(txn, WeaveReader::Admin(admin), item),
            |txn, actor, grant| {
                Ok(self
                    .weave_item_correction_labels_in_txn(txn, item.id())?
                    .iter()
                    .filter(|label| label.actor == actor && label.admin_grant == Some(grant))
                    .count())
            },
            |txn, actor, grant, now| {
                let correction = WeaveItemCorrection {
                    id: EntityId::now(),
                    item,
                    actor,
                    recorded_at: now,
                    admin_grant: Some(grant),
                };
                ITEM_LABELS.put(
                    &self.store,
                    txn,
                    &(item.id(), correction.id),
                    &StoredItemCorrection {
                        id: correction.id,
                        item,
                        actor,
                        recorded_at: now,
                        admin_grant: Some(grant),
                    },
                )?;
                Ok(correction)
            },
        )
    }

    /// One Admin wrong tap in one writer: its clock, the Admin's own lane
    /// (its proof revalidated here), the visibility check `admit` on that
    /// lane, the bound on the labels `own` counts (this person's under this
    /// grant), and the label `put` writes. As a person's tap, no label is
    /// refused for how many there are (rule 5): past the bound it files
    /// anyway and leaves the typed own-rate check.
    fn file_weave_admin_label<T>(
        &self,
        admin: &AuthenticatedWeaveAdmin,
        frame: &WeaveAdminFrame,
        admit: impl FnOnce(&ScopedRead<'_>, &heed::RoTxn<'_>) -> Result<()>,
        own: impl FnOnce(&heed::RoTxn<'_>, EntityId, EntityId) -> Result<usize>,
        put: impl FnOnce(&mut heed::RwTxn<'_>, EntityId, EntityId, u64) -> Result<T>,
    ) -> Result<T> {
        let (actor, grant) = (admin.actor(), admin.membership_grant());
        let mut txn = self.store.env.write_txn()?;
        // The injected authorization clock persists in this SAME writer
        // before the proof and the relationship grants are judged.
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        let (own, limit) = {
            let lane = ScopedRead::weave_admin_lane_in(self, &txn, admin, frame)?;
            admit(&lane, &txn)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            let limit =
                policy
                    .weave_correction_limit(&actor.to_hex())
                    .ok_or(Error::InvalidConfig(
                        "weave correction policy unavailable".into(),
                    ))?;
            (own(&txn, actor, grant)?, limit)
        };
        if own >= limit {
            crate::own_rate::observe_in_txn(
                &self.store,
                &mut txn,
                crate::own_rate::OwnRateKind::WeaveCorrection,
                actor,
                0,
                u64::try_from(own).unwrap_or(u64::MAX).saturating_add(1),
                crate::own_rate::OwnRate {
                    threshold: u64::try_from(limit).unwrap_or(u64::MAX),
                    window_seconds: 0,
                },
            )?;
        }
        let label = put(&mut txn, actor, grant, now)?;
        txn.commit()?;
        Ok(label)
    }
}
