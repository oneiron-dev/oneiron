//! Per-ref sync policy (ARCH-0053 §7: sync_policy per ref, not per hub).
//! A row is vault data, so moving a ref's pin is an owner write, never an
//! engine release. The pin only chooses which bytes a fetch asks for; their
//! authority stays with the content hash, its scan verdicts and the install door.
use serde::{Deserialize, Serialize};

use super::{HubPin, HubRef, HubSyncPolicy, TrackedHubRef};
use crate::{
    Vault,
    consent::AuthenticatedOwner,
    entity_id::EntityId,
    error::{Error, Result},
    side_table::{self, LegacyJson, SideTable},
};

const REF_SYNC: SideTable<(EntityId, String), RefSyncRow, LegacyJson> =
    SideTable::new(&side_table::SKILL_HUB_REF_SYNC);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefSyncRow {
    sync_policy: String,
    pin_type: String,
    pin_value: String,
    latest_seen: Option<String>,
    latest_trusted: Option<String>,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// Each policy follows one kind of pin: a commit, a tag, or a frozen content
/// hash. A mirror has no pin of its own, so it has no ref row.
fn check_policy_pin(policy: HubSyncPolicy, pin: &HubPin) -> Result<()> {
    match (policy, pin) {
        (HubSyncPolicy::PinnedCommit, HubPin::Commit(_))
        | (HubSyncPolicy::PinnedRef, HubPin::Tag(_) | HubPin::Semver(_))
        | (HubSyncPolicy::ContentHashFrozen, HubPin::ContentHash(_)) => Ok(()),
        _ => Err(invalid("hub ref pin does not fit its sync policy")),
    }
}

impl RefSyncRow {
    fn from_tracked(tracked: &TrackedHubRef) -> Result<Self> {
        check_policy_pin(tracked.sync_policy, &tracked.hub_ref.pin)?;
        let pin_value = match &tracked.hub_ref.pin {
            HubPin::Commit(value)
            | HubPin::Tag(value)
            | HubPin::Semver(value)
            | HubPin::ContentHash(value) => value.clone(),
            HubPin::None => return Err(invalid("hub ref sync needs a pin")),
        };
        Ok(Self {
            sync_policy: tracked.sync_policy.as_str().to_owned(),
            pin_type: tracked.hub_ref.pin.pin_type().to_owned(),
            pin_value,
            latest_seen: tracked.latest_seen.clone(),
            latest_trusted: tracked.latest_trusted.clone(),
        })
    }

    fn into_tracked(self, hub: EntityId, ref_string: &str) -> Result<TrackedHubRef> {
        let sync_policy = HubSyncPolicy::parse(&self.sync_policy)
            .ok_or_else(|| invalid("stored hub ref sync policy is invalid"))?;
        let pin = match self.pin_type.as_str() {
            "commit" => HubPin::Commit(self.pin_value),
            "tag" => HubPin::Tag(self.pin_value),
            "semver" => HubPin::Semver(self.pin_value),
            "content_hash" => HubPin::ContentHash(self.pin_value),
            _ => return Err(invalid("stored hub ref pin is invalid")),
        };
        check_policy_pin(sync_policy, &pin)?;
        Ok(TrackedHubRef {
            hub_ref: HubRef::new(hub, ref_string, pin)?,
            sync_policy,
            latest_seen: self.latest_seen,
            latest_trusted: self.latest_trusted,
        })
    }
}

impl Vault {
    /// The owner's stored policy for one hub ref, if one was set.
    pub fn hub_ref_sync(&self, hub: &EntityId, ref_string: &str) -> Result<Option<TrackedHubRef>> {
        let txn = self.store.env.read_txn()?;
        self.hub_ref_sync_in_txn(&txn, hub, ref_string)
    }

    pub(crate) fn hub_ref_sync_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        hub: &EntityId,
        ref_string: &str,
    ) -> Result<Option<TrackedHubRef>> {
        REF_SYNC
            .get(&self.store, txn, &(*hub, ref_string.to_owned()))?
            .map(|row| row.into_tracked(*hub, ref_string))
            .transpose()
    }

    /// Owner door: set one ref's policy and pin. Revisions already seen and
    /// trusted stay; a moved pin trusts nothing new until its bytes pass the
    /// scan and install doors.
    pub fn set_hub_ref_sync(
        &self,
        owner: &AuthenticatedOwner,
        hub_ref: HubRef,
        sync_policy: HubSyncPolicy,
    ) -> Result<TrackedHubRef> {
        check_policy_pin(sync_policy, &hub_ref.pin)?;
        self.with_write_txn_grouped(|txn| {
            self.check_restore_owner_in_txn(txn, owner)?;
            self.hub_record_in_txn(txn, &hub_ref.hub_id)?;
            let prior = self.hub_ref_sync_in_txn(txn, &hub_ref.hub_id, &hub_ref.ref_string)?;
            let key = (hub_ref.hub_id, hub_ref.ref_string.clone());
            let mut tracked = TrackedHubRef::new(hub_ref, sync_policy);
            if let Some(prior) = prior {
                tracked.latest_seen = prior.latest_seen;
                tracked.latest_trusted = prior.latest_trusted;
            }
            REF_SYNC.put(&self.store, txn, &key, &RefSyncRow::from_tracked(&tracked)?)?;
            Ok(tracked)
        })
    }

    /// Marks a revision a fetch resolved (seen) or an install accepted
    /// (trusted). The two marks never overwrite one another.
    pub(crate) fn mark_hub_ref(
        &self,
        tracked: &TrackedHubRef,
        revision: &str,
        trusted: bool,
    ) -> Result<()> {
        let hub = tracked.hub_ref.hub_id;
        let ref_string = &tracked.hub_ref.ref_string;
        self.with_write_txn_grouped(|txn| {
            let mut row = self
                .hub_ref_sync_in_txn(txn, &hub, ref_string)?
                .unwrap_or_else(|| tracked.clone());
            if trusted {
                row.trust(revision)?;
            } else {
                row.observe(revision)?;
            }
            REF_SYNC.put(
                &self.store,
                txn,
                &(hub, ref_string.clone()),
                &RefSyncRow::from_tracked(&row)?,
            )
        })
    }
}
