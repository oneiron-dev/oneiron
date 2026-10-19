//! Where a [`Memory`] caller sits, and the rows its reads derive an answer
//! from, for a host that judges that answer again before it leaves this
//! device (DEC-0005).

use super::{Memory, MemoryError, MemoryResult};
use crate::entity_id::EntityId;

/// The rows the reads of a [`Memory`] surface derived their answers from.
///
/// A read that picks rows itself, ones its caller never named, lists them
/// here as it reads: a room thread's TASKs and their results, the TASK an ask
/// takes its class from, every row a native query reads, the ones it counts
/// but does not return among them. A host lists the rows its caller names by
/// ref.
#[derive(Debug, Default)]
pub struct ProducerRows(std::sync::Mutex<Vec<EntityId>>);

impl ProducerRows {
    /// The rows listed so far; the set is left empty.
    #[must_use]
    pub fn take(&self) -> Vec<EntityId> {
        std::mem::take(&mut *self.rows())
    }

    /// Lists `rows` as producers of the answer being read.
    pub(crate) fn list(&self, rows: impl IntoIterator<Item = EntityId>) {
        self.rows().extend(rows);
    }

    fn rows(&self) -> std::sync::MutexGuard<'_, Vec<EntityId>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl<'v> Memory<'v> {
    /// Lists in `producers` every row this surface's reads derive an answer
    /// from without their caller naming it. A surface opened inside a room
    /// lists into the same set.
    #[must_use]
    pub fn listing_producers(mut self, producers: &'v ProducerRows) -> Self {
        self.producers = Some(producers);
        self
    }
}

impl Memory<'_> {
    /// Serves a caller at `locality`, as the host found it from the
    /// connection. Every read lane, and the whole-vault export, then reads as
    /// [`ScopedReadActorKey::at`](crate::claim::ScopedReadActorKey::at) does:
    /// a caller off this device reads no device-local world (DEC-0005). It
    /// only narrows; a handle off the device never reads on it again.
    #[must_use]
    pub fn at(mut self, locality: crate::claim::CallerLocality) -> Self {
        if locality == crate::claim::CallerLocality::OffDevice {
            self.locality = locality;
            self.destination.meet(&locality.into());
        }
        self
    }

    /// Serves a caller whose rows go to `destination`, as the host found it
    /// from the connection: the machine it proved rides beside the locality,
    /// and every read lane, the export and each producer check judge the
    /// world settings for that machine in their own snapshot (mesh PR2b).
    /// It only narrows, as [`Self::at`] does.
    #[must_use]
    pub fn for_destination(mut self, destination: &crate::settings::ReadDestination) -> Self {
        if destination.is_off_device() {
            self.locality = crate::claim::CallerLocality::OffDevice;
        }
        self.destination.meet(destination);
        self
    }

    /// Where this surface's caller reads from.
    pub(crate) const fn locality(&self) -> crate::claim::CallerLocality {
        self.locality
    }

    /// Where this surface's rows go.
    pub(crate) fn destination(&self) -> &crate::settings::ReadDestination {
        &self.destination
    }

    /// Lists `rows` as producers of the answer being read, when a host
    /// collects them ([`Memory::listing_producers`]).
    pub(crate) fn produced_from(&self, rows: impl IntoIterator<Item = EntityId>) {
        if let Some(producers) = self.producers {
            producers.list(rows);
        }
    }

    /// Lists `row` as a producer of the answer being read, which a caller
    /// off this device reads as no row while a device-local world keeps it.
    pub(crate) fn read_producer_in(
        &self,
        txn: &heed::RoTxn<'_>,
        row: EntityId,
    ) -> MemoryResult<()> {
        self.produced_from([row]);
        let store = &self.vault.store;
        let kept = crate::settings::device_local_worlds_for(self.vault, txn, &self.destination)?;
        if crate::settings::device_local_keeps_among(store, txn, &kept, &row)? {
            return Err(MemoryError::from(crate::error::Error::EntityNotFound));
        }
        Ok(())
    }
}
