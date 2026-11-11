//! The pre-dispatch producer and its one admitted call.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use oneiron::Vault;
use oneiron_docedit::resource::{ResourceAllocation, ResourcePort, ResourceRefusal, Resources};
use oneiron_organ_protocol::Value;

use super::sized::Run;
use super::{CallMeasure, CallRoom, CallSize, Lent, OrganHost, Slot, lock};
use crate::clock::WaitClock;
use crate::error::HostError;
use crate::handlers::AskHandlers;
use crate::outcome::OrganOutcome;
use crate::process::Revocations;
use crate::resource_memory::{FloorLease, FloorRefusal, SharedFloor};
use crate::shutdown;
use crate::spec::OrganCall;

/// Checked authority and the original normal call clock. A pre-dispatch
/// rebuild replaces only its room, never this header or its clock.
pub(crate) struct ProducerStart<'h> {
    host: &'h OrganHost,
    call: OrganCall,
    slot: Arc<Slot>,
    begun: Instant,
    deadline: Instant,
    waits: Arc<WaitClock>,
}

impl OrganHost {
    pub(crate) fn start_producer(&self, call: OrganCall) -> Result<ProducerStart<'_>, HostError> {
        let begun = Instant::now();
        let longest = std::time::Duration::from_millis(u64::from(u32::MAX));
        let deadline = begun + call.deadline.min(longest);
        let slot = self.checked_slot(&call)?;
        Ok(ProducerStart {
            host: self,
            call,
            slot,
            begun,
            deadline,
            waits: Arc::new(WaitClock::default()),
        })
    }
}

impl ProducerStart<'_> {
    fn deadline(&self) -> Instant {
        self.deadline
            .checked_add(self.waits.waited())
            .unwrap_or(self.deadline)
    }

    /// No model or input from a preceding failed production is held here.
    /// The caller drops that whole production before asking for a new room.
    pub(crate) fn admit(&self, size: CallSize) -> Result<ProducerCall<'_>, HostError> {
        if self.host.grant_revoked(&self.call.grant) {
            return Err(HostError::Revoked);
        }
        let booking = size.booking.max(self.slot.spec.call_memory_bytes);
        let permit = self
            .host
            .budget
            .admit(self.call.class, 1, booking, self.deadline())?;
        let room = Arc::new(CallRoom::with_waits(
            permit,
            self.host.floor.clone(),
            Arc::clone(&self.waits),
        ));
        let port = Arc::new(ProducerResources {
            room: Arc::clone(&room),
            floor: self.host.floor.clone(),
            revoked: Arc::clone(&self.host.revoked),
            grant: self.call.grant.clone(),
            deadline: self.deadline,
        });
        Ok(ProducerCall {
            start: self,
            room,
            resources: Resources::new(port),
        })
    }
}

/// Consumed by dispatch. Its resources cover the lexical input and handlers
/// through exchange and finish, and cannot authorize a different header.
pub(crate) struct ProducerCall<'s> {
    start: &'s ProducerStart<'s>,
    room: Arc<CallRoom>,
    resources: Resources,
}

impl ProducerCall<'_> {
    pub(crate) fn resources(&self) -> &Resources {
        &self.resources
    }

    pub(crate) fn dispatch(
        self,
        vault: &Vault,
        args: Value,
        lent: Vec<Lent>,
        handlers: &AskHandlers<'_>,
        size: CallSize,
        measure: &mut CallMeasure,
    ) -> Result<(OrganOutcome, Instant), HostError> {
        if self.start.host.grant_revoked(&self.start.call.grant) {
            return Err(HostError::Revoked);
        }
        // The consumer re-admits a complete larger call BEFORE dispatch,
        // with no previous pool held. Do not grow a booking here while
        // retaining the producer's already allocated input.
        let mut how = Run::Sized(size, measure);
        how.booking(&self.start.slot.spec);
        let mut call = self.start.call.clone();
        call.args = args;
        self.start.host.run_in_room(
            vault,
            call,
            lent,
            handlers,
            how,
            Arc::clone(&self.start.slot),
            self.room,
            self.start.begun,
            self.start.deadline(),
            false,
        )
    }
}

struct ProducerResources {
    room: Arc<CallRoom>,
    floor: Option<SharedFloor>,
    revoked: Arc<Revocations>,
    grant: String,
    deadline: Instant,
}

impl ProducerResources {
    fn stopped(&self) -> bool {
        self.revoked.contains(&self.grant) || shutdown::interrupted()
    }

    fn deadline(&self) -> Instant {
        self.deadline
            .checked_add(self.room.waits().waited())
            .unwrap_or(self.deadline)
    }
}

impl ResourcePort for ProducerResources {
    fn reserve(&self, bytes: u64, measured: u64) -> Result<Box<dyn Send + Sync>, ResourceRefusal> {
        let mut allocation = self.allocation();
        allocation.grow(bytes, measured)?;
        Ok(Box::new(allocation))
    }

    fn checkpoint(&self) -> Result<(), ResourceRefusal> {
        if self.stopped() || Instant::now() >= self.deadline() {
            Err(ResourceRefusal::Deadline)
        } else {
            Ok(())
        }
    }

    fn allocation(&self) -> Box<dyn ResourceAllocation> {
        Box::new(ProducerAllocation {
            room: Arc::clone(&self.room),
            floor: self.floor.clone(),
            revoked: Arc::clone(&self.revoked),
            grant: self.grant.clone(),
            deadline: self.deadline,
            state: Mutex::new(AllocationState {
                lease: None,
                charged: 0,
                floor_pending: 0,
                floor_allocated: 0,
            }),
        })
    }
}

struct AllocationState {
    lease: Option<Box<dyn FloorLease>>,
    charged: u64,
    floor_pending: u64,
    floor_allocated: u64,
}

struct ProducerAllocation {
    room: Arc<CallRoom>,
    floor: Option<SharedFloor>,
    revoked: Arc<Revocations>,
    grant: String,
    deadline: Instant,
    state: Mutex<AllocationState>,
}

impl ResourceAllocation for ProducerAllocation {
    fn grow(&mut self, bytes: u64, measured: u64) -> Result<(), ResourceRefusal> {
        let stopped = || self.revoked.contains(&self.grant) || shutdown::interrupted();
        let deadline = self
            .deadline
            .checked_add(self.room.waits().waited())
            .unwrap_or(self.deadline);
        if stopped() || Instant::now() >= deadline {
            return Err(ResourceRefusal::Deadline);
        }
        if bytes == 0 {
            return Ok(());
        }
        let mut state = lock(&self.state);
        // The real producer books its entire planned pool once, while it
        // holds no older pool. Memory waits pause the same normal clock.
        let mut granted = 0;
        if let Some(floor) = &self.floor {
            let already = state.floor_pending.saturating_add(state.floor_allocated);
            granted = self
                .room
                .waits()
                .timing(|| {
                    let reserve = |lease: &mut Option<Box<dyn FloorLease>>, bytes: u64| {
                        if let Some(lease) = lease {
                            lease.grow_untimed(bytes, &stopped)
                        } else {
                            *lease = Some(floor.0.lease_untimed(bytes, &stopped)?);
                            Ok(())
                        }
                    };
                    match reserve(&mut state.lease, bytes) {
                        Err(FloorRefusal::Floor { available, .. })
                            if measured <= available.saturating_sub(already) =>
                        {
                            let grant = measured
                                .max(oneiron_docedit::resource::RESERVE_STEP)
                                .min(available.saturating_sub(already));
                            reserve(&mut state.lease, grant)?;
                            Ok(grant)
                        }
                        Ok(()) => Ok(bytes),
                        Err(error) => Err(error),
                    }
                })
                .map_err(|error| match error {
                    FloorRefusal::Floor { available, .. } => ResourceRefusal::MemoryFloor {
                        needed: measured,
                        available: available.saturating_sub(already),
                    },
                    FloorRefusal::Deadline => ResourceRefusal::Deadline,
                })?;
        }
        if !self.room.hold(bytes, &stopped) {
            if let Some(lease) = &mut state.lease {
                lease.shrink(granted);
            }
            return Err(ResourceRefusal::Deadline);
        }
        state.charged = state.charged.saturating_add(bytes);
        state.floor_pending = state.floor_pending.saturating_add(granted);
        Ok(())
    }

    fn materialized(&mut self, bytes: u64) {
        let mut state = lock(&self.state);
        let pending = state.floor_pending;
        let allocated = state.floor_allocated;
        let before = state.charged;
        if let Some(lease) = &mut state.lease {
            lease.materialized(pending, bytes.saturating_sub(allocated));
            if bytes < allocated {
                lease.shrink(allocated - bytes);
            }
            state.floor_allocated = bytes;
        }
        self.room.producer_materialized(before, bytes);
        state.floor_pending = 0;
        state.charged = bytes;
    }
}

impl Drop for ProducerAllocation {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.room.release(state.charged);
        // The physical lease then drops too, even without a live reading.
    }
}
