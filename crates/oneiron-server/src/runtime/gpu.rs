//! Per-region single-writer GPU registry, suitable for a Durable Object owner.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Lease duration and client renewal cadence, in seconds.
pub const GPU_LEASE_SECONDS: u64 = 300;
pub const GPU_RENEW_SECONDS: u64 = 60;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuHealth {
    pub transport: bool,
    pub app: bool,
    pub inference: bool,
}
impl GpuHealth {
    pub fn healthy(self) -> bool {
        self.transport && self.app && self.inference
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuLease {
    pub id: u64,
    pub pod: String,
    pub expires_at: u64,
    pub renew_at: u64,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GpuRegistryError {
    #[error("no healthy GPU capacity in this region")]
    Unavailable,
    #[error("GPU lease is unknown or expired")]
    LeaseExpired,
    #[error("invalid GPU registry input")]
    InvalidInput,
}
const MINUTES_PER_DAY: u16 = 24 * 60;
/// The widest UTC offset in use (UTC+14:00), in minutes.
const MAX_UTC_OFFSET_MINUTES: i16 = 14 * 60;
/// The clock a pod's hours are read on.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PodClock {
    /// One fixed offset from UTC, in minutes. It does not follow
    /// daylight-saving changes.
    UtcOffset(i16),
    /// An IANA zone, read in the engine's one embedded zone database
    /// ([`oneiron::calendar::utc_to_wall`]), so the hours follow the zone's
    /// daylight-saving changes.
    IanaTimezone(String),
}
/// The daily hours a pod takes new leases, read in one fixed UTC offset or
/// in an IANA zone (CROSS-ARCH-0024 #my-network 07: embeddings can run on
/// the GPU box at night). `start` is the first minute in, `end` the first
/// minute out; a start later than the end runs across midnight. In a zone,
/// the hours are wall-clock minutes: on a day the clocks jump forward the
/// skipped minutes never occur, so a start inside the gap opens at the first
/// minute after it, and on a day they fall back the repeated hour is in or
/// out both times.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuPodHours {
    start_minute: u16,
    end_minute: u16,
    clock: PodClock,
}
impl GpuPodHours {
    /// Minutes after local midnight, read in a fixed UTC offset. A start
    /// equal to the end names no hours, so it is refused rather than read as
    /// all day or none.
    pub fn new(
        start_minute: u16,
        end_minute: u16,
        utc_offset_minutes: i16,
    ) -> Result<Self, GpuRegistryError> {
        if !(-MAX_UTC_OFFSET_MINUTES..=MAX_UTC_OFFSET_MINUTES).contains(&utc_offset_minutes) {
            return Err(GpuRegistryError::InvalidInput);
        }
        Self::on_clock(
            start_minute,
            end_minute,
            PodClock::UtcOffset(utc_offset_minutes),
        )
    }
    /// Minutes after local midnight, read in the IANA zone `iana_timezone`
    /// (such as `"Europe/Berlin"`, in its canonical spelling). A zone the
    /// engine's database does not hold is refused, never read as UTC.
    pub fn in_iana_timezone(
        start_minute: u16,
        end_minute: u16,
        iana_timezone: &str,
    ) -> Result<Self, GpuRegistryError> {
        if oneiron::calendar::utc_to_wall(0, iana_timezone).is_err() {
            return Err(GpuRegistryError::InvalidInput);
        }
        Self::on_clock(
            start_minute,
            end_minute,
            PodClock::IanaTimezone(iana_timezone.to_owned()),
        )
    }
    fn on_clock(
        start_minute: u16,
        end_minute: u16,
        clock: PodClock,
    ) -> Result<Self, GpuRegistryError> {
        if start_minute >= MINUTES_PER_DAY
            || end_minute >= MINUTES_PER_DAY
            || start_minute == end_minute
        {
            return Err(GpuRegistryError::InvalidInput);
        }
        Ok(Self {
            start_minute,
            end_minute,
            clock,
        })
    }
    /// The local minute of the day at `now` (Unix seconds), or `None` when
    /// the zone cannot read that instant.
    fn local_minute(&self, now: u64) -> Option<u16> {
        match &self.clock {
            PodClock::UtcOffset(offset) => {
                let local_seconds = i128::from(now) + i128::from(*offset) * 60;
                u16::try_from(local_seconds.rem_euclid(86_400) / 60).ok()
            }
            PodClock::IanaTimezone(zone) => {
                let wall = oneiron::calendar::utc_to_wall(now, zone).ok()?;
                Some(u16::from(wall.h) * 60 + u16::from(wall.mi))
            }
        }
    }
    /// Whether `now` (Unix seconds) falls inside these hours. An instant the
    /// zone cannot read is outside them.
    pub fn contains(&self, now: u64) -> bool {
        let Some(minute) = self.local_minute(now) else {
            return false;
        };
        let (start, end) = (self.start_minute, self.end_minute);
        if start < end {
            start <= minute && minute < end
        } else {
            minute >= start || minute < end
        }
    }
}
#[derive(Clone, Debug)]
struct Pod {
    capacity: usize,
    health: GpuHealth,
    /// `None`: the pod takes leases at any hour.
    hours: Option<GpuPodHours>,
}
/// One registry instance belongs to exactly one region. The host serializes it.
#[derive(Debug)]
pub struct GpuRegistry {
    region: String,
    pods: BTreeMap<String, Pod>,
    leases: BTreeMap<u64, GpuLease>,
    next_id: u64,
}
impl GpuRegistry {
    pub fn new(region: impl Into<String>) -> Result<Self, GpuRegistryError> {
        let region = region.into();
        if region.is_empty() {
            return Err(GpuRegistryError::InvalidInput);
        }
        Ok(Self {
            region,
            pods: BTreeMap::new(),
            leases: BTreeMap::new(),
            next_id: 1,
        })
    }
    pub fn region(&self) -> &str {
        &self.region
    }
    pub fn register(
        &mut self,
        id: String,
        capacity: usize,
        health: GpuHealth,
    ) -> Result<(), GpuRegistryError> {
        if id.is_empty() || capacity == 0 {
            return Err(GpuRegistryError::InvalidInput);
        }
        self.pods.insert(
            id,
            Pod {
                capacity,
                health,
                hours: None,
            },
        );
        Ok(())
    }
    /// Limits a registered pod's new leases to `hours`; `None` lifts the
    /// limit. A lease taken inside the hours still renews to its end, so a
    /// batch begun there is never split.
    pub fn set_hours(
        &mut self,
        id: &str,
        hours: Option<GpuPodHours>,
    ) -> Result<(), GpuRegistryError> {
        self.pods
            .get_mut(id)
            .ok_or(GpuRegistryError::InvalidInput)?
            .hours = hours;
        Ok(())
    }
    pub fn set_health(&mut self, id: &str, health: GpuHealth) -> Result<(), GpuRegistryError> {
        self.pods
            .get_mut(id)
            .ok_or(GpuRegistryError::InvalidInput)?
            .health = health;
        Ok(())
    }
    /// Expiry frees capacity before every routing or renewal operation.
    pub fn expire(&mut self, now: u64) {
        self.leases.retain(|_, lease| lease.expires_at > now);
    }
    /// Sample two distinct healthy pods inside their hours, then choose the
    /// lower normalized load. `entropy` is fresh host randomness, not a pod-
    /// or client-selected value.
    pub fn acquire(&mut self, now: u64, entropy: [u64; 2]) -> Result<GpuLease, GpuRegistryError> {
        self.expire(now);
        let candidates: Vec<_> = self
            .pods
            .iter()
            .filter_map(|(id, pod)| {
                let load = self.leases.values().filter(|l| &l.pod == id).count();
                let in_hours = pod.hours.as_ref().is_none_or(|hours| hours.contains(now));
                let open = pod.health.healthy() && in_hours && load < pod.capacity;
                open.then_some((id, load, pod.capacity))
            })
            .collect();
        if candidates.is_empty() {
            return Err(GpuRegistryError::Unavailable);
        }
        let a = (entropy[0] % candidates.len() as u64) as usize;
        let b = if candidates.len() == 1 {
            a
        } else {
            (a + 1 + (entropy[1] % (candidates.len() - 1) as u64) as usize) % candidates.len()
        };
        let (left, right) = (candidates[a], candidates[b]);
        let selected =
            if (left.1 as u128) * (right.2 as u128) <= (right.1 as u128) * (left.2 as u128) {
                left
            } else {
                right
            };
        let lease = GpuLease {
            id: self.next_id,
            pod: selected.0.clone(),
            expires_at: now
                .checked_add(GPU_LEASE_SECONDS)
                .ok_or(GpuRegistryError::InvalidInput)?,
            renew_at: now
                .checked_add(GPU_RENEW_SECONDS)
                .ok_or(GpuRegistryError::InvalidInput)?,
        };
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(GpuRegistryError::InvalidInput)?;
        self.leases.insert(lease.id, lease.clone());
        Ok(lease)
    }
    pub fn renew(&mut self, id: u64, now: u64) -> Result<GpuLease, GpuRegistryError> {
        self.expire(now);
        let lease = self
            .leases
            .get_mut(&id)
            .ok_or(GpuRegistryError::LeaseExpired)?;
        if !self
            .pods
            .get(&lease.pod)
            .is_some_and(|p| p.health.healthy())
        {
            return Err(GpuRegistryError::Unavailable);
        }
        lease.expires_at = now
            .checked_add(GPU_LEASE_SECONDS)
            .ok_or(GpuRegistryError::InvalidInput)?;
        lease.renew_at = now
            .checked_add(GPU_RENEW_SECONDS)
            .ok_or(GpuRegistryError::InvalidInput)?;
        Ok(lease.clone())
    }
    pub fn release(&mut self, id: u64) -> bool {
        self.leases.remove(&id).is_some()
    }
}

/// The routing host, not the worker, binds the holding account to a GPU job.
#[derive(Debug)]
pub struct GpuDerivationLease {
    lease: GpuLease,
    scope: oneiron::federation::derivation::DerivationScope,
    computation: Vec<u8>,
    content: Vec<u8>,
}
impl GpuDerivationLease {
    pub fn lease(&self) -> &GpuLease {
        &self.lease
    }
}
impl GpuRegistry {
    pub fn acquire_derivation(
        &mut self,
        scope: oneiron::federation::derivation::DerivationScope,
        computation: Vec<u8>,
        content: Vec<u8>,
        now: u64,
        entropy: [u64; 2],
    ) -> Result<GpuDerivationLease, GpuRegistryError> {
        let lease = self.acquire(now, entropy)?;
        Ok(GpuDerivationLease {
            lease,
            scope,
            computation,
            content,
        })
    }
    pub fn complete_derivation(
        &mut self,
        job: GpuDerivationLease,
        output: Vec<u8>,
        now: u64,
    ) -> Result<oneiron::federation::derivation::SealedOutput, GpuRegistryError> {
        self.expire(now);
        let lease = self
            .leases
            .remove(&job.lease.id)
            .ok_or(GpuRegistryError::LeaseExpired)?;
        if lease.pod != job.lease.pod
            || !self
                .pods
                .get(&lease.pod)
                .is_some_and(|p| p.health.healthy())
        {
            return Err(GpuRegistryError::Unavailable);
        }
        Ok(job
            .scope
            .seal_gpu_output(&job.computation, &job.content, output))
    }
}
#[cfg(test)]
mod sealed_gpu_tests {
    use super::*;
    use oneiron::federation::derivation::DerivationOwner;
    #[test]
    fn shared_pod_completions_remain_owner_sealed() {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a = oneiron::Vault::open(a_dir.path(), oneiron::VaultConfig::device()).unwrap();
        let b = oneiron::Vault::open(b_dir.path(), oneiron::VaultConfig::device()).unwrap();
        let a = a.bind_derivation_owner(DerivationOwner([1; 32])).unwrap();
        let b = b.bind_derivation_owner(DerivationOwner([2; 32])).unwrap();
        let mut registry = GpuRegistry::new("region").unwrap();
        registry
            .register(
                "pod".into(),
                2,
                GpuHealth {
                    transport: true,
                    app: true,
                    inference: true,
                },
            )
            .unwrap();
        let a_job = registry
            .acquire_derivation(a, b"model".to_vec(), b"foreign WORLD".to_vec(), 0, [0, 0])
            .unwrap();
        let b_job = registry
            .acquire_derivation(b, b"model".to_vec(), b"foreign WORLD".to_vec(), 0, [0, 0])
            .unwrap();
        let a_out = registry.complete_derivation(a_job, vec![7], 10).unwrap();
        let b_out = registry.complete_derivation(b_job, vec![7], 10).unwrap();
        assert_ne!(a_out, b_out);
        assert_eq!(a_out.read(b.owner()), None);
        assert_eq!(b_out.read(a.owner()), None);
        assert_eq!(a_out.read(a.owner()), Some([7].as_slice()));
        assert_eq!(b_out.read(b.owner()), Some([7].as_slice()));
    }
}
