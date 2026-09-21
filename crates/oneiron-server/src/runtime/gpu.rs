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
#[derive(Clone, Debug)]
struct Pod {
    capacity: usize,
    health: GpuHealth,
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
        self.pods.insert(id, Pod { capacity, health });
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
    /// Sample two distinct healthy pods, then choose the lower normalized load.
    /// `entropy` is fresh host randomness, not a pod- or client-selected value.
    pub fn acquire(&mut self, now: u64, entropy: [u64; 2]) -> Result<GpuLease, GpuRegistryError> {
        self.expire(now);
        let candidates: Vec<_> = self
            .pods
            .iter()
            .filter_map(|(id, pod)| {
                let load = self.leases.values().filter(|l| &l.pod == id).count();
                (pod.health.healthy() && load < pod.capacity).then_some((id, load, pod.capacity))
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
#[cfg(test)]
mod tests {
    use super::*;
    fn healthy() -> GpuHealth {
        GpuHealth {
            transport: true,
            app: true,
            inference: true,
        }
    }
    #[test]
    fn p2c_balances_and_expiry_reclaims_capacity() {
        let mut r = GpuRegistry::new("west").unwrap();
        for id in ["a", "b"] {
            r.register(id.into(), 100, healthy()).unwrap();
        }
        let mut counts = BTreeMap::new();
        for n in 0..200 {
            let l = r.acquire(0, [n, n * 7]).unwrap();
            *counts.entry(l.pod).or_insert(0) += 1;
        }
        assert_eq!(counts["a"], 100);
        assert_eq!(counts["b"], 100);
        assert_eq!(r.acquire(299, [0, 1]), Err(GpuRegistryError::Unavailable));
        assert!(r.acquire(300, [0, 1]).is_ok());
    }
    #[test]
    fn renewal_and_all_three_health_layers() {
        let mut r = GpuRegistry::new("east").unwrap();
        r.register("a".into(), 1, healthy()).unwrap();
        let l = r.acquire(0, [1, 2]).unwrap();
        assert_eq!(l.renew_at, 60);
        let renewed = r.renew(l.id, 60).unwrap();
        assert_eq!(renewed.expires_at, 360);
        assert_eq!(r.acquire(300, [1, 2]), Err(GpuRegistryError::Unavailable));
        assert_eq!(r.renew(l.id, 360), Err(GpuRegistryError::LeaseExpired));
        for health in [
            GpuHealth {
                transport: false,
                ..healthy()
            },
            GpuHealth {
                app: false,
                ..healthy()
            },
            GpuHealth {
                inference: false,
                ..healthy()
            },
        ] {
            r.set_health("a", health).unwrap();
            assert_eq!(r.acquire(400, [1, 2]), Err(GpuRegistryError::Unavailable));
        }
        r.set_health("a", healthy()).unwrap();
        assert!(r.acquire(400, [1, 2]).is_ok());
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
