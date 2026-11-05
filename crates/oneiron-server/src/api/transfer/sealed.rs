//! The existing sealed-upload disk ledger, extended across immutable work.
use super::*;
use oneiron::authority::PeerMachine;
use oneiron::sync::residence::{SealedBundleStage, SealedBundleStaged};

pub(super) type SealedStageKey = (EntityId, SealedBundleObject, Option<[u8; 32]>);
type Claims = HashMap<SealedStageKey, Arc<DiskClaim>>;

fn key(stage: &SealedBundleStaged) -> SealedStageKey {
    (stage.machine, stage.object, stage.work_id)
}

impl Transfers {
    fn sealed_stage_room(&self, total: u64, written: u64) -> u64 {
        let on_disk = |bytes: u64| {
            bytes.saturating_add(
                bytes
                    .div_ceil(SEALED_BUNDLE_PUT_PART_MAX as u64)
                    .saturating_mul(self.lfs_page()),
            )
        };
        on_disk(total)
            .saturating_mul(SEALED_BUNDLE_DISK_COPY_COUNT)
            .saturating_sub(on_disk(
                written.min(total.saturating_mul(SEALED_BUNDLE_DISK_COPY_COUNT)),
            ))
    }

    fn sealed_work_room(&self, stage: &SealedBundleStaged) -> u64 {
        if stage.terminal {
            return 0;
        }
        self.sealed_stage_room(stage.total, stage.staged.saturating_add(stage.prepared))
    }

    fn reconcile_sealed_in(&self, claims: &mut Claims, stages: &[SealedBundleStaged]) {
        // Begin detaches both headers under this ledger lock. Move the SAME
        // claims to their work address, never release-and-reclaim the room.
        for stage in stages.iter().filter(|stage| stage.work_id.is_some()) {
            let next = key(stage);
            let ordinary = (stage.machine, stage.object, None);
            if !claims.contains_key(&next)
                && !stages.iter().any(|stage| key(stage) == ordinary)
                && let Some(claim) = claims.remove(&ordinary)
            {
                claims.insert(next, claim);
            }
        }
        claims.retain(|key, claim| {
            Arc::strong_count(claim) > 1 || stages.iter().any(|stage| self::key(stage) == *key)
        });
        for stage in stages {
            let claim = claims
                .entry(key(stage))
                .or_insert_with(|| self.disk.claim());
            // If a restarted host cannot cover the rest yet, keep its old
            // claim. The driver checks this admission before allocating.
            self.disk.hold(claim, self.sealed_work_room(stage));
        }
    }

    /// Stage admission and durable handle changes use one ledger lock, so
    /// an offset-zero successor cannot resize the detached work's claim.
    /// `Err(())` is the pre-existing disk-floor refusal, not a work refusal.
    pub(crate) fn stage_sealed_part(
        &self,
        vault: &oneiron::Vault,
        peer: PeerMachine,
        stage: &SealedBundleStage,
        offset: u64,
        part: &[u8],
    ) -> Result<oneiron::Result<u64>, ()> {
        let mut claims = self
            .sealed_stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let stages = match sealed_bundle_stages(vault) {
            Ok(stages) => stages,
            Err(error) => return Ok(Err(error)),
        };
        self.reconcile_sealed_in(&mut claims, &stages);
        let claim = match peer {
            PeerMachine::Proven { machine, .. } => {
                let claim = Arc::clone(
                    claims
                        .entry((machine, stage.object, None))
                        .or_insert_with(|| self.disk.claim()),
                );
                if !self.disk.hold(
                    &claim,
                    self.sealed_stage_room(stage.total, offset)
                        .max(claim.bytes()),
                ) {
                    return Err(());
                }
                Some(claim)
            }
            PeerMachine::Unknown => None,
        };
        let result =
            oneiron::sync::residence::stage_sealed_bundle_part(vault, peer, stage, offset, part);
        drop(claim);
        if let Ok(stages) = sealed_bundle_stages(vault) {
            self.reconcile_sealed_in(&mut claims, &stages);
        }
        Ok(result)
    }

    /// Durable begin and the transfer of its claims are indivisible with
    /// respect to new uploads on every socket of this host.
    pub(crate) fn sealed_stage_change<T>(
        &self,
        vault: &oneiron::Vault,
        change: impl FnOnce() -> T,
    ) -> T {
        let mut claims = self
            .sealed_stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let result = change();
        if let Ok(stages) = sealed_bundle_stages(vault) {
            self.reconcile_sealed_in(&mut claims, &stages);
        }
        result
    }

    /// Restores the ledger before any host allocations. A failed read is a
    /// storage fault, not evidence that retained uploads own no disk room.
    pub(crate) fn restore_sealed_stages(&self, vault: &oneiron::Vault) -> oneiron::Result<()> {
        let mut claims = self
            .sealed_stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let stages = sealed_bundle_stages(vault)?;
        self.reconcile_sealed_in(&mut claims, &stages);
        Ok(())
    }

    /// Reads that fail retain every claim. Work sources and cleanup bytes
    /// remain inventoried past the ordinary stage's idle age.
    pub(crate) fn reconcile_sealed_stages(&self, vault: &oneiron::Vault) {
        let mut claims = self
            .sealed_stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Ok(stages) = sealed_bundle_stages(vault) else {
            return;
        };
        self.reconcile_sealed_in(&mut claims, &stages);
    }

    /// A resumed work may wait for capacity after a restart. Its accepted
    /// state stays Pending; it never writes a stored copy under a zero claim.
    pub(crate) fn hold_sealed_work(
        &self,
        vault: &oneiron::Vault,
        id: [u8; 32],
    ) -> Option<Vec<Arc<DiskClaim>>> {
        let mut claims = self
            .sealed_stages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let stages = sealed_bundle_stages(vault).ok()?;
        self.reconcile_sealed_in(&mut claims, &stages);
        let mut held = Vec::new();
        for stage in stages.iter().filter(|stage| stage.work_id == Some(id)) {
            let claim = Arc::clone(claims.get(&key(stage))?);
            if !self.disk.hold(&claim, self.sealed_work_room(stage)) {
                return None;
            }
            held.push(claim);
        }
        Some(held)
    }
}
