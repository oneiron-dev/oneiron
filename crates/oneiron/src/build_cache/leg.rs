//! Build/verify runner: durable action-key reservation prevents duplicate dispatch.
use super::*;
use crate::checkout::CheckoutTaskClass;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildLegReceipt {
    pub action_key: ActionKey,
    pub task_class: CheckoutTaskClass,
    pub cache_hit: bool,
    pub producer_ref: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedBuildLeg {
    pub cached: CachedActionResult,
    pub receipt: BuildLegReceipt,
}
impl BuildCache<'_> {
    /// Only declared-idempotent task classes can use this runner. A pending
    /// action is never re-sent automatically, including after a process crash.
    pub fn run_leg(
        &self,
        class: CheckoutTaskClass,
        action: &BuildAction,
        execute: impl FnOnce(&Vault) -> BuildCacheResult<ActionResult>,
    ) -> BuildCacheResult<CachedBuildLeg> {
        if !matches!(class, CheckoutTaskClass::Build | CheckoutTaskClass::Verify) {
            return Err(BuildCacheError::InvalidAction(
                "leg is not declared idempotent",
            ));
        }
        let key = action.action_key()?;
        if let Some(cached) = self.get(&key)? {
            return Ok(leg(cached, class, true));
        }
        let reservation = [b"build_cache:running:v2:".as_slice(), key.as_bytes()].concat();
        {
            let mut txn = self.vault.store.env.write_txn().map_err(Error::from)?;
            if self
                .vault
                .store
                .vault_meta
                .get(&txn, &reservation)?
                .is_some()
            {
                return Err(BuildCacheError::ActionInFlight {
                    action_key: key.to_hex(),
                });
            }
            self.vault
                .store
                .vault_meta
                .put(&mut txn, &reservation, class.as_str().as_bytes())?;
            txn.commit().map_err(Error::from)?;
        }
        // Errors deliberately retain the reservation: the host must resolve an
        // uncertain execution instead of treating it as a safe cache miss.
        let candidate = execute(self.vault)?;
        let (cached, hit) = match self.put(action, candidate)? {
            BuildCachePutOutcome::Stored(value) => (value, false),
            BuildCachePutOutcome::Existing(value) => (value, true),
        };
        Ok(leg(cached, class, hit))
    }
}
fn leg(
    cached: CachedActionResult,
    task_class: CheckoutTaskClass,
    cache_hit: bool,
) -> CachedBuildLeg {
    let receipt = BuildLegReceipt {
        action_key: cached.action_key,
        task_class,
        cache_hit,
        producer_ref: cached.result.producer_ref.clone(),
    };
    CachedBuildLeg { cached, receipt }
}
