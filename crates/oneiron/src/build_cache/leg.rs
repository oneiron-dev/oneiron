//! Build/verify runner: durable action-key reservation prevents duplicate dispatch.
use super::*;
use crate::checkout::CheckoutTaskClass;

/// In-flight reservation marker preventing duplicate dispatch of the same build/verify action.
/// Key: bytes32 (action key).
const RUNNING_RESERVATION: SideTable<[u8; BUILD_CACHE_ACTION_KEY_LEN], String, Raw> =
    SideTable::new(&side_table::BUILD_CACHE_RUNNING_RESERVATION);

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
    /// False for captured secret-consuming exhaust, which never enters the cache.
    pub reusable: bool,
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
        {
            let mut txn = self.vault.store.env.write_txn()?;
            self.admit_account_in_txn(&txn)?;
            if let Some(record) = BUILD_CACHE_REAPI_ROW.get(&self.vault.store, &txn, key.as_bytes())? {
                return Ok(leg(self.admit_row_in_txn(&txn, &key, record)?, class, true));
            }
            if RUNNING_RESERVATION.contains(&self.vault.store, &txn, key.as_bytes())? {
                return Err(BuildCacheError::ActionInFlight {
                    action_key: key.to_hex(),
                });
            }
            RUNNING_RESERVATION.put(
                &self.vault.store,
                &mut txn,
                key.as_bytes(),
                &class.as_str().to_owned(),
            )?;
            txn.commit().map_err(Error::from)?;
        }
        // Errors deliberately retain the reservation: the host must resolve an
        // uncertain execution instead of treating it as a safe cache miss.
        let candidate = execute(self.vault)?;
        // Secret-consuming exhaust is retained as artifacts, never as a clean
        // cache row. Its reservation remains so an uncertain retry cannot run it twice.
        {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.admit_account_in_txn(&txn)?;
            let tainted = candidate.artifact_refs().iter().try_fold(false, |tainted, reference| {
                match require_clean_in_txn(self.vault, &txn, reference) {
                    Ok(()) => Ok(tainted),
                    Err(BuildCacheError::TaintedResult { .. }) => Ok(true),
                    Err(error) => Err(error),
                }
            })?;
            if tainted {
                candidate.validate()?;
                for path in candidate.outputs.keys() {
                    if action.declared_outputs().binary_search(path).is_err() {
                        return Err(BuildCacheError::UndeclaredOutput { path: path.as_str().to_owned() });
                    }
                }
                let referenced_bytes = inspect_result_in_txn(self.vault, &txn, &candidate, false)?;
                let mut captured = leg(CachedActionResult {
                    action_key: key, action_size_bytes: action.reapi_digest()?.size_bytes,
                    result: candidate, referenced_bytes,
                }, class, false);
                captured.reusable = false;
                return Ok(captured);
            }
        }
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
    CachedBuildLeg { cached, receipt, reusable: true }
}
