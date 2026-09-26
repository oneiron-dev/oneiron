use crate::attempt_queue::AttemptQueue;
use crate::config::VaultConfig;
use crate::dreamer_runner::{DreamerAttemptPayload, DreamerRunnerStore};
use crate::error::Result;
use rmpv::Value;

use super::{WakeGrain, request_turn_wake};

fn tick(vault: &crate::Vault, ordinal: u64, projection: Option<[u8; 32]>) -> Result<bool> {
    let outcome = request_turn_wake(
        &DreamerRunnerStore::new(vault),
        ordinal,
        projection,
        DreamerAttemptPayload {
            attempt_type: "micro".into(),
            input: Value::from("turn"),
            parent_attempt: None,
        },
        Some(format!("turn:{ordinal}")),
        None,
        ordinal,
    )?;
    Ok(outcome.is_some())
}

#[test]
fn two_vaults_have_independent_turn_grains_and_surprise_is_write_free() -> Result<()> {
    let (_first_dir, first) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let (_second_dir, second) = crate::test_util::open_test_vault_with(VaultConfig::device());
    assert_eq!(first.wake_grain()?, WakeGrain::default());
    second.set_wake_grain(WakeGrain::new(3)?)?;
    assert_eq!(first.wake_grain()?.turns_per_wake, 1);
    assert_eq!(second.wake_grain()?.turns_per_wake, 3);
    let image = [1; 32];
    assert!(!tick(&first, 1, None)?);
    assert!(AttemptQueue::new(&first).list()?.is_empty());
    assert!(tick(&first, 1, Some(image))?);
    assert!(!tick(&second, 1, Some(image))?);
    assert!(!tick(&second, 2, Some(image))?);
    assert!(tick(&second, 3, Some(image))?);
    // No material is a no-op even on a due turn; repeated projection is too.
    let first_count = AttemptQueue::new(&first).list()?.len();
    let second_count = AttemptQueue::new(&second).list()?.len();
    assert!(!tick(&first, 2, None)?);
    assert!(!tick(&second, 6, Some(image))?);
    assert_eq!(AttemptQueue::new(&first).list()?.len(), first_count);
    assert_eq!(AttemptQueue::new(&second).list()?.len(), second_count);
    assert!(tick(&first, 3, Some([2; 32]))?);
    assert!(tick(&second, 9, Some([2; 32]))?);
    assert!(WakeGrain::new(0).is_err());
    Ok(())
}

#[test]
fn new_image_on_same_turn_cannot_be_swallowed_by_advisory_dedupe() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    assert!(tick(&vault, 1, Some([1; 32]))?);
    assert!(tick(&vault, 1, Some([2; 32]))?);
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), 2);
    assert!(!tick(&vault, 1, Some([2; 32]))?);
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), 2);
    Ok(())
}
