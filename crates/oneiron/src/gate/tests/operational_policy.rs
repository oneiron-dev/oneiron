//! Manifest-resident scheduler policy: defaults, restrictive fold and holder cap.
use super::*;

fn row(entries: &[(&str, u64)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::from(*key), Value::from(*value)))
            .collect(),
    )
}
fn mirror(poll: u64, timeout: u64) -> (Value, Value) {
    (
        Value::from("linear_mirror_policy"),
        row(&[
            ("poll_interval_secs", poll),
            ("request_timeout_secs", timeout),
        ]),
    )
}
fn budget(pages: u64) -> (Value, Value) {
    (
        Value::from("linear_sync_budget"),
        row(&[("max_pull_pages_per_pass", pages)]),
    )
}
fn handoff(scan: u64, floor: u64, cap: u64) -> (Value, Value) {
    (
        Value::from("wave_handoff_policy"),
        row(&[
            ("scan_limit", scan),
            ("retry_floor_ms", floor),
            ("retry_cap_ms", cap),
        ]),
    )
}
fn put(vault: &crate::Vault, seed: u8, rows: Vec<(Value, Value)>) -> Result<()> {
    put_policy_manifest_bytes(vault, test_id(seed), &encode_policy_manifest(rows))
}

#[test]
fn shipped_defaults_are_authored_and_resolve_in_snapshot() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let default =
        decode_policy_manifest(&default_policy_manifest()).expect("default manifest decodes");
    assert_eq!(
        default
            .linear_mirror
            .expect("mirror row")
            .poll_interval_secs,
        30
    );
    assert_eq!(
        default
            .linear_mirror
            .expect("mirror row")
            .request_timeout_secs,
        15
    );
    assert_eq!(
        default
            .linear_sync
            .expect("budget row")
            .max_pull_pages_per_pass,
        64
    );
    assert_eq!(default.wave_handoff.expect("handoff row").scan_limit, 256);
    assert_eq!(
        default.wave_handoff.expect("handoff row").retry_floor_ms,
        500
    );
    assert_eq!(
        default.wave_handoff.expect("handoff row").retry_cap_ms,
        60_000
    );
    assert!(
        vault.linear_mirror_policy().is_err(),
        "missing manifest is fail-closed"
    );
    put(&vault, 0x30, vec![])?;
    assert_eq!(vault.linear_mirror_policy()?.poll_interval_secs, 30);
    assert_eq!(vault.linear_sync_budget()?.max_pull_pages_per_pass, 64);
    Ok(())
}

#[test]
fn authored_rows_change_scheduler_and_frontier() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put(
        &vault,
        0x30,
        vec![mirror(45, 12), budget(16), handoff(32, 10, 20)],
    )?;
    let mirror_policy = vault.linear_mirror_policy()?;
    assert_eq!(
        (
            mirror_policy.poll_interval_secs,
            mirror_policy.request_timeout_secs
        ),
        (45, 12)
    );
    assert_eq!(vault.linear_sync_budget()?.max_pull_pages_per_pass, 16);
    assert_eq!(
        (
            vault.wave_handoff_policy()?.scan_limit,
            vault.wave_handoff_policy()?.retry_floor_ms
        ),
        (32, 10)
    );
    let initial_frontier = mirror_policy.policy_frontier;
    put(
        &vault,
        0x31,
        vec![mirror(60, 14), budget(8), handoff(16, 20, 40)],
    )?;
    assert_eq!(
        (
            vault.linear_mirror_policy()?.poll_interval_secs,
            vault.linear_mirror_policy()?.request_timeout_secs
        ),
        (60, 12)
    );
    assert_eq!(vault.linear_sync_budget()?.max_pull_pages_per_pass, 8);
    let wave = vault.wave_handoff_policy()?;
    assert_eq!(
        (wave.scan_limit, wave.retry_floor_ms, wave.retry_cap_ms),
        (16, 20, 40)
    );
    assert_ne!(initial_frontier, wave.policy_frontier);
    Ok(())
}

#[test]
fn holder_cannot_widen_any_axis_or_exceed_bounds() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put(
        &vault,
        0x30,
        vec![mirror(45, 12), budget(16), handoff(32, 10, 20)],
    )?;
    let mirror_policy = vault.linear_mirror_policy()?;
    assert_eq!(
        mirror_policy
            .with_holder(Some(LinearMirrorPolicy {
                poll_interval_secs: 60,
                request_timeout_secs: 8,
                ..mirror_policy
            }))?
            .policy_frontier,
        mirror_policy.policy_frontier
    );
    assert!(
        mirror_policy
            .with_holder(Some(LinearMirrorPolicy {
                poll_interval_secs: 20,
                ..mirror_policy
            }))
            .is_err()
    );
    assert!(
        mirror_policy
            .with_holder(Some(LinearMirrorPolicy {
                request_timeout_secs: 16,
                ..mirror_policy
            }))
            .is_err()
    );
    let budget_policy = vault.linear_sync_budget()?;
    assert_eq!(
        budget_policy
            .with_holder(Some(LinearSyncBudget {
                max_pull_pages_per_pass: 4,
                ..budget_policy
            }))?
            .max_pull_pages_per_pass,
        4
    );
    assert!(
        budget_policy
            .with_holder(Some(LinearSyncBudget {
                max_pull_pages_per_pass: 17,
                ..budget_policy
            }))
            .is_err()
    );
    let wave = vault.wave_handoff_policy()?;
    assert!(
        wave.with_holder(Some(WaveHandoffPolicy {
            scan_limit: 33,
            ..wave
        }))
        .is_err()
    );
    assert!(
        wave.with_holder(Some(WaveHandoffPolicy {
            retry_floor_ms: 9,
            ..wave
        }))
        .is_err()
    );
    assert!(
        wave.with_holder(Some(WaveHandoffPolicy {
            retry_cap_ms: 19,
            ..wave
        }))
        .is_err()
    );
    assert_eq!(
        wave.with_holder(Some(WaveHandoffPolicy {
            scan_limit: 2,
            retry_floor_ms: 21,
            retry_cap_ms: 22,
            ..wave
        }))?
        .scan_limit,
        2
    );
    Ok(())
}

#[test]
fn malformed_values_and_precedence_fail_closed() -> Result<()> {
    for bad in [
        vec![mirror(0, 15)],
        vec![mirror(30, 301)],
        vec![budget(0)],
        vec![handoff(257, 1, 2)],
        vec![handoff(2, 20, 10)],
        vec![(
            Value::from("operational_policy_precedence"),
            Value::from("unspecified"),
        )],
        vec![budget(16), budget(32)],
    ] {
        let (_tmp, vault) = temp_vault();
        put(&vault, 0x30, bad)?;
        assert!(resolve(&vault)?.diagnostics().malformed_manifest_seen);
        assert!(vault.linear_sync_budget().is_err());
    }
    let (_tmp, vault) = temp_vault();
    put(
        &vault,
        0x30,
        vec![
            (
                Value::from("operational_policy_precedence"),
                Value::from("nested_narrowing"),
            ),
            handoff(1, 10, 10),
        ],
    )?;
    let first = vault.wave_handoff_policy()?.policy_frontier;
    put(
        &vault,
        0x31,
        vec![(
            Value::from("operational_policy_precedence"),
            Value::from("holder_override_capped_at_vault"),
        )],
    )?;
    assert!(
        vault.wave_handoff_policy().is_err(),
        "conflicting precedence must not silently pick a winner"
    );
    assert_ne!(first, resolve(&vault)?.read_frontier_hash()?);
    Ok(())
}

#[test]
fn default_manifest_page_fixture_changes_live_vault_policy() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    let default_id = default_policy_manifest_id()?;
    let before = vault.linear_sync_budget()?;
    assert_eq!(before.max_pull_pages_per_pass, 64);
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        default_id,
        &crate::gate::default_manifest_with_linear_sync_pages_for_test(2),
    )?;
    let changed = vault.linear_sync_budget()?;
    assert_eq!(changed.max_pull_pages_per_pass, 2);
    assert_ne!(before.policy_frontier, changed.policy_frontier);
    Ok(())
}

#[test]
fn changed_manifest_budget_changes_real_linear_pull_pass() -> Result<()> {
    use crate::linear_sync::{
        LinearChangePage, LinearChangeSource, LinearEgress, LinearIssueChange, LinearIssueRef,
        LinearSyncAdapter, LinearSyncResult, MirroredTaskFields, VaultLinearTaskStore,
    };
    use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

    #[derive(Clone, Default)]
    struct PagedSource(Rc<RefCell<Vec<Option<String>>>>);
    impl LinearChangeSource for PagedSource {
        fn changes_since(&mut self, cursor: Option<&str>) -> LinearSyncResult<LinearChangePage> {
            self.0.borrow_mut().push(cursor.map(str::to_owned));
            Ok(LinearChangePage {
                changes: Vec::new(),
                next_cursor: match cursor {
                    None => Some("p1".into()),
                    Some("p1") => Some("p2".into()),
                    Some("p2") => None,
                    _ => panic!("unexpected cursor"),
                },
            })
        }
    }
    struct NoOutbound;
    impl LinearEgress for NoOutbound {
        fn create_issue(
            &mut self,
            _: [u8; 32],
            _: EntityId,
            _: &MirroredTaskFields,
        ) -> LinearSyncResult<LinearIssueChange> {
            panic!("no task is dirty")
        }
        fn update_issue_conditional(
            &mut self,
            _: [u8; 32],
            _: &LinearIssueRef,
            _: &BTreeMap<String, [u8; 32]>,
            _: &MirroredTaskFields,
        ) -> LinearSyncResult<LinearIssueChange> {
            panic!("no task is dirty")
        }
    }

    let tmp = tempfile::tempdir()?;
    let vault = crate::Vault::open(tmp.path(), crate::config::VaultConfig::default())?;
    let source = PagedSource::default();
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        source.clone(),
        NoOutbound,
    );
    let manifest_id = default_policy_manifest_id()?;
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &crate::gate::default_manifest_with_linear_sync_pages_for_test(2),
    )?;
    let limited = vault.linear_sync_budget()?;
    assert_eq!(limited.max_pull_pages_per_pass, 2);
    assert!(
        adapter
            .synchronize(100, limited.max_pull_pages_per_pass)
            .is_err()
    );
    assert_eq!(*source.0.borrow(), vec![None, Some("p1".into())]);

    crate::test_util::put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &crate::gate::default_manifest_with_linear_sync_pages_for_test(3),
    )?;
    let widened_by_owner = vault.linear_sync_budget()?;
    assert_eq!(widened_by_owner.max_pull_pages_per_pass, 3);
    assert_ne!(limited.policy_frontier, widened_by_owner.policy_frontier);
    let (_, pulled) = adapter
        .synchronize(101, widened_by_owner.max_pull_pages_per_pass)
        .expect("new policy admits the remaining page");
    assert_eq!(pulled.new_cursor.as_deref(), Some("p2"));
    assert_eq!(
        *source.0.borrow(),
        vec![None, Some("p1".into()), Some("p2".into())]
    );
    Ok(())
}
