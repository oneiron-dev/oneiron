//! L1-03 PR 1 (PLAN-L1-03 D4): the MCP task handle row.
//!
//! A handle is a transport handle over a record the engine keeps (ARCH-0028
//! `#mcp-tasks`). Its id is 32 random bytes as 64 lowercase hex digits, and
//! the row is keyed by the id's hash. It answers only the actor whose request
//! minted it, until its time to live runs out; after that it reads as missing
//! for everyone and its row is gone. Unknown, another actor's and expired all
//! read the same, so nothing tells that a hidden handle exists.
//!
//! L1-03 PR 4: a handle keeps the first end a read of its record saw, so a
//! task's end never changes, even when the record goes on working (a night
//! step's remainder runs a policy interval later).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test mcp_task_store`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::mcp_task::{McpTaskEnd, McpTaskEnded, McpTaskId, McpTaskSubject};
use oneiron::{EntityId, Vault, VaultConfig};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

/// Host milliseconds of the first mint.
const T0: u64 = 1_794_700_000_000;

fn open_vault() -> Result<(tempfile::TempDir, Arc<Vault>), TestError> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    Ok((dir, vault))
}

#[test]
fn mcp_task_row_answers_only_its_actor_until_its_ttl() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let holder = EntityId::now();
    let stranger = EntityId::now();
    let subject = McpTaskSubject::WorkflowRun {
        root_attempt_ref: EntityId::now(),
    };

    let id = vault.mint_mcp_task(holder, subject.clone(), Some(1000), T0)?;

    let wire = id.to_hex();
    assert_eq!(wire.len(), 64, "the taskId is 32 bytes as hex");
    assert!(
        wire.bytes()
            .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f')),
        "the taskId is lowercase hex: {wire}"
    );
    assert_eq!(
        McpTaskId::from_hex(&wire),
        Some(id.clone()),
        "the wire id parses back"
    );
    assert_eq!(
        McpTaskId::from_hex(&wire.to_uppercase()),
        None,
        "only lowercase hex parses"
    );
    assert_eq!(
        McpTaskId::from_hex(&wire[..62]),
        None,
        "a short id does not parse"
    );
    assert!(
        !format!("{id:?}").contains(&wire[..16]),
        "the handle id is never written to a log"
    );

    let row = vault
        .mcp_task(holder, &id, T0 + 999)?
        .ok_or("the holder reads its handle before its time to live runs out")?;
    assert_eq!(row.actor_ref, holder);
    assert_eq!(row.subject, subject, "the handle names the record it wraps");
    assert_eq!((row.created_at_ms, row.ttl_ms), (T0, Some(1000)));
    assert_eq!(row.cancel_requested_at_ms, None);

    assert_eq!(
        vault.mcp_task(stranger, &id, T0 + 999)?,
        None,
        "another actor's read finds no handle"
    );
    assert_eq!(
        vault.mcp_task(
            holder,
            &McpTaskId::from_hex(&"0".repeat(64)).ok_or("zero id")?,
            T0
        )?,
        None,
        "an unknown id reads as missing too"
    );

    assert_eq!(
        vault.mcp_task(holder, &id, T0 + 1000)?,
        None,
        "the handle ends when its time to live runs out"
    );
    assert_eq!(
        vault.mcp_task(holder, &id, T0 + 1)?,
        None,
        "the expired handle's row is gone: a read at an earlier clock finds nothing either"
    );

    let kept = vault.mint_mcp_task(holder, subject.clone(), None, T0)?;
    assert_ne!(
        kept.to_hex(),
        wire,
        "two mints over one record are two handles"
    );
    assert!(
        vault.mcp_task(holder, &kept, u64::MAX)?.is_some(),
        "a handle with no time to live does not expire"
    );

    assert_eq!(
        vault.request_mcp_task_cancel(stranger, &kept, T0 + 5)?,
        None,
        "another actor cannot ask the handle's work to stop"
    );
    let asked = vault
        .request_mcp_task_cancel(holder, &kept, T0 + 5)?
        .ok_or("the holder asks its work to stop")?;
    assert_eq!(asked.cancel_requested_at_ms, Some(T0 + 5));
    let again = vault
        .request_mcp_task_cancel(holder, &kept, T0 + 9)?
        .ok_or("the holder asks again")?;
    assert_eq!(
        again.cancel_requested_at_ms,
        Some(T0 + 5),
        "the first request's time stays"
    );
    Ok(())
}

#[test]
fn a_handle_keeps_the_first_end_it_saw() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let holder = EntityId::now();
    let stranger = EntityId::now();
    let id = vault.mint_mcp_task(
        holder,
        McpTaskSubject::NightStep {
            wake_root_ref: EntityId::now(),
        },
        Some(1000),
        T0,
    )?;
    let minted = vault
        .mcp_task(holder, &id, T0)?
        .ok_or("the holder reads its new handle")?;
    assert_eq!(minted.ended, None, "a new handle keeps no end");
    assert_eq!(
        minted.last_updated_at_ms(),
        T0,
        "a new handle last changed at its mint"
    );

    assert_eq!(
        vault.end_mcp_task(stranger, &id, McpTaskEnd::Completed, T0 + 5)?,
        None,
        "another actor cannot end the handle"
    );
    assert_eq!(
        vault
            .mcp_task(holder, &id, T0 + 5)?
            .ok_or("the handle stands")?
            .ended,
        None,
        "another actor's end wrote nothing"
    );

    let ended = vault
        .end_mcp_task(holder, &id, McpTaskEnd::Completed, T0 + 10)?
        .ok_or("the holder's read saw the end")?;
    assert_eq!(
        ended.ended,
        Some(McpTaskEnded {
            end: McpTaskEnd::Completed,
            at_ms: T0 + 10
        })
    );
    assert_eq!(
        ended.last_updated_at_ms(),
        T0 + 10,
        "the end is the handle's last change"
    );

    let again = vault
        .end_mcp_task(holder, &id, McpTaskEnd::CompletedWithError, T0 + 20)?
        .ok_or("a later read saw another end")?;
    assert_eq!(
        again.ended,
        Some(McpTaskEnded {
            end: McpTaskEnd::Completed,
            at_ms: T0 + 10
        }),
        "the first end stays: a task's end never changes"
    );
    let asked = vault
        .request_mcp_task_cancel(holder, &id, T0 + 30)?
        .ok_or("the holder asks after the end")?;
    assert_eq!(
        (
            asked.ended.map(|ended| ended.end),
            asked.last_updated_at_ms()
        ),
        (Some(McpTaskEnd::Completed), T0 + 30),
        "a later cancel request leaves the end and is the last change"
    );

    assert_eq!(
        vault.end_mcp_task(holder, &id, McpTaskEnd::Completed, T0 + 1000)?,
        None,
        "an expired handle keeps no end"
    );
    assert_eq!(
        vault.mcp_task(holder, &id, T0 + 1)?,
        None,
        "and its row is gone"
    );
    Ok(())
}
