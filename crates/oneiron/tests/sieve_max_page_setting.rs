//! Restriction wave 20, row C83: the sieve owner pages' row cap becomes the owner Setting key
//! `dreamer_wake.sieve.max_page`, default 1000 (today's cap), so nothing moves until the owner
//! sets it.
//!
//! The capped tests fail while the doors do not read the key (each page still carries every
//! span) and pass once they do; the no-row test passes on both.
//!
//! Public paths only: a witnessed turn, `Vault::sieve_pass`, `Vault::set_setting` for the owner's
//! row and the generated engine fn `oneiron::verbs::vault_sieve_queue`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test sieve_max_page_setting`.

use oneiron::dreamer_wake::sieve_doors::SievePageRequest;
use oneiron::memory::{Memory, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Two messages, each with a name and a date: spans the sieve's rules read.
const FIRST: &str = "We met Owen Hart on October 12, 2026.";
const SECOND: &str = "Then Yuki Mori called on October 13, 2026.";

fn message(id: EntityId, text: &str, order: u32) -> WitnessMessage {
    WitnessMessage {
        id: Some(id.to_hex()),
        author: WitnessAuthor::User,
        message_type: "text".to_owned(),
        content: text.to_owned(),
        parts: None,
        metadata: None,
        is_visible: true,
        order,
        quote: None,
    }
}

/// A vault whose sieve queue holds at least two spans of one witnessed turn.
fn queued_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let at = vault.now_recorded_at();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            project: None,
            occurred_at: at,
            messages: vec![
                message(EntityId::now(), FIRST, 0),
                message(EntityId::now(), SECOND, 1),
            ],
            assertions: Default::default(),
        })?;
    let mut passes = 0_u64;
    while vault.sieve_pass(vault.now_recorded_at() + passes)?.more {
        passes += 1;
        assert!(passes < 1_000, "FIXTURE: the sieve never settles");
    }
    let queued = vault.sieve_queue(usize::MAX)?.spans.len();
    assert!(
        queued >= 2,
        "FIXTURE: the turn queued {queued} spans, not two or more"
    );
    Ok((dir, vault))
}

fn owner_memory(vault: &Vault) -> Result<Memory<'_>, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(vault.memory(owner, EdgeActorClass::Human))
}

/// The owner sets `dreamer_wake.sieve.max_page` to `value` at the vault scope.
fn set_max_page(vault: &Vault, value: u32) -> TestResult {
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let outcome = vault.set_setting(
        SettingCaller::Owner(&proof),
        SetSetting::vault_value("dreamer_wake.sieve.max_page", serde_json::json!(value)),
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the owner's change did not apply: {outcome:?}"
    );
    Ok(())
}

/// The spans one owner page of the sieve queue carries for `limit`.
fn queue_page(vault: &Vault, limit: Option<u32>) -> Result<usize, Box<dyn std::error::Error>> {
    let memory = owner_memory(vault)?;
    let page = oneiron::verbs::vault_sieve_queue(&memory, SievePageRequest { limit })?;
    Ok(page.spans.len())
}

#[test]
fn sieve_queue_pages_one_span_once_max_page_is_one() -> TestResult {
    let (_dir, vault) = queued_vault()?;
    set_max_page(&vault, 1)?;
    assert_eq!(
        queue_page(&vault, None)?,
        1,
        "a page naming no limit reads the cap in force"
    );
    Ok(())
}

#[test]
fn sieve_queue_caps_a_larger_limit_at_max_page() -> TestResult {
    let (_dir, vault) = queued_vault()?;
    set_max_page(&vault, 1)?;
    assert_eq!(
        queue_page(&vault, Some(5))?,
        1,
        "a limit above the cap in force reads the cap"
    );
    Ok(())
}

#[test]
fn a_stored_zero_max_page_reads_as_one() -> TestResult {
    let (_dir, vault) = queued_vault()?;
    set_max_page(&vault, 0)?;
    assert_eq!(
        queue_page(&vault, None)?,
        1,
        "a stored 0 reads as 1, so a page still carries one span"
    );
    Ok(())
}

#[test]
fn sieve_queue_pages_every_span_with_no_setting_row() -> TestResult {
    let (_dir, vault) = queued_vault()?;
    let queued = vault.sieve_queue(usize::MAX)?.spans.len();
    assert_eq!(
        queue_page(&vault, None)?,
        queued,
        "with no row the cap is 1000, so the page carries every queued span"
    );
    assert_eq!(
        queue_page(&vault, Some(1))?,
        1,
        "a request's own limit still bounds the page"
    );
    Ok(())
}
