//! One concern finding through the engine's real landing path, for the
//! integration tests (`crate::test_doors::agent_health`). Compiled only under
//! `--cfg oneiron_test_support`; never API.
//!
//! `land_concern` builds one `Finding` with no attempt and no task, reads the
//! dial book as the nightly review reads it, and lands the finding through
//! `pipeline::land` with no digest pairs, no refreshes and no escalation, so
//! the real DIAGNOSTIC emit, route, merge and card write run. A finding with
//! no attempt has no leader and no spawner: `route` gives no recipients and
//! copies the card to the owner, and `merge` adds the live owners as its
//! recipients. The caller creates the owner first: until the owner PERSON
//! exists the live-owner census is empty, and a card with no recipients
//! projects no inbox row.

use super::dials::DialBook;
use super::pipeline::land;
use super::vocabulary::{Finding, card_key, card_ref};
use super::{Attempts, Dispatches};
use crate::store::diagnostic_record::AgentHealthSignal;
use crate::{EntityId, Result, Vault};

/// Lands one finding about `subject` with `signal` and `evidence` at `now`,
/// and answers the card's `health:` handle.
///
/// The finding is shaped as the `misalignment` detector emits one: no task,
/// no attempt, no generation witness, `actual` and `measured` 1 against a
/// dial of 0, no exact pair, no counter-evidence, no confession, no brief
/// and no silence. `land` reads the agent's own blocked mark itself.
///
/// # Errors
///
/// The dial reads and the landing's storage errors.
pub fn land_concern(
    vault: &Vault,
    subject: EntityId,
    signal: AgentHealthSignal,
    evidence: Vec<EntityId>,
    now: u64,
) -> Result<String> {
    let finding = Finding {
        subject,
        signal,
        task: None,
        attempt: None,
        generation: None,
        evidence,
        source_rows: None,
        window: (now, now),
        actual: 1,
        dial: 0,
        measured: 1,
        exact_dial: None,
        exact_measured: None,
        counter: Vec::new(),
        confession: None,
        blocked: false,
        observed_brief: None,
        silence: None,
    };
    let dispatched = Dispatches::new();
    let attempts = Attempts::new();
    let book = DialBook::read(vault, &dispatched)?;
    land(
        vault,
        vec![finding],
        &[],
        &[],
        &dispatched,
        &attempts,
        &book,
        now,
        false,
    )?;
    Ok(card_ref(&card_key(subject, signal, None)))
}
