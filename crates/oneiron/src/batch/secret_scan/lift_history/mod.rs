//! The historical lift sweep (OF-067; ARCH-0069 #mask-on-write). A row
//! written while the owner's switch was off, or before the write wall
//! existed, is read again by the batch door's rules. Each secret they place
//! goes to custody through the row's own writer door, which leaves its handle
//! where the secret was. A hit the sweep cannot place is never skipped: it
//! files a value-free lift proposal for the owner ([`SecretLiftProposal`]).
//!
//! A run is queued when the switch goes from off to on, in the switch's own
//! transaction, or when the owner asks ([`Vault::start_secret_lift`]). A
//! vault that was always on has nothing to sweep, so no run starts on its
//! own. The housekeeping pass works a run a page at a time from a
//! `(family, last key)` cursor and stops between pages at its deadline. Each
//! row the sweep rewrites commits in one transaction with its custody records
//! and the run's progress, so a page read again after a crash finds that row
//! clean. A run pauses while the switch is off. It ends with one owner
//! receipt: counts per family, never a value or a digest.
//!
//! The owner hears of the proposals a run leaves open through one needs-you
//! notice ([`notice`]), and closes each with a reason, or it closes on its
//! own once its row reads clean ([`proposals`]).
//!
//! What a run cannot reach is the owner's: a checkpoint, a backup or a peer
//! copy already sent keeps the raw value, and only a HardErase reaches it.

mod attempts;
mod authored;
mod carriers;
mod loro_blocks;
mod notice;
mod proposals;
mod record_text;
mod records;
mod retained;
mod side_rows;

use std::borrow::Cow;
use std::ops::Bound;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{SecretScanMode, secret_scan_mode_in_txn};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, GateError, Result};
use crate::secret_snapshot::SecretLiftProposal;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// Rows one census page reads before the pass may stop.
const LIFT_PAGE_ROWS: usize = 64;

/// Failed rows a run keeps to try again once its walk ends; a row past the
/// bound counts as failed at once.
const RETRY_BOUND: usize = 256;

/// Proposals [`Vault::secret_lift_status`] lists; the count covers all.
const STATUS_PROPOSALS: usize = 100;

/// Whether a record whose retained history still holds a value the sweep
/// masked files a proposal (CALLS, open). The sweep holds no owner's proof,
/// so it cannot run the owner's history purge, which keeps pinned versions
/// and answers to a hold and the shared veto: it keeps every retained
/// revision, and the owner purges the record.
const PROPOSE_HISTORY: bool = true;

const RUN: SideTable<(), LiftRun, Named> = SideTable::new(&side_table::SECRET_LIFT_RUN);
const RECEIPTS: SideTable<EntityId, SecretLiftReceipt, Named> =
    SideTable::new(&side_table::SECRET_LIFT_RECEIPT);
const PROPOSALS: SideTable<Vec<u8>, SecretLiftHistoryProposal, Named> =
    SideTable::new(&side_table::SECRET_LIFT_PROPOSAL);

/// A family of carriers the sweep walks, in walk order.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LiftFamily {
    /// The entity table: a record's body, the text it was indexed with and
    /// the text it staged for idle publication, a NOTE's live text, title and
    /// pin quotes, a file's bytes.
    Records,
    /// The attempt records (`job_records`), with the intake events their rows
    /// carry: an inbound surface event is queued inside its attempt's row.
    Attempts,
    /// The rows of each side table the catalog classes as authored.
    SideRows,
    /// Carriers no door rewrites: receipt ledgers, op logs, snapshots,
    /// stream seeds and documents' stored history.
    Carriers,
}

impl LiftFamily {
    const ALL: [Self; 4] = [
        Self::Records,
        Self::Attempts,
        Self::SideRows,
        Self::Carriers,
    ];

    /// The family's stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Records => "records",
            Self::Attempts => "attempts",
            Self::SideRows => "side_rows",
            Self::Carriers => "carriers",
        }
    }

    fn next(self) -> Option<Self> {
        Self::ALL
            .into_iter()
            .skip_while(|family| *family != self)
            .nth(1)
    }
}

/// What queued a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiftTrigger {
    /// The owner switched the scan from off to on.
    Switch,
    /// The owner asked for a run.
    Owner,
}

/// Why the sweep filed a proposal instead of placing a hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiftCause {
    /// No rule the door has places it: a recovery phrase, a key split over
    /// fields, a masked copy the row's own reading refuses.
    Unplaceable,
    /// The row's own writer refuses a rewrite: an immutable record.
    Immutable,
    /// A legal hold keeps the record as it stands.
    Held,
    /// A file, whose bytes stay as they are; its keys are marked.
    File,
    /// A carrier no door rewrites.
    NoDoor,
    /// The record's retained history still holds the value.
    History,
}

impl LiftCause {
    /// The cause's stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unplaceable => "unplaceable",
            Self::Immutable => "immutable",
            Self::Held => "held",
            Self::File => "file",
            Self::NoDoor => "no_door",
            Self::History => "history",
        }
    }
}

/// Why a proposal closed. The owner closes one as `not_a_secret`, `rotated`
/// or `accepted`; the others close it on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LiftCloseReason {
    /// The owner: what the sweep found is no secret.
    NotASecret,
    /// The owner rotated or revoked the value where it is issued.
    Rotated,
    /// The owner keeps the row as it stands.
    Accepted,
    /// A later run read the row again and found no hit there.
    ReadClean,
    /// The owner answered each key the sweep lifted out of the record
    /// through a found-key door: rotate, delete or not a secret.
    Answered,
    /// The row was deleted.
    Deleted,
}

impl LiftCloseReason {
    /// The reason's stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotASecret => "not_a_secret",
            Self::Rotated => "rotated",
            Self::Accepted => "accepted",
            Self::ReadClean => "read_clean",
            Self::Answered => "answered",
            Self::Deleted => "deleted",
        }
    }
}

/// How many open proposals one cause holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiftCauseCount {
    pub cause: LiftCause,
    pub open: u64,
}

/// One family's counts in a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LiftCounts {
    pub family: LiftFamily,
    /// Rows the census read.
    pub read: u64,
    /// Rows the sweep rewrote with their handles.
    pub masked: u64,
    /// Proposals it filed.
    pub proposals: u64,
    /// Rows that failed again when retried.
    pub failed: u64,
}

impl LiftCounts {
    const fn new(family: LiftFamily) -> Self {
        Self {
            family,
            read: 0,
            masked: 0,
            proposals: 0,
            failed: 0,
        }
    }
}

/// The run in progress. One row.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LiftRun {
    run_id: EntityId,
    trigger: LiftTrigger,
    requested_by: Option<EntityId>,
    requested_at: u64,
    /// Bumped by each queueing, so a page read before the walk started over
    /// does not move its cursor.
    epoch: u64,
    family: LiftFamily,
    /// The last key the walk finished in `family`; empty at its start.
    after: Vec<u8>,
    counts: Vec<LiftCounts>,
    /// Rows to try again once the walk ends.
    retry: Vec<(LiftFamily, Vec<u8>)>,
}

impl LiftRun {
    fn counts(&mut self, family: LiftFamily) -> &mut LiftCounts {
        if let Some(at) = self.counts.iter().position(|row| row.family == family) {
            return &mut self.counts[at];
        }
        self.counts.push(LiftCounts::new(family));
        let last = self.counts.len() - 1;
        &mut self.counts[last]
    }
}

/// The owner's receipt for one finished run. Holds no value and no digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretLiftReceipt {
    pub receipt_id: String,
    pub trigger: LiftTrigger,
    /// The owner who asked, as hex; none for a switch's run.
    pub requested_by: Option<String>,
    pub requested_at: u64,
    pub finished_at: u64,
    pub families: Vec<LiftCounts>,
    pub masked: u64,
    pub proposals: u64,
    pub failed: u64,
}

/// A hit the sweep left for the owner, with why. A closed one keeps its
/// cause and says when, by whom and why it closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretLiftHistoryProposal {
    /// The proposal's id, as hex: what the owner's close names.
    #[serde(default)]
    pub id: String,
    pub family: LiftFamily,
    pub cause: LiftCause,
    /// The record or row (`record:<id>`, `side:<table>:<key>`,
    /// `carrier:<table>:<key>`), the detector's reason and a suggested
    /// custody name. No value.
    pub proposal: SecretLiftProposal,
    pub run_id: String,
    pub filed_at: u64,
    /// When it closed; none while it is open.
    pub closed_at: Option<u64>,
    /// Who closed it: the owner, as hex, or `sweep` when it closed on its
    /// own.
    pub closed_by: Option<String>,
    pub close_reason: Option<LiftCloseReason>,
    /// The owner's close's Gate receipt, `gate:<hex>`; none for one that
    /// closed on its own.
    pub close_receipt: Option<String>,
}

impl SecretLiftHistoryProposal {
    /// Whether the proposal is still open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.closed_at.is_none()
    }
}

/// Where a run stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretLiftProgress {
    pub run_id: String,
    pub trigger: LiftTrigger,
    pub requested_at: u64,
    /// The family the walk is in.
    pub family: LiftFamily,
    /// Rows waiting to be tried again.
    pub retrying: u64,
    pub counts: Vec<LiftCounts>,
}

/// The sweep's state for the owner: the run in progress, the last receipt
/// and the proposals still open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretLiftStatus {
    pub mode: SecretScanMode,
    /// A run waits while the switch is off.
    pub paused: bool,
    pub running: Option<SecretLiftProgress>,
    pub last: Option<SecretLiftReceipt>,
    pub open_proposals: u64,
    /// The open proposals, counted by why the sweep left each.
    pub open_by_cause: Vec<LiftCauseCount>,
    /// The proposals closed, by the owner or on their own.
    pub closed_proposals: u64,
    /// The first open proposals, in key order.
    pub proposals: Vec<SecretLiftHistoryProposal>,
}

/// `vault.secrets.lift_history`'s input: the status, after closing one
/// proposal or queueing a run when asked.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretLiftRequest {
    /// Queue a run now. A run already queued walks again from the start.
    #[serde(default)]
    pub start: bool,
    /// Close one open proposal first, with the owner's reason.
    #[serde(default)]
    pub close: Option<SecretLiftClose>,
}

/// The owner's close of one lift proposal.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretLiftClose {
    /// The proposal's `id`.
    pub proposal: String,
    /// `not_a_secret`, `rotated` or `accepted`.
    pub reason: LiftCloseReason,
}

/// What one housekeeping run of the sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LiftPass {
    pub(crate) read: u64,
    pub(crate) masked: u64,
    pub(crate) proposals: u64,
    pub(crate) failed: u64,
    pub(crate) paused: bool,
    pub(crate) finished: bool,
}

/// Queues a run in the caller's transaction. A run already queued walks
/// again from its first family and keeps what it counted.
pub(crate) fn enqueue_lift_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    trigger: LiftTrigger,
    requested_by: Option<EntityId>,
    at: u64,
) -> Result<()> {
    let run = match RUN.get_lenient(store, txn, &())? {
        Some(run) => LiftRun {
            epoch: run.epoch.wrapping_add(1),
            family: LiftFamily::Records,
            after: Vec::new(),
            ..run
        },
        None => LiftRun {
            run_id: store.clock.entity_id()?,
            trigger,
            requested_by,
            requested_at: at,
            epoch: 0,
            family: LiftFamily::Records,
            after: Vec::new(),
            counts: Vec::new(),
            retry: Vec::new(),
        },
    };
    RUN.put(store, txn, &(), &run)
}

/// What one row came to.
enum Done {
    /// Nothing the door finds, or the row is gone.
    Clean,
    /// Rewritten with its handles; `history` when the record's retained
    /// history still holds the value.
    Masked { history: bool, reason: &'static str },
    /// Left for the owner.
    Propose(LiftCause, &'static str),
}

/// One census page: rows read, the keys of the rows that hold a hit, and
/// where the next page starts (`None` once the family is done).
struct Page {
    read: u64,
    hits: Vec<Vec<u8>>,
    next: Option<Vec<u8>>,
}

/// Runs the queued run's pages until it ends or `passed` says the pass's
/// deadline has. Returns what it did and whether the sweep is done for now:
/// no run, a paused run, or a finished one.
pub(crate) fn run_lift_pass(vault: &Vault, passed: impl Fn() -> bool) -> Result<(LiftPass, bool)> {
    let mut pass = LiftPass::default();
    // Proposals whose rows were deleted or answered close between runs too.
    proposals::review(vault)?;
    loop {
        let (run, mode) = {
            let txn = vault.store.env.read_txn()?;
            (
                RUN.get_lenient(&vault.store, &txn, &())?,
                secret_scan_mode_in_txn(&vault.store, &txn)?,
            )
        };
        let Some(run) = run else {
            return Ok((pass, true));
        };
        if mode == SecretScanMode::Off {
            pass.paused = true;
            return Ok((pass, true));
        }
        if !walk_page(vault, &run, &mut pass)? {
            return Ok((pass, true));
        }
        if run_finished(vault, &run, &mut pass)? {
            return Ok((pass, true));
        }
        if passed() {
            return Ok((pass, false));
        }
    }
}

/// One page of the run's walk; `false` when the switch went off under it.
fn walk_page(vault: &Vault, run: &LiftRun, pass: &mut LiftPass) -> Result<bool> {
    let family = run.family;
    let (mut page, cleared) = {
        let txn = vault.store.env.read_txn()?;
        let page = match family {
            LiftFamily::Records => records::census(vault, &txn, &run.after, LIFT_PAGE_ROWS)?,
            LiftFamily::Attempts => attempts::census(vault, &txn, &run.after, LIFT_PAGE_ROWS)?,
            LiftFamily::SideRows => side_rows::census(vault, &txn, &run.after, LIFT_PAGE_ROWS)?,
            LiftFamily::Carriers => carriers::census(vault, &txn, &run.after, LIFT_PAGE_ROWS)?,
        };
        // A row an open proposal names that this page read without a hit
        // is settled too, so its proposal closes.
        let cleared =
            proposals::open_in_page(vault, &txn, family, &run.after, page.next.as_deref())?;
        (page, cleared)
    };
    pass.read += page.read;
    let mut keys = std::mem::take(&mut page.hits);
    keys.extend(cleared);
    keys.sort_unstable();
    keys.dedup();
    for key in &keys {
        if !settle(vault, run, family, key, true, pass)? {
            pass.paused = true;
            return Ok(false);
        }
    }
    let mut txn = vault.store.env.write_txn()?;
    let Some(mut current) = RUN.get_lenient(&vault.store, &txn, &())? else {
        return Ok(true);
    };
    if current.run_id == run.run_id && current.epoch == run.epoch && current.family == family {
        current.counts(family).read += page.read;
        match page.next {
            Some(next) => current.after = next,
            None => {
                current.after = Vec::new();
                // The last family's end leaves the cursor past it, for the
                // retries and the receipt.
                current.family = family.next().unwrap_or(family);
                if family.next().is_none() {
                    current.after = vec![u8::MAX];
                }
            }
        }
        RUN.put(&vault.store, &mut txn, &(), &current)?;
    }
    txn.commit()?;
    Ok(true)
}

/// Retries the rows the walk could not finish and writes the receipt once
/// the walk is past its last family; `true` when the run ended.
fn run_finished(vault: &Vault, run: &LiftRun, pass: &mut LiftPass) -> Result<bool> {
    let current = {
        let txn = vault.store.env.read_txn()?;
        RUN.get_lenient(&vault.store, &txn, &())?
    };
    let Some(current) = current else {
        return Ok(true);
    };
    if current.run_id != run.run_id
        || current.family != LiftFamily::Carriers
        || current.after != [u8::MAX]
    {
        return Ok(false);
    }
    for (family, key) in &current.retry {
        if !settle(vault, &current, *family, key, false, pass)? {
            pass.paused = true;
            return Ok(false);
        }
    }
    let mut txn = vault.store.env.write_txn()?;
    let Some(mut ended) = RUN.get_lenient(&vault.store, &txn, &())? else {
        return Ok(true);
    };
    if ended.run_id != current.run_id || ended.epoch != current.epoch {
        return Ok(false);
    }
    let finished_at = crate::ports::recorded_at_in_txn(&vault.store, &mut txn)?;
    for family in LiftFamily::ALL {
        ended.counts(family);
    }
    ended.counts.sort_by_key(|row| row.family);
    let total = |pick: fn(&LiftCounts) -> u64| ended.counts.iter().map(pick).sum::<u64>();
    let receipt = SecretLiftReceipt {
        receipt_id: ended.run_id.to_hex(),
        trigger: ended.trigger,
        requested_by: ended.requested_by.map(|owner| owner.to_hex()),
        requested_at: ended.requested_at,
        finished_at,
        masked: total(|row| row.masked),
        proposals: total(|row| row.proposals),
        failed: total(|row| row.failed),
        families: ended.counts.clone(),
    };
    RECEIPTS.put(&vault.store, &mut txn, &ended.run_id, &receipt)?;
    RUN.delete(&vault.store, &mut txn, &())?;
    notice::after_run_in_txn(
        vault,
        &mut txn,
        ended.run_id,
        receipt.proposals,
        finished_at,
    )?;
    txn.commit()?;
    pass.finished = true;
    tracing::info!(
        run = %receipt.receipt_id,
        masked = receipt.masked,
        proposals = receipt.proposals,
        failed = receipt.failed,
        "secret lift: a run ended"
    );
    Ok(true)
}

/// Reads one row again in its own write transaction and settles it: the
/// rewrite, the custody it mints, a proposal and the run's progress commit
/// together. A row whose rewrite fails for a reason the door does not give is
/// kept to try again once the walk ends (`first`), or counted as failed;
/// either way its failure is logged without its value. `false` when the
/// switch went off under the page.
fn settle(
    vault: &Vault,
    run: &LiftRun,
    family: LiftFamily,
    key: &[u8],
    first: bool,
    pass: &mut LiftPass,
) -> Result<bool> {
    let mut txn = vault.store.env.write_txn()?;
    if secret_scan_mode_in_txn(&vault.store, &txn)? == SecretScanMode::Off {
        return Ok(false);
    }
    let lifted = match family {
        LiftFamily::Records => records::lift(vault, &mut txn, key),
        LiftFamily::Attempts => attempts::lift(vault, &mut txn, key),
        LiftFamily::SideRows => side_rows::lift(vault, &mut txn, key),
        LiftFamily::Carriers => lift_carrier(vault, &mut txn, key),
    };
    let done = match lifted {
        Ok(done) => done,
        Err(error) => {
            // The rewrite's writes go with its transaction.
            drop(txn);
            txn = vault.store.env.write_txn()?;
            match refused(&error) {
                Some((cause, reason)) => Done::Propose(cause, reason),
                None => {
                    tracing::warn!(
                        family = family.code(),
                        kind = ?error.kind(),
                        retried = first,
                        "secret lift: a row could not be rewritten"
                    );
                    progress_in_txn(vault, &mut txn, run, family, key, |current| {
                        if first && current.retry.len() < RETRY_BOUND {
                            current.retry.push((family, key.to_vec()));
                            return;
                        }
                        current
                            .retry
                            .retain(|(at, held)| !(*at == family && held == key));
                        current.counts(family).failed += 1;
                        pass.failed += 1;
                    })?;
                    txn.commit()?;
                    return Ok(true);
                }
            }
        }
    };
    // A row that reads clean now closes the proposal it holds open.
    let closed = match done {
        Done::Clean | Done::Masked { .. } => {
            proposals::close_clean_in_txn(vault, &mut txn, family, key)?
        }
        Done::Propose(..) => false,
    };
    if closed {
        notice::settle_in_txn(vault, &mut txn)?;
    }
    let filed = match done {
        Done::Clean => None,
        Done::Masked { history, reason } => {
            let filed = (history && PROPOSE_HISTORY)
                .then(|| {
                    file_in_txn(
                        vault,
                        &mut txn,
                        run,
                        family,
                        key,
                        LiftCause::History,
                        reason,
                    )
                })
                .transpose()?;
            Some((true, filed.unwrap_or(false)))
        }
        Done::Propose(cause, reason) => Some((
            false,
            file_in_txn(vault, &mut txn, run, family, key, cause, reason)?,
        )),
    };
    progress_in_txn(vault, &mut txn, run, family, key, |current| {
        if !first {
            current
                .retry
                .retain(|(at, held)| !(*at == family && held == key));
        }
        if let Some((masked, filed)) = filed {
            if masked {
                current.counts(family).masked += 1;
                pass.masked += 1;
            }
            if filed {
                current.counts(family).proposals += 1;
                pass.proposals += 1;
            }
        }
    })?;
    txn.commit()?;
    Ok(true)
}

/// Applies `change` to the run row in `txn`, and moves its cursor past `key`
/// when the walk is still the one `run` read.
fn progress_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    run: &LiftRun,
    family: LiftFamily,
    key: &[u8],
    change: impl FnOnce(&mut LiftRun),
) -> Result<()> {
    let Some(mut current) = RUN.get_lenient(&vault.store, txn, &())? else {
        return Ok(());
    };
    if current.run_id != run.run_id {
        return Ok(());
    }
    change(&mut current);
    if current.epoch == run.epoch
        && current.family == family
        && current.after.as_slice() < key
        && current.after != [u8::MAX]
    {
        current.after = key.to_vec();
    }
    RUN.put(&vault.store, txn, &(), &current)
}

/// A carrier row read by its door, then by its Loro blocks decompressed: a
/// hit only a block holds files a `no_door` proposal.
fn lift_carrier(vault: &Vault, txn: &mut RwTxn<'_>, key: &[u8]) -> Result<Done> {
    match carriers::lift(vault, txn, key)? {
        Done::Clean => Ok(
            loro_blocks::hit_at(vault, txn, key)?.map_or(Done::Clean, |reason| {
                Done::Propose(LiftCause::NoDoor, reason)
            }),
        ),
        done => Ok(done),
    }
}

/// Files a proposal for `key` unless one is open for it, or the owner closed
/// it; `true` when filed. An open one takes the door's word on its cause; one
/// that closed because its row read clean or was gone opens again.
fn file_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    run: &LiftRun,
    family: LiftFamily,
    key: &[u8],
    cause: LiftCause,
    reason: &'static str,
) -> Result<bool> {
    let row_key = proposal_key(family, cause, key);
    if let Some(held) = PROPOSALS.get_lenient(&vault.store, txn, &row_key)? {
        if held.is_open() {
            proposals::refresh_in_txn(vault, txn, &row_key, held, cause, reason)?;
            return Ok(false);
        }
        if !proposals::reopens(&held) {
            return Ok(false);
        }
    }
    let path = match family {
        LiftFamily::Records => records::path(key),
        LiftFamily::Attempts => attempts::path(key),
        LiftFamily::SideRows => side_rows::path(key),
        LiftFamily::Carriers => carriers::path(key),
    };
    let filed_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    PROPOSALS.put(
        &vault.store,
        txn,
        &row_key,
        &SecretLiftHistoryProposal {
            id: hex(&row_key),
            family,
            cause,
            proposal: SecretLiftProposal {
                suggested_secret_name: format!("lifted.{}.{}", family.code(), short(&path)),
                path,
                detector_reason: reason.to_owned(),
                project_id: String::new(),
            },
            run_id: run.run_id.to_hex(),
            filed_at,
            closed_at: None,
            closed_by: None,
            close_reason: None,
            close_receipt: None,
        },
    )?;
    Ok(true)
}

fn proposal_key(family: LiftFamily, cause: LiftCause, key: &[u8]) -> Vec<u8> {
    let cause = match cause {
        LiftCause::History => b'h',
        _ => b'r',
    };
    [family.code().as_bytes(), &[0, cause][..], key].concat()
}

/// The tail of a path a suggested name keeps: its last segment's first
/// twelve characters.
fn short(path: &str) -> String {
    path.rsplit(':')
        .next()
        .unwrap_or(path)
        .chars()
        .take(12)
        .collect()
}

/// The proposal a rewrite's failure files: the door's refusal names a hit no
/// rule places, a legal hold keeps the record, and any refusal of the row's
/// own writer marks a row it will not rewrite. `None` for a failure of the
/// store, retried.
fn refused(error: &Error) -> Option<(LiftCause, &'static str)> {
    if let Error::Gate(GateError::GateWriteRejected { reason_codes, .. }) = error
        && let Some(reason) = reason_codes
            .iter()
            .rev()
            .find(|code| code.starts_with("gate.secret_scan."))
    {
        return Some((LiftCause::Unplaceable, *reason));
    }
    match error.kind() {
        ErrorKind::Storage
        | ErrorKind::Io
        | ErrorKind::MapFull
        | ErrorKind::ConcurrentWrite
        | ErrorKind::InvariantViolation => None,
        _ => Some((LiftCause::Immutable, "gate.secret_scan.detected")),
    }
}

/// The first rows of a declared table after `after`, a whole key, up to
/// `limit`; with whether the table ends there.
fn table_page<'txn>(
    vault: &Vault,
    txn: &'txn RoTxn<'_>,
    prefix: &[u8],
    after: &[u8],
    limit: usize,
) -> Result<(Vec<(Vec<u8>, Cow<'txn, [u8]>)>, bool)> {
    let end = prefix_end(prefix);
    let start = if after.is_empty() || after < prefix {
        Bound::Included(prefix)
    } else {
        Bound::Excluded(after)
    };
    let upper = end.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
    let mut rows = Vec::new();
    for row in vault.store.vault_meta.range(txn, &(start, upper))? {
        let (key, value) = row?;
        if !key.starts_with(prefix) {
            break;
        }
        rows.push((key.into_owned(), value));
        if rows.len() == limit {
            return Ok((rows, false));
        }
    }
    Ok((rows, true))
}

/// `bytes` as lowercase hex, for a proposal's path.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The exclusive upper bound of every key under `prefix`.
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

impl Vault {
    /// Queues a run of the historical lift sweep (OF-067): every record and
    /// authored row the vault stored is read again by the write door's rules,
    /// each secret they place goes to custody with its handle left in place,
    /// and each hit they cannot place files a lift proposal. The housekeeping
    /// pass runs it; `oneiron maintain` runs it to its end. A run already
    /// queued walks again from the start. Only a live vault owner may ask.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof belongs to
    /// another vault, its person is no longer live, or the actor is not an
    /// owner of this vault.
    pub fn start_secret_lift(
        &self,
        owner: &AuthenticatedOwner,
        now: u64,
    ) -> Result<SecretLiftStatus> {
        let mut txn = self.store.env.write_txn()?;
        let actor = live_owner_in_txn(self, owner, &txn)?;
        enqueue_lift_in_txn(&self.store, &mut txn, LiftTrigger::Owner, Some(actor), now)?;
        txn.commit()?;
        self.secret_lift_status()
    }

    /// The lift sweep's state: the run in progress, the last receipt and the
    /// proposals still open.
    pub fn secret_lift_status(&self) -> Result<SecretLiftStatus> {
        let txn = self.store.env.read_txn()?;
        let mode = secret_scan_mode_in_txn(&self.store, &txn)?;
        let running = RUN
            .get_lenient(&self.store, &txn, &())?
            .map(|run| SecretLiftProgress {
                run_id: run.run_id.to_hex(),
                trigger: run.trigger,
                requested_at: run.requested_at,
                family: run.family,
                retrying: u64::try_from(run.retry.len()).unwrap_or(u64::MAX),
                counts: run.counts,
            });
        let last = RECEIPTS
            .iter_rev_from(&self.store, &txn, &[])?
            .next()
            .transpose()?
            .map(|(_, receipt)| receipt);
        let mut open_proposals = 0_u64;
        let mut closed_proposals = 0_u64;
        let mut open_by_cause: Vec<LiftCauseCount> = Vec::new();
        let mut proposals = Vec::new();
        for row in PROPOSALS.iter_from(&self.store, &txn, &[])? {
            let (key, mut proposal) = row?;
            if !proposal.is_open() {
                closed_proposals += 1;
                continue;
            }
            open_proposals += 1;
            match open_by_cause
                .iter_mut()
                .find(|count| count.cause == proposal.cause)
            {
                Some(count) => count.open += 1,
                None => open_by_cause.push(LiftCauseCount {
                    cause: proposal.cause,
                    open: 1,
                }),
            }
            if proposals.len() < STATUS_PROPOSALS {
                proposal.id = hex(&key);
                proposals.push(proposal);
            }
        }
        Ok(SecretLiftStatus {
            paused: mode == SecretScanMode::Off && running.is_some(),
            mode,
            running,
            last,
            open_proposals,
            open_by_cause,
            closed_proposals,
            proposals,
        })
    }

    /// The owner closes one open lift proposal with a reason: `not_a_secret`,
    /// `rotated` or `accepted`. The close keeps the proposal's cause, stamps
    /// when and by whom, and writes a Gate receipt naming the proposal, its
    /// row, its cause and the reason, never a value. The lift notice resolves
    /// once no proposal is open.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is not a
    /// live owner of this vault. [`Error::EntityNotFound`] for an id no
    /// proposal has. [`GateError::InvalidConsentBound`] for a reason the owner
    /// does not give, or a proposal already closed.
    pub fn close_secret_lift_proposal(
        &self,
        owner: &AuthenticatedOwner,
        proposal: &str,
        reason: LiftCloseReason,
    ) -> Result<SecretLiftHistoryProposal> {
        let mut txn = self.store.env.write_txn()?;
        let actor = live_owner_in_txn(self, owner, &txn)?;
        let closed = proposals::dismiss_in_txn(self, &mut txn, actor, proposal, reason)?;
        notice::settle_in_txn(self, &mut txn)?;
        txn.commit()?;
        Ok(closed)
    }
}

/// The owner's actor, when the proof is a live owner of this vault.
fn live_owner_in_txn(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    txn: &RoTxn<'_>,
) -> Result<EntityId> {
    let actor = owner.revalidate_in_txn(vault, txn)?;
    if !crate::policy_model::owners_in_txn(vault, txn)?.contains(&actor) {
        return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
            "only the vault owner runs the secret lift sweep",
        )));
    }
    Ok(actor)
}

/// `vault.secrets.lift_history`: the sweep's state for the owner, after
/// closing the proposal `input.close` names and queueing a run when
/// `input.start` asks for one.
///
/// # Errors
/// As [`Vault::close_secret_lift_proposal`] and [`Vault::start_secret_lift`].
pub fn secret_lift_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &SecretLiftRequest,
) -> Result<SecretLiftStatus> {
    if let Some(close) = &input.close {
        vault.close_secret_lift_proposal(owner, &close.proposal, close.reason)?;
    }
    if input.start {
        return vault.start_secret_lift(owner, vault.now_recorded_at());
    }
    {
        let txn = vault.store.env.read_txn()?;
        live_owner_in_txn(vault, owner, &txn)?;
    }
    vault.secret_lift_status()
}
