//! FIX [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE] (lead ruling
//! BK-HOME-MOVE-CARRIES-BOOKINGS = A, 21 Nov 06:2x: "Money follows the home, and a move must
//! never silently strand a visitor's link or a deposit"): the booking rows a home move
//! carries, as adapters on the home handoff carrier (`crate::sync::home_handoff`). The
//! lifecycle writes on the home alone (`door::home_node_refusal`), so the new home holds every
//! booking row the old home did, and the old home's fence stops its deposit writes and its
//! settle drain once it froze them (`deposit::settle::settles_deposits_here`).
//!
//! - `booking.token.v1:` ([`BookingTokenRows`]): the visitors' action tokens and checkout
//!   leases, the deposits with their booking links and applied provider events, and the
//!   emergency picks. Every key is a digest and no row names an actor or holds one's words,
//!   so tokens travel as their digests only and nothing travels apart. Each carried deposit
//!   that still owes a provider move gets a settle row here, in the adopting writer.
//! - `booking.hold.v1:` ([`BookingHoldRows`]): each live soft hold, with the visitor's session
//!   key, time zone and constraint and the owner's cap reason sealed apart. A visitor has no
//!   entity until the confirm names a booker contact, so this content is sealed under the page
//!   the visitor held through: never beside the facts, never under a machine key.
//! - `booking.lifecycle.receipt.v1:` ([`BookingReceiptRows`]): the transition receipts a
//!   retried confirm, move or cancel replays, with the confirmation's parties and answers and
//!   the invite's addresses sealed apart under the booker contact's key.
//!
//! Adoption lands a row this node lacks and keeps an equal one. On a node that froze its
//! booking rows for an earlier move and adopted none since, its rows are the history the
//! carried rows succeed: each carried row replaces this node's, and a row the carried set
//! dropped (a hold confirmed or replaced, a receipt an emergency withdrew) goes. On a node that
//! holds its own rows, a row that differs under one key is a Conflict, so no section lands,
//! with two exceptions: this node's hold of a session stands over a carried one (a newer hold
//! of the session replaces the older by construction), and a receipt whose facts agree keeps
//! the content this node holds.
//!
//! Each row's content travels sealed under its actor's erasable key (FIX 8875). A hold whose
//! content does not open here cannot stand without its session key, so it lands nothing; a
//! receipt whose content does not open lands as its facts alone.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use oneiron_records::authority::leave_notice_continuity::home_rows::NoActorContent;
use serde::{Deserialize, Serialize};

use super::deposit::{
    DEPOSIT, DEPOSIT_BOOKING, DEPOSIT_PROVIDER_EVENT, DepositBookingRow, DepositProviderEventRow,
    DepositRow, queue_carried_settle_in_txn,
};
use super::emergency::{EMERGENCY_PICK, EmergencyPickRow};
use super::storage::{HOLD, RECEIPT};
use super::token::SessionKey;
use super::types::{BookingCapOverride, SoftHoldRow};
use super::{
    BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND, BookingConfirmationContext, CHECKOUT_LEASE,
    CheckoutLeaseRow, LifecycleReceiptRow, LifecycleTokenRow, TOKEN, digest_serde,
    entity_ref_serde, entity_refs_serde, opt_digest_serde, time_range_serde,
};
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::booking::{ConstraintObject, EventTypeKey};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    ActorContent, HomeFence, HomeMove, HomeTable, Partitioned, TableAdopt, froze_home_state_in_txn,
};
use crate::temporal::TimeRange;

fn invalid(detail: &str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}

/// A 32-byte key suffix of one of the three tables.
fn digest_key(suffix: Vec<u8>) -> Result<[u8; 32]> {
    suffix
        .try_into()
        .map_err(|_| invalid("a booking row's key is not one 32-byte digest"))
}

// -------------------------------------------------------------------------
// booking.token.v1: tokens, leases, deposits, provider events, picks
// -------------------------------------------------------------------------

/// Every row under `booking.token.v1:`, each with its key and its shape.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BookingTokenRows {
    rows: Vec<CarriedTokenRow>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedTokenRow {
    #[serde(with = "digest_serde")]
    key: [u8; 32],
    row: TokenTableRow,
}

/// The six row shapes one `booking.token.v1:` declaration holds (`super::TOKEN`'s doc): each
/// denies unknown fields and needs fields no other has, so a stored row decodes as one shape.
#[derive(Serialize, Deserialize)]
enum TokenTableRow {
    Token(LifecycleTokenRow),
    CheckoutLease(CheckoutLeaseRow),
    Deposit(DepositRow),
    DepositBooking(DepositBookingRow),
    DepositProviderEvent(DepositProviderEventRow),
    EmergencyPick(EmergencyPickRow),
}

impl TokenTableRow {
    /// The one shape the stored `bytes` decode as.
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut shapes = [
            TOKEN.decode_value(bytes).ok().map(Self::Token),
            CHECKOUT_LEASE
                .decode_value(bytes)
                .ok()
                .map(Self::CheckoutLease),
            DEPOSIT.decode_value(bytes).ok().map(Self::Deposit),
            DEPOSIT_BOOKING
                .decode_value(bytes)
                .ok()
                .map(Self::DepositBooking),
            DEPOSIT_PROVIDER_EVENT
                .decode_value(bytes)
                .ok()
                .map(Self::DepositProviderEvent),
            EMERGENCY_PICK
                .decode_value(bytes)
                .ok()
                .map(Self::EmergencyPick),
        ]
        .into_iter()
        .flatten();
        match (shapes.next(), shapes.next()) {
            (Some(row), None) => Ok(row),
            _ => Err(invalid(
                "a booking.token.v1 row decodes as no one row shape",
            )),
        }
    }

    /// The row as its own table stores it.
    fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Token(row) => TOKEN.encode_value(row),
            Self::CheckoutLease(row) => CHECKOUT_LEASE.encode_value(row),
            Self::Deposit(row) => DEPOSIT.encode_value(row),
            Self::DepositBooking(row) => DEPOSIT_BOOKING.encode_value(row),
            Self::DepositProviderEvent(row) => DEPOSIT_PROVIDER_EVENT.encode_value(row),
            Self::EmergencyPick(row) => EMERGENCY_PICK.encode_value(row),
        }
    }

    /// Writes the row under `key` through its own table: never through a deposit writer,
    /// whose fence refuses on a node that froze its booking rows, as an adopting one did.
    fn put(&self, vault: &Vault, txn: &mut RwTxn<'_>, key: &[u8; 32]) -> Result<()> {
        let store = &vault.store;
        match self {
            Self::Token(row) => TOKEN.put(store, txn, key, row),
            Self::CheckoutLease(row) => CHECKOUT_LEASE.put(store, txn, key, row),
            Self::Deposit(row) => DEPOSIT.put(store, txn, key, row),
            Self::DepositBooking(row) => DEPOSIT_BOOKING.put(store, txn, key, row),
            Self::DepositProviderEvent(row) => DEPOSIT_PROVIDER_EVENT.put(store, txn, key, row),
            Self::EmergencyPick(row) => EMERGENCY_PICK.put(store, txn, key, row),
        }
    }
}

/// Whether the row stored here under one key equals `carried`, both read as their shape
/// encodes them now. A stored row that decodes as no one shape equals nothing.
fn equal_token_row(stored: &[u8], carried: &[u8]) -> Result<bool> {
    Ok(match TokenTableRow::decode(stored) {
        Ok(here) => here.encode()? == carried,
        Err(_) => false,
    })
}

impl HomeTable for BookingTokenRows {
    type Rows = Self;
    type Actor = NoActorContent;
    const TABLE: &'static SideTableDecl = &side_table::BOOKING_TOKEN;
    const SCHEMA_VERSION: u16 = 1;

    /// No deposit's provider move is on the wire: no settle row is leased. A move asked
    /// outside the queue (the server's capture right after a confirm) carries the same
    /// idempotency key the new home asks it under, so it is one move.
    fn quiescent(vault: &Vault, txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(!AttemptQueue::new(vault)
            .working_kind_rows_in_txn(txn, BOOKING_DEPOSIT_SETTLE_ATTEMPT_KIND)?
            .iter()
            .any(|record| record.state == AttemptState::Leased))
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, NoActorContent>> {
        let mut rows = Vec::new();
        for stored in TOKEN.iter_raw_from(&vault.store, txn, &[])? {
            let (key, bytes) = stored?;
            rows.push(CarriedTokenRow {
                key: digest_key(key)?,
                row: TokenTableRow::decode(&bytes)?,
            });
        }
        Ok(Partitioned {
            facts: Self { rows },
            actors: Vec::new(),
        })
    }

    /// Lands each carried row as the module doc says, then queues a settle row for each
    /// carried deposit that still owes a move: the old home asks none once it froze.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        fence: &HomeFence,
        rows: Partitioned<Self, NoActorContent>,
    ) -> Result<TableAdopt> {
        let history = froze_home_state_in_txn(vault, txn)?;
        let carried: BTreeMap<[u8; 32], TokenTableRow> = rows
            .facts
            .rows
            .into_iter()
            .map(|carried| (carried.key, carried.row))
            .collect();
        if history {
            for key in TOKEN.scan_keys(&vault.store, txn, &[])? {
                if !carried.contains_key(&key) {
                    TOKEN.delete(&vault.store, txn, &key)?;
                }
            }
        }
        for (key, row) in &carried {
            let encoded = row.encode()?;
            match TOKEN.get_bytes(&vault.store, txn, key)? {
                Some(stored) if equal_token_row(&stored, &encoded)? => {}
                Some(_) if !history => return Ok(TableAdopt::Conflict),
                _ => row.put(vault, txn, key)?,
            }
        }
        let generation = fence.movement().generation.serial;
        let now = vault.store.clock.now_recorded_at();
        for (key, row) in &carried {
            if matches!(row, TokenTableRow::Deposit(_)) {
                queue_carried_settle_in_txn(vault, txn, key, generation, now)
                    .map_err(|error| Error::InvalidConfig(error.to_string()))?;
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        Ok(TOKEN
            .scan_keys(&vault.store, txn, &[])?
            .iter()
            .map(|key| TOKEN.key_bytes(key))
            .collect())
    }
}

// -------------------------------------------------------------------------
// booking.hold.v1: soft holds
// -------------------------------------------------------------------------

/// Every live soft hold's facts.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BookingHoldRows {
    holds: Vec<HoldFacts>,
}

/// One hold without the visitor's content or the owner's words.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HoldFacts {
    /// The session key's digest, the hold's key.
    #[serde(with = "digest_serde")]
    key: [u8; 32],
    #[serde(with = "entity_ref_serde")]
    page_ref: EntityId,
    event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    slot: TimeRange,
    #[serde(with = "digest_serde")]
    token_hash: [u8; 32],
    expires_at: u64,
    #[serde(with = "opt_digest_serde")]
    checkout_lease_hash: Option<[u8; 32]>,
}

/// One hold's content: the visitor's session key, time zone and constraint, and the owner's
/// reason for booking past a cap, sealed under the page the visitor held through.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HoldContent {
    #[serde(with = "entity_ref_serde")]
    page_ref: EntityId,
    #[serde(with = "digest_serde")]
    key: [u8; 32],
    session_key: SessionKey,
    visitor_tz: String,
    constraint: Option<ConstraintObject>,
    cap_override: Option<BookingCapOverride>,
}

impl ActorContent for HoldContent {
    fn actor(&self) -> EntityId {
        self.page_ref
    }
}

impl HomeTable for BookingHoldRows {
    type Rows = Self;
    type Actor = HoldContent;
    const TABLE: &'static SideTableDecl = &side_table::BOOKING_HOLD;
    const SCHEMA_VERSION: u16 = 1;

    /// A hold is written and consumed inside one booking writer: none is in flight.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    /// Every hold still live at the export. A dead hold is no hold to any read
    /// (`SoftHoldRow::is_live_at`), so it stays behind as this node's history.
    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, HoldContent>> {
        let now = vault.store.clock.now_recorded_at();
        let mut holds = Vec::new();
        let mut actors = Vec::new();
        for (key, hold) in HOLD.scan(&vault.store, txn)? {
            if !hold.is_live_at(now) {
                continue;
            }
            let SoftHoldRow {
                page_ref,
                event_type,
                slot,
                session_key,
                visitor_tz,
                constraint,
                token_hash,
                expires_at,
                checkout_lease_hash,
                cap_override,
            } = hold;
            holds.push(HoldFacts {
                key,
                page_ref,
                event_type,
                slot,
                token_hash,
                expires_at,
                checkout_lease_hash,
            });
            actors.push(HoldContent {
                page_ref,
                key,
                session_key,
                visitor_tz,
                constraint,
                cap_override,
            });
        }
        Ok(Partitioned {
            facts: Self { holds },
            actors,
        })
    }

    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self, HoldContent>,
    ) -> Result<TableAdopt> {
        let history = froze_home_state_in_txn(vault, txn)?;
        let mut contents: BTreeMap<[u8; 32], HoldContent> = rows
            .actors
            .into_iter()
            .map(|content| (content.key, content))
            .collect();
        let mut landed = BTreeSet::new();
        for facts in rows.facts.holds {
            let Some(content) = contents
                .remove(&facts.key)
                .filter(|content| content.page_ref == facts.page_ref)
            else {
                continue;
            };
            let hold = SoftHoldRow {
                page_ref: facts.page_ref,
                event_type: facts.event_type,
                slot: facts.slot,
                session_key: content.session_key,
                visitor_tz: content.visitor_tz,
                constraint: content.constraint,
                token_hash: facts.token_hash,
                expires_at: facts.expires_at,
                checkout_lease_hash: facts.checkout_lease_hash,
                cap_override: content.cap_override,
            };
            landed.insert(facts.key);
            match HOLD.get_lenient(&vault.store, txn, &facts.key)? {
                Some(here) if here == hold => {}
                Some(_) if !history => {}
                _ => HOLD.put(&vault.store, txn, &facts.key, &hold)?,
            }
        }
        if history {
            for key in HOLD.scan_keys(&vault.store, txn, &[])? {
                if !landed.contains(&key) {
                    HOLD.delete(&vault.store, txn, &key)?;
                }
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        Ok(HOLD
            .scan_keys(&vault.store, txn, &[])?
            .iter()
            .map(|key| HOLD.key_bytes(key))
            .collect())
    }
}

// -------------------------------------------------------------------------
// booking.lifecycle.receipt.v1: transition receipts
// -------------------------------------------------------------------------

/// Every lifecycle receipt's facts.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BookingReceiptRows {
    receipts: Vec<ReceiptFacts>,
}

/// One receipt without its parties: the revision it replays, the session a confirm bound,
/// and the rows its writer read.
#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReceiptFacts {
    #[serde(with = "digest_serde")]
    key: [u8; 32],
    #[serde(with = "entity_ref_serde")]
    event_ref: EntityId,
    uid: String,
    sequence: u32,
    #[serde(with = "opt_digest_serde")]
    session_hash: Option<[u8; 32]>,
    #[serde(with = "entity_refs_serde")]
    reads: Vec<EntityId>,
}

/// One confirm receipt's parties: the confirmation context (hosts, zones, booker, the
/// visitor's zone, constraint and intake answers) and the invite's organizer and recipient,
/// sealed under the booker contact's key, so the booker's erase leaves them unreadable
/// wherever a copy went. An invite identity is bound only beside a confirmation, and an
/// erase of the booking scrubs both together (FIX 9636).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptContent {
    #[serde(with = "entity_ref_serde")]
    booker: EntityId,
    #[serde(with = "digest_serde")]
    key: [u8; 32],
    confirmation: BookingConfirmationContext,
    invite_identity: Option<(String, String)>,
}

impl ActorContent for ReceiptContent {
    fn actor(&self) -> EntityId {
        self.booker
    }
}

impl ReceiptFacts {
    fn of(key: [u8; 32], receipt: &LifecycleReceiptRow) -> Self {
        Self {
            key,
            event_ref: receipt.event_ref,
            uid: receipt.uid.clone(),
            sequence: receipt.sequence,
            session_hash: receipt.session_hash,
            reads: receipt.reads.clone(),
        }
    }
}

impl HomeTable for BookingReceiptRows {
    type Rows = Self;
    type Actor = ReceiptContent;
    const TABLE: &'static SideTableDecl = &side_table::BOOKING_LIFECYCLE_RECEIPT;
    const SCHEMA_VERSION: u16 = 1;

    /// A receipt commits with its transition in one booking writer: none is in flight.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    /// Every receipt's facts, and each confirmation's parties apart. A confirmation whose
    /// booker is not one entity id names no actor to seal it under, so it stays behind.
    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, ReceiptContent>> {
        let mut receipts = Vec::new();
        let mut actors = Vec::new();
        for (key, receipt) in RECEIPT.scan(&vault.store, txn)? {
            receipts.push(ReceiptFacts::of(key, &receipt));
            let Some(confirmation) = receipt.confirmation else {
                continue;
            };
            let Ok(booker) = EntityId::from_hex(&confirmation.booker_ref) else {
                continue;
            };
            actors.push(ReceiptContent {
                booker,
                key,
                confirmation,
                invite_identity: receipt.invite_identity,
            });
        }
        Ok(Partitioned {
            facts: Self { receipts },
            actors,
        })
    }

    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self, ReceiptContent>,
    ) -> Result<TableAdopt> {
        let history = froze_home_state_in_txn(vault, txn)?;
        let mut contents: BTreeMap<[u8; 32], ReceiptContent> = rows
            .actors
            .into_iter()
            .map(|content| (content.key, content))
            .collect();
        let mut carried = BTreeSet::new();
        for facts in rows.facts.receipts {
            carried.insert(facts.key);
            let content = contents.remove(&facts.key);
            let receipt = LifecycleReceiptRow {
                event_ref: facts.event_ref,
                uid: facts.uid.clone(),
                sequence: facts.sequence,
                session_hash: facts.session_hash,
                invite_identity: content
                    .as_ref()
                    .and_then(|content| content.invite_identity.clone()),
                confirmation: content.map(|content| content.confirmation),
                reads: facts.reads.clone(),
            };
            match RECEIPT.get_lenient(&vault.store, txn, &facts.key)? {
                None => RECEIPT.put(&vault.store, txn, &facts.key, &receipt)?,
                Some(here) if here == receipt => {}
                Some(_) if history => RECEIPT.put(&vault.store, txn, &facts.key, &receipt)?,
                Some(here) if ReceiptFacts::of(facts.key, &here) == facts => {
                    if here.confirmation.is_none() && receipt.confirmation.is_some() {
                        RECEIPT.put(&vault.store, txn, &facts.key, &receipt)?;
                    }
                }
                Some(_) => return Ok(TableAdopt::Conflict),
            }
        }
        if history {
            for key in RECEIPT.scan_keys(&vault.store, txn, &[])? {
                if !carried.contains(&key) {
                    RECEIPT.delete(&vault.store, txn, &key)?;
                }
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        Ok(RECEIPT
            .scan_keys(&vault.store, txn, &[])?
            .iter()
            .map(|key| RECEIPT.key_bytes(key))
            .collect())
    }
}
