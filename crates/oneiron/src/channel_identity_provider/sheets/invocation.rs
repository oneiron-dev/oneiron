//! A Sheets write's claim on its caller's invocation (FIX 4862,
//! REVIEW-6403): one row per logical call, written in the transaction of
//! the write's intent record and settled in the transaction of its outcome
//! record. The replay rule the row keeps is said once, in the Sheets
//! module's "Writes".

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::receipt::{SEND_DELIVERED, SEND_NOT_SENT, SEND_UNCERTAIN};
use super::run::SheetsAnswer;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::outbound_consent::ConnectorCallInvocation;
use crate::outbound_consent::tool_call::MutationIntent;
use crate::side_table::{self, Named, SideTable};
use crate::store::{GateDecisionId, Store};
use crate::vault::Vault;

/// The Sheets writes' invocation rows, by invocation ref.
const SHEETS_WRITE_INVOCATION: SideTable<EntityId, SheetsWriteInvocation, Named> =
    SideTable::new(&side_table::SHEETS_WRITE_INVOCATION);

/// The derivation domain of a write's invocation ref, so one caller's one
/// logical call always names the same row.
const SHEETS_WRITE_INVOCATION_DOMAIN: &[u8] = b"oneiron.sheets_write_invocation.v1";

/// The invocation's row binds another request; nothing was sent. The code
/// a connector call's ledger refuses the same conflict with.
const INVOCATION_CONFLICT: &str = "connector_call_invocation_conflict";

/// The invocation's earlier send may have reached Google, and no answer
/// was kept; nothing was sent again.
const WRITE_UNCERTAIN: &str = "sheets_write_uncertain";

/// The request one invocation's row binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SheetsWriteIdentity {
    /// The tool's name.
    pub(super) tool: String,
    pub(super) spreadsheet_id: String,
    /// The effect request's digest, lower hex.
    pub(super) request: String,
    pub(super) mutation: MutationIntent,
}

/// One invocation's row: the request it bound, the intent record its send
/// stands behind, and where that send is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SheetsWriteInvocation {
    identity: SheetsWriteIdentity,
    intent: GateDecisionId,
    state: SheetsWriteState,
}

/// Where an invocation's send is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SheetsWriteState {
    /// Claimed, and its outcome record not yet written: the send may be
    /// under way, or may have been lost with its process.
    Sending,
    /// Its outcome record was written.
    Settled {
        /// `delivered`, `rejected_<status>`, `not_sent` or `uncertain`.
        send: String,
        /// The outcome record's id.
        outcome: GateDecisionId,
    },
}

/// One write's claim on its caller's invocation: the row's ref and the
/// request it binds.
pub(super) struct SheetsWriteClaim {
    invocation_ref: EntityId,
    identity: SheetsWriteIdentity,
}

impl SheetsWriteClaim {
    /// The claim `actor`'s `invocation` makes for the write `identity`
    /// names.
    ///
    /// # Errors
    ///
    /// A derived ref in the reserved range.
    pub(super) fn new(
        actor: EntityId,
        invocation: ConnectorCallInvocation,
        identity: SheetsWriteIdentity,
    ) -> Result<Self> {
        let invocation_ref = EntityId::derive(
            SHEETS_WRITE_INVOCATION_DOMAIN,
            &[
                actor.to_hex().as_bytes(),
                invocation.attempt_id.as_bytes(),
                &invocation.call_seq.to_le_bytes(),
            ],
        )?;
        Ok(Self {
            invocation_ref,
            identity,
        })
    }

    /// What the invocation's row answers this write with, read before
    /// anything connects; `None` when the write sends.
    ///
    /// # Errors
    ///
    /// Storage and decoding faults.
    pub(super) fn answer(&self, vault: &Vault) -> Result<Option<SheetsAnswer>> {
        let txn = vault.store.env.read_txn()?;
        self.answer_in_txn(&vault.store, &txn)
    }

    /// What the invocation's row answers this write with, in `txn`; `None`
    /// when the write sends: no row yet, or the same request whose earlier
    /// send reached nothing.
    ///
    /// # Errors
    ///
    /// Storage and decoding faults.
    pub(super) fn answer_in_txn(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<SheetsAnswer>> {
        let Some(row) = SHEETS_WRITE_INVOCATION.get(store, txn, &self.invocation_ref)? else {
            return Ok(None);
        };
        if row.identity != self.identity {
            return Ok(Some(SheetsAnswer::NotSent(INVOCATION_CONFLICT.to_owned())));
        }
        Ok(match row.state {
            SheetsWriteState::Settled { send, .. } if send == SEND_NOT_SENT => None,
            SheetsWriteState::Sending => Some(SheetsAnswer::Uncertain(WRITE_UNCERTAIN.to_owned())),
            SheetsWriteState::Settled { send, .. } if send == SEND_UNCERTAIN => {
                Some(SheetsAnswer::Uncertain(WRITE_UNCERTAIN.to_owned()))
            }
            SheetsWriteState::Settled { send, outcome } => Some(SheetsAnswer::Answered {
                is_error: send != SEND_DELIVERED,
                output: json!({
                    "spreadsheetId": row.identity.spreadsheet_id,
                    "replayed": true,
                    "send": send,
                    "receipts": { "intent": row.intent.to_hex(), "outcome": outcome.to_hex() },
                    "note": "This invocation sent this write before, so it was not sent again. Google's reply to it is not kept."
                }),
            }),
        })
    }

    /// Claims the invocation for the send behind `intent`, in that intent
    /// record's transaction.
    ///
    /// # Errors
    ///
    /// Storage and encoding faults.
    pub(super) fn claim_in_txn(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        intent: GateDecisionId,
    ) -> Result<()> {
        let row = SheetsWriteInvocation {
            identity: self.identity.clone(),
            intent,
            state: SheetsWriteState::Sending,
        };
        SHEETS_WRITE_INVOCATION.put(store, txn, &self.invocation_ref, &row)
    }

    /// Settles the claim behind `intent` with what its send came to, in its
    /// `outcome` record's transaction.
    ///
    /// # Errors
    ///
    /// Storage and encoding faults.
    pub(super) fn settle_in_txn(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        intent: GateDecisionId,
        send: &str,
        outcome: GateDecisionId,
    ) -> Result<()> {
        let row = SheetsWriteInvocation {
            identity: self.identity.clone(),
            intent,
            state: SheetsWriteState::Settled {
                send: send.to_owned(),
                outcome,
            },
        };
        SHEETS_WRITE_INVOCATION.put(store, txn, &self.invocation_ref, &row)
    }
}
