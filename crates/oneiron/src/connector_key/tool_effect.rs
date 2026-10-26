//! The budget effect of one dispatched scoped tool call (FIX 8688): the
//! tool's own approved declaration first, then its catalog's call class, so
//! a catalog's description never budgets every one of its tools alike.
//! Entry: `scoped_tool_effect_in_txn`. Defines its own items.

use crate::error::Result;
use crate::outbound_intent_ledger::BudgetClass;
use crate::store::Store;

use super::lifecycle::scoped_server_call_class_in_txn;

/// What one dispatched scoped tool call does, for its budget class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectorToolEffect {
    /// The tool's approved slate row declares it read-only and not
    /// destructive: retrieval, whatever its catalog describes.
    ReadOnly,
    /// A tool not declared read-only on a catalog the owner registered as
    /// counterparty communication.
    CounterpartyCommunication,
    /// A tool not declared read-only on any other catalogued server.
    OtherOperation,
    /// A tool not declared read-only on a server no catalog entry names.
    Unclassified,
}

/// The budget class of an unclassified tool: the scoped-MCP default, which
/// leaves scoped tool calls off the `Sends` rows (ARCH-0054). `Rate` and
/// `Spend` rows still meet an `Operation`.
pub(crate) const UNCLASSIFIED_TOOL_BUDGET_CLASS: BudgetClass = BudgetClass::Operation;

impl ConnectorToolEffect {
    /// The class the effect charges: counterparty communication alone is a
    /// `Send`.
    pub(crate) const fn budget_class(self) -> BudgetClass {
        match self {
            Self::CounterpartyCommunication => BudgetClass::Send,
            Self::ReadOnly | Self::OtherOperation => BudgetClass::Operation,
            Self::Unclassified => UNCLASSIFIED_TOOL_BUDGET_CLASS,
        }
    }
}

/// The effect of the prepared tool on `server`: `read_only` is the frozen
/// call's approved declaration, never a caller's word or a tool-name guess.
pub(crate) fn scoped_tool_effect_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    server: &str,
    read_only: bool,
) -> Result<ConnectorToolEffect> {
    if read_only {
        return Ok(ConnectorToolEffect::ReadOnly);
    }
    Ok(match scoped_server_call_class_in_txn(store, txn, server)? {
        None => ConnectorToolEffect::Unclassified,
        Some(class) if class.debits_sends() => ConnectorToolEffect::CounterpartyCommunication,
        Some(_) => ConnectorToolEffect::OtherOperation,
    })
}
