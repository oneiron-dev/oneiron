//! Package and native-identity inspection kept with a deck rejection.

use crate::error::Result;
use oneiron_docedit::edit::wire::{DeckInspection, inspect_deck};
use oneiron_docedit::retained_opc::{Limits, Package};
use serde::{Deserialize, Serialize};

/// The base a refused deck transaction ran over, read as a deck (FIX 4486):
/// its native edit targets as `vault.artifacts.inspect_deck` reads them, and
/// every part its package holds, or that it could not be read. Never a
/// workbook's sheets or flags. An unreadable base is reported as such beside
/// the transaction's own refusal, which it never replaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeckRejectionInspection {
    /// The base read as a deck: slides, shapes, fingerprints, duplicate
    /// identities and marks, and its package's part names in order.
    Inspected {
        deck: DeckInspection,
        parts: Vec<String>,
    },
    /// The base did not open as a package, or not as a deck.
    Unreadable { reason: String },
}

impl DeckRejectionInspection {
    /// `base` read as a deck under the transaction's own package `limits`.
    /// A resource refusal is the engine's error (FIX 10587), never unreadable.
    pub(crate) fn of_base(base: &[u8], limits: Limits) -> Result<Self> {
        let package = match Package::open(
            base,
            limits,
            &crate::entity_doc::document_resources::document_resources(),
        ) {
            Ok(package) => package,
            Err(error) => {
                if let Some(refusal) = error.resource() {
                    return Err(crate::entity_doc::document_resources::document_refused(
                        refusal,
                    ));
                }
                return Ok(Self::Unreadable {
                    reason: format!("the deck package cannot be opened: {error}"),
                });
            }
        };
        match inspect_deck(&package) {
            Ok(deck) => {
                let parts = package.names().map(str::to_owned).collect();
                Ok(Self::Inspected { deck, parts })
            }
            Err(error) => {
                if let Some(refusal) = error.resource() {
                    return Err(crate::entity_doc::document_resources::document_refused(
                        refusal,
                    ));
                }
                Ok(Self::Unreadable {
                    reason: format!("the deck cannot be read: {error}"),
                })
            }
        }
    }
}
