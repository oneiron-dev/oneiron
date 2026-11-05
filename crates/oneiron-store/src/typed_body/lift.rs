//! Typed bodies the historical lift sweep reads again (OF-067, Engine ruling
//! G2 = b). A typed body's operation log is its receipt ledger: a new call
//! that brings a key into a clean body is refused, and a body that held one
//! before keeps it. The sweep marks the keys of each text in a body's state
//! (owner ruling C2), under that text's hash: an office body's runs and
//! cells, a deck's slide text and each stamped operation of its fork log.
//! One door serves every typed body and each of its forks. The snapshot, the
//! operations, the receipts and every frontier stay as they are. A reader
//! other than the owner reads each lifted key as its handle, a writer that
//! carries a handle back writes its value again, and a commit on a body that
//! still reads as secret marks the texts it leaves.

use heed::{RoTxn, RwTxn};
use loro::LoroDoc;

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub fn collect_texts(value: &serde_json::Value, texts: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => texts.push(text.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_texts(item, texts);
            }
        }
        serde_json::Value::Object(fields) => {
            for item in fields.values() {
                collect_texts(item, texts);
            }
        }
        _ => {}
    }
}

/// The custody records the marks of a typed body's lifted texts name: each
/// key once, in custody-id order. Only
/// [`Vault::typed_body_lifted_sources_in_txn`] and
/// [`Vault::typed_body_read_lifted_in_txn`] make one, so a read's sight
/// ([`Vault::typed_body_sight`]) is judged over the keys the body holds,
/// never over keys a caller names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedSources(pub Vec<EntityId>);

impl LiftedSources {
    /// Whether the body's texts name no key: every reader reads it alike.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The keys, each once, in custody-id order.
    pub fn keys(&self) -> &[EntityId] {
        &self.0
    }

    /// These keys and `keys`, the custody records the marks of what a read
    /// shows name, each once, in custody-id order: the keys of the parts a
    /// deck preview's asked slides draw (FIX 10453).
    pub fn with_keys(mut self, keys: impl IntoIterator<Item = EntityId>) -> Self {
        self.0.extend(keys);
        self.0.sort_unstable();
        self.0.dedup();
        self
    }
}
