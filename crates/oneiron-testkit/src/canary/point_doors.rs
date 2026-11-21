//! The scan's point and ledger doors ([CANARY-SCAN-COVERAGE] step 1 and 3):
//! the keyed value at the canary address, the filtered claim list, every
//! receipt ledger, the caller's own inbox items, the latest proactivity
//! digest, and the doors an in-process caller never passes.

use oneiron::receipt::ReceiptKind;
use oneiron_contracts::register::Register;
use serde_json::{Value, json};

use super::{CLAIM_LIST_LIMIT, KV_KEY, KV_NAMESPACE, PAGE, Reader};

/// Items one `self.inbox.lens` page holds at most (the verb's cap).
const INBOX_LENS_LIMIT: usize = 200;

impl Reader<'_, '_> {
    /// Reads the point and ledger doors. `self.inbox.get` marks the item
    /// opened, and a digest item seen: those are the reads that write.
    pub(super) fn read_point_doors(&mut self) {
        self.read(
            "vault.kv.get",
            "vault.kv.get",
            json!({"namespace": [KV_NAMESPACE], "key": KV_KEY}),
        );
        if let Some(answer) = self.read(
            "vault.claims.list_filtered",
            "vault.claims.list_filtered",
            json!({"limit": CLAIM_LIST_LIMIT}),
        ) {
            let rows = answer
                .pointer("/value")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if rows >= CLAIM_LIST_LIMIT {
                self.scan.incomplete.push(format!(
                    "vault.claims.list_filtered: {rows} rows filled the limit"
                ));
            }
        }
        self.read_receipts();
        self.read_inbox_items();
        self.read(
            "vault.proactivity.digest",
            "vault.proactivity.digest",
            json!({}),
        );
        for (verb, input) in host_door_inputs() {
            self.read(verb, verb, input);
        }
    }

    /// The default (gate) receipt ledger, then each receipt kind's own pages:
    /// a kind is read by itself, so one the verb refuses hides no other.
    fn read_receipts(&mut self) {
        self.walk_cursor("vault.receipts", "vault.receipts", json!({"limit": PAGE}));
        for kind in ReceiptKind::ROWS {
            let name = kind.name();
            self.walk_cursor(
                &format!("vault.receipts ({name})"),
                "vault.receipts",
                json!({"kinds": [name], "limit": PAGE}),
            );
        }
    }

    /// The caller's own inbox slice (`self.inbox.lens`), then each item it
    /// lists, opened (`self.inbox.get`).
    fn read_inbox_items(&mut self) {
        let Some(page) = self.read(
            "self.inbox.lens",
            "self.inbox.lens",
            json!({"limit": INBOX_LENS_LIMIT}),
        ) else {
            return;
        };
        let items: Vec<String> =
            page.get("items")
                .and_then(Value::as_array)
                .map_or_else(Vec::new, |items| {
                    items
                        .iter()
                        .filter_map(|item| item.get("item_id").and_then(Value::as_str))
                        .map(str::to_owned)
                        .collect()
                });
        if items.len() >= INBOX_LENS_LIMIT {
            self.scan.incomplete.push(format!(
                "self.inbox.lens: {} items filled the page",
                items.len()
            ));
        }
        for item in &items {
            self.read(
                &format!("self.inbox.get {item}"),
                "self.inbox.get",
                json!({"item_id": item}),
            );
        }
    }
}

/// Doors no in-process caller passes, each with an input it decodes: a
/// served host's model step receipt, digest read and export transfer refuse
/// an embedded vault (`host_only`), and a scoped export asks the caller's
/// verified credential first. The scan calls each once, so its refusal is
/// on record, and an answer, if one ever comes, is read like any other.
fn host_door_inputs() -> [(&'static str, Value); 4] {
    [
        ("ai.steps.receipt", json!({"step_key": "canary-step"})),
        (
            "vault.proactivity.digest.get",
            json!({"id": "0".repeat(64)}),
        ),
        (
            "vault.export.transfer.read",
            json!({"transfer_ref": format!("export_transfer:{}", "0".repeat(32))}),
        ),
        (
            "vault.export.scoped",
            json!({"selector": {}, "channel": {"channel_ref": "canary", "scope": {}}}),
        ),
    ]
}
