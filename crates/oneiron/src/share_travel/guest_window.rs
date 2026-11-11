//! Prepared guest-window share receipts; never a claim of peer delivery.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{BornWithField, ExportTarget, ExportTravel, travelled_value};
use crate::federation::FederationGrantScope;
use crate::{EntityId, Vault};

/// Advisory metadata beside the signed export. The digest names the final
/// released update, and row keys are its transport keys after projection.
/// This is an export preparation, not recipient authority or delivery proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuestWindowTravelNote {
    pub content_hash: String,
    pub travelled: BTreeMap<String, Vec<BornWithField>>,
    /// The receipt write failed. Its one retry is held only in this open
    /// vault's memory; neither this flag nor that queue is a durable ledger.
    pub receipt_owed: bool,
}

pub(super) fn receipt_fields(
    grant_ref: &str,
    member_ref: &str,
    scope: FederationGrantScope,
    window_key: &str,
    rows: &BTreeMap<String, Vec<BornWithField>>,
) -> Vec<(String, String)> {
    let mut fields = vec![
        ("grant".to_owned(), grant_ref.to_owned()),
        ("recipient".to_owned(), member_ref.to_owned()),
        ("window_key".to_owned(), window_key.to_owned()),
        (
            "row_fields".to_owned(),
            rows.iter()
                .map(|(row, names)| format!("{row}:{}", travelled_value(names.iter().copied())))
                .collect::<Vec<_>>()
                .join(";"),
        ),
    ];
    let (scope, binding, value) = match scope {
        FederationGrantScope::Vault { vault_id } => ("vault", "vault_id", vault_id.to_string()),
        FederationGrantScope::Ask { ask_ref } => ("ask", "ask_ref", ask_ref.to_hex()),
        FederationGrantScope::Connect { peer_vault_id } => (
            "connect",
            "peer_vault_id",
            crate::entity_id::bytes_to_hex_lower(&peer_vault_id),
        ),
    };
    fields.push(("scope".to_owned(), scope.to_owned()));
    fields.push((binding.to_owned(), value));
    fields
}

impl Vault {
    /// Records what the signed guest export prepared. A failed receipt never
    /// blocks working exports: warn, queue one in-memory retry, and return
    /// the owed state to the actual caller beside the signed bytes.
    #[expect(
        clippy::too_many_arguments,
        reason = "the authenticated export's own bindings"
    )]
    pub(crate) fn record_guest_window_travel(
        &self,
        grant: &EntityId,
        recipient: &EntityId,
        scope: FederationGrantScope,
        window_key: &str,
        world: &EntityId,
        source_rows: &[EntityId],
        update: &[u8],
        by: &EntityId,
        travelled: BTreeMap<String, Vec<BornWithField>>,
    ) -> GuestWindowTravelNote {
        let mut note = GuestWindowTravelNote {
            content_hash: blake3::hash(update).to_hex().to_string(),
            travelled,
            receipt_owed: false,
        };
        let travel = ExportTravel {
            at: self.store.clock.now_recorded_at(),
            target: ExportTarget::GuestWindow {
                grant_ref: grant.to_hex(),
                member_ref: recipient.to_hex(),
                scope,
                window_key: window_key.to_owned(),
                world_ref: *world,
                source_rows: source_rows.to_vec(),
                rows: note.travelled.clone(),
            },
            content_hash: note.content_hash.clone(),
            by: by.to_hex(),
            travelled: note
                .travelled
                .values()
                .flatten()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            notices: Vec::new(),
        };
        self.retry_owner_export_receipts();
        if let Err(error) = self.append_export_travel(&travel) {
            tracing::warn!(%error, "guest export prepared without its travel receipt; queued for one retry");
            self.owner_export_receipts().push(travel);
            note.receipt_owed = true;
        }
        note
    }
}
