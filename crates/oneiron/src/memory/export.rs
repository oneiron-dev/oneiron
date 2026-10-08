//! Full-vault memory export through the existing five-format pack writers.

use serde::{Deserialize, Serialize};

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::Vault;
use crate::authority::VerifiedSlip;
use crate::context_pack::PackFormat;
use crate::edge::EdgeActorClass;
use crate::memory::verify_actor_binding_in_txn;
use crate::side_table::{self, Named, SideTable};

/// Format for the full-vault export; absence uses the model-injection default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExportOptions {
    #[serde(default)]
    pub format: Option<String>,
}

/// One whole-vault export, written by the call that renders it, so every
/// owner can see that the vault left and in what shape. Never the bytes. A
/// receipt that cannot be written is logged and does not withhold the export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportReceipt {
    /// Vault clock seconds.
    pub at: u64,
    pub format: String,
    pub bytes: u64,
    /// BLAKE3 of the rendered document, lowercase hex.
    pub digest: String,
    /// The exporting actor as hex, or `host` for a host-root export.
    pub by: String,
}

const EXPORT_RECEIPTS: SideTable<u64, ExportReceipt, Named> =
    SideTable::new(&side_table::EXPORT_RECEIPT);

/// Rendered full-vault document in the chosen OF-096 format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryExport {
    pub format: String,
    pub rendered: String,
}

impl Memory<'_> {
    /// Embedded full-vault export. Only the constructor-owned, leased owner
    /// handle may use this door; binding a different PERSON never grants it.
    pub fn export(&self, opts: &ExportOptions) -> MemoryResult<MemoryExport> {
        self.export_routed(opts, None)
    }

    /// Full-vault export with the caller's authenticated owner-grade slip.
    /// HTTP passes the verifier-produced instrument, never a client option.
    pub fn export_with_verified_owner(
        &self,
        opts: &ExportOptions,
        proof: &VerifiedSlip,
    ) -> MemoryResult<MemoryExport> {
        self.export_routed(opts, Some(proof))
    }

    fn export_routed(
        &self,
        opts: &ExportOptions,
        proof: Option<&VerifiedSlip>,
    ) -> MemoryResult<MemoryExport> {
        render_export(self.vault, opts, &self.actor.to_hex(), |txn| {
            verify_actor_binding_in_txn(self.vault, txn, self.actor, self.actor_class)?;
            if self.actor_class != EdgeActorClass::Human {
                return Err(export_forbidden());
            }
            if let Some(proof) = proof {
                validate_verified_owner(self.vault, txn, proof)?;
                // A holder proof authorizes its own bound actor, not another
                // PERSON selected through `Vault::memory` or an HTTP field.
                if proof.claims().actor_class.as_deref() != Some("human")
                    || proof.claims().holder_ref != self.actor.to_hex()
                {
                    return Err(export_forbidden());
                }
            } else {
                // `memory(actor)` is public. Only a process holding the vault
                // writer lease and bound to its constructor's seeded owner
                // can use the local door; an arbitrary PERSON cannot.
                let owner = crate::vault::embedded_owner_actor_id()?;
                if self.actor != owner
                    || !self
                        .vault
                        .writer_lease()
                        .is_some_and(crate::store::VaultWriterLease::held_by_current_process)
                    || !crate::vault::live_entity_row_in_txn(&self.vault.store, txn, &owner)?
                        .is_live()
                {
                    return Err(export_forbidden());
                }
                if self
                    .vault
                    .authority_fold_readonly_in_txn(txn)?
                    .vault_root_is_conflicted()
                {
                    return Err(MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        "conflicting vault roots suspend full-vault export",
                        &["Resolve the authority fork before exporting."],
                    ));
                }
            }
            Ok(())
        })
    }
}

impl Vault {
    /// Host-root export without inventing an actor or creating a root on read.
    /// The verifier-produced root is rechecked in the export snapshot.
    pub fn export_with_verified_host_owner(
        &self,
        opts: &ExportOptions,
        proof: &VerifiedSlip,
    ) -> MemoryResult<MemoryExport> {
        render_export(self, opts, "host", |txn| {
            validate_verified_owner(self, txn, proof)?;
            if proof.claims().holder_ref != "host" {
                return Err(export_forbidden());
            }
            Ok(())
        })
    }

    /// Every whole-vault export receipt, oldest first.
    pub fn export_receipts(&self) -> crate::Result<Vec<ExportReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(EXPORT_RECEIPTS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect())
    }
}

fn validate_verified_owner(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proof: &VerifiedSlip,
) -> MemoryResult<()> {
    if !proof.is_full_vault_owner_grade() || !vault.capability_slip_is_live_in_txn(txn, proof)? {
        return Err(export_forbidden());
    }
    Ok(())
}

fn render_export(
    vault: &Vault,
    opts: &ExportOptions,
    by: &str,
    admit: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<()>,
) -> MemoryResult<MemoryExport> {
    let name = opts.format.as_deref().unwrap_or("toon");
    let format = match name {
        "toon" => PackFormat::Toon,
        "md" => PackFormat::Markdown,
        "json" => PackFormat::Json,
        "yaml" => PackFormat::Yaml,
        "txt" => PackFormat::Plaintext,
        _ => {
            return Err(MemoryError::bad_request_with(
                format!("unknown export format {name:?}"),
                &["Use one of: toon, md, json, yaml, txt."],
            ));
        }
    };
    let document = vault.export_whole_vault_with_admission(format, admit)?;
    let rendered = String::from_utf8(document.bytes().to_vec())
        .map_err(|_| MemoryError::bad_request("export serializer emitted non-UTF-8 text"))?;
    let receipt = ExportReceipt {
        at: vault.store.clock.now_recorded_at(),
        format: name.to_owned(),
        bytes: rendered.len() as u64,
        digest: blake3::hash(rendered.as_bytes()).to_hex().to_string(),
        by: by.to_owned(),
    };
    // Export is never gated: a vault that cannot take one more write (a full
    // map, a failing disk) still hands the owner their data, and says so.
    if let Err(error) = vault.with_write_txn(|txn| {
        let sequence = match EXPORT_RECEIPTS
            .iter_rev_from(&vault.store, txn, &[])?
            .next()
        {
            None => 0,
            Some(row) => row?
                .0
                .checked_add(1)
                .ok_or(crate::Error::IndexOverflow("export receipt sequence"))?,
        };
        EXPORT_RECEIPTS.put(&vault.store, txn, &sequence, &receipt)
    }) {
        tracing::warn!(%error, "whole-vault export served without its receipt");
    }
    Ok(MemoryExport {
        format: name.to_owned(),
        rendered,
    })
}

fn export_forbidden() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "full-vault export requires an authenticated owner",
        &["Use an embedded owner handle or an authenticated full-vault owner credential."],
    )
}
