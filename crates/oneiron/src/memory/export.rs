//! Full-vault memory export through the existing five-format pack writers.

use serde::{Deserialize, Serialize};

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::Vault;
use crate::authority::VerifiedSlip;
use crate::context_pack::PackFormat;
use crate::edge::EdgeActorClass;
use crate::memory::verify_actor_binding_in_txn;

/// Format for the full-vault export; absence uses the model-injection default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExportOptions {
    #[serde(default)]
    pub format: Option<String>,
}

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
        render_export(self.vault, opts, |txn| {
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
        render_export(self, opts, |txn| {
            validate_verified_owner(self, txn, proof)?;
            if proof.claims().holder_ref != "host" {
                return Err(export_forbidden());
            }
            Ok(())
        })
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
