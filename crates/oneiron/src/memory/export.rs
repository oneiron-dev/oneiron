//! Full-vault memory export: the whole-vault archive (OF-222). Export is never
//! gated and is never a backup; backups stay the vault's encrypted snapshot.

use serde::{Deserialize, Serialize};

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::Vault;
use crate::authority::VerifiedSlip;
use crate::batch::export::VAULT_ARCHIVE_FORMAT;
use crate::claim::CallerLocality;
use crate::edge::EdgeActorClass;
use crate::memory::verify_actor_binding_in_txn;
use crate::side_table::{self, Named, SideTable};

/// The export target. `archive` (the default) is the whole vault: one ZIP of
/// one JSONL file per record kind, each attached file once by BLAKE3, and a
/// manifest. It re-imports into a fresh vault.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExportOptions {
    #[serde(default)]
    pub format: Option<String>,
    /// Whether the archive carries custody secret values. Absent means yes:
    /// "all your data is all your data" (owner, 2026-10-17). `false` exports
    /// each custody record as its handle only; a re-import lists those as
    /// missing secrets to re-enter.
    #[serde(default)]
    pub include_secrets: Option<bool>,
}

/// The `format` that names the whole-vault archive.
pub const EXPORT_TARGET_ARCHIVE: &str = "archive";

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
    /// BLAKE3 of the archive, lowercase hex.
    pub digest: String,
    /// The exporting actor as hex, or `host` for a host-root export.
    pub by: String,
    /// OF-490: each agent whose diaries this export read, with the reason.
    pub diary_reads: Vec<crate::batch::export::ExportDiaryRead>,
}

const EXPORT_RECEIPTS: SideTable<u64, ExportReceipt, Named> =
    SideTable::new(&side_table::EXPORT_RECEIPT);

/// One whole-vault export. On the wire the archive is standard base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryExport {
    /// The archive manifest's `format`.
    pub format: String,
    #[serde(with = "archive_base64")]
    pub archive: Vec<u8>,
    /// BLAKE3 of `archive`, lowercase hex, as its receipt records it.
    pub digest: String,
}

mod archive_base64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}

impl Memory<'_> {
    /// Embedded full-vault export. Only the constructor-owned, leased owner
    /// handle may use this door; binding a different PERSON never grants it.
    pub fn export(&self, opts: &ExportOptions) -> MemoryResult<MemoryExport> {
        self.export_routed(opts, None)
    }

    /// Full-vault export with the caller's authenticated owner-grade slip.
    /// HTTP passes the verifier-produced instrument, never a client option.
    /// A caller off this device (see [`Memory::at`]) takes no device-local
    /// world with it (DEC-0005).
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
        render_export(
            self.vault,
            opts,
            &self.actor.to_hex(),
            self.locality,
            |txn| {
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
                    // A live slip outlives its holder's Owner role: whole-vault
                    // export asks for the role now, in the export's snapshot.
                    if !crate::policy_model::is_live_vault_owner_in_txn(
                        self.vault,
                        txn,
                        &self.actor,
                    )? {
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
            },
        )
    }
}

impl Vault {
    /// Host-root export without inventing an actor or creating a root on read.
    /// The verifier-produced root is rechecked in the export snapshot. A
    /// caller at `locality` off this device takes no device-local world with
    /// it (DEC-0005).
    pub fn export_with_verified_host_owner(
        &self,
        opts: &ExportOptions,
        proof: &VerifiedSlip,
        locality: CallerLocality,
    ) -> MemoryResult<MemoryExport> {
        render_export(self, opts, "host", locality, |txn| {
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
    locality: CallerLocality,
    admit: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<()>,
) -> MemoryResult<MemoryExport> {
    let name = opts.format.as_deref().unwrap_or(EXPORT_TARGET_ARCHIVE);
    if name != EXPORT_TARGET_ARCHIVE {
        return Err(MemoryError::bad_request_with(
            format!("unknown export format {name:?}"),
            &["Use: archive."],
        ));
    }
    let include_secrets = opts.include_secrets.unwrap_or(true);
    let export = vault.export_whole_vault_with_admission(locality, include_secrets, admit)?;
    let digest = blake3::hash(&export.bytes).to_hex().to_string();
    let receipt = ExportReceipt {
        at: vault.store.clock.now_recorded_at(),
        format: name.to_owned(),
        bytes: export.bytes.len() as u64,
        digest: digest.clone(),
        by: by.to_owned(),
        diary_reads: export.diary_reads,
    };
    // Export is never gated: a vault that cannot take one more write (a full
    // map, a failing disk) still hands the owner their data, and says so.
    if let Err(error) = vault.with_write_txn_grouped(|txn| {
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
        format: VAULT_ARCHIVE_FORMAT.to_owned(),
        archive: export.bytes,
        digest,
    })
}

fn export_forbidden() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "full-vault export requires an authenticated owner",
        &["Use an embedded owner handle or an authenticated full-vault owner credential."],
    )
}
