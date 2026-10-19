//! Full-vault memory export: the whole-vault archive (OF-222). Export is never
//! gated and is never a backup; backups stay the vault's encrypted snapshot.

use std::io::{Read, Seek, SeekFrom, Write};

use serde::{Deserialize, Serialize};

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::Vault;
use crate::authority::{ActSurface, HostActionAuthority, OwnerAct, OwnerActKind, VerifiedSlip};
use crate::claim::CallerLocality;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::verify_actor_binding_in_txn;
use crate::side_table::{self, Named, SideTable};
use crate::write_envelope::WriteActor;

/// The export target. `archive` (the default) is the whole vault: one ZIP of
/// one JSONL file per record kind, each attached file once by BLAKE3, and a
/// manifest. It re-imports into a fresh vault. `okf` is "Export to OKF": a
/// ZIP of markdown concepts with YAML frontmatter (Open Knowledge Format
/// v0.1) for other tools, lossy and labelled as not a full copy.
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
/// The `format` that names the lossy OKF bundle.
pub const EXPORT_TARGET_OKF: &str = "okf";

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
    /// The owner's act this export carried out, on a door that records one
    /// (Engine 10-19 02:4x): kind [`OwnerActKind::Export`], on the whole
    /// vault's reserved target, by the owner the export's snapshot
    /// revalidated, with where he said so (audit only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<OwnerAct>,
}

const EXPORT_RECEIPTS: SideTable<u64, ExportReceipt, Named> =
    SideTable::new(&side_table::EXPORT_RECEIPT);

/// One export: the archive, or the OKF bundle. On the wire the ZIP is
/// standard base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryExport {
    /// The archive manifest's `format`.
    pub format: String,
    #[serde(with = "archive_base64")]
    pub archive: Vec<u8>,
    /// BLAKE3 of `archive`, lowercase hex, as its receipt records it.
    pub digest: String,
}

/// One export written to the caller's file (FIX 2766): its format, length and
/// BLAKE3, as its receipt records them. The archive is the caller's file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryExportReceipt {
    /// The archive manifest's `format`.
    pub format: String,
    pub bytes: u64,
    /// BLAKE3 of the archive, lowercase hex.
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
        self.export_routed(opts, None, None)
    }

    /// Full-vault export with the caller's authenticated owner-grade slip.
    /// HTTP passes the verifier-produced instrument, never a client option.
    /// A caller off this device (see [`Memory::at`]) takes no device-local
    /// world with it (DEC-0005). The receipt records the owner's act (FIX
    /// 4626), by the slip's holder, whom the export's own snapshot
    /// revalidates as a live owner, with the `surface` the door read from its
    /// request, audit only.
    pub fn export_with_verified_owner(
        &self,
        opts: &ExportOptions,
        proof: &VerifiedSlip,
        surface: ActSurface,
    ) -> MemoryResult<MemoryExport> {
        let act = export_act(self.actor, surface)?;
        self.export_routed(opts, Some(proof), Some(act))
    }

    /// [`Self::export`] written to `sink` as it is built (FIX 2766): a vault
    /// larger than memory exports, and the archive is never held whole. Its
    /// source rows are listed as [`Self::export`] lists them.
    pub fn export_to<W: Read + Write + Seek>(
        &self,
        opts: &ExportOptions,
        sink: W,
    ) -> MemoryResult<MemoryExportReceipt> {
        let (receipt, sources) = render_export_to(
            self.vault,
            opts,
            ExportBy::plain(&self.actor.to_hex()),
            self.locality,
            WriteActor::new(self.actor, EdgeActorClass::Human),
            |txn| self.export_admitted_in_txn(txn, None),
            sink,
        )?;
        self.produced_from(sources);
        Ok(receipt)
    }

    /// The export, its source rows listed as this surface lists its reads
    /// ([`Memory::listing_producers`]), its receipt carrying `act` when the
    /// door recorded one.
    fn export_routed(
        &self,
        opts: &ExportOptions,
        proof: Option<&VerifiedSlip>,
        act: Option<OwnerAct>,
    ) -> MemoryResult<MemoryExport> {
        let name = self.actor.to_hex();
        let (export, sources) = render_export(
            self.vault,
            opts,
            ExportBy { name: &name, act },
            self.locality,
            WriteActor::new(self.actor, EdgeActorClass::Human),
            |txn| self.export_admitted_in_txn(txn, proof),
        )?;
        self.produced_from(sources);
        Ok(export)
    }

    /// Whether [`Self::export`], or [`Self::export_with_verified_owner`]
    /// with `proof`, admits this caller now, in a read snapshot of its own.
    /// A door asks first, so the verb's hooks never run on an export it
    /// refuses; the export asks again in its own snapshot.
    pub fn admit_export(&self, proof: Option<&VerifiedSlip>) -> MemoryResult<()> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.export_admitted_in_txn(&txn, proof)
    }

    fn export_admitted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: Option<&VerifiedSlip>,
    ) -> MemoryResult<()> {
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
            if !crate::policy_model::is_live_vault_owner_in_txn(self.vault, txn, &self.actor)? {
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
                || !crate::vault::live_entity_row_in_txn(&self.vault.store, txn, &owner)?.is_live()
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
    }
}

impl Vault {
    /// Host-root export without inventing an actor or creating a root on read.
    /// The verifier-produced root is rechecked in the export snapshot. A
    /// caller at `locality` off this device takes no device-local world with
    /// it (DEC-0005).
    ///
    /// A whole-vault export is an owner act, not a backup (FIX 2222): a
    /// self-hosted root exports as the owner it acts as, and a host root on
    /// any other vault gets `HOST_ACTION_REQUIRES_SUPPORT_GRANT`. Its receipt
    /// records that owner's act from `surface` (FIX 4626), audit only.
    pub fn export_with_verified_host_owner(
        &self,
        opts: &ExportOptions,
        proof: &VerifiedSlip,
        surface: ActSurface,
        locality: CallerLocality,
    ) -> MemoryResult<MemoryExport> {
        self.export_with_verified_host_owner_listing(opts, proof, surface, locality)
            .map(|(export, _)| export)
    }

    /// [`Self::export_with_verified_host_owner`], beside the rows the
    /// archive is derived from (DEC-0005): each row its snapshot read past
    /// the caller's locality, whether the archive carries it, counts it or
    /// folds it into another section. A refusal lists none.
    pub fn export_with_verified_host_owner_listing(
        &self,
        opts: &ExportOptions,
        proof: &VerifiedSlip,
        surface: ActSurface,
        locality: CallerLocality,
    ) -> MemoryResult<(MemoryExport, Vec<EntityId>)> {
        // A host-root export reads diaries as the owner the root acts as
        // (OF-490, FIX 2222), resolved by the rule every host action takes.
        let owner = self.admit_host_owner(proof)?;
        let reader = WriteActor::new(owner, EdgeActorClass::Human);
        // The act names that owner, whom the export's own snapshot must
        // resolve again below.
        let by = ExportBy {
            name: "host",
            act: Some(export_act(owner, surface)?),
        };
        render_export(self, opts, by, locality, reader, |txn| {
            if host_owner_export_admitted(self, txn, proof)? == owner {
                Ok(())
            } else {
                Err(export_forbidden())
            }
        })
    }

    /// [`Self::export_with_verified_host_owner_listing`] for a host action
    /// that presents no slip (FIX 2222 remainder): the explicit local dev
    /// mode's ([`Vault::dev_action_authority`]), or a self-hosted root's as
    /// its host action resolved it. The same archive and the same served
    /// listing, read as the same owner (the embedded owner Human the action
    /// acts as), under the same owner-floor checks: the action must hold in
    /// a snapshot of its own and again in the export's own snapshot (a
    /// self-hosted vault, the owner-verb rule, a root that still binds that
    /// owner when there is one, and a live owner PERSON). Anywhere else the
    /// typed `HOST_ACTION_REQUIRES_SUPPORT_GRANT` refusal. Its receipt
    /// records the act of the owner the action acts as, from `surface` (FIX
    /// 4626), audit only.
    pub fn export_with_host_action_listing(
        &self,
        opts: &ExportOptions,
        action: &HostActionAuthority,
        surface: ActSurface,
        locality: CallerLocality,
    ) -> MemoryResult<(MemoryExport, Vec<EntityId>)> {
        {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            action
                .guard()
                .holds_in(self, &txn)
                .map_err(MemoryError::from)?;
        }
        let by = ExportBy {
            name: "host",
            act: Some(export_act(action.actor().entity_ref(), surface)?),
        };
        render_export(self, opts, by, locality, action.actor(), |txn| {
            action
                .guard()
                .holds_in(self, txn)
                .map_err(MemoryError::from)
        })
    }

    /// Full-vault export for an owner the request itself authenticated: a
    /// managed vault's attested owner (`ManagedOwnerAction`), which carries
    /// neither a slip nor a host action. The proof is revalidated in the
    /// export's own snapshot (its vault, a live person, a live Owner role,
    /// any credential or host action it bound), and the actor it names there
    /// must be the export's reader. The same archive and served listing as
    /// the slip path, read at the caller's own `locality`: a caller off this
    /// device takes no device-local world with it (DEC-0005). The proof is
    /// this request's alone, never a durable owner authorization. The
    /// export's receipt records the owner's act (Engine 10-19 02:4x), with
    /// the `surface` he said so from, audit only.
    pub fn export_with_authenticated_owner_listing(
        &self,
        opts: &ExportOptions,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        locality: CallerLocality,
    ) -> MemoryResult<(MemoryExport, Vec<EntityId>)> {
        let actor = self.admit_authenticated_owner(owner)?;
        let reader = WriteActor::new(actor, EdgeActorClass::Human);
        // The act names the owner the export's own snapshot revalidates
        // below: a snapshot that names anyone else releases nothing.
        let name = actor.to_hex();
        let by = ExportBy {
            name: &name,
            act: Some(export_act(actor, surface)?),
        };
        render_export(self, opts, by, locality, reader, |txn| {
            if authenticated_owner_export_admitted(self, txn, owner)? == actor {
                Ok(())
            } else {
                Err(export_forbidden())
            }
        })
    }

    /// Whether [`Self::export_with_authenticated_owner_listing`] admits
    /// `owner` now, in a read snapshot of its own; the export asks again in
    /// its own.
    pub fn admit_authenticated_owner_export(&self, owner: &AuthenticatedOwner) -> MemoryResult<()> {
        self.admit_authenticated_owner(owner)?;
        Ok(())
    }

    /// The owner `owner` exports as, in a read snapshot of its own.
    fn admit_authenticated_owner(&self, owner: &AuthenticatedOwner) -> MemoryResult<EntityId> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        authenticated_owner_export_admitted(self, &txn, owner)
    }

    /// Whether [`Self::export_with_verified_host_owner`] admits `proof` now,
    /// in a read snapshot of its own; the export asks again in its own.
    pub fn admit_host_owner_export(&self, proof: &VerifiedSlip) -> MemoryResult<()> {
        self.admit_host_owner(proof)?;
        Ok(())
    }

    /// The owner `proof` exports as, in a read snapshot of its own.
    fn admit_host_owner(&self, proof: &VerifiedSlip) -> MemoryResult<EntityId> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        host_owner_export_admitted(self, &txn, proof)
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

/// The owner a host root exports as, in `txn`: the one it acts as under
/// the host-action rule (FIX 2222), which also requires the live, full root.
/// Off a self-hosted vault the typed refusal; a credential that is not the
/// host's own exports nothing.
fn host_owner_export_admitted(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    proof: &VerifiedSlip,
) -> MemoryResult<EntityId> {
    if proof.claims().holder_ref != "host" {
        return Err(export_forbidden());
    }
    vault
        .host_action_owner_in_txn(txn, Some(proof))
        .map_err(MemoryError::from)
}

/// The owner a request's own proof exports as, in `txn`: the proof belongs
/// to this vault, and its person is live and owns it now (the proof's
/// `revalidate_in_txn`, the rule every owner act takes). A proof that no
/// longer holds gets the export's own refusal, naming why.
fn authenticated_owner_export_admitted(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> MemoryResult<EntityId> {
    owner
        .revalidate_in_txn(vault, txn)
        .map_err(|error| match error {
            crate::Error::Gate(crate::error::GateError::ConsentOwnerNotAuthenticated(reason)) => {
                owner_proof_export_refused(reason)
            }
            other => MemoryError::from(other),
        })
}

/// The refusal of a request owner proof that no longer holds in the
/// export's snapshot, with the proof's own reason.
fn owner_proof_export_refused(reason: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("full-vault export requires an authenticated owner: {reason}"),
        &["Authenticate again as this vault's live owner, then export."],
    )
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

/// Who an export is by, as its receipt records it: the exporting actor as
/// hex (or `host`), and the owner's act when the door named where the owner
/// said so.
struct ExportBy<'a> {
    name: &'a str,
    act: Option<OwnerAct>,
}

impl<'a> ExportBy<'a> {
    /// An export by `name` that records no owner act.
    fn plain(name: &'a str) -> Self {
        Self { name, act: None }
    }
}

/// The act an owner export records: kind [`OwnerActKind::Export`], by
/// `owner`, on the whole vault's reserved target, from `surface` (audit
/// only). An export changes nothing, so its `seen` is zero.
fn export_act(owner: EntityId, surface: ActSurface) -> MemoryResult<OwnerAct> {
    let target = crate::policy_setting_doors::owner_act_target("vault.export")?;
    Ok(OwnerAct::by_owner(
        owner,
        OwnerActKind::Export,
        target,
        surface,
        [0; 32],
    ))
}

/// The export both owner paths render in one frame, for a door that answers
/// with the whole archive, beside the rows its snapshot read: built through a
/// spool file under the vault's staging directory (FIX 2766) and read back
/// whole only here.
fn render_export(
    vault: &Vault,
    opts: &ExportOptions,
    by: ExportBy<'_>,
    locality: CallerLocality,
    reader: WriteActor,
    admit: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<()>,
) -> MemoryResult<(MemoryExport, Vec<EntityId>)> {
    let mut spool = vault.archive_spool_file()?;
    let (receipt, sources) =
        render_export_to(vault, opts, by, locality, reader, admit, &mut spool)?;
    spool.seek(SeekFrom::Start(0)).map_err(crate::Error::from)?;
    let mut archive = Vec::new();
    spool
        .read_to_end(&mut archive)
        .map_err(crate::Error::from)?;
    Ok((
        MemoryExport {
            format: receipt.format,
            archive,
            digest: receipt.digest,
        },
        sources,
    ))
}

/// One export written to `sink` as it is built (FIX 2766): the archive is
/// never held whole, and its digest and length are read back from `sink`
/// for the export's receipt.
fn render_export_to<W: Read + Write + Seek>(
    vault: &Vault,
    opts: &ExportOptions,
    by: ExportBy<'_>,
    locality: CallerLocality,
    reader: WriteActor,
    admit: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<()>,
    sink: W,
) -> MemoryResult<(MemoryExportReceipt, Vec<EntityId>)> {
    let name = opts.format.as_deref().unwrap_or(EXPORT_TARGET_ARCHIVE);
    let include_secrets = opts.include_secrets.unwrap_or(true);
    let (mut sink, export) = match name {
        EXPORT_TARGET_ARCHIVE => vault.export_whole_vault_with_admission(
            locality,
            include_secrets,
            reader,
            admit,
            sink,
        )?,
        EXPORT_TARGET_OKF => vault.export_okf_with_admission(locality, reader, admit, sink)?,
        _ => {
            return Err(MemoryError::bad_request_with(
                format!("unknown export format {name:?}"),
                &["Use one of: archive, okf."],
            ));
        }
    };
    let format = export.manifest().format.clone();
    let (bytes, digest) = written_digest(&mut sink).map_err(crate::Error::from)?;
    let receipt = ExportReceipt {
        at: vault.store.clock.now_recorded_at(),
        format: name.to_owned(),
        bytes,
        digest: digest.clone(),
        by: by.name.to_owned(),
        diary_reads: export.diary_reads().to_vec(),
        act: by.act,
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
    Ok((
        MemoryExportReceipt {
            format,
            bytes,
            digest,
        },
        export.sources,
    ))
}

/// The length and BLAKE3 of what `sink` holds, read back from its start.
fn written_digest<R: Read + Seek>(sink: &mut R) -> std::io::Result<(u64, String)> {
    sink.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let bytes = std::io::copy(sink, &mut hasher)?;
    Ok((bytes, hasher.finalize().to_hex().to_string()))
}

fn export_forbidden() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        "full-vault export requires an authenticated owner",
        &["Use an embedded owner handle or an authenticated full-vault owner credential."],
    )
}
