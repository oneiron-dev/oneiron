//! Wire version constants, SLIM gating and the revisions of the additive
//! extensions a v3 vault reports on `Ping`.

use serde::{Deserialize, Deserializer};

/// First contract version carrying the SLIM rung. The v1 -> v2 bump is
/// additive-only: every v1 request and response keeps byte-identical semantics
/// except `Ping.contract_version`, which now reports 2 as the negotiation signal;
/// v1 peers are never sent a v2-only request.
pub const SLIM_CONTRACT_VERSION: u32 = 2;

/// The wire version this crate speaks. v3 adds the typed ctl refusal
/// ([`CtlResponse::Refused`](crate::CtlResponse::Refused)): a vault frozen for
/// reap answers a write it refuses with the bound it names, where v2 answered
/// `Ok { ok: false }`. v3 also carries the vault's live training setting
/// ([`ManagedTrainingSetting`](crate::ManagedTrainingSetting)) on every ledger
/// report, required on `LedgerUpdate` and `PrepareReap` alike, and how the
/// vault came up ([`ManagedReadiness`](crate::ManagedReadiness)) on every
/// `Ping`. v3 also carries the training purge ctl request
/// ([`CtlRequest::TrainingPurge`](crate::CtlRequest::TrainingPurge)), the
/// owner-signing recovery ctl request
/// ([`CtlRequest::RecoverOwnerSigning`](crate::CtlRequest::RecoverOwnerSigning))
/// and the legal holds ctl request
/// ([`CtlRequest::LegalHolds`](crate::CtlRequest::LegalHolds)), each with a
/// build floor: a supervisor sends one only to vaults built at or after it,
/// and a v3 vault built before it answers it as an unknown request. The
/// managed backup facts on `Ping`
/// ([`ManagedBackupFacts`](crate::ManagedBackupFacts)) carry a build floor
/// too: a v3 vault built before it sends none, which a supervisor reads as
/// unknown. So does the revision of the shared owner-path rule
/// (`settings_paths_revision`, FIX 5187) on `Ping`. The supervisor SLIM
/// recovery surface (FIX 5186) carries a build floor too: the `slim_status`
/// and `unslim` ctl requests and the optional `wait_id` on `Shed`, proven by
/// `slim_recovery_revision` on `Ping`
/// ([`SLIM_RECOVERY_REVISION`](crate::slim_control::SLIM_RECOVERY_REVISION)).
/// A v3 vault built before it answers either request as unknown and ignores
/// a `wait_id`, shedding unguarded, so a supervisor relies on that guard only
/// after the vault's `Ping` reports the revision. A vault VM's outbox
/// carrier ([`vm_outbox`](crate::vm_outbox), FIX 5235) carries a build floor
/// too, at the engine revision it merged in, proven by `vm_outbox_revision`
/// on `Ping`: the image manifest pins an engine at or after it, and a
/// supervisor relies on the carrier only once the vault reports it. The cold
/// managed restore start mode ([`restore`](crate::restore): `--restore`, its two pipes, the
/// commit marker and the `restore_status` ctl request) carries a build
/// floor too, at the engine revision it merged in: a supervisor starts a
/// restore only on an installed engine at or after it, since an older one
/// refuses the flag before it touches anything. The idle reap preparation
/// with its backup ([`CtlRequest::PrepareIdleReap`](crate::CtlRequest::PrepareIdleReap))
/// carries a build floor too, proven by `prepare_idle_reap: true` in `Ping`'s
/// managed backup facts; a v3 vault built before it answers it as an
/// unknown request. The host-order legal holds a cold restore carries
/// ([`host_holds`](crate::restore::host_holds), FIX 1485: the source's
/// `host_order_holds` ctl request, the restore input's optional
/// `host_holds` and the receipt's `host_holds`) carry a build floor too, at
/// the engine revision they merged in: a supervisor asks a source for its
/// family, hands one on the input pipe and reads a receipt only with
/// installed engines at or after it. A v3 vault built before it answers the
/// request as an unknown request, which is never a family, and refuses an
/// input that carries one as an unknown field; the receipt's new required
/// field rides v3 with no version move, and no reader of a receipt without
/// it is kept. The managed artifact origin's internal authority
/// ([`ArtifactInternalHost`](crate::artifact_origin::ArtifactInternalHost),
/// FIX 6716) carries a build floor too, at the engine revision it merged in,
/// proven by `artifact_internal_host_revision` on `Ping`. An engine at or
/// after it answers only on `<vault_id>.artifact.invalid` and
/// `<app>.<vault_id>.artifact.invalid`, and refuses `--artifact-public-slug`
/// and a managed `--artifact-domains`, as a vault VM profile refuses its
/// `artifact_domains` and `artifact_public_slug` keys; one before it answers
/// only at the slug those flags named. A `Ping` comes after the flags are
/// parsed, so a supervisor pins installed engines and VM images at or after
/// the floor before it stops passing them, and opens artifact ingress only
/// once the vault reports the revision. The confirm on `host_order_holds`
/// ([`HostHoldsCursor`](crate::restore::HostHoldsCursor), FIX 6820: a cursor
/// at the family's end, answered with no bytes while the family is still
/// the cursor's) carries a build floor too, at the engine revision it
/// merged in: a supervisor confirms a source's family only on an installed
/// engine at or after it, and a v3 vault built before it answers a confirm
/// `cursor_invalid`, which confirms nothing. The shared model root
/// ([`SharedModelRoot`](crate::settings_paths::SharedModelRoot), FIX 6828:
/// `--shared-model-root` and the model directories it admits) carries a
/// build floor too, at the engine revision it merged in, proven by
/// `settings_paths_revision` 2 on `Ping`. An engine before it refuses the
/// flag before it touches anything, and a model directory in the root as
/// outside the vault, so a supervisor passes the flag, and publishes a
/// model directory in the root, only with installed engines at or after
/// the floor. The relay locker delete the engine executes
/// ([`relay_delete`](crate::relay_delete), FIX 6826: the
/// `relay_delete_execute`, `relay_delete_rechecks` and `relay_locker_bind`
/// ctl requests, `Ping`'s `engine_instance`, and `host relay`'s
/// `--hold-guard-socket`, `--hold-guard-vault` and `--hold-guard-required`)
/// carries a build floor too, at the engine revision it merged in, proven by
/// `relay_delete_revision` on `Ping`. A v3 vault built before it answers each
/// request as an unknown request, which deletes, binds and proves nothing,
/// and a relay binary before it refuses the flags, so a supervisor binds a
/// locker, forwards a relay's requests and starts a guarded relay only with
/// installed engines at or after the floor. The container CLI's directories
/// (FIX 6876: `--container-home` and `--container-runtime-dir`, the `HOME`
/// and `XDG_RUNTIME_DIR` the guests' container CLI runs with) carry a build
/// floor too, at the engine revision they merged in, with no `Ping` field:
/// an engine before it refuses either flag before it touches anything, so a
/// supervisor passes them only with installed engines at or after the
/// floor. The writes in flight at an idle reap's freeze
/// ([`IdleReapInFlight`](crate::IdleReapInFlight), FIX 6902:
/// `idle_reap.in_flight_at_freeze`, required on every `prepare_idle_reap`
/// answer) carry a build floor too, at the engine revision they merged in,
/// with no `Ping` field: they ride v3 and idle reap schema 1 with no version
/// move, a vault built before the floor answers without them, and no reader
/// of an answer without them is kept, so a supervisor that reads them runs
/// only with installed engines at or after the floor. The vault VM's restore
/// channel ([`vm_restore`](crate::vm_restore), FIX 6584: vsock port 1032, its
/// control and stream records, `serve`'s `--vm-restore-revision`, `host vm`'s
/// `--restore`, `--restore-input-fd`, `--restore-result-fd`,
/// `--restore-marker-identity-fd` and `--restore-marker-result-fd`, and the
/// VM profile's `restore_source_disk`) carries a build floor too, at the
/// engine revision it merged in, proven by the image manifest's required
/// `restore_wire_revision` 1, with no `Ping` field. Every cold boot of an
/// image at or after the floor, an ordinary open's included, dials the
/// channel before its provision connection, so a host and its image come from
/// the same build: a supervisor checks the manifest's revision, its hashes
/// and the merge floor before it prepares the VMM or hands over the fscrypt
/// key or any credential, and boots no image before the floor. The channel's
/// fields are all required, its two nullable keys (a restore's
/// `source_device` and an observation's `marker`) present as `null`: the
/// hello's `revision` and `vault`, the boot's `mode` and an inspection's
/// `identity`, and the marker reply's `revision`, `vault`, `binding`,
/// `identity` and `observation`, with its `state` and its `data_present` or
/// `reason`. No reader of a record without them is kept. Supervisor and vault
/// move to v3 together; no v2 reader is kept.
///
/// VM backup-label registration (FIX 7046): a vault VM's outbox companion
/// names its engine's registered backup label on the carrier
/// ([`VmOutboxFrame::BackupRegistered`](crate::vm_outbox::VmOutboxFrame::BackupRegistered)),
/// and the host keeps the last one it was told for the vault its attachment
/// is bound to, which the host library's `read_vm_backup_label` reads. It
/// carries a build floor, at the engine revision it merged in: carrier
/// revision 2 ([`VM_OUTBOX_WIRE_REVISION`](crate::vm_outbox::VM_OUTBOX_WIRE_REVISION))
/// makes the frame's `label` required, and each end refuses the other's
/// revision 1 at the hello, with no reader of it kept. So the host library and
/// the installed guest image and its companion are all at or after the
/// floor, and a supervisor that accepts an image by its outbox revision (LC's
/// image acceptance, revision 1 today) moves to 2 at the floor in its
/// consuming change. An image before the floor, or one whose engine registered
/// no backup plan, gives no binding, and none is guessed from a backup's file
/// name. No `Ping` field is added and this version stays 3.
///
/// VM custody anchor channels (FIX 6517): a vault VM's custody anchor
/// exchange and proxy ([`vm_anchor`](crate::vm_anchor): vsock ports 1031 and
/// 1033, their records and the credential payload, `serve`'s
/// `--vm-anchor-revision`, `--vm-anchor-url` and `--vm-anchor-socket` with a
/// vault VM engine's `--custody-anchor-credentials-fd`, and `host vm`'s
/// `--custody-anchor-credentials-fd` and `--custody-anchor-url`) carry a
/// build floor, at the engine revision they merged in, proven by the image
/// manifest's required `anchor_wire_revision` 1 and `anchor_proxy_revision`
/// 1, published together, with no `Ping` field. Every serving cold boot of an
/// image at or after the floor dials the exchange after its provision
/// connection, so a host and its image come from the same build: a
/// supervisor checks both revisions, the manifest's hashes and the merge
/// floor before it prepares the VMM or hands over the fscrypt key, the
/// credential frame or the anchor credential, and boots no image before the
/// floor. The records' fields are all required, their two nullable keys (the
/// header's `anchor_url` and an accepted reply's `anchor_identity_digest`)
/// present as `null`: the header's `revision`, `vault`, `anchor_url` and
/// `has_credentials`; the reply's `state` with its `revision`, `vault` and
/// `anchor_identity_digest`, or its `code`; the proxy hello's `revision`,
/// `vault` and `anchor_identity_digest`; and the proxy reply's `state` with
/// its `revision` or its `code`. No reader of a record without them is kept.
/// A node's credential, its pipe and its reader are unchanged, and a vault VM
/// handed no credential keeps its anchor pending, as a node's child does. No
/// `Ping` field is added and this version stays 3.
pub const CONTRACT_VERSION: u32 = 3;

/// True when a peer advertising `version` accepts the SLIM ctl surface.
/// Supervisors ping first and send `Shed` only when this holds. With a v1 peer,
/// they skip the shed rung and retain the existing reap protocol. It proves
/// nothing of the recovery surface (`slim_status`, `unslim`, `Shed.wait_id`):
/// only `Ping`'s `slim_recovery_revision` does.
#[must_use]
pub const fn supports_slim(version: u32) -> bool {
    version >= SLIM_CONTRACT_VERSION
}

/// One extension's revision on `Ping` as a supervisor reads it: a value that
/// is not a whole number a u32 holds reads as `None`, unknown, and never
/// fails the `Ping` it rides.
pub(super) fn observed_revision<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u32>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value
        .as_ref()
        .and_then(serde_json::Value::as_u64)
        .and_then(|revision| u32::try_from(revision).ok()))
}
