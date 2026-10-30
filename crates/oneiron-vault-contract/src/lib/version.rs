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
/// VM checkpoint-fact member (FIX 7326/7327): a sealed backup's signed
/// checkpoint fact rides the carrier beside it as a `Backup` member
/// ([`vm_outbox_member`](crate::vm_outbox::vm_outbox_member)): exactly one
/// plain part, a backup artifact's own name with `.cpfact` after it,
/// guest-origin, in its artifact's set, put before the artifact and retired
/// after it, and retired only by the engine's prune. It carries a build
/// floor, at the engine revision it merged in: the host library, the guest
/// engine and its companion at or after the floor. An older host refuses the
/// new member (`MemberNotAllowed`), so deploy the host engine before an image
/// that writes facts: there, the refused fact is not sent again, and its
/// artifact is carried alone on the next turn. An artifact with no fact (one
/// taken before the floor, or whose fact was not signed or did not land) is
/// a set of one, as before, and nothing requires a fact. No field is added to
/// [`VmOutboxDescriptor`](crate::vm_outbox::VmOutboxDescriptor),
/// [`VmOutboxFrame::BackupRegistered`](crate::vm_outbox::VmOutboxFrame::BackupRegistered),
/// `Ping` or an image manifest, the carrier stays at wire revision 2, and
/// this version stays 3.
///
/// VM diverged-copy notice (FIX 11736, FIX 11737): after the owner answers
/// a copy the carrier never agreed on, the guest tells the host
/// ([`VmOutboxFrame::DivergenceCleared`](crate::vm_outbox::VmOutboxFrame::DivergenceCleared)):
/// a guest copy removed or moved aside clears the host's refusal of its own
/// version, and a host copy the owner kept moves aside on the host. It
/// carries a build floor, at the engine revision it merged in: carrier
/// revision 3 ([`VM_OUTBOX_WIRE_REVISION`](crate::vm_outbox::VM_OUTBOX_WIRE_REVISION)),
/// and each end refuses the other's revision 2 at the hello, with no reader
/// of it kept. The host library, the guest image and its companion are all
/// at or after the floor, and LC's image acceptance moves its outbox
/// revision to 3 at the floor. No `Ping` field is added and this version
/// stays 3.
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
///
/// VM guest network (FIX 6808): a vault VM's one NIC, the VM profile's
/// `network` ([`VmTapAttachment`](crate::vm::VmTapAttachment): `tap_name` and
/// `guest_mac`) and the config drive's `/config/network.json`
/// ([`VmGuestNetworkConfig`](crate::vm::VmGuestNetworkConfig): `guest_mac`,
/// `guest_ipv4`, `prefix_len`, `gateway` and `dns_servers`), with
/// `oneiron-vm-init`'s `--guest-config-dir`, carries a build floor, at the
/// engine revision it merged in, proven by the image manifest's required
/// `vm_network_revision` 1, with no `Ping` field. Every key is required: the
/// profile's `network` is present as `null` for a VM with no NIC, and both
/// objects refuse a missing or an unknown key, with no reader of a profile or
/// a file without them kept. A host library before the floor refuses a
/// profile that names `network` and one at or after it refuses a profile
/// that does not, so profiles move with the host library, and an image
/// before the floor sets up no NIC: a supervisor checks the manifest's
/// revision, its hashes and the merge floor before it prepares the VMM or
/// hands over the fscrypt key or any credential, and boots no image before
/// the floor with a NIC planned. The TAP, its rules and every name and
/// address are the supervisor's; the engine defaults none. No `Ping` field is
/// added and this version stays 3.
///
/// VM managed profile (FIX 6809): the config drive's five typed files,
/// `/config/organization-owner`, `/config/member-vault`,
/// `/config/failure-signal-export`, `/config/failure-signal-training` and
/// `/config/fast-dims`
/// ([`VM_GUEST_ORGANIZATION_OWNER_FILE`](crate::vm::VM_GUEST_ORGANIZATION_OWNER_FILE)
/// and its four siblings), which `oneiron-vm-init` reads before the vault's
/// key goes in and passes to an open's or a cold restore's engine as its
/// managed-profile flags, carry a build floor, at the engine revision they
/// merged in, proven by the image manifest's required
/// `vm_managed_profile_revision` 1
/// ([`VM_MANAGED_PROFILE_REVISION`](crate::vm::VM_MANAGED_PROFILE_REVISION)).
/// An image before the floor ignores the files, so its vault would start
/// without its tenancy or its owner's choices: a supervisor checks the
/// revision, the manifest's hashes and the merge floor before it stages any
/// of the files, prepares the VMM or hands over the fscrypt key or any
/// credential, and boots no image before the floor for a profile that needs
/// one of them. Each file is optional, and one that is not there gives the
/// engine no flag, never a `false`; one that is there holds its one value and
/// at most one final LF, or the boot is refused, with no reader of another
/// form kept. No `Ping` field is added and this version stays 3.
///
/// VM trusted organ builds (FIX 7889): the config drive's
/// `/config/trusted-organ-builds`
/// ([`VM_GUEST_TRUSTED_ORGAN_BUILDS_FILE`](crate::vm::VM_GUEST_TRUSTED_ORGAN_BUILDS_FILE)),
/// one organ build's blake3 per line, which the image's init passes to an
/// open's or a cold restore's engine as one `--trusted-organ-build` each,
/// carries a build floor, at the engine revision it merged in, proven by the
/// image manifest's required `vm_trusted_organ_builds_revision` 1
/// ([`VM_TRUSTED_ORGAN_BUILDS_REVISION`](crate::vm::VM_TRUSTED_ORGAN_BUILDS_REVISION)).
/// An image before the floor ignores the file, so every pack organ build in
/// its vault runs as third party: a supervisor checks the revision, the
/// manifest's hashes and the merge floor before it stages a list, and counts
/// a list applied only on an image at or after the floor. No file, or an
/// empty one, lists none; a line the flag's parser refuses refuses the boot,
/// as the flag does on a node, with no reader of another form kept. No
/// `Ping` field is added and this version stays 3.
///
/// Guest runtime fact (FIX 7670): `--guest-runtime-fact`
/// ([`GUEST_RUNTIME_FACT_ARG`](crate::GUEST_RUNTIME_FACT_ARG)) carries the
/// trusted supervisor's one observation of the guest runtime it provisioned
/// for the vault's UID, in [`GuestRuntimeFact`](crate::GuestRuntimeFact)'s
/// ten closed spellings, one value per spawn. It carries a build floor, at
/// the engine revision it merged in, with no `Ping` revision field: an
/// engine before it refuses the flag before it touches anything, and one at
/// or after it refuses a spelling not among the ten, so a supervisor passes
/// it only with installed engines at or after the floor. An engine never
/// requires it: no flag means no observation, never provisioned or disabled.
/// Provisioned means the image was imported and the observed preconditions
/// held, never that a guest started, and no fact refuses the vault's start.
/// This version stays 3.
///
/// Hosted private origins (FIX 7657): `--hosted-private-origin`, repeatable,
/// managed only, names one private origin a hosted node's web fetch may
/// reach, `http|https://<dns-name>[:port]` (the port the scheme's own by
/// default; a name of two or more labels, never an address or a wildcard;
/// no path, query, fragment or credentials). At and after the engine
/// revision it merged in, a managed node's fetch refuses RFC1918, CGNAT
/// 100.64.0.0/10 and ULA fc00::/7 addresses typed `hosted_private_network`
/// except at a listed origin, and never admits infrastructure. It carries a
/// build floor, at that revision, with no `Ping` revision field: an engine
/// before it refuses the flag before it touches anything, and one at or
/// after it refuses an entry that does not parse, so a supervisor passes it
/// only with installed engines at or after the floor. No flag means no
/// private origin. A vault VM has no config-drive file for it. This version
/// stays 3.
///
/// Browser readiness on `Ping` (FIX 7670): a
/// [`CtlResponse::Ping`](crate::CtlResponse::Ping) carries an optional
/// `browser` ([`BrowserReadiness`](crate::BrowserReadiness)), how the
/// vault's browser stands now, beside the boot-only `readiness`, which does
/// not change. It carries a build floor, at the engine revision it merged
/// in. Absent, it says this engine offers no browser, as an engine built
/// before the floor sends none; that line is still a `Ping`, and no browser
/// state stands in for it. Present, its `state` and each state's keys are
/// required: `image`, `runtime_fact` (present as `null` when the supervisor
/// observed none) and, where the state has them, `tier`, `reason` and
/// `last_observed_at`. No browser state, and no absent `browser`, fails the
/// ready handshake, turns `ok` false or asks for a restart. This version
/// stays 3.
///
/// Browser readiness on the owner's status (FIX 7670): the authenticated
/// `GET /v1/owner/status` reply requires `browser`, the same
/// [`BrowserReadiness`](crate::BrowserReadiness) a managed `Ping` carries,
/// read from the same value, with the same required keys. It carries a build
/// floor, at the engine revision it merged in: a client that reads it runs
/// against an engine at or after the floor, no reader of a status reply
/// without it is kept, and no default stands in for it. Public `/api/health`
/// carries none of it. No SDK row is added and this version stays 3.
///
/// Managed restore wake sequence floor (FIX 969): the cold restore plan's
/// required `wake_sequence_floor`
/// ([`ManagedRestorePlan`](crate::restore::ManagedRestorePlan)), the
/// receipt's required `wake_sequence_floor` and `report.checkpoint_sequence`
/// ([`ManagedRestoreReceipt`](crate::restore::ManagedRestoreReceipt)), and
/// the `checkpoint_sequence_below_floor` failure reason with its required
/// `floor` and `observed` carry a build floor, at the engine revision they
/// merged in, with no `Ping` field. An artifact-backed wake or migrate sends
/// the signed checkpoint sequence of the source copy the supervisor verified
/// as its floor, a historical restore sends `null`, and an ordinary open
/// sends no plan; the floor is never a custody sequence or a default. A
/// signed sequence below it fails `artifact_open` with the destination
/// removed, before the manifest opens, and never with a receipt. A verified
/// receipt always carries the artifact's checkpoint sequence, a historical
/// restore's too. The floor key is required even when `null`; an engine
/// before the floor refuses a plan that carries it as an unknown field, so a
/// supervisor sends it, and reads the receipt's new keys and the reason,
/// only with installed engines and vault VM images at or after the floor.
/// No reader of a plan or receipt without them is kept, the restore input
/// and receipt schemas stay 1, and this version stays 3.
///
/// Artifact publication serving blob descriptor (FIX 1195; includes FIX
/// 9575): an owner device's engine and a serving sync server's engine
/// exchange `ARTIFACT_PUBLICATION` documents only as bounded parts, each a
/// fixed header (the change id, the BLAKE3 of the whole serialized
/// publication, its total length, the part's offset and the part's length)
/// and at most 256 KiB of that publication. The whole publication requires
/// its change id and, for a blob, the serving descriptor (`content_hash`,
/// `export_name` and `export_media_type`, all required), which the pointer
/// and the owner bind; no blob version record, provenance, run, claim or
/// history rides it. `ARTIFACT_RECEIPT` names the whole publication's digest
/// and its outcome only, once it is complete, never a part's acceptance. The
/// device's outbox marker requires its change id. It carries a build floor,
/// at the engine revision it merged in, with no `Ping` field: owner devices
/// and sync servers both run at or after the floor before they publish, and
/// no reader of a raw blob version publication, a whole-frame publication,
/// an outbox marker without a change id or a missing field is kept. The
/// transport frame limits, full-vault sync, the Code arm, pins, tiers and
/// unpublish are unchanged, and this version stays 3.
///
/// Relay retained-generation retirement (FIX 1283; includes FIX 9499 and FIX
/// 9500): the relay, the supervisor's broker and the vault engine move
/// together at the engine revision it merged in, proven by
/// `relay_delete_revision` 2 on `Ping`
/// ([`RELAY_DELETE_REVISION`](crate::relay_delete::RELAY_DELETE_REVISION)).
/// `relay_delete_execute` requires `generation`
/// ([`RelayDeleteGeneration`](crate::relay_delete::RelayDeleteGeneration):
/// `current`, or `preimage` with its 32-lowercase-hex `generation_id`), and
/// every answer repeats it with the other six fields. A `held` answer
/// requires `visibility`
/// ([`RelayHoldVisibility`](crate::relay_delete::RelayHoldVisibility):
/// `visible` or `silent_only`); the relay answers a silent-only one with a
/// neutral `completion_pending` that names no hold, and a visible one with
/// `held_until_release`. A relay's deferred-delete intent requires its
/// generation too. The supervisor binds a locker and forwards a relay's
/// retirements only to an engine boot that proved revision 2; a relay
/// binary, broker or engine before the floor is not mixed with one after it.
/// No missing-field default and no reader of an older request, answer or
/// intent is kept. An engine before the floor, unavailable or unproven,
/// leaves destruction deferred and never refuses or delays an authenticated
/// upload, which answers 204 on storage alone. The objects directory binding
/// is unchanged and this version stays 3.
///
/// Wake ledger pages (FIX 9549; includes FIX 9498): a ledger push and a
/// frozen pull carry one complete report, every wake entry and the training
/// setting at one revision, in pages of at most
/// [`MAX_LEDGER_PAGE_ENTRIES`](crate::MAX_LEDGER_PAGE_ENTRIES) entries
/// ([`LedgerPage`](crate::LedgerPage): `rev`, `report_digest`, `total`,
/// `offset`, `entries`, `training`, all required), however many entries the
/// report holds: the old 128-entry bound on a whole list is gone, and no
/// count, size or time bound replaces it. `ledger_update` requires `page`
/// in place of `rev`, `entries` and `training`, and the supervisor answers
/// each page with a [`LedgerAck`](crate::LedgerAck) that requires `report`
/// and `offset` (each `null` only for a line it could not read) and
/// `committed`, true only on the last page once the whole report, the
/// host's fire time for each window included, is durable. `prepare_reap`
/// answers `quiescent` and `ledger`
/// ([`LedgerReportHead`](crate::LedgerReportHead): `rev`, `report_digest`,
/// `total`) in place of `ledger_rev`, `next_wake` and `training`, and
/// `prepare_idle_reap`'s `idle_reap` requires `ledger` in place of the same
/// three; the supervisor reads that frozen report with `ledger_page` and
/// releases it with `ledger_pulled`, both of which carry `vault` and the
/// spawn `token`, before any snapshot or stop. A report with no entries is
/// one page with none. It carries a build floor at the engine revision it
/// merged in, with no `Ping` field: the installed supervisor, its host
/// library, the vault engine and every vault VM image move together at or
/// after the floor, both reap pulls and the push consumer included. No
/// migration, missing-field default, shim or reader of a whole-list push or
/// pull is kept, and this version stays 3.
///
/// Owner shed admission (FIX 10157): the facade's `vault.slim.drop_heavy`
/// answer (the engine's `slim::public::SlimDropOutcome`) gains the status
/// `nothing_pending`, with no other key: the owner's request waited while
/// more than one outbound step was pending, then found none pending on a
/// FULL vault, so no shed was owed and none ran. It carries a build floor,
/// at the engine revision it merged in, with no `Ping` field: a client that
/// reads the status runs against an engine at or after the floor, and no
/// reader of an answer without it is kept. The supervisor's `Shed` ctl
/// request and its answers are unchanged, and this version stays 3.
///
/// Catalog rate currency (FIX 9534): a model catalog cost (the engine's
/// `llm::LlmCatalogCost`, on every facade, SDK and binding surface that
/// carries a catalog entry, and in each stored registry row and mesh peer
/// row) carries `currency`, the provider's three-letter code or `null` when
/// it named none (a missing key reads as `null`, FIX 11778), and a usage
/// rate snapshot (the host's `UsageCostRates`, on usage events posted and
/// stored) now requires `currency` as a code or `null` in place of a code
/// alone. An unpriced call gains the reason `unknown_currency`: rates with
/// a `null` currency that are not zero throughout, kept with their snapshot,
/// and no amount. Only a legacy pre-9534 stored copy of the installed
/// first-party model pack's row, which has always quoted US dollars, reads
/// a missing `currency` key as `USD`: its source rows name that pack (FIX
/// 11778 narrows the pack decode out; first-party bytes name their own
/// currency). It carries a build floor, at the engine revision it merged
/// in, with no `Ping` field: a reader or writer of catalog rows or usage
/// events runs at or after the floor, and no other missing-field default or
/// reader of a row without it is kept. This version stays 3.
///
/// Wire health check revisions (FIX 9531): each kept call-volume question is
/// a health check of its own on the owner's `/v1/owner/wire-health` read,
/// its `subject` the crossed set's digest and the question's sequence
/// (`wire:<digest>:<seq>`), with its own question and unit. An answered
/// check's `state.by` gains the value `cover`: the answer to an earlier
/// revision of the same crossed set that still covered it, whose `question`
/// and `unit` it cites, and it was not asked itself. It carries a build
/// floor, at the engine revision it merged in, with no `Ping` field: a reader
/// of the checks runs against an engine at or after the floor, and no reader
/// of a check without it is kept. This version stays 3.
///
/// Custom endpoint usage (FIX 7765): an unpriced call gains the reason
/// `custom_endpoint`, on usage events posted and stored: a call on the
/// owner's own key whose route goes to no provider API origin a catalog price
/// is quoted for, with a token count and no `costRates`. Such a call logs
/// token counts only, whatever price its model id has. It carries a build
/// floor, at the engine revision it merged in, with no `Ping` field: a reader
/// of usage events runs at or after the floor, and no reader of an event
/// without it is kept. This version stays 3.
///
/// Backup handoff readiness (FIX 6705): a managed vault's readiness on
/// `Ping` gains the facility `backup_handoff` and the reason
/// `install_failed`: its backup handoff policy could not be installed, so
/// its pruning past `keep` is held and every backup is kept; backups are
/// still taken and the vault serves. It carries a build floor, at the engine
/// revision it merged in, with no `Ping` field: a supervisor that reads the
/// readiness runs at or after the floor, and no reader of a readiness
/// without them is kept. This version stays 3.
///
/// Superseded wire health checks (FIX 10868): a check on the owner's
/// `/v1/owner/wire-health` read gains the state `superseded`, with `by`, the
/// subject of the later revision of the same crossed set that was held while
/// it was still held or asked, and `question` and `unit`, the ones it was
/// asked on or `null`. A superseded check is never asked or polled again;
/// the later revision is asked in its place. It carries a build floor, at the
/// engine revision it merged in, with no `Ping` field: a reader of the checks
/// runs against an engine at or after the floor, and no reader of a check
/// without it is kept. This version stays 3.
///
/// Checkpoint host-order holds and mode-root trust (FIX 6598, 6817, 968): a
/// restore input's `host_holds` requires `origin`, `live_source` or
/// `checkpoint_artifact` with the member's `snapshot_id`, `recipient_id`,
/// `recipient_epoch` and `member_blake3`; the plan takes an optional
/// `backup_mode_roots`, only on an artifact-backed wake or migrate; and a
/// receipt's `source` carries `mode_root_policy_digest` only where a
/// delegation from the vault's mode roots admitted the signer. They carry a
/// build floor, at the engine revision they merged in, with no `Ping`
/// field: a supervisor sends and reads them only with engines and vault VM
/// images at or after it, no reader without them is kept, the restore input
/// and receipt schemas stay 1, and this version stays 3.
///
/// A vault's deletion on `Ping` (FIX 11710,
/// [`PingDeletion`](crate::PingDeletion)): an optional `deletion`, present
/// once the vault's Owners deleted it, with `deleted_at` and
/// `backup_retain_until`. It carries a build floor, at the engine revision
/// it merged in, with no revision field: a vault built before it sends
/// none, so a supervisor reads an absent `deletion` as a standing vault
/// only from installed engines at or after the floor, and as unknown from
/// one before it. A block that does not read is unknown too, never a failed
/// `Ping`. This version stays 3.
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
