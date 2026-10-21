# Vault VM restore transport

A vault VM (`oneiron-server host vm`) can be cold-restored in its guest, and a
lost restore result can be settled from its disk (FIX 6584). This page is the
supervisor's contract: the image floor, the descriptors and who owns them, the
source drive, and the decision table for a lost result. The wire lives in
`oneiron_vault_contract::vm_restore`; the native restore it carries is
`oneiron_vault_contract::restore` and is unchanged.

## Image floor: check it before any secret

- The image manifest (`deploy/firecracker/build.py manifest`) carries a required
  `restore_wire_revision: 1`.
- Every cold boot of an image at or after the floor dials the restore channel,
  vsock port 1032, before its provision connection. That includes an ordinary
  open. So the host and the image must come from the same build.
- Before it prepares the VMM or hands over the fscrypt key or any credential,
  the supervisor checks three things: the manifest's `restore_wire_revision`,
  its artifact hashes, and that the image's `engine_revision` is at or after
  the merge floor.
- No older image is booted, and no reader of an image without the field is
  kept. `CONTRACT_VERSION` stays 3, and `Ping` has no field for this.

## The channel

The guest's root bootstrap dials 1032 and sends a hello (`revision`, `vault`).
The host answers with the boot's mode. Hello, mode and the inspection's reply
are each a control record: a big-endian u32 length, then that many bytes of one
JSON object. A control record is at most 256 KiB (`4 * MAX_CTL_LINE`).

| Mode | What the guest does |
|---|---|
| `open` | It boots as before the channel existed. |
| `restore` | It lays out the storage without `/vault/storage/data`, mounts the source drive when `source_device` is not `null`, and starts the engine. The engine gets `--restore --restore-input-fd R --restore-result-fd W --vm-restore-revision 1` on ordinary pipes. |
| `inspect_marker` | It provisions the disk and starts no engine, companion or listener. It reads the commit marker once and answers. |

During a restore, the stream records are `tag:u8, length:u32-be, payload`:

- Host to guest: `1` for an input chunk, `2` for the input's end.
- Guest to host: `3` for a result chunk, `4` for the result's end.
- A chunk carries 1 to 65536 bytes. An end record carries none.
- The input is exactly R's bytes and the result is exactly W's bytes. Nothing
  is parsed, rewritten or capped by total size.
- An end record tells the producer's EOF apart from a broken channel. The
  native `verified` or `failed` frame decides the outcome, not the end record.

## `host vm` modes and descriptors

The runner owns each descriptor that is passed to it. It refuses two flags
that name one descriptor, and it checks that each pipe is the correct end
before it reads anything.

| Mode | Flags | Order |
|---|---|---|
| Open (today) | `--listen`, `--credentials-fd C`, `--fscrypt-key-fd F` | Reads C, then F. The VM starts on the first connection or a due wake. |
| Restore | Open's flags plus `--restore --restore-input-fd R --restore-result-fd W` | See the restore order below. |
| Inspect | `--config`, `--vault-name`, `--fscrypt-key-fd F`, `--restore-marker-identity-fd Q`, `--restore-marker-result-fd S` (no `--listen`, `--credentials-fd` or `--restore`) | Reads F and Q, boots, writes one observation to S, stops the VM and exits. |

Restore order:

1. The runner reads F first. Write F before R, or while R is being written.
2. The runner starts the VM at once and streams R to the guest as it reads.
3. After R's EOF, the runner reads C. Write C after R, as for a native start.
4. While the restore runs, the runner drains W. It closes W after the result's
   end, or when the channel ends.
5. The runner binds `--listen` only after the restored vault is ready.

The descriptors:

- R is the read end of a pipe. It carries one `ManagedRestoreInput`, then EOF.
- W is the write end of a pipe. It takes the native result frames, one JSON line
  each.
- Q is the read end of a pipe. It carries one `ManagedRestoreIdentity` JSON
  object (at most 256 KiB), then EOF.
- S is the write end of a pipe. It takes one `VmRestoreMarkerObservation` JSON
  object, then EOF. When the inspection does not complete, S gets nothing and
  the process exits non-zero.

The library forms are `VaultVm::start_restore(VmRestoreHostIo, &key, timeout)`
and `VaultVm::inspect_restore_marker(&identity, &key, timeout)`. The first
returns C's frame once the vault is ready and W is drained. The second returns
the observation.

Timeouts:

- The boot timeout covers only the boot's own steps: the VMM API calls, the
  hello, the provision, the credential connection's accept, the join, and the
  inspection's reply.
- A restore has no deadline. A guest that ends closes the channel, and the
  runner sees that.

Loss:

- If R breaks before its end, the guest ends its engine before the engine can
  read an EOF. A truncated input is never handed over as complete.
- If W is lost after the input's end, only the observation is lost. The
  restore goes on, and what it kept stays kept.
- A failed restore stops the VM and lets the guest's last result records out
  within the stop's grace.

## Source drive (`restore_source_disk`)

- `restore_source_disk` is an optional key in the VM profile. It names a clean,
  read-only ext4 image that the supervisor stages.
- The image holds only the sealed artifact and its keyless custody head. It
  never holds a secret, an unsealed backup or a credential.
- The host attaches it only on a restore's boot, after the root, vault and
  config drives: `/dev/vdc` without a config drive, `/dev/vdd` with one.
- The guest mounts it at `/restore` with `ro,nosuid,nodev,noexec`, and unmounts
  it when the engine ends.
- Make its files readable by the vault's guest UID, and author the plan's
  `artifact` path under `/restore`.
- If the plan's sources are already readable inside the guest, no drive is
  needed.

Snapshots:

- Neither the restore nor the inspection ever takes a snapshot.
- A restore or an inspection is refused while a RAM snapshot is published.
  Resume that generation instead.
- A restored, serving generation sleeps and snapshots as usual. The exception
  is a generation whose boot attached the source drive: a sleep stops it
  instead. Firecracker reloads drives from their host paths when it loads a
  snapshot, and the staged source may be gone by then.

## Lost result: decision table

If the same restored guest is still serving, read ctl `restore_status` and
reassemble the receipt as for a native vault.

If it is not serving, follow these steps:

1. Confirm that every earlier generation is dead: its VMM and its runner.
2. Confirm that nothing else writes the disk and that no RAM snapshot is
   published.
3. Run the inspector.
4. Read the result from this table. `VmRestoreMarkerObservation::destination`
   computes the same mapping.

| Observation | Destination |
|---|---|
| `observed`, and `marker` names the attempt (`restore_id`, `plan_digest`, `attempt_id`, `generation`) | `committed_not_serving`: kept and not serving |
| `observed`, `data_present: false`, `marker: null` | `removed` |
| `observed` in any other case: data without a marker, or a marker for another attempt | `uncertain`: held |
| `unreadable` (`binding_mismatch`, `data_unreadable`, `marker_unreadable`, `frame_invalid`) | `uncertain`: held |
| The inspector failed, or S is empty | `uncertain`: held |

A marker means the restore was kept. It does not mean the vault served, and it
does not license an ordinary open. A missing marker never licenses an
overwrite.

## Not here yet

- **Custody anchor credentials.** A VM restore whose plan names an HTTP custody
  anchor gets no anchor credential until the anchor channel lands. It has the
  same outcome as a native start without one.
- **Supervisor-side work.** The VM launcher and its lifecycle adapter, source
  image staging and erase inventory, and each generation's ownership, kill and
  reconcile are the supervisor's.
