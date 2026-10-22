# Vault VM restore transport

A vault VM (`oneiron-server host vm`) can be cold-restored in its guest, and a
lost restore result can be settled from its disk (FIX 6584). Its engine gets the
custody anchor door's owner credential and reaches the anchor URL through its
host (FIX 6517). Its guest can have one NIC for outbound IPv4 (FIX 6808), and
its engine takes the vault's managed profile from the config drive (FIX 6809).
This page is the supervisor's contract: the image floor, the descriptors and who
owns them, the source drive, the custody anchor channels, the guest network, the
managed profile, and the decision table for a lost result. The wire lives in
`oneiron_vault_contract::vm_restore` and `oneiron_vault_contract::vm_anchor`,
and the network's two views and the profile's files in
`oneiron_vault_contract::vm`; the native restore it carries is
`oneiron_vault_contract::restore` and is unchanged, and so is the native anchor
credential.

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
- The custody anchor channels (FIX 6517) add two required manifest fields,
  published together: `anchor_wire_revision: 1` and `anchor_proxy_revision: 1`.
  Every serving cold boot of an image at or after their floor dials the anchor
  exchange, vsock port 1031, after its provision connection. The floor is the
  engine commit that merged FIX 6517's VM half. The supervisor checks both
  revisions, with the hashes and that floor, before it prepares the VMM or
  hands over F, C or the anchor credential A.
- The guest network (FIX 6808) adds a required manifest field,
  `vm_network_revision: 1`. Its floor is the engine commit that merged FIX
  6808's engine half. An image before it sets up no NIC. The supervisor checks
  the revision, with the hashes and that floor, before it prepares a VMM whose
  profile plans a NIC or hands over F, C or A, and boots no image before the
  floor with a NIC planned.
- At that floor the profile's `network` key is required: `null` for a VM with
  no NIC. A host library before the floor refuses a profile that names
  `network`, and one at or after it refuses a profile without it, so profiles
  change with the host library.
- The managed profile (FIX 6809) adds a required manifest field,
  `vm_managed_profile_revision: 1`. Its floor is the engine commit that merged
  FIX 6809. An image before it ignores the profile's files, so its vault would
  start without its tenancy or its owner's choices. The supervisor checks the
  revision, with the hashes and that floor, before it stages any of the files,
  prepares the VMM or hands over F, C or A, and boots no image before the floor
  for a profile that needs one of them.
- The guest runtime (FIX 7671) adds two required manifest fields:
  `vm_guest_runtime_revision` (1 for an image that stages the guests' whole
  rootless runtime and both image archives, 0 for one built without) and
  `guest_runtime` (the image's descriptor, `null` exactly at 0). The
  supervisor writes `/config/browser-runtime` or `/config/desktop-runtime`
  only for an image at revision 1, each naming the descriptor's guest-local
  CLI, never a host path. The bootstrap prepares the runtime for the vault UID
  and passes the engine one `--guest-runtime-fact` on every serving boot; no
  fact stops the vault.
- The trusted organ builds file (FIX 7889) adds a required manifest field,
  `vm_trusted_organ_builds_revision: 1`, which the rootfs receipt carries into
  the manifest. Its floor is the engine commit that merged FIX 7889. An image
  before it ignores `/config/trusted-organ-builds`, so every pack organ build
  in its vault runs as third party. The supervisor checks the revision, with
  the hashes and that floor, before it stages a list, and counts a list
  applied only on an image at or after the floor.

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
| Inspect | `--config`, `--vault-name`, `--fscrypt-key-fd F`, `--restore-marker-identity-fd Q`, `--restore-marker-result-fd S` (no `--listen`, `--credentials-fd`, `--restore` or anchor flags) | Reads F and Q, boots, writes one observation to S, stops the VM and exits. |
| Anchor (with Open or Restore) | `--custody-anchor-url URL`, and optionally `--custody-anchor-credentials-fd A`, which needs the URL | Reads A once, after the first cold boot's C went to the guest. See the custody anchor channels below. |

Open and Restore give the engine the vault's managed profile the same way:
from the config drive's typed files (see the managed profile below), never from
a flag, pipe or descriptor of the runner's. An inspection reads none of them.

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

## Custody anchor channels (FIX 6517)

`--custody-anchor-url` is the anchor URL the vault's effective settings bind,
the restore plan's `custody` URL included, exactly as they spell it. It is not a
secret, but it is never logged. A is the read end of a pipe carrying the same
native credential a node's engine reads on `--custody-anchor-credentials-fd`:
one JSON object, then EOF. A needs the URL. Pass A only for the exact URL it was
issued for.

The exchange, vsock port 1031, once per serving cold boot (not an inspection):

1. After provisioning, the host sends the header: `revision`, `vault`,
   `anchor_url` (`null` when no URL was given) and `has_credentials`. The guest
   reads it before its engine starts.
2. After the engine's credential frame C, the host sends the payload: a
   big-endian u32 length, then exactly A's bytes, or a length of 0 when there
   is no A, then a half-close.
3. The guest answers `accepted` (with the URL's digest) or `refused` with a
   closed code. The host waits for that answer before the ready byte.
   `accepted` means the bytes crossed. It does not mean the vault is ready or
   that its anchor answered.

The order is R, then C, then A, as for a native start. The header and its
answer are at most 64 KiB (`MAX_CTL_LINE`), and so is A in a VM; a node's A has
no bound. The host reads A once, holds it in memory (wiped when dropped), and
sends it again after each later cold boot's C. A RAM snapshot holds the guest's
copy, as it holds the data key; a resume runs no second exchange. A is never
written to the profile, the boot arguments, a drive, the outbox or a log.

The proxy, vsock port 1033: the guest bootstrap serves
`/run/oneiron/custody-anchor.sock` (the vault UID's, mode 0600) when a URL was
given. Each stream on it says a hello naming the URL by its BLAKE3 digest. The
host checks the hello against the boot, dials the URL's host and port (its only
destination, which may be the host's own 127.0.0.1 relay) and carries bytes
both ways. It adds no credential and reads nothing. The engine's anchor client
takes this socket only when its configured base URL is byte for byte the bound
URL; the URL, its TLS and its host checks are unchanged. The proxy runs with
each VMM generation and ends with its exit, a stop or a kill, along with every
stream it carries. A RAM resume starts it again for the same URL.

| Case | Outcome |
|---|---|
| No URL and no A | As before: the anchor is unset, or pending when the settings name a URL. |
| URL, no A | The anchor stays `custody_anchor_pending`. |
| URL and A, and the vault's effective URL is the same string | The engine reads A with the native reader and calls the door through the proxy. |
| A, and the vault's effective URL differs | The start is refused (`custody anchor credentials fd rejected`), as for a malformed native A. No byte of A is read. |
| A malformed header, a short payload, bytes after it, or a wrong vault | The boot is refused. If A was announced, the guest ends its engine before the engine can read an EOF. |
| The proxy cannot reach the URL's host and port | The call fails as unreachable, and the anchor stays pending. The vault still starts. |

## Source drive (`restore_source_disk`)

- `restore_source_disk` is an optional key in the VM profile. It names a clean,
  read-only ext4 image that the supervisor stages.
- The image holds only the sealed artifact and its keyless custody head. It
  never holds a secret, an unsealed backup or a credential.
- The host attaches it only on a restore's boot, after the root, vault and
  config drives: `/dev/vdc` without a config drive, `/dev/vdd` with one. A
  profile with a `network` always has a config drive, so its source drive is
  `/dev/vdd`.
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
- A generation with a NIC sleeps and snapshots as usual. Loading the snapshot
  opens the same TAP by its name again, and a resume runs no second network
  setup in the guest. So keep the TAP, its MAC, its rules and the config drive
  as they are while a snapshot is published. A changed network plan needs a
  cold boot: drop the published snapshot first.

## Guest network (FIX 6808)

A vault VM can have one NIC, for the guest's outbound IPv4: mesh relays and
peers, model endpoints, connector endpoints. It adds no public ingress, port
forward, bridge or listener. Every host surface (HTTP, ctl, the ledger,
artifacts, voice, the outbox, restore and the anchor channels) stays on vsock.

The supervisor owns the host side, and the engine owns none of it:

- One TAP per vault, made, up and given its gateway address before the VMM
  starts, and openable by the VMM's identity.
- IPv4 forwarding from that TAP only out of the operator's egress interface,
  masquerade there, and only established or related traffic back. Drop new,
  invalid and other inbound forwarding to the TAP, the host's own new
  connections to the guest, traffic between TAPs, and all IPv6 on the TAP.
- Every name and address: the TAP's name, the MAC, the guest's address and
  prefix, the gateway and the nameservers. The engine has no default for any
  of them, and it never runs `ip` or `nft` or changes a host sysctl.

The supervisor writes one plan as two views, under the lock it builds the
config drive with. The MAC is the same string in both.

- The VM profile's `network` (`vm::VmTapAttachment`), or `null`:

  ```json
  {"tap_name": "ovm61000", "guest_mac": "02:00:00:00:ee:48"}
  ```

- The config drive's `network.json`, the guest's `/config/network.json`
  (`vm::VM_GUEST_NETWORK_FILE`, `vm::VmGuestNetworkConfig`), one JSON object of
  exactly these keys:

  ```json
  {"guest_mac":"02:00:00:00:00:01","guest_ipv4":"10.247.0.2","prefix_len":30,"gateway":"10.247.0.1","dns_servers":[]}
  ```

  The values are examples. An empty `dns_servers` gives the guest no resolver,
  so plan DNS before anything the vault reaches by name. Ordinary JSON
  whitespace is fine; an unknown, repeated or missing key, a wrong type or
  bytes after the object refuse the boot. The file is at most 16384 bytes
  (`vm::MAX_VM_CONFIG_FILE_BYTES`).

Both views are checked by the contract's `validate`:

- The MAC is six two-digit hex octets in either case, joined by `:`, unicast
  and not all zero.
- The TAP name is 1 to 15 bytes of printable ASCII, with no `/` or `:`, and
  neither `.` nor `..`.
- The prefix length is 1 to 31. The guest address and the gateway are unicast
  (not `0.0.0.0`, broadcast, multicast or loopback), differ, share the prefix,
  and below a /31 are neither its network nor its broadcast address.
- Each nameserver is unicast and not loopback: the guest's loopback has no
  resolver.

On the host, `VaultVm::prepare` refuses a `network` not in its form, or one
without a `config_disk`, before anything is made. Every boot (an open, a
restore and an inspection) then sends `PUT /network-interfaces/vault-egress`
with `{"iface_id": "vault-egress", "host_dev_name": <tap_name>, "guest_mac":
<guest_mac>}` after the vsock device and before `InstanceStart`.

In the guest, the image's init passes `oneiron-vm-init --guest-config-dir
/config` once the config drive is mounted. On a boot that serves, not an
inspection, the bootstrap reads `network.json` whole, then, still root and
before the vault's key goes in or any engine or companion starts:

1. It finds the one link whose MAC is the plan's. None, or more than one,
   refuses the boot.
2. It turns IPv6 off on that link, then brings loopback and the link up.
3. It gives the link the plan's address and prefix, and adds the default route
   through the gateway. The kernel's answer to each step is checked.
4. With nameservers, it writes them to `/run/oneiron-net/resolv.conf` and
   bind-mounts that over the image's empty `/etc/resolv.conf`.

A `network.json` that is not there means no NIC setup: an attached NIC stays
down. One that cannot be read, is not a regular file, is over its bound or is
malformed, or a step that fails, refuses the provisioning as `provision_failed`
with the step named (link, address, route or DNS). Readiness means the guest
set up what it was told. It does not prove that the operator's egress, DNS,
relays or providers answer.

A NIC does not replace the custody anchor proxy. The host's loopback is not the
guest's, so an anchor URL on the host's `127.0.0.1` relay still goes through
1033.

## Managed profile (FIX 6809)

A vault VM's engine takes the same managed-profile flags a supervisor passes a
node's child. In a VM they come from five typed files on the config drive,
which the guest's bootstrap reads itself. There is no generic argument file and
no shell parser.

| File (`vm::` constant) | Body | The engine gets |
|---|---|---|
| `/config/organization-owner` (`VM_GUEST_ORGANIZATION_OWNER_FILE`) | Exactly 64 hex digits, in either case | `--organization-owner <id>`, as written |
| `/config/member-vault` (`VM_GUEST_MEMBER_VAULT_FILE`) | `true` or `false` | `true`: a bare `--member-vault`. `false`: no flag, the engine's own false |
| `/config/failure-signal-export` (`VM_GUEST_FAILURE_SIGNAL_EXPORT_FILE`) | `true` or `false` | `--failure-signal-export true` or `--failure-signal-export false` |
| `/config/failure-signal-training` (`VM_GUEST_FAILURE_SIGNAL_TRAINING_FILE`) | `true` or `false`, apart from the export file | `--failure-signal-training true` or `--failure-signal-training false` |
| `/config/fast-dims` (`VM_GUEST_FAST_DIMS_FILE`) | Decimal digits: a nonzero width a u16 holds | `--fast-dims <width>` |

- Each body is the whole value, with at most one final LF: no space, CR, sign,
  prefix, comment or second line. Write the hex in lowercase and end each file
  with one LF.
- A file that is not there gives no flag, so the engine's own default stands.
  It is never read as `false`. Write both failure-signal files from the owner's
  explicit choices, `false` included.
- A file that is there but empty, unreadable, not a regular file, over 16384
  bytes or not in its form refuses the provisioning as `provision_failed`. The
  refusal names the file, never its bytes.
- On each boot that serves (an open or a restore, not an inspection) the
  bootstrap reads all five with `network.json`, before the vault's key goes in.
  An open's engine and a restore's engine get the same flags.
- The engine checks the values as it does on a node: `--member-vault` needs
  `--organization-owner`, a shared vault's organization is its derivation
  owner, and the width is below the vault's effective dimensions.
- The image's init passes none of these flags itself.

The supervisor publishes the profile as one set. Under the lock it builds the
config drive with, it writes the files for the profile it publishes, removes
the ones whose values became absent, and builds the one drive that an open and
a restore both boot with. A RAM resume reads no file again, so a changed
profile takes effect at the next cold boot: drop a published snapshot first.

## Trusted organ builds (FIX 7889)

A vault VM's engine takes `--trusted-organ-build` as a node's serve does. In a
VM the operator's list is `/config/trusted-organ-builds`
(`VM_GUEST_TRUSTED_ORGAN_BUILDS_FILE`) on the config drive: one organ build's
blake3, 64 hex digits, per line. The image's init passes each line, as written,
to the engine as its own `--trusted-organ-build`. The drive carries the flag;
it is not another source, and nothing a pack carries adds to the list.

- No file, or an empty one, lists none: every pack organ build runs as third
  party, as on a node without the flag.
- Blank lines pass nothing. A last line without a final LF still counts.
- A line the flag refuses (not exactly 64 hex digits, or with a space or a CR)
  refuses the boot, as the flag does on a node.

To build the drive offline, put the list in the operator's tree beside the
other config files and run `deploy/firecracker/build.py config-disk
--source-dir <tree> --size-mib <size> --output <new directory>`. It writes a
fresh read-only `config.ext4` with the tree's files at its root, and a receipt
with its SHA256. Give that image as the VM profile's `config_disk`. It never
writes to a drive a VM has attached.

Publish the list with the profile, under the same config-drive lock: write the
list the operator holds now, drop the entries they removed, and build the one
drive an open and a restore both boot with. A RAM resume reads no file again,
so a changed list takes effect at the next cold boot: drop a published snapshot
first.

## RAM snapshot custody (FIX 9497)

A sleep's RAM snapshot holds the guest's fscrypt key and decrypted vault
pages, so it is written only to protected backing, from its first byte:

- With the profile's `snapshot_custody` (`{"socket": ..., "dir": ...}`), only
  into `dir`. Before any snapshot file is written or looked for, `host vm`
  sends the custody socket `{"op":"unlock","vault":"<name>"}` and checks that
  `dir` is an fscrypt v2 directory whose key is present. It holds the unlock
  while the VMM may write or map the files, and once that VMM is reaped it
  sends `{"op":"evict","vault":"<name>"}` and checks that the key is gone. A
  dropped driver's reaper thread evicts only after its own reap. The answer
  is one line, `{"ok":true,"error":null}` or `{"ok":false,"error":"<why>"}`.
- With `snapshot_custody: null`, only into a state directory that is already
  protected: RAM-backed (tmpfs or ramfs) or an fscrypt v2 directory whose key
  is present.
- Otherwise the snapshot is withheld and the vault stops, as an off-record
  sleep does, with the log line `snapshot withheld: the state dir is
  unprotected, and bound snapshot custody would allow it`.

A start, a cold restore and an inspection unlock a bound custody before they
look for a snapshot. One whose custody does not unlock refuses with
`VmSnapshotCustodyUnavailable`, boots nothing and keeps the snapshot; start it
again once the custody answers. The supervisor supplies the custody: a
per-vault encrypted directory, the key held outside `host vm`, unlock and
evict bound to the vault, and an eviction that really removes the key. `host
vm` never holds the key.

## Wake ledger pages (FIX 9549, FIX 9498)

The guest's wake ledger report reaches the host whole, in pages of at most
`MAX_LEDGER_PAGE_ENTRIES`: a push sends a report's pages in order on one
ledger connection, and a sleep reads the report its freeze holds with
`ledger_page` and releases it with `ledger_pulled`, before any snapshot or
stop. `host vm` commits a report only once every page is in and its digest
checks, durably, and answers the last page `committed`. Each ledger
connection is a task of its own, at most 8 at once; a silent one never holds
up the runner. Each window fires at one second inside it, chosen once for the
vault, alarm and window and kept with the report, so vaults sharing a window
spread across it; a sleep returns that second as the next wake.

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

- **Owner anchor credentials.** Which URLs get A, and the owner's own anchor
  credentials (FIX 6707), stay the supervisor's choice.
- **Supervisor-side work.** The VM launcher and its lifecycle adapter, source
  image staging and erase inventory, and each generation's ownership, kill and
  reconcile are the supervisor's.
- **Host network.** The TAP, its rules, DNS sourcing, operator relays and the
  network's activation are the supervisor's (FIX 6808's host half).
- **Profile publication.** Writing and removing the five profile files under
  the config drive's lock, building the drive an open and a restore share, and
  holding back a profile until the image's revision and floor check out are the
  supervisor's (FIX 6809's LC half, FIX 7081).
- **Trusted organ builds publication.** Writing the operator's list under the
  config drive's lock, building the drive (`config-disk` or the supervisor's
  own builder) and picking an image whose manifest names
  `vm_trusted_organ_builds_revision: 1` are the supervisor's (FIX 7889's host
  half). `host vm` takes paths, not a manifest, so no host check reads the
  revision.
