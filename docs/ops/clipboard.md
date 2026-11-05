# Clipboard native storage doors

The native Clipboard backend is available through `oneiron::clipboard`.
The macOS watcher, private-copy routing, quiet secret-purpose questions,
cleanup scheduling, owner controls and separate Clipboard search consumer are
not implemented by this backend alone. No OS capture or runtime proof is implied.

## Identity and ordinary text

`clipboard_world_id()` selects a fixed engine role in each isolated vault.
It derives from `oneiron.clipboard.world.v1` with the existing Files-world
counter/range rule, excludes base reality, and needs no authority-genesis
fallback. Imported worlds retain the existing source-vault-bound foreign
mapping. The WORLD row carries `system_role: clipboard`; neither the display
name nor a local-only binding adopts another world. A conflicting row is not
rewritten.

`Vault::open_clipboard_world(owner, surface)` revalidates the actual owner in
its writer. Before any clip payload, the existing native world-privacy door
sets an unconfigured world to `MyMachines` plaintext reads,
`CloudAndMyMachines` sealed copies and `Inherit` model order. It supplies the
observed zero revision, so a concurrent owner choice is not overwritten.
Reopen preserves existing settings. Native profile, holder and key-work
outcomes are not replaced with a fabricated profile or an `Everywhere`
plaintext fallback. This is not end-to-end sync/key-release runtime proof.

`capture_clipboard_text_as_owner` is **ordinary-text-only**. The host must
classify pasteboard types before reading or passing text. Marked private
copies go directly to the separate private-copy secret-custody door; errors
must never send them here. The backend writes each ordinary copy as its own
`clipboard.captured` CLAIM, with its world and subject both naming the
Clipboard role. Its value is `{text, copied_at}`. The ordinary CLAIM batch
door scans and masks detected secrets before storage/indexing. No raw text
ASSET/entity bypass is used. Repeated equal copies are separate records.

`clipboard_entries_as_owner(owner, before, limit)` revalidates before reading
one snapshot. It returns masked text, newest `(copied_at, clip)` first, with
an exclusive position and no upper count clamp. Zero requests no rows. It
retains only the selected page's text. This owner API is not an agent grant
or proof that ordinary recall excludes the Clipboard world.

## Retention and erasure

`ClipboardRetention` has three arms:

- `max_text_bytes: None` disables the size arm.
- `low_disk: true` enables low-disk cleanup initially.
- `older_than_days: None` disables the age arm.

`Some(0)` is an actual selected size/age, not disabled. The one low-disk
threshold is `CLIPBOARD_LOW_DISK_FREE_BYTES` (5 GiB). The host supplies a real
free-space observation for the vault's filesystem. Cleanup first selects
old clips by age, then oldest remaining clips until selected masked-text
bytes cover the larger of size excess and measured free-space deficit.
It invokes the existing `PolicyDelete` hard tier, not shell-only hiding.
A current-policy or owner change before publication cancels old-policy work.
Legal holds, native deletion receipts, dependent work and historical sweep
behavior remain those of the existing deletion door.

`erase_clipboard_as_owner` supports one clip, a half-open timestamp range
`[from, before)`, or all ordinary clips. It uses the native user hard-delete
path with owner revalidation and a same-clip pre-scrub check. Erasing the
world empties its text records and keeps the empty role's WORLD metadata.
Private-copy custody is not joined or erased by these ordinary-text APIs.

Reports name completed native deletions and selected masked-text bytes.
They do **not** claim measured free filesystem pages, immediate LMDB file
shrinkage, backup removal completion, sync delivery, or secret-custody-byte
reclamation. Host scheduling and a working low-disk observation remain
required before claiming automatic cleanup.
