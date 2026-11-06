# Clipboard storage and Mac intake

The native Clipboard backend is available through `oneiron::clipboard`.
The Mac app supplies the watcher, private-copy routing, cleanup scheduling
and owner controls described below. Purpose questions have a native projection
and owner IPC, not a new visual layout or a separate Clipboard search consumer.
No OS capture or runtime proof is implied.

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
A concurrent first opener's nonzero revision is accepted without replaying
our defaults. Reopen preserves existing settings. Native profile, holder and key-work
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
an exclusive position and no upper count clamp. Zero requests no rows. Pages
show active, readable clips; cleanup and erasure also reach closed/retracted
or source-withdrawn clips whose stored text remains. Destructive selection and
its pre-scrub recheck validate the raw stored CLAIM's exact predicate, world
and subject; ordinary page reads retain the native visibility filter. The page
retains only its selected text. This owner API is not an agent grant
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
Malformed values in this family are warned about without logging their text
and skipped by paging/cleanup; clip/all erasure can still remove them without
parsing their text. Timestamp-range erasure selects only valid timestamps.

They do **not** claim measured free filesystem pages, immediate LMDB file
shrinkage, backup removal completion, sync delivery, or secret-custody-byte
reclamation. Host scheduling and a working low-disk observation remain
required before claiming automatic cleanup.

## Mac app intake and owner IPC

The Mac app registers one `root_rekey::clipboard` watcher after its embedded
vault state is managed. Startup reads only a pasteboard change-count baseline,
not the previous payload or a clipboard-history database. The worker polls
observed changes every 500 ms. This is observation-based capture, not a claim
that polling preserves copies replaced between observations. `copied_at` is
the host's observation time in seconds, not an OS-supplied copy timestamp.

All pasteboard calls run on the main thread. Types are classified before any
payload read. A changed count during classification/read discards and wipes
the result rather than trusting type evidence from an earlier copy. Only
wiping Rust buffers cross to the serial worker. A failed capture retries the
still-current copy; a private failure never falls back to ordinary intake.
Exit signals both the idle worker and a pending main-thread reply wait; it
does not join on the main thread or hold an owner lease across that wait.

Known confidential markers go through `private_copy::capture_private_copy`
to native private secret custody. The host generates a content-free
`private-copy-<fresh-id>` name and passes CustodyPortable, T0Doored, no effector
bindings and no manifest. The native private-copy flag, not the tier, prevents
model reveal. The returned handle is not copied into ordinary clip text.
Private viewing retains the separate Touch ID/Mac-password owner command and
its explicit authentication override.

The generic transient marker establishes neither producer nor secrecy. Its
initial routing policy is private custody, with an explicit owner override;
this is not a claim that every transient copy came from Enpass. Private-copy
`device_only` is a separate explicit input, initially false. It is not a
substitute for the Clipboard world's separate privacy/residence switch.

The owner IPC commands are:

- `clipboard_settings` and `set_clipboard_settings`: the native retention
  arms plus device-local capture settings `enabled` (initially true),
  `transient_as_private` (initially true) and `private_device_only`
  (initially false). Routing settings are one coherent device preference,
  sampled before each observed copy's payload. Changes apply to the next
  observation, not an already observed copy.
- `clipboard_entries`: the native owner page, with its exclusive position
  and full requested positive limit.
- `clipboard_erase`: the native clip/range/all hard-delete selection.

These commands use the existing owner-act mutex, a fresh writer lease and
the actual local owner. They do not add agent grants or a settings layout.
Every 60 seconds the same worker obtains Foundation's actual free-byte
observation for the vault's filesystem and attempts native cleanup. A failed
observation never becomes a fabricated free-space value. Native current-policy
checks and delete outcomes still govern the work; selected text bytes are
not measured disk reclamation.

This source does not supply a visual purpose-question layout, the separate
Cmd-K/related-clip consumer, default recall isolation or end-to-end
sync/key-release proof. The ordinary scanner still masks at the native CLAIM
door; no handle is guessed from text to pretend a purpose question exists.
No pasteboard, GUI, runtime, deployment or automatic-cleanup result is claimed
by this source description.

## Detected-secret purpose metadata

The ordinary capture caller keeps the actual native clip id and asks
`clipboard_secret_purpose_questions_as_owner` for its value-free questions.
The reader validates the exact Clipboard CLAIM family under one owner-checked
snapshot. It joins the existing found-key row and its actual mask origin;
private-copy custody, known-file references to a different origin, settled
keys and keys with a purpose answer do not become new Clipboard questions.
The native known-value index already substitutes the existing handle for
repeat text without filing another found-key note. No text is re-scanned or
parsed for a guessed `scN` handle.

After capture commits, the Mac caller sends nonempty metadata to the existing
main window as `clipboard-secret-purpose`. The writer lease and owner-act
mutex have ended before event delivery. A read or delivery failure does not
retry an already committed capture: the existing found-key inbox notice
remains durable, and `clipboard_secret_purpose_questions(clip)` can read the
derived questions again. No second question queue or notice producer exists.
The event carries no prompt prose or secret value; a visual client supplies
its own localized presentation. Event emission is not proof that a visual
client received or displayed it.

`set_secret_handle_purpose(handle, purpose)` uses the same owner-act mutex,
fresh lease and actual local owner as the other commands. The native setter
revalidates that owner in its writer. Purpose is a separate custody-keyed
attribute, not a display label, found-key disposition, grant, reveal or binding.
None or whitespace-only input clears it; other freeform text, including line
breaks, is preserved subject to the ordinary authored side-row secret wall.
There is no new single-line or byte cap. The reply returns actual stored,
possibly masked text, not a retained unmasked input copy. Native
`secret_handle_purpose(owner, handle)` reads this metadata with its receipt.

The new attribute is `Named Authored`, with a native masked-value decoder.
It does not inherit the label row's never-scan custody classification. Its
Gate receipt contains pointers and the set/clear action, never purpose text.
The row stores the Gate id as native bytes, not authored prose. It has its
own LIVE restore row and the existing Unclassified checkpoint payload class.
Holder erase, both run-bound cleanup paths and cloud-registration slot erase
revoke the attribute's own lifted side-row custody, then delete the attribute
in the same writer as the custody row. Clear uses that same native side-row
origin and revoke-before-delete path. Existing found-key history is not claimed
physically erased by that revoke. Rotation and revoke preserve
the stable custody-keyed attribute; the custody body and value codec do not
change.

This is source and interface coverage only. No native Mac compile, GUI,
clipboard observation, question delivery, authored-wall execution, checkpoint
restore or whole-vault erasure result is claimed here.
