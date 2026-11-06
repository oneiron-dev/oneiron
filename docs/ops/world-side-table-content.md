# World-key side-table content

`world_keys` supplies `WorldSideRowBinding`, `seal_side_row`, `open_side_row`,
and `Vault::world_content_key_in_txn` for engine-owned side-table consumers.
These are crate-private composition APIs, not external verbs or new authority.

## Binding and transaction

The caller supplies its actual vault id, exact `WorldKeyId`, stable row-family
bytes, and canonical row associated data. Bind every field whose substitution
would change the row's meaning, including its native identity and revisions.
The binding is an expectation from the admitted row, not a copy of an untrusted
envelope's claims. An envelope header can select a retained key only after its
world is checked against the actual row; successful opening must still check
the complete expected binding.

Load `machine_secret_outside_txn` before entering the consumer's transaction.
In that same transaction, perform the consumer's native admission, choose the
key id, and call `world_content_key_in_txn`. For a new seal, choose the actual
fold's `current_world_key(world).id`. For an open, use the row's exact retained
id, not the current key. The getter checks the machine identity again, judges
its current world-read setting, and opens a non-conflicted counted wrap with
the exact pad in the caller's snapshot. It creates no transaction or ring cache.
Keep the caller's existing custody guards and transaction lifetime.

Seal and open both use the same row associated data. The envelope also binds
the vault, world/generation/mint, row family, crypto epoch and suite under
`Purpose::WorldSideRow` (29). It uses the existing symmetric-KEK envelope
HKDF/AEAD schedule. `WorldDek` (11) remains key wrapping; permanently reserved
`SealedWorldContent` (12) is not reused. Opening returns a zeroizing buffer.

Key possession is not row permission. Keep the consumer's actual machine,
world, purpose, consent, subject, space, deletion and revision checks. The
getter does not invent a live-WORLD or still-private gate: widening a world's
read setting must not strand content already sealed under one of its keys.
Neither pure seal/open function fetches a key or changes admission.

## Retained keys and erasure

Repin and holder reassertion rewrap the same key bytes and retain their ids.
Concurrent first-generation mints, or a later ensure after a signer loses
standing, can leave more than one retained id. The fold keeps those ids for
reading even when they are not current. Opening does not require the original
signer to remain standing; it does require a non-conflicted id, a counted
opening wrap, current machine-read admission, and its available pad.

The getter checks the world's destruction fact before opening. Native world
key destruction removes all of its pads; no old-id, current-key, data-key or
recovery-kit fallback is added. The key handle itself is short-lived secret
material; callers must not persist it or treat it as a permission receipt.

Base reality has no world key. A consumer's explicit native base case stays
separate; this API does not mint a base key or require base content to take a
private-world path. This is not a legacy reader or a migration.

## Voice recognition integration

Voice enrolment seals a private world's centroid and each complete sample
payload under the current counted world key selected in the same writer as
its source-world resolution and consent admission. Base reality is an explicit
unsealed variant. A non-base world with `EffectiveRead::Everywhere` uses a separate
unsealed variant that retains its actual world id. Neither needs a working machine
key or counted world key. The material writer rechecks the native Everywhere
predicate in that same transaction before accepting an unsealed world payload.
Private worlds still require their actual current counted key for enrollment.
The device secret is read before the transaction, never loaded inside the writer.

Stored print rows separate vector-free metadata from their material. Matching
checks the existing space, expiry, purpose, consent, subject and machine-world
admission before opening a centroid. A world's native key-destruction fact excludes
its prints in that same snapshot and again in the roster writer; a surviving
metadata row cannot abort matching other worlds' valid prints. Missing WORLD rows
or unexpected key/open/storage errors are not treated as destruction. Each open uses its stored exact retained
world key id in that snapshot, not a current-key retry. Key requirements follow
the stored material, not the presence of a world id: public unsealed rows need no
key, while a sealed row widened later still opens its exact retained key.
Privacy edits do not rewrite old rows. An already-public row remains decodable
when the world narrows; existing current machine-world admission still runs before
its material is read. No new migration, refusal or current-key gate is added. The actual native row
key is checked against its subject and active space before it supplies a
binding. The public admitted print record still carries its vector; the
node-local stored row has a new required layout with no old-format reader.

Associated data binds the native row family and key, world, subject, complete
embedding space and dimension, fresh print generation, enrolled purposes,
consent event, contact and relationship, legal evidence, sample membership and
languages, calibration and creation time. A sample also binds its actual
sample id. Only `updated_at` and `delete_after` remain native lifecycle fields
outside that immutable-material binding: ending a relationship must not need
to decrypt or reseal recognition bytes, including after world-key destruction.

Withdrawal, expiry pruning and subject/contact erasure read vector-free
metadata and remove the same exact print/sample rows and active pointer without
opening a vector or needing a surviving key. The existing retention wake,
consent replay and render-reference lifetimes are unchanged. Sealed payloads
are never substituted for base data, and neither path falls back to another
world or generation when an open fails.

No external surface, configuration, storage table, recovery power, policy limit
or migration is added. Normal engine rollout is sufficient; no deploy is
performed by this source change. Publishing the supplier alone did not seal a
consumer; the voice producer and readers are a separate integration.
