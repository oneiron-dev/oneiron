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

## Integration still required

FIX10786 is the supplier slice of FIX10215. Voice centroid/sample encoding,
actual enrolment and matching integration remain in the voice lane. Their
associated data must bind the actual row family/key, world, subject, complete
space/dimension, fresh enrolment generation, enrolled purpose set and consent
event; sample rows must also bind the actual sample id. Base behavior and all
existing consent-withdrawal, expiry, prune and subject/relationship deletion
paths must survive that integration. Publishing these helpers alone does not
seal any existing consumer or complete FIX10215.

No new external surface, configuration, storage table, recovery power, policy
limit, migration or deploy action is introduced by the supplier alone.
