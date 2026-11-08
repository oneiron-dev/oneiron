# Shared owner-change wait

One scalar, `owner_change_wait_secs`, names the wait every ownership-membership
act starts with: adding an owner, removing an owner, or transferring
ownership. It lives in the vault's trusted default policy manifest as an
optional top-level MessagePack scalar (seconds). When the key is absent, every
start keeps its long-standing per-setting wait byte for byte.

## Setting and reading

- `Vault::set_owner_change_wait_days(owner, vault_id, days)` writes whole
  days. The caller revalidates as a person and must hold live Owner
  membership in the vault. `None` removes the key; `Some(0)` persists an
  explicit zero, which completes a stored owner act immediately: a holder
  keeps the stricter of its requested wait and the common, and an
  explicit host selection is unaffected. Days convert at exactly 86400
  seconds per day; a product that overflows `u64` is refused.
- `Vault::owner_change_wait_secs()` reads the resolved scalar from the
  current trusted manifest. A fail-closed resolution refuses instead of
  answering.

The write replaces the scalar on the current trusted default manifest body
and goes through the holder manifest writer, like the shared-act table
writes. No new table, no new restore class, no new role or co-approval: one
live Owner sets one number.

## Served doors

`vault.shared.owner_change_wait.set` lets one live Owner set whole days over
HTTP, MCP or the SDK and answers the effective wait in seconds;
`vault.shared.owner_change_wait.get` reads it for the owner. The scalar stays
store-global: the get takes no vault, and the set's vault only gates Owner
membership.

## Start-time precedence

The generic pending-act start resolves the scalar once and applies it after
unchanged policy validation, only for the three membership acts:

- Stored row: the start waits exactly the common, even when the vault holds
  a sole owner (no zero shortcut).
- Holder row: the start waits the stricter of the holder's requested wait
  and the common. The common is a floor here, never a new refusal: anything
  the holder row already admitted still starts.
- Explicit host selection (`Host(Some(..))` or `Host(None)`): the common
  is ignored. A generic stored start with no caller setting is NOT this:
  it takes the common exactly, per the stored row above.

Any other act kind, or an absent common, computes exactly the old wait.

## Conflicts and caching

Two trusted manifests naming different scalars fail the gate closed, the
same strict-equality rule as the shared-act table; two naming the same
scalar are one configuration stated twice. Decodes are cached under their
body's BLAKE3, so a rewritten (hence different-bytes) manifest always
decodes fresh with no invalidation hook.
