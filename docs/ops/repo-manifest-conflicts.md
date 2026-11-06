# Repo manifest conflicts: review one, discard its carried copy

One window can carry a manifest under a portable id while this vault holds
another copy under the same id with another CODE entity or another
`minted_at`. The merge keeps the held copy and leaves the carried copy aside
in the window. This door reviews that exact durable state and, on an explicit
owner call, drops the carried head plus the parts only it lists.

Native API, in `crate::sync::window`:

- `review_repo_manifest_conflict(vault, key, portable)` reads the window's
  durable snapshot plus every pending update, a window with only pending
  updates included, with the raw held manifest and both CODE anchors live in
  the same read transaction. It opens no live window and scans no vault.
  `Some` means present, canonical, joined and map-key, head and manifest
  bound with a CODE or `minted_at` mismatch. `None` means missing, pending,
  unbound or non-conflicting. The review names durable state only, never the
  current contents of a live window.
- `discard_reviewed_repo_manifest_carrier_as(vault, owner, review)` keeps the
  held copy. It runs only while the exact reviewed window is closed. A live
  window answers `WindowLive` with nothing written and nothing unloaded;
  retry after the window unloads through the existing lifecycle, such as
  `WindowManager::unload_window`. Inside one grouped write it revalidates the
  owner first, rebuilds the latest durable document plus every pending update
  in that same writer, then compares the semantic version vector, the exact
  raw held and carried copies, the current binding and the same CODE liveness.
  Any mismatch answers `Stale` with no write.

On a match the bare local document alone drops exactly this portable head
plus the part rows it lists that no remaining valid head lists, committing
detached with the bridge origin. Unrelated pending parts, every other head,
aliases, CODE rows, manifests, minted markers, by-CODE rows and refs stay
untouched. The snapshot pair persists, exactly the imported update keys prune
atomically and the freshness byte writes last. No observed or live document
ever changes.

`Discarded { update }` returns the raw ordinary window delta since the
reviewed vector, only after the commit. The caller owns it and routes it
through an existing admitted sync channel such as the durable `SyncQueue`.
Nothing here queues, delivers, resolves globally or erases physical history,
and no outbox or ledger is added. The action adopts no identity and never
unloads a window itself.
