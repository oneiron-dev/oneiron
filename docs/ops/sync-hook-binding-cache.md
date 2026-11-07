# Sync tombstones and the verb-hook binding cache

Sync entity imports and tombstone replay invalidate the verb-hook binding cache
after their durable store commit. Tombstone replay carries the original CLAIM
kind and its actual-change result from the same writer that applies the delete.

Observer B carries that flag through successful item savepoints to the parent's
durable-commit callback. Later post-commit errors cannot skip the invalidation.
Forward rematerialization publishes it after its chunk commit. Its
single-item fallback uses the native replay wrapper's own commit. Each committing
door invalidates once, before post-commit garbage collection can fail.

Aborted savepoints, failed parent commits, quarantined rows and no-op replays do
not invalidate the cache. The flag does not change deletion admission, hook
grants or the binding predicate. Restore and other raw-writer invalidation are
separate from these sync replay paths.
