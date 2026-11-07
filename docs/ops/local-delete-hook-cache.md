# Local deletion and the verb-hook binding cache

Verb hooks cache enabled Pre/Post pack bindings. A binding is a live
`agent.connector_subscription` CLAIM with binding version 2. Its body disappearing
must be visible to the binding cache without waiting for its existing age limit.

`Vault::notify_local_delete_materialized` invalidates the vault's existing
verb-hook binding generation when the committed ID list is non-empty. This is
coarse invalidation: deletion of a non-binding row may also cause the next lookup
to reload. It does not decode a deleted body, read authority, change a grant,
or add a transaction.

The helper is an **after-commit** notification. Local soft deletion calls it after
its scrub transaction commits, before the later tombstone publication. A later
publication error does not undo that scrub or suppress cache invalidation. The
hard-delete and headerless paths also call it after their destructive transaction
commits. An aborted transaction never reaches this helper.

The notification applies with or without the `sync` feature. It does not cancel
an invocation that already selected a binding. Existing binding filters, grants,
receipts, deletion results, timers, and the cache's age fallback are unchanged.
Sync replay, archive import, and recovery have their own commit owners; this
local-delete notification is not a claim that those paths notify the cache.
