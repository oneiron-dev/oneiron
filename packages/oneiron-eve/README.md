# @oneiron/eve

An [eve](https://eve.dev) memory provider over the Oneiron Memory Wire
(RESEARCH-0363). It is **unpublished** (`"private": true`) until the owner
calls the vault usable (RESEARCH-0363 p2).

Built against eve `1.0.0-rc.18` (npm `eve`, Apache-2.0), whose provider is
phase-keyed: `recall["turn.started"]` and `capture["turn.completed"]`. The
package imports nothing from eve: `index.d.ts` mirrors eve's provider shapes,
and the factory returns a plain object that an eve slot takes.

```ts
import { defineMemory } from "eve/memory";
import { byPrincipal } from "eve/memory/scope";
import { HttpBaseClient, createSignedFetch } from "@oneiron/client";
import { oneironMemoryProvider } from "@oneiron/eve";

export default defineMemory({
  description: "What the caller's Oneiron vault remembers.",
  provider: oneironMemoryProvider({
    // The client bound to this eve partition: the end user's vault (p4), or
    // a credential narrowed to the world the deploy keeps for this scope
    // key (p3). Null disables the slot for that scope.
    connect: (scope) => {
      const credential = credentialFor(scope.key); // the deploy's own store
      return credential
        ? new HttpBaseClient({ baseUrl: process.env.ONEIRON_URL, fetch: createSignedFetch(credential) })
        : null;
    },
  }),
  scope: byPrincipal,
});
```

## What each phase does

- **Partition.** Every call goes through `connect(scope, slot)`, so each eve
  scope reads and writes only what its own credential reads and writes. If
  `connect` answers null, recall answers nothing and capture writes nothing.
  There is never a shared fallback pool. This is eve's "partition every
  read and write by `memory.scope.key`" rule, enforced by the credential
  rather than by putting the key into the query text.
  `recallScope(scope, slot)` can add a `vault.recall` scope (for example
  `{ world_ref }`).
- **Recall** (`turn.started`). This is `vault.recall` with the turn input's
  text as its query, `effort: "light"` and `limit` (default 8). It sends
  `operation_id` = `eve:` + sha256 of eve's `operationId`. A replayed handler
  then gets the same answer. A replay whose first answer changed since (a
  record was erased or retracted, or the read narrowed) gets
  `INVALID_STATE` and answers no memory. This needs the vault's
  `operation_id` on `vault.recall` (oneiron #7780). An older vault ignores
  the key and recalls afresh.
- **Keyed messages.** Each pack item becomes one message, with id
  `oneiron:<short name>` and content `<predicate>: <value_text>` for a
  claim, or the item's text otherwise. The id uses the short id's name
  without its `:hash` byte, which changes when the record's body changes,
  so an edit supersedes the same message.
- **Removal.** The provider remembers the ids it served to each eve
  session for each partition and slot (eve keeps recalled messages per
  session): at most 256 ids per session slot and 1,024 session slots, least
  recently used first out, in process memory. Missing from a later pack is
  not proof of removal, because recall answers its top items. So each
  missing id is checked, at most 16 per turn; an id that still holds goes
  to the back, so every served id is checked in turn:
  - a claim, through `vault.claims.history`, which answers the claim's
    whole supersession timeline: gone when the served claim's own version
    is not active (retracted or superseded) or is no longer in it;
  - another record, through `vault.get`: gone when it no longer reads;
  - either, when the answer is `NOT_FOUND`.

  A keyed eve message can be replaced but never removed, and eve refuses
  blank content (it fails the turn). So a confirmed-gone id is answered as
  `{ id, content: REMOVED_CONTENT }`, a short notice that replaces that
  message in the session's recalled messages. A pack item with no text is
  left out for the same reason. After eve's `clear()` on a session, a later
  removal can add one such notice that replaces nothing.
- **Capture** (`turn.completed`, on unless `capture: false`). This
  witnesses the settled turn with `vault.witness`: the turn input's user
  text, then the assistant text after the history's last user message
  (tool and reasoning parts are left out). The vault keeps one speaker per
  TURN, so each speaker is its own call. Both go into one conversation per
  scope and slot (a 32-hex id from the partition). The turn and message
  ids come from the operation id, so eve's replay of a capture sends the
  same ids again. In eve, a throwing `turn.completed` capture is logged and
  does not undo the turn. There is no `compaction.requested` capture: a
  throwing compaction capture fails the compaction, and every settled turn
  is already witnessed.
- **Recalled content is user data.** Item text is passed through as message
  content and never read as instructions by this package.

## Tests

```sh
bun test
```

The tests run against a fake Memory Wire server: a `Bun.serve` stub on
`POST /v1/core/facade/<verb>`, driven through the facade shape of
`@oneiron/client`'s `HttpBaseClient`. They need no vault, no native build
and no eve install.
