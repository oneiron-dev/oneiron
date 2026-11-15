// An eve memory provider over the Oneiron Memory Wire (RESEARCH-0363).
// Every effect is a facade call on a client the host binds to one eve
// partition; this package opens nothing and holds no credential itself.
import { createHash } from "node:crypto";

/** Items one recall asks for. */
export const RECALL_LIMIT_DEFAULT = 8;
/** Previously served ids checked for removal on one turn. */
export const REMOVAL_CHECKS_PER_TURN = 16;
/**
 * Served ids remembered per session, partition and slot; the least recently
 * served or checked go first.
 */
export const SERVED_IDS_PER_SLOT = 256;
/**
 * Session, partition and slot triples whose served ids one provider
 * remembers; the least recently recalled go first.
 */
export const TRACKED_SESSION_SLOTS = 1024;
/**
 * The content that replaces a served message once the vault confirms its
 * record gone. eve refuses blank recall content, and a keyed message can
 * only be replaced, never removed.
 */
export const REMOVED_CONTENT = "(This memory was retracted, replaced or removed, and no longer holds.)";

const MESSAGE_ID_PREFIX = "oneiron:";

/**
 * The provider object an eve slot takes:
 * `defineMemory({ provider: oneironMemoryProvider({ connect }), scope })`.
 * `connect(scope, slot)` answers the client bound to that partition (an
 * `@oneiron/client` `HttpBaseClient` whose credential reads the end user's
 * vault, or a world the deploy keeps for that scope key), or null, which
 * disables the slot for that scope: recall answers nothing and capture
 * writes nothing, never a shared pool.
 */
export function oneironMemoryProvider(options) {
  if (typeof options?.connect !== "function") {
    throw new TypeError("oneironMemoryProvider needs connect(scope, slot)");
  }
  const connect = options.connect;
  const recallScope = options.recallScope ?? (() => undefined);
  const limit = options.limit ?? RECALL_LIMIT_DEFAULT;
  const capture = options.capture ?? true;
  const served = new Map();

  const provider = {
    recall: {
      "turn.started": async (context) => {
        const { scope, slot } = context.memory;
        const client = await connect(scope, slot);
        if (!client) {
          return null;
        }
        const query = messagesText(context.turn.input, "user");
        if (query === "") {
          return null;
        }
        const request = {
          query,
          effort: "light",
          limit,
          operation_id: recallOperationId(context.operationId),
        };
        const narrowed = await recallScope(scope, slot);
        if (narrowed) {
          request.scope = narrowed;
        }
        const answer = await facadeJson(
          client.facade.vault.recall(request, { signal: context.abortSignal }),
        );
        if (answer.error?.code === "INVALID_STATE") {
          // A replay of this operation whose first answer changed since (a
          // record erased or retracted, or the read narrowed): no old
          // answer is served, and nothing new either.
          return null;
        }
        if (!answer.ok) {
          throw wireError("vault.recall", answer);
        }
        const seen = servedFor(served, context.session?.id ?? "", scope, slot);
        const messages = [];
        const now = new Set();
        for (const item of answer.body?.items ?? []) {
          const id = messageId(item);
          const content = itemContent(item);
          // eve refuses a blank message and fails the whole turn on it.
          if (id === null || now.has(id) || content.trim() === "") {
            continue;
          }
          now.add(id);
          messages.push({ id, content });
          seen.delete(id);
          seen.set(id, { ref: item.record?.id ?? item.short_id, kind: item.kind });
        }
        messages.unshift(...(await removedMessages(client, seen, now, context.abortSignal)));
        while (seen.size > SERVED_IDS_PER_SLOT) {
          seen.delete(seen.keys().next().value);
        }
        return messages.length === 0 ? null : { messages };
      },
    },
  };
  if (capture) {
    provider.capture = {
      "turn.completed": async (context) => {
        const { scope, slot } = context.memory;
        const client = await connect(scope, slot);
        if (!client) {
          return;
        }
        await witnessTurn(client, context);
      },
    };
  }
  return provider;
}

/**
 * The operation id a recall sends for eve's `operationId`: eve's id is
 * stable per session, turn, step, phase and slot, and its hash fits the
 * engine's alphabet and 128-character cap.
 */
export function recallOperationId(operationId) {
  return `eve:${sha256Hex(operationId)}`;
}

/**
 * The keyed message id of one pack item: the item's bare short name. A
 * short id's `:hash` byte changes when the record's body changes, so the
 * name alone keeps one record under one message id across edits.
 */
export function messageId(item) {
  const name = shortName(item.short_id);
  if (name !== "") {
    return MESSAGE_ID_PREFIX + name;
  }
  return item.record?.id ? MESSAGE_ID_PREFIX + item.record.id : null;
}

/** The text one keyed message carries for an item. */
export function itemContent(item) {
  const text = item.value_text ?? "";
  return item.predicate ? `${item.predicate}: ${text}` : text;
}

/**
 * The 32-hex conversation an eve partition and slot witness into: one
 * conversation per scope and slot, the same one every turn.
 */
export function conversationRef(scope, slot) {
  return sha256Hex(
    ["oneiron-eve:v1:conversation", scope.namespace, scope.key, JSON.stringify(scope.value), slot].join("\0"),
  ).slice(0, 32);
}

/**
 * Keyed removal notices for the ids served before that this turn's pack
 * left out and the vault confirms gone: a claim whose own version is not
 * active (retracted or superseded), a record that no longer reads (it was
 * erased, or this read narrowed past it). An id that is only outside this
 * turn's top items stays as it is, and goes to the back of the checks, so
 * every served id is checked in turn. A check that throws fails the turn
 * before any removal is recorded, so the next turn checks again.
 */
async function removedMessages(client, seen, now, signal) {
  const checked = [];
  for (const [id, record] of [...seen]) {
    if (now.has(id)) {
      continue;
    }
    if (checked.length >= REMOVAL_CHECKS_PER_TURN) {
      break;
    }
    checked.push({ id, record, gone: await recordGone(client, record, signal) });
  }
  const removed = [];
  for (const { id, record, gone } of checked) {
    seen.delete(id);
    if (gone) {
      removed.push({ id, content: REMOVED_CONTENT });
    } else {
      seen.set(id, record);
    }
  }
  return removed;
}

async function recordGone(client, record, signal) {
  if (!record.ref) {
    return false;
  }
  if (record.kind === "CLAIM") {
    const answer = await facadeJson(
      client.facade.vault.claims.history({ claim_ref: record.ref }, { signal }),
    );
    if (notFound(answer)) {
      return true;
    }
    if (!answer.ok) {
      return false;
    }
    // The history is the claim's whole supersession timeline, oldest first:
    // the served claim's own version decides, not the chain's newest. No
    // own version means the served claim no longer reads.
    const name = shortName(record.ref);
    const own = (answer.body?.value ?? []).find(
      (version) => version.claim_ref === record.ref || shortName(version.short_ref) === name,
    );
    return own === undefined || own.lifecycle !== "active";
  }
  const answer = await facadeJson(
    client.facade.vault.get({ entity_ref: record.ref }, { signal }),
  );
  if (notFound(answer)) {
    return true;
  }
  return answer.ok && (answer.body?.value ?? null) === null;
}

/**
 * Witnesses a settled turn: the turn's user input, then the assistant text
 * that answered it. The engine keeps one speaker per TURN, so each speaker
 * run is its own witness call. Ids derive from the operation id, so eve's
 * replay of this capture sends the same turns and messages again.
 */
async function witnessTurn(client, context) {
  const { scope, slot } = context.memory;
  const runs = [
    { author: "user", text: messagesText(context.turn.input, "user") },
    { author: "companion", text: messagesText(trailingAssistant(context.messages), "assistant") },
  ];
  const conversation = conversationRef(scope, slot);
  const occurredAt = Math.floor(Date.now() / 1000);
  for (const [index, run] of runs.entries()) {
    if (run.text === "") {
      continue;
    }
    const seed = `${context.operationId}\0${index}`;
    const answer = await facadeJson(
      client.facade.vault.witness(
        {
          conversation_ref: conversation,
          turn_ref: sha256Hex(`oneiron-eve:v1:turn\0${seed}`).slice(0, 32),
          occurred_at: occurredAt,
          messages: [
            {
              id: sha256Hex(`oneiron-eve:v1:message\0${seed}`).slice(0, 32),
              author: run.author,
              message_type: "dialogue",
              content: run.text,
              is_visible: true,
              order: 0,
            },
          ],
        },
        { signal: context.abortSignal },
      ),
    );
    if (!answer.ok) {
      throw wireError("vault.witness", answer);
    }
  }
}

/** The assistant messages after the history's last user message. */
function trailingAssistant(messages) {
  const tail = [];
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    if (messages[index].role === "user") {
      break;
    }
    tail.unshift(messages[index]);
  }
  return tail;
}

/** The text parts of the `role` messages, one per line. */
function messagesText(messages, role) {
  const lines = [];
  for (const message of messages ?? []) {
    if (message.role !== role) {
      continue;
    }
    if (typeof message.content === "string") {
      lines.push(message.content);
      continue;
    }
    for (const part of message.content ?? []) {
      if (part.type === "text") {
        lines.push(part.text);
      }
    }
  }
  return lines.map((line) => line.trim()).filter((line) => line !== "").join("\n");
}

/**
 * The ids served to one eve session for one partition and slot. Each
 * session keeps its own recalled messages, so each tracks its own removals.
 */
function servedFor(served, sessionId, scope, slot) {
  const key = `${sessionId}\0${conversationRef(scope, slot)}`;
  const seen = served.get(key) ?? new Map();
  served.delete(key);
  served.set(key, seen);
  while (served.size > TRACKED_SESSION_SLOTS) {
    served.delete(served.keys().next().value);
  }
  return seen;
}

/** A short id's name, without its `:hash` byte or `@` revision pin. */
function shortName(ref) {
  return (ref ?? "").split(/[:@]/)[0];
}

/**
 * One facade call's answer: `{ ok, status, body, error }`. A call a verb
 * hook stopped on an ask (`FacadePending`, no `Response`) is a refusal
 * here: an eve phase cannot wait for the owner.
 */
async function facadeJson(call) {
  const response = await call;
  if (!(response instanceof Response)) {
    return { ok: false, status: 202, body: null, error: { code: "PENDING_ASK" } };
  }
  const body = await response.json().catch(() => null);
  return {
    ok: response.ok,
    status: response.status,
    body,
    error: response.ok ? null : (body?.error ?? { code: `HTTP_${response.status}` }),
  };
}

function notFound(answer) {
  return answer.error?.code === "NOT_FOUND" || answer.status === 404;
}

function wireError(verb, answer) {
  const error = new Error(
    `${verb} answered ${answer.status} ${answer.error?.code ?? ""}: ${answer.error?.message ?? ""}`.trim(),
  );
  error.code = answer.error?.code;
  error.status = answer.status;
  return error;
}

function sha256Hex(text) {
  return createHash("sha256").update(text).digest("hex");
}
