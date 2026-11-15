// bun test: the provider against a fake Memory Wire server. The server is a
// Bun.serve stub on POST /v1/core/facade/<verb> that records each body and
// answers what the test scripts; the client is the facade shape of
// @oneiron/client's HttpBaseClient over fetch. No vault, no eve install.
import { afterAll, beforeEach, describe, expect, test } from "bun:test";

// A namespace import: a name the module lacks reads as undefined here, so
// each test that needs it fails alone rather than the whole file.
import * as oneironEve from "./index.js";

const { conversationRef, oneironMemoryProvider, recallOperationId, REMOVED_CONTENT } = oneironEve;

const calls = [];
let answers = {};

const server = Bun.serve({
  port: 0,
  async fetch(request) {
    const verb = decodeURIComponent(new URL(request.url).pathname.replace("/v1/core/facade/", ""));
    const body = await request.json();
    calls.push({ verb, body });
    const answer = answers[verb];
    if (!answer) {
      return Response.json({ error: { code: "NOT_FOUND", message: `no route ${verb}` } }, { status: 404 });
    }
    const [status, json] = typeof answer === "function" ? answer(body) : answer;
    return Response.json(json, { status });
  },
});
afterAll(() => server.stop(true));

function post(verb) {
  return (input, init = {}) =>
    fetch(new URL(`/v1/core/facade/${encodeURIComponent(verb)}`, server.url), {
      ...init,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
}

const client = {
  facade: {
    vault: {
      recall: post("vault.recall"),
      witness: post("vault.witness"),
      get: post("vault.get"),
      claims: { history: post("vault.claims.history") },
    },
  },
};

const scope = { key: "user:owen", namespace: "preview", value: "owen" };

function turnStarted(operationId, text, sessionId = "session-1") {
  return {
    abortSignal: new AbortController().signal,
    messages: [{ role: "user", content: text }],
    operationId,
    session: { id: sessionId },
    memory: { scope, slot: "memory" },
    turn: { id: "turn-1", input: [{ role: "user", content: text }], sequence: 1 },
  };
}

function claimItem(name, hash, text) {
  return {
    short_id: `${name}:${hash}`,
    kind: "CLAIM",
    predicate: "preference.seat",
    value_text: text,
    record: { id: `${name.padEnd(32, "0")}` },
  };
}

function pack(...items) {
  return [200, { items, scope_honesty: { out_of_scope_worlds: [] }, pack_version: 1 }];
}

function history(...versions) {
  return () => [200, { value: versions, narrowing: {} }];
}

// The rules eve 1.0.0-rc.18 puts on a recall result
// (dist/src/shared/memory-state.js validateMemoryRecallResult); eve fails
// the turn on a result that breaks one.
function expectEveAccepts(result) {
  if (result == null) {
    return;
  }
  expect(Object.keys(result)).toEqual(["messages"]);
  const ids = new Set();
  for (const message of result.messages) {
    expect(Object.keys(message).filter((key) => key !== "id" && key !== "content")).toEqual([]);
    expect(typeof message.content).toBe("string");
    expect(message.content.trim().length).toBeGreaterThan(0);
    if (message.id !== undefined) {
      expect(message.id.length).toBeGreaterThan(0);
      expect(ids.has(message.id)).toBe(false);
      ids.add(message.id);
    }
  }
}

function recallBodies() {
  return calls.filter((call) => call.verb === "vault.recall").map((call) => call.body);
}

beforeEach(() => {
  calls.length = 0;
  answers = {};
});

describe("recall", () => {
  test("renders one keyed message per item, keyed by the bare short name", async () => {
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"), {
      short_id: "ms2:0f",
      kind: "MESSAGE",
      value_text: "I fly on Friday",
      record: { id: "b".repeat(32) },
    });
    const provider = oneironMemoryProvider({ connect: () => client });
    const result = await provider.recall["turn.started"](turnStarted("op-1", "Where do I sit?"));
    expectEveAccepts(result);
    expect(result).toEqual({
      messages: [
        { id: "oneiron:cl", content: "preference.seat: window seat" },
        { id: "oneiron:ms2", content: "I fly on Friday" },
      ],
    });
  });

  test("sends eve's operation id as operation_id, in the engine's alphabet", async () => {
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"));
    const provider = oneironMemoryProvider({
      connect: () => client,
      recallScope: () => ({ world_ref: "c".repeat(32) }),
    });
    const operationId = "eve-memory-operation-v1:session/with spaces:1:turn-1:turn.started:memory";
    await provider.recall["turn.started"](turnStarted(operationId, "Where do I sit?"));
    const [body] = recallBodies();
    expect(body.operation_id).toBe(recallOperationId(operationId));
    expect(body.operation_id).toMatch(/^[A-Za-z0-9._:-]{1,128}$/);
    expect(body.query).toBe("Where do I sit?");
    expect(body.scope).toEqual({ world_ref: "c".repeat(32) });
    expect(body.format).toBeUndefined();
    expect(body.deadline_ms).toBeUndefined();
  });

  test("a replayed operation sends the same request and renders the same messages", async () => {
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"));
    const provider = oneironMemoryProvider({ connect: () => client });
    const first = await provider.recall["turn.started"](turnStarted("op-2", "Where do I sit?"));
    const again = await provider.recall["turn.started"](turnStarted("op-2", "Where do I sit?"));
    const [one, two] = recallBodies();
    expect(two).toEqual(one);
    expect(JSON.stringify(again)).toBe(JSON.stringify(first));
  });

  test("an edited record keeps its message id", async () => {
    const provider = oneironMemoryProvider({ connect: () => client });
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"));
    const before = await provider.recall["turn.started"](turnStarted("op-3", "seat?"));
    answers["vault.recall"] = pack(claimItem("cl", "9f", "aisle seat"));
    const after = await provider.recall["turn.started"](turnStarted("op-4", "seat?"));
    expect(after.messages[0].id).toBe(before.messages[0].id);
    expect(after.messages[0].content).toBe("preference.seat: aisle seat");
  });

  test("a retracted claim's message is replaced by the removal notice eve accepts", async () => {
    const provider = oneironMemoryProvider({ connect: () => client });
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"), claimItem("cm", "11", "vegetarian"));
    await provider.recall["turn.started"](turnStarted("op-5", "seat?"));
    answers["vault.recall"] = pack(claimItem("cm", "11", "vegetarian"));
    answers["vault.claims.history"] = (body) => [
      200,
      { value: [{ claim_ref: body.claim_ref, lifecycle: "retracted" }], narrowing: {} },
    ];
    const result = await provider.recall["turn.started"](turnStarted("op-6", "seat?"));
    expectEveAccepts(result);
    expect(result.messages).toEqual([
      { id: "oneiron:cl", content: REMOVED_CONTENT },
      { id: "oneiron:cm", content: "preference.seat: vegetarian" },
    ]);
    const histories = calls.filter((call) => call.verb === "vault.claims.history");
    expect(histories.map((call) => call.body)).toEqual([{ claim_ref: "cl".padEnd(32, "0") }]);
  });

  test("an item only outside this turn's top items stays, and is replaced once it is retracted", async () => {
    const provider = oneironMemoryProvider({ connect: () => client });
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"), claimItem("cm", "11", "vegetarian"));
    await provider.recall["turn.started"](turnStarted("op-7", "seat?"));
    answers["vault.recall"] = pack(claimItem("cm", "11", "vegetarian"));
    let lifecycle = "active";
    answers["vault.claims.history"] = (body) => [200, { value: [{ claim_ref: body.claim_ref, lifecycle }], narrowing: {} }];
    const kept = await provider.recall["turn.started"](turnStarted("op-8", "seat?"));
    expect(kept.messages).toEqual([{ id: "oneiron:cm", content: "preference.seat: vegetarian" }]);
    lifecycle = "retracted";
    const later = await provider.recall["turn.started"](turnStarted("op-9", "seat?"));
    expectEveAccepts(later);
    expect(later.messages[0]).toEqual({ id: "oneiron:cl", content: REMOVED_CONTENT });
  });

  test("a superseded claim is replaced though its timeline's newest version is active", async () => {
    const provider = oneironMemoryProvider({ connect: () => client });
    const served = "cl".padEnd(32, "0");
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"));
    await provider.recall["turn.started"](turnStarted("op-20", "seat?"));
    answers["vault.recall"] = pack();
    // claims.history answers the whole supersession timeline, oldest first.
    answers["vault.claims.history"] = history(
      { claim_ref: served, short_ref: "cl:a3", lifecycle: "superseded" },
      { claim_ref: "cn".padEnd(32, "0"), short_ref: "cn:5b", lifecycle: "active" },
    );
    const result = await provider.recall["turn.started"](turnStarted("op-21", "seat?"));
    expectEveAccepts(result);
    expect(result).toEqual({ messages: [{ id: "oneiron:cl", content: REMOVED_CONTENT }] });
  });

  test("a claim whose own version is active stays, whatever an older version's lifecycle", async () => {
    const provider = oneironMemoryProvider({ connect: () => client });
    const served = "cl".padEnd(32, "0");
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"));
    await provider.recall["turn.started"](turnStarted("op-22", "seat?"));
    answers["vault.recall"] = pack();
    answers["vault.claims.history"] = history(
      { claim_ref: "ck".padEnd(32, "0"), short_ref: "ck:01", lifecycle: "superseded" },
      { claim_ref: served, short_ref: "cl:a3", lifecycle: "active" },
    );
    const result = await provider.recall["turn.started"](turnStarted("op-23", "seat?"));
    expect(result).toBeNull();
  });

  test("a record that no longer reads is replaced by the removal notice", async () => {
    const provider = oneironMemoryProvider({ connect: () => client });
    const message = { short_id: "ms2:0f", kind: "MESSAGE", value_text: "I fly on Friday", record: { id: "b".repeat(32) } };
    answers["vault.recall"] = pack(message);
    await provider.recall["turn.started"](turnStarted("op-10", "when?"));
    answers["vault.recall"] = pack();
    answers["vault.get"] = [200, { value: null, narrowing: {} }];
    const result = await provider.recall["turn.started"](turnStarted("op-11", "when?"));
    expectEveAccepts(result);
    expect(result).toEqual({ messages: [{ id: "oneiron:ms2", content: REMOVED_CONTENT }] });
    expect(calls.find((call) => call.verb === "vault.get").body).toEqual({ entity_ref: "b".repeat(32) });
  });

  test("every served id is checked in turn past the per-turn cap", async () => {
    const provider = oneironMemoryProvider({ connect: () => client });
    const names = Array.from({ length: oneironEve.REMOVAL_CHECKS_PER_TURN + 1 }, (_, index) => `c${index}`);
    const erased = names[names.length - 1];
    answers["vault.recall"] = pack(...names.map((name) => claimItem(name, "a3", `fact ${name}`)));
    await provider.recall["turn.started"](turnStarted("op-24", "facts?"));
    answers["vault.recall"] = pack();
    answers["vault.claims.history"] = (body) =>
      body.claim_ref === erased.padEnd(32, "0")
        ? [404, { error: { code: "NOT_FOUND", message: "no claim" } }]
        : [200, { value: [{ claim_ref: body.claim_ref, lifecycle: "active" }], narrowing: {} }];
    const first = await provider.recall["turn.started"](turnStarted("op-25", "facts?"));
    expect(first).toBeNull();
    const second = await provider.recall["turn.started"](turnStarted("op-26", "facts?"));
    expectEveAccepts(second);
    expect(second).toEqual({ messages: [{ id: `oneiron:${erased}`, content: REMOVED_CONTENT }] });
  });

  test("each session of one partition and slot tracks its own removals", async () => {
    const provider = oneironMemoryProvider({ connect: () => client });
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"));
    await provider.recall["turn.started"](turnStarted("op-27", "seat?", "session-1"));
    await provider.recall["turn.started"](turnStarted("op-28", "seat?", "session-2"));
    answers["vault.recall"] = pack();
    answers["vault.claims.history"] = [404, { error: { code: "NOT_FOUND", message: "erased" } }];
    const one = await provider.recall["turn.started"](turnStarted("op-29", "seat?", "session-1"));
    const two = await provider.recall["turn.started"](turnStarted("op-30", "seat?", "session-2"));
    // Both sessions recalled cl, so both are told it is gone.
    const removedIds = [one, two].map((result) => result?.messages.map((message) => message.id));
    expect(removedIds).toEqual([["oneiron:cl"], ["oneiron:cl"]]);
    expect(one).toEqual({ messages: [{ id: "oneiron:cl", content: REMOVED_CONTENT }] });
    expect(two).toEqual(one);
  });

  test("an item with no text is left out, since eve refuses a blank message", async () => {
    const provider = oneironMemoryProvider({ connect: () => client });
    answers["vault.recall"] = pack(
      { short_id: "pe:01", kind: "PERSON", value_text: "  ", record: { id: "d".repeat(32) } },
      claimItem("cl", "a3", "window seat"),
    );
    const result = await provider.recall["turn.started"](turnStarted("op-31", "seat?"));
    expectEveAccepts(result);
    expect(result).toEqual({ messages: [{ id: "oneiron:cl", content: "preference.seat: window seat" }] });
  });

  test("a replay the vault refuses as changed answers no memory", async () => {
    answers["vault.recall"] = [409, { error: { code: "INVALID_STATE", message: "this operation's recall answer changed" } }];
    const provider = oneironMemoryProvider({ connect: () => client });
    const result = await provider.recall["turn.started"](turnStarted("op-12", "seat?"));
    expect(result).toBeNull();
  });

  test("another refusal is the turn's error", async () => {
    answers["vault.recall"] = [403, { error: { code: "FORBIDDEN", message: "no read" } }];
    const provider = oneironMemoryProvider({ connect: () => client });
    await expect(provider.recall["turn.started"](turnStarted("op-13", "seat?"))).rejects.toThrow("FORBIDDEN");
  });
});

describe("partition", () => {
  test("a scope connect answers null for recalls and witnesses nothing", async () => {
    answers["vault.recall"] = pack(claimItem("cl", "a3", "window seat"));
    const provider = oneironMemoryProvider({ connect: () => null });
    const result = await provider.recall["turn.started"](turnStarted("op-14", "seat?"));
    await provider.capture["turn.completed"](turnStarted("op-14", "seat?"));
    expect(result).toBeNull();
    expect(calls).toEqual([]);
  });

  test("a provider without connect is refused", () => {
    expect(() => oneironMemoryProvider({})).toThrow("connect");
  });
});

describe("capture", () => {
  function turnCompleted(operationId) {
    const input = [{ role: "user", content: "Book me a window seat." }];
    return {
      abortSignal: new AbortController().signal,
      operationId,
      memory: { scope, slot: "memory" },
      turn: { id: "turn-2", input, sequence: 2 },
      messages: [
        { role: "user", content: "earlier question" },
        { role: "assistant", content: "earlier answer" },
        ...input,
        { role: "assistant", content: [{ type: "reasoning", text: "thinking" }, { type: "tool-call", toolName: "book" }] },
        { role: "tool", content: [{ type: "tool-result" }] },
        { role: "assistant", content: [{ type: "text", text: "Booked 14A." }] },
      ],
    };
  }

  test("witnesses the settled turn as one call per speaker", async () => {
    answers["vault.witness"] = [200, { conversation_ref: "x" }];
    const provider = oneironMemoryProvider({ connect: () => client });
    await provider.capture["turn.completed"](turnCompleted("op-15"));
    const witnessed = calls.filter((call) => call.verb === "vault.witness").map((call) => call.body);
    expect(witnessed.map((body) => body.messages.map((message) => [message.author, message.content]))).toEqual([
      [["user", "Book me a window seat."]],
      [["companion", "Booked 14A."]],
    ]);
    for (const body of witnessed) {
      expect(body.conversation_ref).toBe(conversationRef(scope, "memory"));
      expect(body.conversation_ref).toMatch(/^[0-9a-f]{32}$/);
      expect(body.turn_ref).toMatch(/^[0-9a-f]{32}$/);
      expect(body.messages[0].id).toMatch(/^[0-9a-f]{32}$/);
      expect(body.messages[0].message_type).toBe("dialogue");
      expect(body.messages[0].is_visible).toBe(true);
      expect(Number.isInteger(body.occurred_at)).toBe(true);
    }
    expect(witnessed[0].turn_ref).not.toBe(witnessed[1].turn_ref);
  });

  test("a replayed capture sends the same turn and message ids", async () => {
    answers["vault.witness"] = [200, {}];
    const provider = oneironMemoryProvider({ connect: () => client });
    await provider.capture["turn.completed"](turnCompleted("op-16"));
    await provider.capture["turn.completed"](turnCompleted("op-16"));
    const ids = calls.map((call) => [call.body.turn_ref, call.body.messages[0].id]);
    expect(ids.slice(2)).toEqual(ids.slice(0, 2));
  });

  test("capture: false leaves the capture phase out", () => {
    const provider = oneironMemoryProvider({ connect: () => client, capture: false });
    expect(provider.capture).toBeUndefined();
  });
});
