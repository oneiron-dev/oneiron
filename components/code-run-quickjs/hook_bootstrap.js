// Hook body setup. The guest calls this with the parsed input before the body
// runs; it returns the closure that turns the body's result into the outcome.
(value => {
  "use strict";
  const abi = globalThis.__oneironHookAbi;
  delete globalThis.__oneironHookAbi;
  const scopedRead = abi["scoped-read"], aiVerdict = abi["ai-verdict"];
  const emitOutcome = abi["emit-outcome"];
  const encode = JSON.stringify, decode = JSON.parse, finite = Number.isFinite;
  const isArray = Array.isArray, keys = Object.keys, frozen = Object.isFrozen;
  const freezeOne = Object.freeze, push = Function.prototype.call.bind(Array.prototype.push);
  const pop = Function.prototype.call.bind(Array.prototype.pop);
  const PromiseType = Promise;
  // JSON has no NaN or Infinity: one would cross as null, so it is refused.
  const nonFinite = Symbol();
  const checked = (_, item) => {
    if (item instanceof Number) item = +item;
    if (typeof item === "number" && !finite(item)) throw nonFinite;
    return item;
  };
  const text = (item, code) => {
    let out;
    try { out = encode(item, checked); } catch (error) {
      throw error === nonFinite ? new RangeError("non_finite_" + code) : new TypeError("invalid_" + code);
    }
    if (typeof out !== "string") throw new TypeError("invalid_" + code);
    return out;
  };
  const isRecord = item => item !== null && typeof item === "object" && !isArray(item);
  // Iterative, so deep input cannot exhaust the stack.
  const freeze = root => {
    const stack = [root];
    while (stack.length) {
      const item = pop(stack);
      if (item === null || typeof item !== "object" || frozen(item)) continue;
      freezeOne(item);
      for (const key of keys(item)) push(stack, item[key]);
    }
    return root;
  };
  let emitted = false;
  // The one outcome. A refused emit throws and leaves the body free to retry.
  const emit = outcome => {
    if (emitted) throw new TypeError("outcome_already_emitted");
    if (!isRecord(outcome) || typeof outcome.kind !== "string") throw new TypeError("invalid_outcome");
    emitOutcome(text(outcome, "outcome"));
    emitted = true;
  };
  // A scoped read under the hook's grant; the host's refusal is the rejection.
  const read = request => new PromiseType(resolve => {
    if (!isRecord(request)) throw new TypeError("invalid_read_request");
    resolve(decode(scopedRead(text(request, "read_request"))));
  });
  // ai.verdict: only a fact hook that declares the generative class gets an
  // answer; any other body's call is refused by the host.
  const verdict = request => new PromiseType(resolve => {
    if (!isRecord(request)) throw new TypeError("invalid_verdict_request");
    resolve(decode(aiVerdict(text(request, "verdict_request"))));
  });
  const set = (name, item) => Object.defineProperty(globalThis, name,
    {value: item, writable: false, configurable: false});
  set("input", freeze(value));
  set("oneiron", freezeOne({read, emit}));
  set("ai", freezeOne({verdict}));
  // No entropy reaches a hook; a seeded stand-in would repeat across runs.
  Object.defineProperty(Math, "random", {value: () => { throw new TypeError("hook_has_no_random"); },
    writable: false, configurable: false});
  // No std/os modules, timers, fetch, process, require, network or WASI exist.
  // The body's return value is its outcome unless it emitted one; returning
  // nothing without an emit is the Nothing outcome.
  return result => {
    if (emitted) {
      if (result !== undefined) throw new TypeError("outcome_already_emitted");
      return;
    }
    emit(result === undefined ? {kind: "nothing"} : result);
  };
})
