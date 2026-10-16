(() => {
  "use strict";
  const abi = globalThis.__oneironAbi;
  delete globalThis.__oneironAbi;
  const sdk = createHostSdk(abi);
  // The SDK verb table: one `self.memory` method per row the host serves, so a
  // row added to the table reaches the guest with no component rebuild.
  if (sdk.self?.verbs) {
    const {names} = sdk.self.verbs, send = abi["verb-call"];
    delete sdk.self.verbs;
    // JSON has no NaN or Infinity: encoding one, boxed or not, would send
    // null, an absent value, so a non-finite number is refused before the
    // call instead. The input is encoded once and that checked text is what
    // the call sends; any input JSON cannot carry is refused as a code.
    const encode = JSON.stringify, decode = JSON.parse, finite = Number.isFinite;
    const nonFinite = Symbol();
    const checked = (_, value) => {
      if (value instanceof Number) value = +value;
      if (typeof value === "number" && !finite(value)) throw nonFinite;
      return value;
    };
    const verbInput = input => {
      let text;
      try { text = encode(input, checked); } catch (error) {
        throw error === nonFinite ? new RangeError("non_finite_verb_input") : new TypeError("invalid_verb_input");
      }
      if (typeof text !== "string") throw new TypeError("invalid_verb_input");
      return text;
    };
    const memory = sdk.self.memory ??= Object.create(null);
    for (const name of names()) {
      const parts = name.split(".");
      let target = memory;
      for (const part of parts.slice(0, -1)) target = target[part] ??= Object.create(null);
      if (Object.hasOwn(target, parts.at(-1))) throw new TypeError("verb row shadows a host import");
      target[parts.at(-1)] = (input = {}) => {
        const text = verbInput(input);
        return Promise.resolve(send(name, text)).then(decode);
      };
    }
  }
  const {clock, random} = sdk.oneiron;
  // The result streams to the host as it is written (hidden @abi imports),
  // so no step result is held whole here and none has a size budget.
  delete sdk.oneiron.output;
  const sendText = abi["output-text"], sendBytes = abi["output-bytes"];
  const nativeStringify = JSON.stringify;
  const string = String;
  const proposals = [];
  let done = false;
  const text = v => typeof v === "string" ? v : nativeStringify(v) ?? string(v);
  const call = Function.prototype.call;
  const startsWith = call.bind(String.prototype.startsWith);
  const slice = call.bind(String.prototype.slice);
  const charCodeAt = call.bind(String.prototype.charCodeAt);
  const join = call.bind(Array.prototype.join);
  const push = call.bind(Array.prototype.push);
  const subarray = call.bind(Uint8Array.prototype.subarray);
  // A lone surrogate is not UTF-8: it becomes U+FFFD before it is sent.
  const wellFormed = String.prototype.toWellFormed
    ? call.bind(String.prototype.toWellFormed)
    : value => value.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, "\ufffd");
  // One message carries at most 1 MiB. A UTF-16 unit encodes to at most three
  // UTF-8 bytes, so a text frame of this many units always fits one.
  const TEXT_FRAME = 349525, BYTE_FRAME = 1048576;
  const sendFramed = (target, value, start) => {
    let at = 0;
    do {
      let end = value.length - at > TEXT_FRAME ? at + TEXT_FRAME : value.length;
      if (end < value.length && (charCodeAt(value, end - 1) & 0xfc00) === 0xd800) --end;
      sendText(target, start, wellFormed(slice(value, at, end)));
      start = false;
      at = end;
    } while (at < value.length);
  };
  // console.log lines gather into frames; a step's lines join with "\n".
  let logParts = [], logUnits = 0, logged = false;
  const flushLog = () => {
    if (!logParts.length) return;
    const value = join(logParts, "");
    logParts = []; logUnits = 0;
    sendFramed("console", value, false);
  };
  const outputPath = (path, proposal = false) => {
    if (typeof path !== "string" || !(startsWith(path, "/mnt/outputs/") || proposal && startsWith(path, "/mnt/workspace/")))
      throw new TypeError("output path must be under /mnt/outputs");
    let start = 1;
    for (let i = 1; i <= path.length; ++i) {
      if (path[i] === "\\" || path[i] === "\0") throw new TypeError("invalid output path");
      if (i === path.length || path[i] === "/") {
        const size = i - start;
        if (!size || size === 1 && path[start] === "." || size === 2 && path[start] === "." && path[start + 1] === ".")
          throw new TypeError("invalid output path");
        start = i + 1;
      }
    }
    return path;
  };
  const set = (name, value) => Object.defineProperty(globalThis, name,
    {value, writable: false, configurable: false});
  const freeze = object => {
    for (const v of Object.values(object)) if (v && typeof v === "object") freeze(v);
    return Object.freeze(object);
  };
  set("oneiron", freeze(sdk.oneiron));
  set("sandbox", freeze(sdk.sandbox));
  if (sdk.self) {
    set("self", freeze(sdk.self));
    set("ask", sdk.ask);
  }
  if (sdk.vault) set("vault", freeze(sdk.vault));
  const randomDouble = () => {
    const bytes = random.bytes(7);
    let value = bytes[0] & 31;
    for (let i = 1; i < 7; ++i) value = value * 256 + bytes[i];
    return value / 9007199254740992;
  };
  Object.defineProperty(Math, "random", {value:randomDouble, writable:false, configurable:false});
  set("console", Object.freeze({log(...args) {
    const line = join(args.map(text), " ");
    if (logged) push(logParts, "\n");
    logged = true;
    // A long line is framed as it stands, never copied into a joined one.
    if (line.length >= TEXT_FRAME) { flushLog(); sendFramed("console", line, false); return; }
    push(logParts, line);
    logUnits += line.length + 1;
    if (logUnits >= TEXT_FRAME) flushLog();
  }}));
  // Each finish replaces the answer; the last one is the step's result.
  set("finish", value => { done = true; sendFramed("finish", text(value), true); });
  // Appends to the step's file at `path`, so a large file is written in pieces.
  set("writeOutput", (path, bytes) => {
    path = outputPath(path);
    if (!(bytes instanceof Uint8Array)) {
      bytes = Array.from(bytes);
      if (!bytes.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) throw new TypeError("invalid output bytes");
      bytes = new Uint8Array(bytes);
    }
    let at = 0;
    do {
      sendBytes(path, subarray(bytes, at, at + BYTE_FRAME));
      at += BYTE_FRAME;
    } while (at < bytes.length);
  });
  if (!sdk.self) set("propose", Object.freeze({
    file(path, bytes) {
      path = outputPath(path, true); bytes = Array.from(bytes);
      if (!bytes.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) throw new TypeError("invalid proposal bytes");
      proposals.push({tag:"file-write", val:{path, bytes}});
    },
    delete(path) {
      path = outputPath(path, true);
      if (!startsWith(path, "/mnt/workspace/")) throw new TypeError("deletion must be in workspace");
      proposals.push({tag:"file-delete", val:{path}});
    },
    rename(from, to) {
      from = outputPath(from, true); to = outputPath(to, true);
      if (!startsWith(from, "/mnt/workspace/") || !startsWith(to, "/mnt/workspace/") || from === to)
        throw new TypeError("rename must name distinct workspace files");
      proposals.push({tag:"file-rename", val:{origin:from, destination:to}});
    },
    claim(input) {
      const val = convert("claim-input", input, true);
      proposals.push({tag:"claim-candidate", val});
    }
  }));
  // No std/os modules, timers, fetch, process, require, network or WASI are installed.
  // The closure, not a global property the script can replace, owns completion.
  // The answer and files are already with the host; only the lines still
  // gathering are sent, and only when no finish replaced them.
  return () => {
    if (!done) flushLog();
    return {resultJson: nativeStringify({done}), proposals};
  };
})();
