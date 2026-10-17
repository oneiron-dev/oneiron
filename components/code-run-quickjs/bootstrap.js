(() => {
  "use strict";
  const abi = globalThis.__oneironAbi;
  delete globalThis.__oneironAbi;
  const sdk = createHostSdk(abi);
  // The SDK verb table: each row the host serves at its full path, so a row
  // added to the table reaches the guest with no component rebuild. A
  // `self.*` row sits on `self`, a bare row (`describe`, `ask`) is a global,
  // and every other row sits on its root (`vault.recall`, `tasks.create`).
  const roots = new Set(), bare = Object.create(null);
  let guard = (_, object) => object;
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
    // `self.fold` takes `(span, {note?})`, sent as `[from, through]` or `[[from, through], {note}]`.
    const verb = name => name === "self.fold"
      ? (span, options) => Promise.resolve(send(name, verbInput(options === undefined ? span : [span, options]))).then(decode)
      : (input = {}) => { const text = verbInput(input); return Promise.resolve(send(name, text)).then(decode); };
    // A call under a root the SDK does not have (`tools.`, `self.mcp.`,
    // `memory.`) or of a verb a root does not hold is sent as written: the
    // host answers the typed WRONG_ROOT correction before any effect, and the
    // call throws it. Nothing ever runs under the wrong name.
    // Keys the language itself looks up (`await`, `JSON.stringify`, string
    // coercion) are never verbs.
    const plain = new Set(["then", "toJSON", "toString", "valueOf", "constructor", "prototype"]);
    const refusal = path => new Proxy(function () {}, {
      get: (_, key) => typeof key === "string" && !plain.has(key) ? refusal(`${path}.${key}`) : undefined,
      apply: (_, __, [input = {}]) => Promise.resolve(send(path, verbInput(input))).then(text => {
        throw decode(text)?.error ?? new TypeError("unknown_sdk_verb");
      }),
    });
    // Every namespace answers a verb it does not hold with that refusal.
    guard = (path, object) => {
      for (const [key, value] of Object.entries(object))
        if (value && typeof value === "object") object[key] = guard(`${path}.${key}`, value);
      return new Proxy(object, {
        get: (target, key, receiver) => typeof key !== "string" || plain.has(key) || key in target
          ? Reflect.get(target, key, receiver) : refusal(`${path}.${key}`),
      });
    };
    sdk.self.memory ??= Object.create(null);
    for (const name of names()) {
      const parts = name.split(".");
      if (parts.length === 1) {
        if (name in bare) throw new TypeError("verb row shadows a host import");
        bare[name] = verb(name);
        continue;
      }
      roots.add(parts[0]);
      let target = sdk[parts[0]] ??= Object.create(null);
      for (const part of parts.slice(1, -1)) target = target[part] ??= Object.create(null);
      // A segment can be a verb and hold verbs at once (`self.memory.diary`
      // and `self.memory.diary.query`): the verb carries its children.
      const leaf = parts.at(-1), held = target[leaf];
      if (typeof held === "function") throw new TypeError("verb row shadows a host import");
      target[leaf] = held ? Object.assign(verb(name), held) : verb(name);
    }
    // A result is named by its ref: a bound name (`r7`), a handle, a range
    // of either (`r7#0-4096`), or a card or chunk that carries one.
    const refOf = r => {
      const ref = typeof r === "string" ? r : (r?.ref ?? r?.handle ?? r?.name);
      if (typeof ref !== "string") throw new TypeError("result ref must be a name, handle or card");
      return ref;
    };
    const read = (name, input) => Promise.resolve(send(name, verbInput(input))).then(decode);
    // Every result card the program is given carries its reads as methods
    // that are not fields, so its JSON is unchanged: `r.slice({lines: [0, 50]})`.
    const card = value => {
      if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
      const ref = refOf(value);
      const methods = {
        slice: sel => bare.slice(ref, sel),
        search: (pattern, opts) => bare.search(ref, pattern, opts),
        query: q => bare.query(ref, q),
        chunks: by => bare.chunks(ref, by),
        describe: () => bare.describe(ref),
      };
      for (const key in methods) Object.defineProperty(value, key, {value: methods[key], enumerable: false});
      return Object.freeze(value);
    };
    // `store(value, name?, {sources?, receipt?})` streams the value to the
    // host as the result frames do, then binds it: a string as given, any
    // other value as its JSON. The host answers the stored result's card.
    // `sources` are the results it was made from, whose taint it inherits;
    // `receipt` names a fold's source, jobs and summary tree, of which the
    // host computes the fold receipt.
    if ("store" in bare) throw new TypeError("verb row shadows a host import");
    const listOf = (items, map) => Array.from(items ?? [], map);
    bare.store = (value, name, options) => {
      if (name !== undefined && name !== null && typeof name !== "string") throw new TypeError("store name must be a string");
      const input = name == null ? {} : {name};
      if (options !== undefined) {
        if (!options || typeof options !== "object") throw new TypeError("store options must be an object");
        if (options.sources !== undefined) input.sources = listOf(options.sources, refOf);
        if (options.receipt !== undefined) {
          const receipt = options.receipt;
          input.receipt = {
            source: refOf(receipt?.source),
            tasks: listOf(receipt.tasks, String),
            tree: listOf(receipt.tree, node => ({summary: refOf(node?.summary), inputs: listOf(node.inputs, refOf)})),
          };
          if (receipt.recipe !== undefined) input.receipt.recipe = receipt.recipe;
        }
      }
      const sent = verbInput(input);
      sendFramed("store", text(value), true);
      return Promise.resolve(send("store", sent)).then(decode).then(card);
    };
    // `summarize(r, {effort?, group?, defer?})`: the row takes its ref and
    // group as refs. A made summary answers its card; a deferred one its
    // task and state.
    const summarizeVerb = bare.summarize;
    if (summarizeVerb) bare.summarize = (r, options = {}) => {
      const input = {...options, ref: refOf(r)};
      if (options.group !== undefined) input.group = listOf(options.group, refOf);
      return summarizeVerb(input).then(reply =>
        reply && typeof reply.handle === "string" ? card(reply) : reply);
    };
    // `describe` of a result answers its card; of anything else, the verb's
    // own answer.
    const describeVerb = bare.describe;
    if (describeVerb) bare.describe = r => {
      const result = r && typeof r === "object" && (typeof r.ref === "string" || typeof r.handle === "string");
      return describeVerb(result ? refOf(r) : r).then(reply =>
        reply && typeof reply.handle === "string" && typeof reply.bytes === "number" ? card(reply) : reply);
    };
    // A result's reads: deterministic, each answered in one message, each
    // with where to go on from. The host checks the run's grant, the rows
    // the result was served from and its taint at every one.
    for (const name of ["slice", "search", "query", "chunks"])
      if (name in bare) throw new TypeError("verb row shadows a host import");
    bare.slice = (r, sel = {}) => read("slice", {ref: refOf(r), ...sel});
    bare.search = (r, pattern, opts = {}) => read("search", {ref: refOf(r), pattern, ...opts});
    bare.query = (r, q) => read("query", typeof q === "string" ? {ref: refOf(r), path: q} : {ref: refOf(r), ...q})
      .then(reply => {
        if (reply && reply.derived) reply.derived = card(reply.derived);
        return reply;
      });
    // `chunks(r, by)` pages its chunks only as they are iterated, a page
    // per host call; `page(cursor?)` answers one page as it comes.
    bare.chunks = (r, by = {}) => {
      const ref = refOf(r);
      const page = (cursor = by.cursor) => read("chunks", {ref, ...by, cursor}).then(reply => {
        if (reply && Array.isArray(reply.chunks)) reply.chunks = reply.chunks.map(card);
        return reply;
      });
      return Object.freeze({
        page,
        [Symbol.asyncIterator]() {
          let entries = [], at = 0, cursor = by.cursor, more = true;
          return {
            async next() {
              while (at >= entries.length) {
                if (!more) return {done: true, value: undefined};
                const reply = await page(cursor);
                entries = reply.chunks ?? [];
                at = 0;
                cursor = reply.next;
                more = !reply.done && cursor !== undefined;
              }
              return {done: false, value: entries[at++]};
            },
          };
        },
      });
    };
    // The bundled helpers (reader_forks.js, diff.js): plain JS over the
    // calls above, never engine verbs. Each step they take is one of those
    // calls, checked and recorded as the program's own.
    for (const name of ["readAll", "diff"])
      if (name in bare) throw new TypeError("verb row shadows a host import");
    const helpers = {
      slice: bare.slice, chunks: bare.chunks, store: bare.store, describe: bare.describe,
      can: bare.can, summarize: bare.summarize, spawn: sdk.self.spawn, wait: sdk.tasks?.wait,
    };
    if (helpers.can && helpers.summarize && helpers.spawn && helpers.wait) bare.readAll = makeReaderForks(helpers);
    if (helpers.can) bare.diff = makeDiff(helpers);
    for (const root of ["tools", "connectors", "mcp", "memory", "board", "shared", "home", "sdk"])
      if (!roots.has(root)) bare[root] = refusal(root);
    for (const root of ["connectors", "mcp"]) sdk.self[root] ??= refusal(`self.${root}`);
    roots.add("self");
    for (const root of roots) sdk[root] = guard(root, sdk[root]);
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
  if (sdk.self) set("self", freeze(sdk.self));
  if (sdk.vault) roots.add("vault");
  for (const root of roots) if (root !== "self") set(root, freeze(sdk[root]));
  for (const [name, call] of Object.entries(bare)) set(name, call);
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
