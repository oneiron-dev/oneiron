(() => {
  "use strict";
  const abi = globalThis.__oneironAbi;
  delete globalThis.__oneironAbi;
  const sdk = createHostSdk(abi);
  // The SDK verb table: one `self.memory` method per row the host serves, so a
  // row added to the table reaches the guest with no component rebuild.
  if (sdk.self?.verbs) {
    const {names, call} = sdk.self.verbs;
    delete sdk.self.verbs;
    const memory = sdk.self.memory ??= Object.create(null);
    for (const name of names()) {
      const parts = name.split(".");
      let target = memory;
      for (const part of parts.slice(0, -1)) target = target[part] ??= Object.create(null);
      if (Object.hasOwn(target, parts.at(-1))) throw new TypeError("verb row shadows a host import");
      target[parts.at(-1)] = (input = {}) => call(name, input).then(JSON.parse);
    }
  }
  const {clock, random} = sdk.oneiron;
  const nativeStringify = JSON.stringify;
  const string = String;
  const logs = [];
  const files = [];
  const proposals = [];
  let done = false;
  let answer = "";
  let outputBytes = 0;
  const charge = n => { outputBytes += n; if (outputBytes > 262144) throw new RangeError("output budget"); };
  const text = v => typeof v === "string" ? v : nativeStringify(v) ?? string(v);
  const startsWith = Function.prototype.call.bind(String.prototype.startsWith);
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
    const line = args.map(text).join(" "); charge(line.length); logs.push(line);
  }}));
  set("finish", value => { done = true; answer = text(value); charge(answer.length); });
  set("writeOutput", (path, bytes) => {
    path = outputPath(path);
    bytes = Array.from(bytes);
    if (!bytes.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) throw new TypeError("invalid output bytes");
    charge(bytes.length); files.push({path, bytes});
  });
  if (!sdk.self) set("propose", Object.freeze({
    file(path, bytes) {
      path = outputPath(path, true); bytes = Array.from(bytes);
      if (!bytes.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) throw new TypeError("invalid proposal bytes");
      charge(bytes.length); proposals.push({tag:"file-write", val:{path, bytes}});
    },
    delete(path) {
      path = outputPath(path, true);
      if (!startsWith(path, "/mnt/workspace/")) throw new TypeError("deletion must be in workspace");
      charge(path.length); proposals.push({tag:"file-delete", val:{path}});
    },
    rename(from, to) {
      from = outputPath(from, true); to = outputPath(to, true);
      if (!startsWith(from, "/mnt/workspace/") || !startsWith(to, "/mnt/workspace/") || from === to)
        throw new TypeError("rename must name distinct workspace files");
      charge(from.length + to.length); proposals.push({tag:"file-rename", val:{origin:from, destination:to}});
    },
    claim(input) {
      const val = convert("claim-input", input, true);
      charge(nativeStringify(val).length); proposals.push({tag:"claim-candidate", val});
    }
  }));
  // No std/os modules, timers, fetch, process, require, network or WASI are installed.
  // The closure, not a global property the script can replace, owns completion.
  return () => ({resultJson: nativeStringify({done, observation: done ? answer : logs.join("\n"), outputs:files}), proposals});
})();
