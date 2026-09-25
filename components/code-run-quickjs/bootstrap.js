(() => {
  "use strict";
  const abi = globalThis.__oneironAbi;
  delete globalThis.__oneironAbi;
  const sdk = createHostSdk(abi);
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
  if (sdk.self) set("self", freeze(sdk.self));
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
    claim(input) {
      const val = convert("claim-input", input, true);
      charge(nativeStringify(val).length); proposals.push({tag:"claim-candidate", val});
    }
  }));
  // No std/os modules, timers, fetch, process, require, network or WASI are installed.
  // The closure, not a global property the script can replace, owns completion.
  return () => ({resultJson: nativeStringify({done, observation: done ? answer : logs.join("\n"), outputs:files}), proposals});
})();
