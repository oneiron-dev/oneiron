// Generated from code-run.wit; do not edit.
const schema = {"records":{"time-range":[{"name":"start","type":"u64","json":null},{"name":"end","type":"u64","json":null}],"search-input":[{"name":"query","type":"string","json":null},{"name":"limit","type":"option<u32>","json":null}],"claim-input":[{"name":"id","type":"string","json":null},{"name":"predicate","type":"string","json":null},{"name":"subject","type":"string","json":"json"},{"name":"value","type":"string","json":"json"},{"name":"confidence","type":"option<f32>","json":null},{"name":"occurred","type":"option<time-range>","json":null},{"name":"learnedAt","type":"option<u64>","json":null}],"search-output":[{"name":"results","type":"list<string>","json":"json-list"}],"claim-output":[{"name":"id","type":"string","json":null}],"edge-output":[{"name":"src","type":"string","json":null},{"name":"kind","type":"string","json":null},{"name":"tgt","type":"string","json":null}],"wait-output":[{"name":"waitId","type":"string","json":null}],"speech-output":[{"name":"order","type":"u32","json":null},{"name":"isVisible","type":"bool","json":null}],"supersede-input":[{"name":"newId","type":"string","json":null},{"name":"oldId","type":"string","json":null},{"name":"now","type":"u64","json":null}],"edge-input":[{"name":"src","type":"string","json":null},{"name":"kind","type":"string","json":null},{"name":"tgt","type":"string","json":null},{"name":"weight","type":"option<f32>","json":null}],"prompt-input":[{"name":"prompt","type":"string","json":null}],"text-input":[{"name":"text","type":"string","json":null}],"credential-input":[{"name":"operation","type":"string","json":null},{"name":"credentialHandle","type":"string","json":null},{"name":"args","type":"string","json":"json"}],"file-proposal":[{"name":"path","type":"string","json":null},{"name":"bytes","type":"list<u8>","json":null}],"step-result":[{"name":"resultJson","type":"string","json":null},{"name":"proposals","type":"list<proposal-delta>","json":null}]},"imports":[{"js":"sandbox.fs.read_file","wit":"read-file","params":[{"name":"path","type":"string"}],"result":"list<u8>","async":true},{"js":"sandbox.credential.call","wit":"credential-call","params":[{"name":"input","type":"credential-input"}],"result":"string","async":true},{"js":"oneiron.clock.now_unix_ms","wit":"clock-now-unix-ms","params":[],"result":"u64","async":false},{"js":"oneiron.random.bytes","wit":"random-bytes","params":[{"name":"length","type":"u32"}],"result":"list<u8>","async":false},{"js":"self.memory.search","wit":"memory-search","params":[{"name":"input","type":"search-input"}],"result":"search-output","async":true},{"js":"self.memory.put_claim","wit":"memory-put-claim","params":[{"name":"input","type":"claim-input"}],"result":"claim-output","async":true},{"js":"self.memory.supersede_claim","wit":"memory-supersede-claim","params":[{"name":"input","type":"supersede-input"}],"result":"claim-output","async":true},{"js":"self.memory.put_edge","wit":"memory-put-edge","params":[{"name":"input","type":"edge-input"}],"result":"edge-output","async":true},{"js":"ask","wit":"ask","params":[{"name":"input","type":"prompt-input"}],"result":"wait-output","async":true},{"js":"self.speak","wit":"speak","params":[{"name":"input","type":"text-input"}],"result":"speech-output","async":true},{"js":"self.think","wit":"think","params":[{"name":"input","type":"text-input"}],"result":"speech-output","async":true},{"js":"self.express","wit":"express","params":[{"name":"input","type":"text-input"}],"result":"speech-output","async":true}]};

function convert(type, value, encode) {
  if (type.startsWith("option<")) return value == null ? undefined : convert(type.slice(7, -1), value, encode);
  if (type === "list<u8>") return value instanceof Uint8Array ? value : new Uint8Array(value);
  if (type.startsWith("list<")) return value.map(item => convert(type.slice(5, -1), item, encode));
  if (["u64", "u32", "u8"].includes(type)) {
    const n = Number(value);
    const max = type === "u8" ? 255 : type === "u32" ? 4294967295 : Number.MAX_SAFE_INTEGER;
    if (!Number.isSafeInteger(n) || n < 0 || n > max) throw new RangeError("invalid guest integer");
    return n;
  }
  if (schema.records[type]) {
    const result = {};
    for (const field of schema.records[type]) {
      const v = value[field.name];
      if (field.json) {
        const transform = encode ? JSON.stringify : JSON.parse;
        result[field.name] = field.json === "json-list" ? v.map(item => transform(item)) : transform(v);
        if (result[field.name] === undefined) throw new TypeError("missing guest JSON field");
      } else result[field.name] = convert(field.type, v, encode);
    }
    return result;
  }
  return value;
}

// The guest bootstrap injects the ABI. Missing imports stay absent: foreign
// SDK instances cannot grow write methods that their component did not import.
export function createHostSdk(abi) {
  const sdk = Object.create(null);
  for (const row of schema.imports) {
    if (!Object.hasOwn(abi, row.wit)) continue;
    let target = sdk;
    const parts = row.js.split(".");
    for (const part of parts.slice(0, -1)) target = target[part] ??= Object.create(null);
    target[parts.at(-1)] = (...args) => {
      const values = row.params.map((param, i) => convert(param.type, args[i], true));
      const result = abi[row.wit](...values);
      return row.async ? Promise.resolve(result).then(v => convert(row.result, v, false)) : convert(row.result, result, false);
    };
  }
  return sdk;
}
