const {readFileSync} = require("node:fs");
const {join} = require("node:path");
const {runInNewContext} = require("node:vm");
const {test} = require("node:test");
const assert = require("node:assert/strict");

const script = readFileSync(join(__dirname, "../src/api/esign/ceremony.js"), "utf8");

async function open(pathname, hash = "") {
  const requests = [];
  const history = [];
  const status = {textContent: ""};
  const nodes = new Map([["status", status]]);
  const document = {
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, {});
      return nodes.get(id);
    },
  };
  runInNewContext(script, {
    location: {pathname, hash},
    history: {replaceState(...args) { history.push(args); }},
    document,
    window: {addEventListener() {}},
    fetch: async (path, options) => {
      requests.push({path, options});
      return {ok: true, json: async () => ({outcome: "not_your_turn"})};
    },
  });
  await new Promise(resolve => setImmediate(resolve));
  return {requests, history, status};
}

test("a signing link's fragment bearer is posted only after scrubbing the URL", async () => {
  // F37: the capability rides in the fragment, which no request target holds.
  const token = "ab".repeat(32);
  const {requests, history} = await open("/sign", `#${token}`);
  assert.deepEqual(history[0], [null, "", "/sign"]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].path, "/sign/action");
  assert.equal(JSON.parse(requests[0].options.body).token, token);
  assert.equal(requests[0].options.credentials, "omit");
});

test("path tokens and malformed fragments never submit a bearer", async () => {
  const token = "ab".repeat(32);
  for (const [path, hash] of [[`/sign/${token}`, ""], ["/sign", ""], ["/sign", "#invalid"], ["/sign", `#${token}0`], ["/sign", `#${token.toUpperCase()}`]]) {
    const {requests, history, status} = await open(path, hash);
    assert.deepEqual(history[0], [null, "", "/sign"]);
    assert.equal(requests.length, 0);
    assert.match(status.textContent, /unavailable/);
  }
});
