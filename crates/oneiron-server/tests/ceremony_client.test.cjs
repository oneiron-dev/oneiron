const {readFileSync} = require("node:fs");
const {join} = require("node:path");
const {runInNewContext} = require("node:vm");
const {test} = require("node:test");
const assert = require("node:assert/strict");

const script = readFileSync(join(__dirname, "../src/api/esign/ceremony.js"), "utf8");
const exchange = "ef".repeat(32);
const ceremony = "c3".repeat(16);

async function open(pathname, hash = "", search = "") {
  const requests = [];
  const history = [];
  const listeners = {};
  const submitted = [];
  const location = {pathname, hash, search, reloads: 0, reload() { this.reloads += 1; }};
  const status = {textContent: ""};
  const nodes = new Map([["status", status]]);
  const element = tag => {
    const node = {tag, children: [], append(...more) { this.children.push(...more); }};
    if (tag === "form") node.submit = function () { submitted.push({action: this.action, method: this.method, fields: this.children.map(({name, value}) => ({name, value})), scrubbed: history.length}); };
    return node;
  };
  const document = {
    body: element("body"),
    createElement: element,
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, {});
      return nodes.get(id);
    },
  };
  runInNewContext(script, {
    location,
    history: {replaceState(...args) { history.push(args); }},
    document,
    window: {addEventListener(name, listener) { listeners[name] = listener; }},
    fetch: async (path, options) => {
      requests.push({path, options, scrubbed: history.length});
      const body = path === "/sign/exchange" ? {exchange} : {outcome: "not_your_turn"};
      return {ok: true, json: async () => body};
    },
  });
  await new Promise(resolve => setImmediate(resolve));
  return {requests, history, status, location, listeners, submitted};
}

test("a signing link's fragment is traded once for a session, only after scrubbing the URL", async () => {
  // F37: the capability rides in the fragment, which no request target holds.
  const token = "ab".repeat(32);
  const {requests, history, submitted} = await open("/sign", `#${token}`);
  assert.deepEqual(history[0], [null, "", "/sign"]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].scrubbed, 1, "the URL is scrubbed before the bearer is posted");
  assert.equal(requests[0].path, "/sign/exchange");
  assert.equal(requests[0].options.headers["x-oneiron-esign-capability"], token);
  assert.equal(requests[0].options.body, undefined);
  // ARCH-0064a [SGN-03]: a top-level form POST consumes the exchange.
  assert.deepEqual(submitted, [{action: "/sign/session", method: "POST", fields: [{name: "exchange", value: exchange}], scrubbed: 1}]);
});

test("a page at its ceremony's address runs on that ceremony's session and never sends a capability", async () => {
  const {requests, history, submitted} = await open("/sign", "", `?ceremony=${ceremony}`);
  assert.deepEqual(history[0], [null, "", `/sign?ceremony=${ceremony}`], "the ceremony stays in the address, so a reload keeps it");
  assert.equal(requests.length, 1);
  assert.equal(requests[0].path, "/sign/action");
  assert.equal(requests[0].options.credentials, "same-origin");
  assert.equal(requests[0].options.headers["x-oneiron-esign-capability"], undefined);
  // Review round 1 of #7663: each call names the ceremony the page shows.
  assert.equal(requests[0].options.headers["x-oneiron-sign-ceremony"], ceremony);
  assert.deepEqual(JSON.parse(requests[0].options.body), {action: {action: "load"}});
  assert.equal(submitted.length, 0);
});

test("a page with no ceremony, or a malformed one, sends nothing", async () => {
  for (const search of ["", "?ceremony=invalid", `?ceremony=${ceremony}0`, `?ceremony=${ceremony.toUpperCase()}`, `?other=1&ceremony=${ceremony}`]) {
    const {requests, history, status, submitted} = await open("/sign", "", search);
    assert.deepEqual(history[0], [null, "", "/sign"]);
    assert.equal(requests.length, 0, search);
    assert.equal(submitted.length, 0);
    assert.match(status.textContent, /unavailable/);
  }
});

test("malformed fragments never submit a bearer", async () => {
  const token = "ab".repeat(32);
  for (const hash of ["#invalid", `#${token}0`, `#${token.toUpperCase()}`]) {
    const {requests, history, status, submitted} = await open("/sign", hash);
    assert.deepEqual(history[0], [null, "", "/sign"]);
    assert.equal(requests.length, 0);
    assert.equal(submitted.length, 0);
    assert.match(status.textContent, /unavailable/);
  }
});

test("a second invitation opened in the same tab reloads instead of reusing the first bearer", async () => {
  const {requests, location, listeners} = await open("/sign", `#${"ab".repeat(32)}`);
  location.hash = `#${"cd".repeat(32)}`;
  listeners.hashchange();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(location.reloads, 1);
  assert.equal(requests.length, 1);
});
