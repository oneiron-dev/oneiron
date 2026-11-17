const {readFileSync} = require("node:fs");
const {join} = require("node:path");
const {runInNewContext} = require("node:vm");
const {test} = require("node:test");
const assert = require("node:assert/strict");

const script = readFileSync(join(__dirname, "../src/api/esign_qr/page.js"), "utf8");

const PAGE = {
  document_ref: "0".repeat(32),
  title: "Agreement",
  outcome: "completed",
  sealed_at: 1800000000,
  audit_chain_sha256: "ef".repeat(32),
  signers: [{name: "Owen", role: "approver", signed_at: 1800000000}],
  items: [{
    item: 0,
    sealed_artifact: "1".repeat(32),
    sealed_version: 1,
    sha256: "12".repeat(32),
    profile: {requested: "baseline_t", achieved: "baseline_b", degraded: [{requested: "baseline_t", achieved: "baseline_b", reason: "timestamp_unavailable"}]},
    self_verify: "passed",
  }],
};

const settle = async () => {
  for (let turn = 0; turn < 6; turn += 1) await new Promise(resolve => setImmediate(resolve));
};

async function open(hash, answer = {ok: true, json: async () => PAGE}, pdfAnswer = {ok: true, blob: async () => "sealed-bytes"}) {
  const requests = [];
  const history = [];
  const rows = [];
  const paragraphs = [];
  const buttons = [];
  const clicked = [];
  const listeners = new Map();
  const reloads = [];
  const status = {textContent: ""};
  const report = {append(...nodes) { rows.push(...nodes.map(node => node.textContent)); }};
  const reading = {append(...nodes) {
    for (const node of nodes) {
      paragraphs.push(node.textContent);
      if (node.tag === "button") buttons.push(node);
    }
  }};
  const nodes = new Map([["status", status], ["report", report], ["reading", reading]]);
  const document = {
    getElementById(id) { return nodes.get(id); },
    createElement(tag) {
      const handlers = new Map();
      return {
        tag,
        textContent: "",
        addEventListener(type, handler) { handlers.set(type, handler); },
        handlers,
        click() { clicked.push({tag, href: this.href, download: this.download}); },
      };
    },
  };
  runInNewContext(script, {
    location: {pathname: "/esign/verify", hash, reload() { reloads.push(requests.length); }},
    history: {replaceState(...args) { history.push(args); }},
    window: {addEventListener(type, listener) { listeners.set(type, listener); }},
    document,
    URL: {createObjectURL(blob) { return `blob:${blob}`; }, revokeObjectURL() {}},
    setTimeout() {},
    fetch: async (path, options) => {
      requests.push({path, options, scrubbed: history.length});
      return path === "/esign/verify/pdf" ? pdfAnswer : answer;
    },
  });
  await settle();
  return {requests, history, status, rows, paragraphs, buttons, clicked, listeners, reloads};
}

test("a QR page's fragment capability is posted in its header only after scrubbing the URL", async () => {
  const token = "ab".repeat(32);
  const {requests, history, status, rows} = await open(`#${token}`);
  assert.deepEqual(history[0], [null, "", "/esign/verify"]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].scrubbed, 1, "the URL is scrubbed before the capability is posted");
  assert.equal(requests[0].path, "/esign/verify/report");
  assert.equal(requests[0].options.method, "POST");
  assert.equal(requests[0].options.credentials, "omit");
  assert.equal(requests[0].options.referrerPolicy, "no-referrer");
  assert.equal(requests[0].options.headers["x-oneiron-esign-qr-capability"], token);
  assert.equal(requests[0].options.body, undefined);
  assert.match(status.textContent, /signed and sealed/);
  assert.ok(rows.includes("Agreement"));
  assert.ok(rows.includes("12".repeat(32)), "the item's hash is shown");
  assert.ok(rows.includes("baseline_t: timestamp_unavailable"), "what the seal could not reach is shown");
  assert.ok(!rows.some(row => row.includes(token)), "the capability is never drawn");
});

test("a sealed report keeps a missing trust root and a changed document in two sentences", async () => {
  const {rows, paragraphs} = await open(`#${"ab".repeat(32)}`);
  assert.ok(rows.includes("every applicable check ran and passed"), "the seal-time checks are stated");
  const trust = paragraphs.filter(text => text.includes("your reader does not have the trust root for this signer"));
  const changed = paragraphs.filter(text => text.includes("this document was changed after signing"));
  assert.equal(trust.length, 1, "the trust-root sentence is shown once");
  assert.equal(changed.length, 1, "the changed-document sentence is shown once");
  assert.notEqual(trust[0], changed[0], "the two facts are separate sentences");
  assert.ok(!trust[0].includes("changed"), "a missing trust root never reads as a change");
  assert.match(changed[0], /nothing has changed since it was sealed/);
});

test("a sealed report sends each party to its own signing link for the PDF", async () => {
  for (const pdf_download of [undefined, false]) {
    const {rows, paragraphs, buttons} = await open(`#${"ab".repeat(32)}`, {ok: true, json: async () => ({...PAGE, pdf_download})});
    const pdf = paragraphs.filter(text => text.includes("never shows the signed PDF"));
    assert.equal(pdf.length, 1, "the page says once that it shows no PDF");
    assert.match(pdf[0], /from their own signing link/, "the possession factor is the party's signing link");
    assert.ok(!rows.some(text => /\.pdf|download/i.test(text)), "no report row offers the PDF");
    assert.deepEqual(buttons, [], "no download is offered while the owner's QR PDF download is off");
  }
});

test("with the owner's QR PDF download on, each item downloads under the capability header", async () => {
  const token = "ab".repeat(32);
  const {requests, paragraphs, buttons, clicked, status} = await open(`#${token}`, {ok: true, json: async () => ({...PAGE, pdf_download: true})});
  assert.ok(!paragraphs.some(text => text.includes("never shows the signed PDF")), "the no-PDF sentence is not shown");
  assert.equal(paragraphs.filter(text => text.includes("The owner lets this page download the sealed PDF")).length, 1);
  assert.deepEqual(buttons.map(button => button.textContent), ["Download sealed item 1"]);
  assert.equal(requests.length, 1, "nothing is downloaded before the button is pressed");
  buttons[0].handlers.get("click")();
  await settle();
  assert.equal(requests.length, 2);
  const download = requests[1];
  assert.equal(download.path, "/esign/verify/pdf");
  assert.equal(download.options.method, "POST");
  assert.equal(download.options.credentials, "omit");
  assert.equal(download.options.referrerPolicy, "no-referrer");
  assert.equal(download.options.headers["x-oneiron-esign-qr-capability"], token);
  assert.deepEqual(JSON.parse(download.options.body), {item: 0});
  assert.ok(!download.path.includes(token), "the capability never rides a URL");
  assert.deepEqual(clicked, [{tag: "a", href: "blob:sealed-bytes", download: "sealed-document-1.pdf"}]);
  assert.match(status.textContent, /signed and sealed/);
});

test("a refused QR PDF download says so and saves nothing", async () => {
  const {buttons, clicked, status} = await open(`#${"ab".repeat(32)}`, {ok: true, json: async () => ({...PAGE, pdf_download: true})}, {ok: false, status: 404});
  buttons[0].handlers.get("click")();
  await settle();
  assert.deepEqual(clicked, []);
  assert.match(status.textContent, /not available from this page/);
});

test("a later QR fragment in the same tab reloads the page instead of keeping the first report", async () => {
  const {requests, listeners, reloads, rows} = await open(`#${"ab".repeat(32)}`);
  assert.equal(requests.length, 1);
  assert.ok(rows.includes("Agreement"), "the first report is drawn");
  const listener = listeners.get("hashchange");
  assert.equal(typeof listener, "function", "the page listens for a fragment change");
  listener();
  assert.deepEqual(reloads, [1], "the next fragment reloads the page, which reads its own capability");
});

test("malformed fragments never post a capability", async () => {
  const token = "ab".repeat(32);
  for (const hash of ["", "#invalid", `#${token}0`, `#${token.toUpperCase()}`]) {
    const {requests, history, status} = await open(hash);
    assert.deepEqual(history[0], [null, "", "/esign/verify"]);
    assert.equal(requests.length, 0);
    assert.match(status.textContent, /not valid/);
  }
});

test("a refused capability shows one sentence and no report", async () => {
  const {requests, status, rows, paragraphs} = await open(`#${"cd".repeat(32)}`, {ok: false, status: 404});
  assert.equal(requests.length, 1);
  assert.match(status.textContent, /not valid, was revoked, or has expired/);
  assert.deepEqual(rows, []);
  assert.deepEqual(paragraphs, [], "a refused capability explains no document");
});
