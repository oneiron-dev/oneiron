// Exercise the production addon inside Node, separately from Rust libtest.
// Usage: node crates/oneiron-napi/tests/node_host.cjs <built-cdylib>
const assert = require("node:assert/strict")
const { copyFileSync, mkdtempSync, rmSync } = require("node:fs")
const { tmpdir } = require("node:os")
const { join, resolve } = require("node:path")

assert.ok(process.argv[2], "pass the production addon path")
const dir = mkdtempSync(join(tmpdir(), "oneiron-addon-host-"))
try {
  const addonPath = join(dir, "oneiron.node")
  copyFileSync(resolve(process.argv[2]), addonPath)
  const { NativeClient } = require(addonPath)
  assert.equal(typeof NativeClient.open, "function")
  const client = NativeClient.open(join(dir, "vault"))
  assert.ok(Array.isArray(client.receipts(10)))
  const address = { namespace: ["host-test"], key: "preference" }
  const request = {
    ...address, value: { theme: "dark" },
    request_id: "node-host-one", source: "user_stated",
  }
  const get = () => JSON.parse(client.keyValueGet(JSON.stringify(address)))
  assert.equal(get(), null)
  const receipt = JSON.parse(client.keyValuePut(JSON.stringify(request)))
  assert.deepEqual(get(), receipt.item)
  assert.equal(JSON.parse(client.keyValuePut(JSON.stringify(request))).replayed, true)
  assert.equal(JSON.parse(client.keyValueDelete(JSON.stringify(address))).existed, true)
  assert.equal(get(), null)
  // Exercise N-API exception conversion on the ordinary production graph too.
  assert.throws(() => NativeClient.open(join(dir, "bad"), 0), /BAD_REQUEST/)
  console.log("NODE-HOST-OK: production addon load, keyed writes/replay/delete, typed refusal")
} finally {
  rmSync(dir, { recursive: true, force: true })
}
