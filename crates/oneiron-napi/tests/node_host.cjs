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
  const { NapiVault, NativeClient } = require(addonPath)
  const vault = new NapiVault(join(dir, "vault"), 4)
  const id = Buffer.alloc(16, 0x41)
  const payload = Buffer.from("native host payload")
  assert.equal(vault.getEntity(id), null)
  assert.equal(vault.entityExists(id), false)
  // ENTITY_TYPE_PERSON is 4 in the current registry.
  vault.putEntity(id, 4, 1, 1, 1, payload)
  const stored = vault.getEntity(id)
  assert.ok(Buffer.isBuffer(stored))
  assert.ok(stored.includes(payload))
  assert.equal(vault.entityExists(id), true)
  assert.deepEqual(vault.getEntity(id), stored)
  assert.equal(vault.deleteEntity(id), true)
  assert.equal(vault.getEntity(id), null)
  assert.equal(vault.deleteEntity(id), false)

  const client = NativeClient.open(join(dir, "client"), 4)
  assert.deepEqual(client.receipts(10), [])
  // Exercise real Node-API exception conversion, not a hostless Rust helper.
  assert.throws(() => NativeClient.open(join(dir, "bad"), 0), (error) => {
    assert.equal(JSON.parse(error.message).code, "BAD_REQUEST")
    return true
  })
  console.log("NODE-HOST-OK: production addon load, entity roundtrip/delete, SDK receipts, typed refusal")
} finally {
  rmSync(dir, { recursive: true, force: true })
}
