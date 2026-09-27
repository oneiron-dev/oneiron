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

  // ── C07: legacy NapiVault entity roundtrip + SDK receipts ──
  const { NapiVault } = require(addonPath)
  const vault = new NapiVault(join(dir, "vault-entity"), 4)
  const id = Buffer.alloc(16, 0x41)
  // Kind 4 is a conversation. The engine takes its body only as a MessagePack
  // map (ConversationBody, every field optional); this is {"title": title}.
  const title = Buffer.from("native host payload")
  const payload = Buffer.concat([
    Buffer.from([0x81, 0xa5]),
    Buffer.from("title"),
    Buffer.from([0xa0 | title.length]),
    title,
  ])
  assert.equal(vault.getEntity(id), null)
  assert.equal(vault.entityExists(id), false)
  vault.putEntity(id, 4, 1, 1, 1, payload)
  const stored = vault.getEntity(id)
  assert.ok(Buffer.isBuffer(stored))
  assert.ok(stored.includes(payload))
  assert.equal(vault.entityExists(id), true)
  assert.deepEqual(vault.getEntity(id), stored)
  assert.equal(vault.deleteEntity(id), true)
  assert.deepEqual(vault.getEntity(id), Buffer.alloc(0)) // shell, not hard purge
  assert.equal(vault.entityExists(id), true)
  assert.equal(vault.deleteEntity(id), true) // the shell still exists

  // ONE-479: reject JS-owned input before napi-rs builds owned String/Vec/DTO.
  // Throwing index getters prove oversized arrays are rejected without traversal.
  const unvisited = (size) => {
    const items = new Array(size)
    Object.defineProperty(items, 0, { get() { throw new Error("element was visited") } })
    return items
  }
  const longQuery = "🧠".repeat(20000) // UTF-16 length != UTF-8 bytes.
  const queryError = /query must be <= .* bytes, got 80000/
  assert.throws(() => vault.searchText(longQuery, 1), queryError)
  assert.throws(() => vault.searchTextScoped(longQuery, 1), queryError)
  assert.throws(() => vault.contextPack(longQuery), queryError)
  assert.throws(() => vault.contextPackScoped(longQuery), queryError)
  assert.throws(() => vault.searchVector(unvisited(5), 1), /query vector length must equal vault dimensions/)
  assert.throws(() => vault.putVector(id, unvisited(5)), /vector length must equal vault dimensions/)
  assert.throws(() => vault.contextPack(undefined, unvisited(5)), /query vector length must equal vault dimensions/)
  assert.throws(() => vault.contextPackScoped(undefined, unvisited(5)), /query vector length must equal vault dimensions/)
  assert.throws(() => vault.batchPutEntities(unvisited(100001)), /batch_put_entities accepts at most/)
  assert.throws(() => vault.putCodebaseSnapshot(id, { files: unvisited(100001) }), /codebase snapshot accepts at most/)
  // A getter cannot swap the checked manifest for an oversized one during DTO conversion.
  let fileReads = 0
  const swappingSnapshot = {
    projectId: "test", repoRef: "bad-repo-ref",
    get files() { return ++fileReads === 1 ? [] : unvisited(100001) },
  }
  try { vault.putCodebaseSnapshot(id, swappingSnapshot) } catch (_) { /* invalid repo is expected */ }
  assert.equal(fileReads, 1)
  console.log("NODE-HOST-OK: JS string and array caps precede native DTO allocation")

  const client2 = NativeClient.open(join(dir, "client"), 4)
  assert.deepEqual(client2.receipts(10), [])
  // Exercise real Node-API exception conversion, not a hostless Rust helper.
  assert.throws(() => NativeClient.open(join(dir, "bad"), 0), (error) => {
    assert.equal(JSON.parse(error.message).code, "BAD_REQUEST")
    return true
  })
  console.log("NODE-HOST-OK: production addon load, entity roundtrip/delete, SDK receipts, typed refusal")
} finally {
  rmSync(dir, { recursive: true, force: true })
}
