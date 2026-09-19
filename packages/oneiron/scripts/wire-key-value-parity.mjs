// Run from the installed npm project, through scripts/wire-test-server.sh.
import assert from "node:assert/strict"
import { Oneiron, OneironError } from "oneiron"
const memory = Oneiron.connect(process.env.ONEIRON_WIRE_URL, process.env.ONEIRON_WIRE_KEY)
const address = { namespace: ["wire-key-parity", "exact"], key: "preference" }
const mode = process.argv[2]
let receipt = null
if (mode === "write") receipt = memory.keyValuePut({ ...address,
  value: { color: "blue" }, requestId: "node-key-parity-one", source: "user_stated" })
else if (mode === "delete") receipt = memory.keyValueDelete(address)
else assert.equal(mode, "read")
const reader = Oneiron.connect(process.env.ONEIRON_WIRE_URL, process.env.ONEIRON_WIRE_READ_KEY)
let readDelete
try { reader.keyValueDelete(address) } catch (error) {
  assert.ok(error instanceof OneironError)
  readDelete = error.code
}
assert.equal(readDelete, "FORBIDDEN")
console.log(JSON.stringify({ receipt, item: memory.keyValueGet(address),
  search: memory.keyValueSearch({ namespacePrefix: ["wire-key-parity"] }),
  namespaces: memory.keyValueNamespaces({ prefix: ["wire-key-parity"] }), readDelete }))
