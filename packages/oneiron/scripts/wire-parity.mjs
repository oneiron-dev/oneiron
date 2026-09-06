// Run only through scripts/wire-test-server.sh, from the installed npm project.
// Missing fixture inputs are errors, never skipped remote coverage.
import assert from "node:assert/strict"
import { Oneiron, OneironError } from "oneiron"

function required(name) {
  assert.ok(process.env[name], `missing fixture input: ${name}`)
  return process.env[name]
}

const url = required("ONEIRON_WIRE_URL")
const memory = Oneiron.connect(url, required("ONEIRON_WIRE_KEY"))
const mode = process.argv[2]
assert.ok(mode === "write" || mode === "read", "expected write or read mode")

function refusal(operation, code) {
  try {
    operation()
  } catch (error) {
    assert.ok(error instanceof OneironError)
    assert.equal(error.code, code)
    assert.ok(error.message.length > 0)
    assert.ok(error.suggestions.length > 0)
    return { code: error.code, message: error.message, suggestions: error.suggestions }
  }
  throw new Error("expected a typed refusal")
}

let witnessed
let claimed
if (mode === "write") {
  // Python pins both SDKs' fixture ages. Do not stamp this write with now:
  // standard recall's recency ranks must survive the later parity reads.
  const occurredAt = Number(required("WIRE_PARITY_OCCURRED_AT"))
  assert.ok(Number.isSafeInteger(occurredAt) && occurredAt >= 0)
  witnessed = memory.witness({
    conversationRef: "33333333333333333333333333333333",
    occurredAt,
    messages: [{
      author: "user", messageType: "dialogue",
      content: "I prefer a window seat when I fly.", order: 0,
    }],
  })
  claimed = memory.claimUpsert({
    id: "44444444444444444444444444444444",
    predicate: "preference.travel.seat",
    subjectRef: witnessed.turnShortId,
    value: { seat: "window" }, confidence: 1, source: "user_stated",
    occurredAt, learnedAt: occurredAt,
  })
}

const recalled = memory.recall("window seat")
const receipts = memory.receipts()
const errors = {
  deep: refusal(() => memory.recall("window seat", { effort: "deep" }), "LEASE_REQUIRED"),
  rebind: refusal(() => memory.asActor("human:00000000000000000000000000000001"), "FORBIDDEN"),
}
for (const name of ["ONEIRON_WIRE_NO_CLASS_KEY", "ONEIRON_WIRE_NO_PRINCIPAL_KEY"]) {
  const unbound = Oneiron.connect(url, required(name))
  errors[name] = refusal(() => unbound.receipts(), "FORBIDDEN")
}
const reader = Oneiron.connect(url, required("ONEIRON_WIRE_READ_KEY"))
assert.ok(Array.isArray(reader.receipts()))
errors.readWrite = refusal(() => reader.witness({
  conversationRef: "77777777777777777777777777777777",
  messages: [{ author: "user", messageType: "dialogue", content: "refused", order: 0 }],
}), "FORBIDDEN")
errors.readClaim = refusal(() => reader.claimUpsert({
  predicate: "preference.travel.seat", subjectRef: "33333333333333333333333333333333",
  value: { seat: "window" }, confidence: 1, source: "user_stated",
}), "FORBIDDEN")

console.log(JSON.stringify({ witnessed, claimed, recalled, receipts, errors }))
