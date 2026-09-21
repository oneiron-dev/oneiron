import { expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Oneiron, OneironError } from "../src/index.js"

test("native exact key, replay, namespace and deletion round trip", () => {
  const dir = mkdtempSync(join(tmpdir(), "oneiron-keyed-"))
  try {
    const memory = Oneiron.open(join(dir, "vault"))
    const address = { namespace: ["preferences"], key: "color" }
    const request = { ...address, value: { name: "blue" }, requestId: "one", source: "user_stated" }
    expect(memory.keyValueGet(address)).toBeNull()
    const receipt = memory.keyValuePut(request)
    expect(memory.keyValuePut(request).replayed).toBe(true)
    expect(memory.keyValueGet(address)).toEqual(receipt.item)
    expect(memory.keyValueSearch({ namespacePrefix: ["preferences"], limit: undefined,
      filter: undefined, offset: undefined })).toEqual([receipt.item])
    expect(memory.keyValueNamespaces({ maxDepth: undefined, limit: undefined })).toEqual([["preferences"]])
    expect(memory.keyValueDelete(address).existed).toBe(true)
    expect(memory.keyValueGet(address)).toBeNull()
    expect(memory.keyValueDelete(address).existed).toBe(false)
    try {
      memory.keyValuePut(request)
      throw new Error("old request resurrected a deleted key")
    } catch (error) {
      expect(error).toBeInstanceOf(OneironError)
      expect((error as OneironError).code).toBe("INVALID_STATE")
    }
    expect(() => memory.keyValuePut({ ...request, value: { invalid: Number.NaN } })).toThrow(OneironError)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
