/**
 * The public export census (ONE-1441 I6 — closed exports).
 *
 * The package's runtime surface is exactly `Oneiron` and `OneironError`. Every
 * raw native class — `VaultBridge`, `ActorScopedVault`, `NativeClient`,
 * `NapiVault` — is an implementation detail, and a package that leaked one
 * would be promising to keep it working.
 */

import { describe, expect, test } from "bun:test"

import { readFileSync } from "node:fs"

import * as pkg from "../src/index.js"

/** The whole public runtime surface, spelled once. */
const PUBLIC_EXPORTS = ["Oneiron", "OneironError"]

/** Names that must never become reachable from the package entry. */
const FORBIDDEN_EXPORTS = [
  "NativeClient",
  "VaultBridge",
  "ActorScopedVault",
  "NapiVault",
  "Vault",
  "OneironClient",
]

describe("export census", () => {
  test("exports exactly the closed public catalog", () => {
    expect(Object.keys(pkg).sort()).toEqual([...PUBLIC_EXPORTS].sort())
  })

  test("exposes no native or storage class", () => {
    for (const name of FORBIDDEN_EXPORTS) {
      expect(pkg).not.toHaveProperty(name)
    }
  })

  test("Oneiron has exactly the declared verb catalog", () => {
    // Direct verbs live on the prototype; dotted verbs live in generated families.
    // Assert both against the same complete facade catalog.
    const instanceMethods = Object.getOwnPropertyNames(pkg.Oneiron.prototype)
      .filter((name) => name !== "constructor")
      .sort()
    const manifest = JSON.parse(readFileSync(new URL("../../../scripts/sdk/agent-verbs.json", import.meta.url), "utf8")) as { verbs: { name: string }[] }
    const verbs = manifest.verbs.map((row) => row.name)
    expect(verbs.length).toBeGreaterThan(0)
    const jsVerbs = verbs.filter((verb) => !verb.includes(".")).map((verb) => verb.replace(/_([a-z])/g, (_, ch) => ch.toUpperCase()))
    expect(instanceMethods).toEqual(["asActor", ...jsVerbs].sort())
    // connect validates configuration only; this census sends no request.
    const instance = pkg.Oneiron.connect("http://127.0.0.1:9/", "census-unused")
    const families = [...new Set(verbs.filter((verb) => verb.includes(".")).map((verb) => verb.split(".")[0]))]
    expect(Object.keys(instance).sort()).toEqual([...families].sort())
    for (const family of families) {
      const projected = (instance as unknown as Record<string, Record<string, unknown>>)[family]
      expect(Object.keys(projected).sort()).toEqual(
        verbs.filter((verb) => verb.startsWith(`${family}.`)).map((verb) => verb.split(".")[1]).sort(),
      )
      expect(Object.values(projected).every((method) => typeof method === "function")).toBe(true)
    }

    expect(typeof pkg.Oneiron.open).toBe("function")
    expect(typeof pkg.Oneiron.connect).toBe("function")
  })

  test("OneironError carries the contract fields", () => {
    const error = new pkg.OneironError("BAD_REQUEST", "nope", ["fix it"])
    expect(error).toBeInstanceOf(Error)
    expect(error.code).toBe("BAD_REQUEST")
    expect(error.message).toBe("nope")
    expect(error.suggestions).toEqual(["fix it"])
  })
})
