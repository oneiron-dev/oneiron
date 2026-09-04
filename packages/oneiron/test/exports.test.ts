/**
 * The public export census (ONE-1441 I6 — closed exports).
 *
 * The package's runtime surface is exactly `Oneiron` and `OneironError`. Every
 * raw native class — `VaultBridge`, `ActorScopedVault`, `NativeClient`,
 * `NapiVault` — is an implementation detail, and a package that leaked one
 * would be promising to keep it working.
 */

import { describe, expect, test } from "bun:test"

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
    // The four calls of the canonical quickstart, plus the two constructors
    // and the actor rebind. Compared as a SET so an accidental extra public
    // method is a failing test rather than a silent surface expansion.
    const instanceMethods = Object.getOwnPropertyNames(pkg.Oneiron.prototype)
      .filter((name) => name !== "constructor")
      .sort()
    expect(instanceMethods).toEqual([
      "asActor",
      "claimUpsert",
      "recall",
      "receipts",
      "witness",
    ])

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
