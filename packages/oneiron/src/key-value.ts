/** Private JSON DTO conversion. No storage, transport, or policy logic. */
import { OneironError } from "./error.js"
import type { KeyValueItem } from "./types.js"

export interface WireItem {
  namespace: string[]; key: string; value: Record<string, unknown>
  created_at: number; updated_at: number; revision: string
}
export function itemFromWire(item: WireItem): KeyValueItem {
  return { namespace: item.namespace, key: item.key, value: item.value,
    createdAt: item.created_at, updatedAt: item.updated_at, revision: item.revision }
}
export function keyedJson(value: unknown): string {
  try {
    const optional = new Set(["source", "limit", "offset", "filter", "max_depth", "namespace_prefix", "prefix", "suffix"])
    const active = new Set<object>()
    const normalize = (node: unknown, root = false): unknown => {
      if (node === null || typeof node === "string" || typeof node === "boolean") return node
      if (typeof node === "number" && Number.isFinite(node)) return node
      if (typeof node !== "object" || node === null) throw new TypeError("keyed values must be finite JSON data")
      if (active.has(node)) throw new TypeError("keyed values must not contain cycles")
      if (!Array.isArray(node) && ![Object.prototype, null].includes(Object.getPrototypeOf(node))) {
        throw new TypeError("keyed values must contain only plain JSON objects and arrays")
      }
      if (Object.getOwnPropertySymbols(node).length) throw new TypeError("JSON object keys must be strings")
      active.add(node)
      // Copy once before JSON.stringify, so accessors/toJSON cannot transform a
      // value after validation. Array.from visits sparse slots as undefined.
      const result = Array.isArray(node)
        ? Array.from(node, entry => normalize(entry))
        : Object.fromEntries(Object.entries(node)
          .filter(([key, entry]) => !(root && entry === undefined && optional.has(key)))
          .map(([key, entry]) => [key, normalize(entry)]))
      active.delete(node)
      return result
    }
    const encoded = JSON.stringify(normalize(value, true))
    if (encoded === undefined) throw new TypeError("keyed input must be JSON data")
    return encoded
  } catch (error) {
    throw new OneironError("BAD_REQUEST", String(error), ["Use finite, JSON-compatible keyed values."])
  }
}
