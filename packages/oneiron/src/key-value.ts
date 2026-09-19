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
    const encoded = JSON.stringify(value, function (this: unknown, key, entry: unknown) {
      if (entry === undefined && this === value && optional.has(key)) return undefined
      if (entry === undefined || typeof entry === "function" || typeof entry === "symbol"
          || (typeof entry === "number" && !Number.isFinite(entry))) {
        throw new TypeError("keyed values must be finite JSON data")
      }
      return entry
    })
    if (encoded === undefined) throw new TypeError("keyed input must be JSON data")
    return encoded
  } catch (error) {
    throw new OneironError("BAD_REQUEST", String(error), ["Use finite, JSON-compatible keyed values."])
  }
}
