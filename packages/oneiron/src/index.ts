/**
 * `oneiron` — memory for agents.
 *
 * Four calls are the whole quickstart: witness a turn, claim a fact, recall
 * it, read the receipts. `Oneiron.open()` gives you an embedded vault bound to
 * a local owner actor; `Oneiron.connect(url, key)` gives you the same handle
 * against a running `oneiron-server`. The two differ by one line.
 *
 * Everything below is a one-line delegate to the native client. There are
 * deliberately no service classes, repositories, request builders, or
 * per-verb error wrappers: every verb's semantics live once, in Rust, and
 * anything this file added would be a second place for them to drift.
 */

import { OneironError, translateNativeError } from "./error.js"
import { NativeClient } from "./native.js"
import type {
  ClaimInput,
  CommitReceipt,
  FacadeReceipt,
  MemoryPack,
  OpenOptions,
  RecallOptions,
  WitnessReceipt,
  WitnessTurn,
} from "./types.js"

/** A handle on one Oneiron memory, embedded or remote. */
export class Oneiron {
  readonly #client: NativeClient

  /**
   * Internal. `open` and `connect` are the only public constructors; direct
   * construction is unsupported and this signature is not part of the
   * contract.
   */
  private constructor(client: NativeClient) {
    this.#client = client
  }

  /**
   * Opens an embedded vault and returns an actor-bound handle.
   *
   * Omitting `path` resolves to `~/.oneiron/default` against the current
   * process home, at call time. The handle is usable immediately: there is no
   * `asActor` call to make first.
   *
   * A second process opening the same directory fails with
   * `VAULT_LOCKED_SINGLE_WRITER`; connect to the owning process instead.
   */
  static open(path?: string, opts: OpenOptions = {}): Oneiron {
    try {
      return new Oneiron(NativeClient.open(path, opts.dimensions))
    } catch (error) {
      throw translateNativeError(error)
    }
  }

  /**
   * Binds a running `oneiron-server` through its facade projection.
   *
   * `key` is a minted slip, passed verbatim as
   * `Authorization: Bearer v2.<claims>.<mac-hex>`. This package never parses,
   * splits, reorders, or validates it: every authority decision is made
   * server-side from the MAC-verified `principal_ref` and `actor_class`
   * claims.
   */
  static connect(url: string, key: string): Oneiron {
    try {
      return new Oneiron(NativeClient.connect(url, key))
    } catch (error) {
      throw translateNativeError(error)
    }
  }

  /**
   * Returns a NEW handle bound to another actor; the original is unchanged.
   *
   * `actorKey` uses the pinned `human:<ref>` / `agent:<ref>` / `system:<ref>`
   * grammar. On a connected handle this fails with `FORBIDDEN`: a remote
   * principal cannot widen or replace the actor its slip bound, so reconnect
   * with a differently scoped slip instead.
   */
  asActor(actorKey: string): Oneiron {
    return new Oneiron(this.#call(() => this.#client.asActor(actorKey)))
  }

  /**
   * Witnesses one conversational turn.
   *
   * Omitting `occurredAt` stamps the current wall clock, in Unix seconds, at
   * the call boundary.
   */
  witness(turn: WitnessTurn): WitnessReceipt {
    return this.#call(() => this.#client.witness(turn))
  }

  /** Upserts one claim. The consent gate, not this call, decides approval. */
  claimUpsert(claim: ClaimInput): CommitReceipt {
    return this.#call(() => this.#client.claimUpsert(claim))
  }

  /**
   * Recalls a memory pack.
   *
   * `effort: "deep"` is lease-gated and returns `LEASE_REQUIRED` until a
   * lease-bearing constructor exists; this package neither mints nor
   * simulates a lease.
   */
  recall(query: string, opts: RecallOptions = {}): MemoryPack {
    return this.#call(() =>
      this.#client.recall(query, opts.effort ?? "standard", opts.scope, opts.limit ?? 10, opts.format),
    )
  }

  /** Governance receipts, newest first. */
  receipts(limit = 100): FacadeReceipt[] {
    return this.#call(() => this.#client.receipts(limit))
  }

  /** The one place a native throw becomes an `OneironError`. */
  #call<T>(operation: () => T): T {
    try {
      return operation()
    } catch (error) {
      throw translateNativeError(error)
    }
  }
}

export { OneironError }
export type * from "./types.js"
