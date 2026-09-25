/**
 * `oneiron` — memory for agents.
 *
 * Four calls are the whole quickstart: witness a turn, claim a fact, recall
 * it, read the receipts. `Oneiron.open()` gives you an embedded vault bound to
 * a local owner actor; `Oneiron.connect(url, key)` gives you the same handle
 * against a running `oneiron-server`, where `key` is the credential
 * `Oneiron.pair(link)` returned once. The two differ by one line.
 *
 * Everything below is a one-line delegate to the native client. There are
 * deliberately no service classes, repositories, request builders, or
 * per-verb error wrappers: every verb's semantics live once, in Rust, and
 * anything this file added would be a second place for them to drift.
 */

import { OneironError, translateNativeError } from "./error.js"
import { NativeClient } from "./native.js"
import { agentVerbs } from "./agent-verbs.js"
import type { TaskCancelReceipt, TaskDescription } from "./agent-verbs.js"

import { itemFromWire, keyedJson } from "./key-value.js"
import type { WireItem } from "./key-value.js"
import type {
  KeyValueAddress,
  KeyValuePut,
  KeyValueItem,
  KeyValuePutReceipt,
  KeyValueDeleteReceipt,
  KeyValueSearch,
  KeyValueNamespaces,
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
  readonly tasks: ReturnType<typeof agentVerbs>["tasks"]
  readonly rooms: ReturnType<typeof agentVerbs>["rooms"]

  /**
   * Internal. `open` and `connect` are the only public constructors; direct
   * construction is unsupported and this signature is not part of the
   * contract.
   */
  private constructor(client: NativeClient) {
    this.#client = client
    const verbs = agentVerbs((method, input) => this.#call(() => {
      const call = this.#client[method as keyof NativeClient] as (input: unknown) => unknown
      return call.call(this.#client, input)
    }))
    this.tasks = verbs.tasks
    this.rooms = verbs.rooms
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
   * `key` is the credential `pair` returned. The package signs every request
   * with it, and never reads the slip's claims: write identity is the
   * server's to decide from the slip it verifies.
   */
  static connect(url: string, key: string): Oneiron {
    try {
      return new Oneiron(NativeClient.connect(url, key))
    } catch (error) {
      throw translateNativeError(error)
    }
  }

  /**
   * Redeems a one-use pairing link and connects with the credential it
   * returns. Store the credential as `ONEIRON_KEY`; the link cannot be
   * redeemed twice.
   */
  static pair(link: string): { memory: Oneiron; credential: string } {
    let paired: { url: string; credential: string }
    try {
      paired = NativeClient.pair(link)
    } catch (error) {
      throw translateNativeError(error)
    }
    return { memory: Oneiron.connect(paired.url, paired.credential), credential: paired.credential }
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

  // BEGIN GENERATED FACADE VERBS
  /** Cancels one task under the ladder's `auto` default. The receipt says what stopped and what became a proposal instead. */
  cancel(taskRef: string): TaskCancelReceipt { return this.#call(() => this.#client.cancel({task_ref: taskRef}) as TaskCancelReceipt) }
  /** Describes one task's card, or the whole TASKS section when no task is named. */
  describe(taskRef?: string): TaskDescription { return this.#call(() => this.#client.describe({task_ref: taskRef}) as TaskDescription) }
  /**
   * Witnesses one conversational turn.
   *
   * Omitting `occurredAt` stamps the current wall clock, in Unix seconds, at
   * the call boundary.
   */
  witness(turn: WitnessTurn): WitnessReceipt { return this.#call(() => this.#client.witness(turn)) }
  /** Upserts one claim. The consent gate, not this call, decides approval. */
  claimUpsert(claim: ClaimInput): CommitReceipt { return this.#call(() => this.#client.claimUpsert(claim)) }
  /**
   * Recalls a memory pack.
   *
   * `effort: "high"`, `"xhigh"`, or `"max"` is lease-gated and returns `LEASE_REQUIRED` until a
   * lease-bearing constructor exists; this package neither mints nor
   * simulates a lease.
   */
  recall(query: string, opts: RecallOptions = {}): MemoryPack { return this.#call(() => this.#client.recall(query, opts.effort ?? "medium", opts.scope, opts.limit ?? 10, opts.format)) }
  /** Governance receipts, newest first. */
  receipts(limit: number = 100): FacadeReceipt[] { return this.#call(() => this.#client.receipts(limit)) }
  /** Exact actor-owned worldless key lookup, never recall. */
  keyValueGet(request: KeyValueAddress): KeyValueItem | null { return this.#call(() => {  const result = JSON.parse(this.#client.keyValueGet(keyedJson(request))) as WireItem | null; return result === null ? null : itemFromWire(result) }) }
  /** Synchronous gated write. Review-required writes fail without changing the key. */
  keyValuePut(request: KeyValuePut): KeyValuePutReceipt { return this.#call(() => { const { requestId, ...rest } = request; const result = JSON.parse(this.#client.keyValuePut(keyedJson({ ...rest, request_id: requestId }))) as {item: WireItem; replayed: boolean; receipt_ref: string}; return {item: itemFromWire(result.item), replayed: result.replayed, receiptRef: result.receipt_ref} }) }
  /** Retracts only the caller's current key; preserves claim history. */
  keyValueDelete(request: KeyValueAddress): KeyValueDeleteReceipt { return this.#call(() => {  const result = JSON.parse(this.#client.keyValueDelete(keyedJson(request))) as {existed: boolean; receipt_refs: string[]}; return {existed: result.existed, receiptRefs: result.receipt_refs} }) }
  /** Exact prefix search, ordered lexically and paginated after filtering. */
  keyValueSearch(request: KeyValueSearch): KeyValueItem[] { return this.#call(() => { const { namespacePrefix = [], ...rest } = request; const result = JSON.parse(this.#client.keyValueSearch(keyedJson({ ...rest, namespace_prefix: namespacePrefix }))) as WireItem[]; return result.map(item => itemFromWire(item)) }) }
  /** Exact segment namespace enumeration. Empty namespaces are not retained. */
  keyValueNamespaces(request: KeyValueNamespaces): string[][] { return this.#call(() => { const { maxDepth, ...rest } = request; const result = JSON.parse(this.#client.keyValueNamespaces(keyedJson({ ...rest, max_depth: maxDepth }))) as string[][]; return result.map(item => item) }) }

// END GENERATED FACADE VERBS

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

export type { OutcomeBinding, CalibrationPair, TaskAssignee, ConsultPayloadRef, TaskAskOptionId, TaskAskTarget, TaskAskQuestion, TaskAskElectorate, TaskAskNeed, TaskAskDecide, TaskAskDefault, TaskAskDisagree, TaskAskClass, TaskAskSpec, TaskAskHandle, TaskAskReceipt, TaskAskWord, TaskAskAnswer, TaskAskCoverage, TaskAskDecision, TaskAskFallback, TaskAskEvidence, TaskAskSettlement, TaskAskResult, TaskAskStatus, TaskAskWait, TaskCancelReceipt, TaskDescription } from "./agent-verbs.js"
