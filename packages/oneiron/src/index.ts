/**
 * `oneiron` — memory for agents.
 *
 * Four calls are the whole quickstart: witness a turn (`vault.witness`),
 * claim a fact (`vault.claims.upsert`), recall it (`vault.recall`), read the
 * receipts (`vault.receipts`). Every verb sits at its SDK path: the shared
 * home under `vault`, tasks under `tasks`, and the bare verbs (`describe`,
 * `can`, `ask`, `wait`, `peek`, `cancel`) on the handle itself. `Oneiron.open()` gives you an embedded vault bound to
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
import { NativeClient, NativeEngine, type NativeEngineConnection } from "./native.js"
import type * as Facade from "./facade-types.js"
import { facadeCall, facadeClient, facadeMethods, facadeNamespaces, type FacadeMethods, type FacadeNamespaces } from "./facade-verbs.js"
import type { CalibrationPair, TaskAskAnswer, TaskAskDefault, TaskAskHandle, TaskAskPersonEvidence, TaskAskPreflight, TaskAskQuestion, TaskAskReceipt, TaskAskShort, TaskAskSpec, TaskAskWait, TaskAskWho, TaskAskWord, TaskCancelReceipt, TaskCanAskRequest, TaskDescription } from "./agent-verbs.js"

import type {
  CheckpointPin,
  EngineOptions,
  EngineReply,
  EngineRequest,
  ExportReceipt,
  FacadeReceipt,
  HostRootProfile,
  MemoryExport,
  NativeLimitQuestion,
  OpenOptions,
} from "./types.js"

/**
 * One lens-card event's body (OF-181): the client's event, and the key a
 * deterministic action's dispatch replays under. Keys keep the wire's
 * camelCase spelling.
 */
export interface LensFrameEventRequest {
  readonly event: Facade.GeneratedUiActionEvent
  readonly idempotencyKey: string
  /**
   * Selections this handle made on the card, each the `selectionRef`
   * `vault.lenses.select` answered (FIX 3268): context for a model round
   * trip, never approval or action authority; any other action ignores it.
   */
  readonly selectedContext?: readonly string[]
  /**
   * The stream profile this event's answer is framed in (FIX 11399): a
   * patch-profile caller takes the card's refinement beside a local
   * action's `$state`. Omitted, the answer is today's plain JSON.
   */
  readonly stream?: Facade.GeneratedUiStreamProfile
}

/**
 * What a lens-card event answers. There is no discriminator: a local action
 * answers the card's new `$state` (beside the card's refinement for a
 * patch-profile caller), a deterministic tool its outcome and the scoped
 * read of its entity arguments, and a model round trip the callback queued
 * for the agent that emitted the card.
 */
export type LensFrameEventReply =
  | { readonly $state: Facade.GeneratedUiStateSnapshot; readonly refinement?: Facade.GeneratedUiSegment | null }
  | { readonly outcome: unknown; readonly readReceipt: Facade.ScopedReadReceipt }
  | { readonly queued: boolean; readonly callbackId: string }

/** What a lens-card close answers: whether the server held its frame. */
export interface CloseLensFrameReply {
  readonly closed: boolean
}

/**
 * What {@link Oneiron.pair} returns: a handle connected with the credential,
 * the credential to store, the checkpoint pin the link named (OF-469),
 * `null` when the vault has no attested checkpoint, and the comm reach the
 * server says the credential carries: whom an agent paired by it may address.
 */
export interface Paired {
  readonly memory: Oneiron
  readonly credential: string
  readonly pin: CheckpointPin | null
  readonly comm: Facade.CommReach
}

/**
 * What {@link Oneiron.openWithHostRoot} returns: the embedded handle, and what
 * the open did with the host root it was given (FIX 4730).
 */
export interface HostRootOpened {
  readonly memory: Oneiron
  readonly hostRoot: HostRootProfile
}

/**
 * The full Oneiron server inside this process, from {@link Oneiron.startEngine} (OF-237).
 * Every call blocks. An engine failure throws `OneironError` with its stable code:
 * `ENGINE_STOPPED`, `ENGINE_CLOSED`, `ENGINE_RELAY_REFUSED`, `ENGINE_WRONG_THREAD`,
 * `ENGINE_CONFIG`, `ENGINE_VAULT_OPEN`, `ENGINE_START_FAILED`, `ENGINE_CONNECTION_ENDED`,
 * `ENGINE_REPLY_TOO_LARGE`, `ENGINE_BAD_REQUEST`, or `INTERNAL_SERVER_ERROR` when no cause is
 * named.
 */
export interface EmbeddedEngine {
  /**
   * A NEW handle served by this engine's server under `key`, the caller's own credential,
   * passed verbatim: the credential `pair` returned, or the host secret as a bare bearer.
   * Every verb is the request a connected handle sends, carried through the server in
   * process, so host doors answer as on any server; `asActor` refuses on it. It makes no
   * request and keeps the engine alive.
   */
  client(key: string): Oneiron
  /**
   * A NEW handle on the engine's own vault, bound to the embedded owner as `open` binds one
   * (FIX 4895): its verbs answer through the vault itself, not the server, so host doors only a
   * server answers refuse on it (use `client` for those). It keeps the engine alive; each call
   * attaches anew and none reopens the path.
   */
  localClient(): Oneiron
  /**
   * Sends one request on the API's origin and returns the whole reply. `/ws` is not served
   * through it, and a reply past the buffered ceiling throws `ENGINE_REPLY_TOO_LARGE`; open a
   * connection for those. Throws `ENGINE_STOPPED` while stopped.
   */
  request(request: EngineRequest): EngineReply
  /** {@link EmbeddedEngine.request} on the artifact app's own origin (`/a/`). */
  requestArtifact(request: EngineRequest): EngineReply
  /**
   * Opens a connection the app holds to the engine's server, served as a socket's connection,
   * HTTP/1.1 with upgrades: a `GET /ws` with its upgrade headers holds `/ws` on it, and a
   * streamed reply arrives as it is written. A stop drains it; after `wake` open another.
   */
  connect(): EngineConnection
  /** {@link EmbeddedEngine.connect} on the artifact app's own origin (`/a/`). */
  connectArtifact(): EngineConnection
  /** Runs what is due; a stopped engine serves again first. */
  wake(): void
  /** Drains, stops every worker, and keeps the vault open for `wake`. */
  stop(): void
  /** Stops the engine in order; every handle it served throws `ENGINE_CLOSED` after. */
  close(): void
}

/**
 * A connection the app holds to its embedded engine's server (FIX 4895): bytes both ways. The
 * app writes the HTTP/1.1 request and, after a `101`, the upgraded protocol's frames; it reads
 * what the server writes. Every call blocks. Once the engine stops or closes, `receive` returns
 * empty and `send` throws.
 */
export interface EngineConnection {
  send(bytes: Uint8Array): void
  /** The next bytes the server wrote; empty once the connection ended. */
  receive(): Uint8Array
  /** Ends the connection; a blocked `receive` returns empty. */
  close(): void
}

/** The verb namespaces and top-level verbs of a handle, generated from the verb table (facade-verbs.ts). */
// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
export interface Oneiron extends FacadeNamespaces, FacadeMethods {}

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
    Object.assign(this, facadeNamespaces(this))
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
      return new Oneiron(NativeClient.open(path, opts.dimensions, opts.deviceClass))
    } catch (error) {
      throw translateNativeError(error)
    }
  }

  /**
   * {@link Oneiron.open}, then this install's own machine profile from the
   * vault's host root secret (FIX 4730), so the owner's acts carry from this
   * install. `hostRootSecret` is the secret's exact bytes (a server's
   * configured `auth_secret` as its UTF-8, or a retained root), never hex or
   * base64 of them. It is JavaScript memory and stays yours: the native side
   * borrows it for this call only and keeps no copy, so clear it
   * (`hostRootSecret.fill(0)`) when you are done with it.
   *
   * Rooted-only: the vault must already be rooted, and nothing here roots it.
   * An empty secret throws `BAD_REQUEST`; a vault open under the managed or
   * relay posture, or a root the provider holds, throws `FORBIDDEN`; a secret
   * that cannot profile this install throws the engine's code and reason, and
   * `open` stays the rootless door. A secret that is not the vault's settled
   * root, over a profile that already stands, opens and says so in
   * `hostRoot.wrongRoot`. The handle binds the local owner actor, as `open`
   * does, and carries no owner proof. With `opts.holdCheckpointRootSigner`
   * (FIX 5343) the handle holds this install's host root as its checkpoint
   * signer, unless the secret went unused; omitted is `false`.
   */
  static openWithHostRoot(
    path: string | undefined,
    hostRootSecret: Uint8Array,
    opts: OpenOptions = {},
  ): HostRootOpened {
    let native: NativeClient
    try {
      native = NativeClient.openWithHostRoot(
        path,
        opts.dimensions,
        hostRootSecret,
        opts.deviceClass,
        opts.holdCheckpointRootSigner,
      )
    } catch (error) {
      throw translateNativeError(error)
    }
    const profile = native.hostRootProfile()
    return {
      memory: new Oneiron(native),
      hostRoot: {
        enrolled: profile?.enrolled ?? false,
        wrongRoot: profile?.wrongRoot ?? false,
      },
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
   * redeemed twice. The pin is already checked against the link and is
   * stored nowhere: a machine that will run a local replica keeps it beside
   * the server origin and the credential, and supplies it when that replica
   * starts.
   */
  static pair(link: string): Paired {
    let paired: { url: string; credential: string; pin?: CheckpointPin; comm: Facade.CommReach }
    try {
      paired = NativeClient.pair(link)
    } catch (error) {
      throw translateNativeError(error)
    }
    return {
      memory: Oneiron.connect(paired.url, paired.credential),
      credential: paired.credential,
      pin: paired.pin ?? null,
      comm: paired.comm,
    }
  }

  /**
   * Opens the vault at `path` and serves it in this process with the full server
   * `oneiron serve` runs (OF-237), once; {@link EmbeddedEngine.client} then binds handles
   * served by it under the caller's own credential, never a second vault open. The config is
   * the one `oneiron serve --config <configFile>` resolves for this path. Opt-in: the addon
   * carries it only when built with the `engine` cargo feature, and otherwise this throws
   * `ENGINE_UNAVAILABLE`.
   */
  static startEngine(path: string, opts: EngineOptions = {}): EmbeddedEngine {
    if (NativeEngine === undefined) {
      throw new OneironError("ENGINE_UNAVAILABLE", "this oneiron build has no embedded engine", [
        "Build the native addon with the `engine` cargo feature, or use Oneiron.connect(url, key).",
      ])
    }
    let native: NativeEngine
    try {
      native = NativeEngine.start(path, opts)
    } catch (error) {
      throw translateNativeError(error)
    }
    const call = <T>(operation: () => T): T => {
      try {
        return operation()
      } catch (error) {
        throw translateNativeError(error)
      }
    }
    const held = (connection: NativeEngineConnection): EngineConnection => ({
      send: (bytes) => call(() => connection.send(bytes)),
      receive: () => call(() => connection.receive()),
      close: () => call(() => connection.close()),
    })
    return {
      client: (key) => new Oneiron(call(() => native.client(key))),
      localClient: () => new Oneiron(call(() => native.localClient())),
      request: (request) => call(() => native.request(request)),
      requestArtifact: (request) => call(() => native.requestArtifact(request)),
      connect: () => held(call(() => native.connect())),
      connectArtifact: () => held(call(() => native.connectArtifact())),
      wake: () => call(() => native.wake()),
      stop: () => call(() => native.stop()),
      close: () => call(() => native.close()),
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
   * Returns a NEW handle whose every verb runs as a turn in a room.
   *
   * It names only the room. Each verb reads the room's roster as it stands at
   * that call and runs inside that roster's Scope (ARCH-0067 §8); a verb that
   * would read around the room fails with `BAD_REQUEST`, and so does
   * rebinding the actor or naming another room.
   */
  inRoomTurn(roomRef: string): Oneiron {
    return new Oneiron(this.#call(() => this.#client.inRoomTurn(roomRef)))
  }

  /**
   * Returns a NEW handle whose every verb runs inside the off-record session
   * `sessionRef` names, bound to this handle's principal: the app host's actor
   * when embedded, the credential's when connected (OF-063). It grants
   * nothing: inside an anonymous session that principal is verified in, a
   * refusal writes no receipt; anywhere else verbs record as before.
   */
  inOffRecordSession(sessionRef: string): Oneiron {
    return new Oneiron(this.#call(() => this.#client.inOffRecordSession(sessionRef)))
  }

  /**
   * Returns a NEW handle whose every read runs under the credential a
   * delegated reader presented (FIX 647): the paired credential `pair`
   * returned, verified once against this vault as the server's door verifies
   * a served request's. Reads refuse when the slip's holder is not this
   * handle's actor; rebindings keep the same proof, so every read still
   * checks it against the bound actor. A handle without one reads as before.
   * On a connected handle this fails with `FORBIDDEN`: it already reads
   * under the credential it connected with.
   */
  withReadCredential(credential: string): Oneiron {
    return new Oneiron(this.#call(() => this.#client.withReadCredential(credential)))
  }

  /**
   * The lasting call receipt the last verb's reply stated, as `call:<32hex>`,
   * whether it answered or refused; `vault.receipts.get` resolves it for the
   * same actor or the vault's owner.
   *
   * Typed returns keep their shape; the ref rides beside them here. `null` for
   * an embedded handle, before any call, after a call that reached no server,
   * and for an anonymous off-record call.
   */
  lastReceiptRef(): string | null {
    return this.#client.lastReceiptRef() ?? null
  }

  /**
   * Content-free hook notice beside the last facade call's reply. Typed
   * results keep their shape. The next facade call clears it before sending;
   * a cloned or vault-direct handle has none. Session-only calls may carry a
   * notice without keeping a durable receipt.
   */
  lastHookNotice(): string | null {
    return this.#client.lastHookNotice() ?? null
  }

  /**
   * The engine `[limits]` rows this client's own vault crossed, latest per
   * row: the row's key plus what it stood at and what the work measured,
   * both exact (`bigint`, never `number`). `null` on a remote, attached, or
   * rebound view; an empty list where no row crossed yet.
   */
  nativeLimitQuestions(): NativeLimitQuestion[] | null {
    return this.#call(() => this.#client.nativeLimitQuestions()) ?? null
  }

  /**
   * Resends the call a `PENDING_ASK` refusal answered, under the invocation
   * its `hook` names (ARCH-0080 §3): pass the caught `OneironError`, the
   * verb's SDK name (`vault.claims.upsert`) and the same input. While the ask
   * is open it throws the same `PENDING_ASK`; once the ask is answered
   * proceed, the saved call runs once and this returns its result. Any other
   * refusal is refused before a call is made. Run one retry of a pending call
   * at a time.
   *
   * The reply is the verb's shared wire JSON, not the typed projection the
   * verb's own method returns.
   */
  retry(pending: OneironError, verb: string, input: unknown): unknown {
    const refusal = {
      code: pending.code,
      message: pending.message,
      suggestions: [...pending.suggestions],
      ...(pending.hook ? {hook: pending.hook} : {}),
    }
    return this.#call(() => this.#client.retry(refusal, verb, input))
  }

  /**
   * Sends one event on a lens card the connected server rendered (OF-181):
   * `POST /v1/core/lens-frames/{cardId}/events` under this handle's
   * credential. `request.event.cardId` must name the same card. A
   * patch-profile caller also names `stream: "patch"` (FIX 11399) and takes
   * the card's refinement beside a local action's `$state`. A card the
   * server no longer holds throws `NOT_FOUND`: render the lens again. An
   * embedded handle throws `BAD_REQUEST`: lens frames live on the served
   * host that rendered the card, so render the lens through a connected
   * handle and send its events on that same handle.
   */
  lensFrameEvent(cardId: string, request: LensFrameEventRequest): LensFrameEventReply {
    return this.#call(() => this.#client.lensFrameEvent(cardId, request) as LensFrameEventReply)
  }

  /**
   * Closes a lens card the connected server rendered and frees its frame
   * (OF-181): `DELETE /v1/core/lens-frames/{cardId}`. A card the server does
   * not hold answers `{ closed: false }`. An embedded handle throws
   * `BAD_REQUEST`.
   */
  closeLensFrame(cardId: string): CloseLensFrameReply {
    return this.#call(() => this.#client.closeLensFrame(cardId) as CloseLensFrameReply)
  }

  /**
   * Exports the whole vault into the file at `path`, owner only, as
   * `vault.export` does: `format` is `archive` (the default) or `okf`. The
   * file is created or truncated; the answer is the archive's format,
   * length and BLAKE3. Over a server the archive streams through a kept
   * transfer, so no ceiling on a reply applies to it.
   */
  exportTo(path: string, format?: string): ExportReceipt {
    return this.#call(() => this.#client.exportTo(path, format) as ExportReceipt)
  }

  /** The facade verbs' guarded call (facade-verbs.ts). */
  [facadeCall]<T>(operation: () => T): T {
    return this.#call(operation)
  }

  /** The facade verbs' native client (facade-verbs.ts). */
  get [facadeClient](): NativeClient {
    return this.#client
  }

  static {
    // The top-level verbs live on the prototype, as methods declared in the class body would.
    for (const [name, method] of Object.entries(facadeMethods)) {
      Object.defineProperty(Oneiron.prototype, name, { value: method, writable: true, configurable: true, enumerable: false })
    }
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
export type { HookStop } from "./error.js"
export type { LegalHoldNotice } from "./facade-types.js"
export type * from "./types.js"
export type * as Facade from "./facade-types.js"

export type { OutcomeBinding, CalibrationPair, TaskAssignee, ConsultPayloadRef, TaskAskOptionId, TaskAskTarget, TaskAskWho, TaskAskShort, TaskAskLadderPrediction, TaskAskQuestion, TaskAskElectorate, TaskAskNeed, TaskAskDecide, TaskAskDefault, TaskAskDisagree, TaskAskClass, TaskAskSpec, TaskAskHandle, TaskAskReceipt, TaskCanAskRequest, TaskAskPreflight, TaskAskPreflightRecipient, TaskAskPersonKind, TaskAskPersonEvidence, TaskAskWord, TaskAskAnswer, TaskAskCoverage, TaskAskDecision, TaskAskFallback, TaskAskEffectAuthorization, TaskAskEvidence, TaskAskSettlement, TaskAskResult, TaskAskStatus, TaskAskWait, TaskCancelReceipt, TaskDescription } from "./agent-verbs.js"
