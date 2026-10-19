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
import { NativeClient, NativeEngine } from "./native.js"
import type * as Facade from "./facade-types.js"
import type { CalibrationPair, TaskAskAnswer, TaskAskDefault, TaskAskHandle, TaskAskPersonEvidence, TaskAskPreflight, TaskAskQuestion, TaskAskReceipt, TaskAskShort, TaskAskSpec, TaskAskWait, TaskAskWho, TaskAskWord, TaskCancelReceipt, TaskCanAskRequest, TaskDescription } from "./agent-verbs.js"

import { itemFromWire, keyedJson } from "./key-value.js"
import type { WireItem } from "./key-value.js"
import type {
  CheckpointPin,
  KeyValueAddress,
  KeyValuePut,
  KeyValueItem,
  KeyValuePutReceipt,
  KeyValueDeleteReceipt,
  KeyValueSearch,
  KeyValueNamespaces,
  ClaimInput,
  CommitReceipt,
  EngineOptions,
  FacadeReceipt,
  MemoryPack,
  MemoryExport,
  OpenOptions,
  RecallOptions,
  WitnessReceipt,
  WitnessTurn,
} from "./types.js"

/**
 * One lens-card event's body (OF-181): the client's event, and the key a
 * deterministic action's dispatch replays under. Keys keep the wire's
 * camelCase spelling.
 */
export interface LensFrameEventRequest {
  readonly event: Facade.GeneratedUiActionEvent
  readonly idempotencyKey: string
}

/**
 * What a lens-card event answers. There is no discriminator: a local action
 * answers the card's new `$state`, a deterministic tool its outcome and the
 * scoped read of its entity arguments, and a model round trip the callback
 * queued for the agent that emitted the card.
 */
export type LensFrameEventReply =
  | { readonly $state: Facade.GeneratedUiStateSnapshot }
  | { readonly outcome: unknown; readonly readReceipt: Facade.ScopedReadReceipt }
  | { readonly queued: boolean; readonly callbackId: string }

/** What a lens-card close answers: whether the server held its frame. */
export interface CloseLensFrameReply {
  readonly closed: boolean
}

/**
 * What {@link Oneiron.pair} returns: a handle connected with the credential,
 * the credential to store, and the checkpoint pin the link named (OF-469),
 * `null` when the vault has no attested checkpoint.
 */
export interface Paired {
  readonly memory: Oneiron
  readonly credential: string
  readonly pin: CheckpointPin | null
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
  /** Runs what is due; a stopped engine serves again first. */
  wake(): void
  /** Drains, stops every worker, and keeps the vault open for `wake`. */
  stop(): void
  /** Stops the engine in order; every handle it served throws `ENGINE_CLOSED` after. */
  close(): void
}

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
    let paired: { url: string; credential: string; pin?: CheckpointPin }
    try {
      paired = NativeClient.pair(link)
    } catch (error) {
      throw translateNativeError(error)
    }
    return {
      memory: Oneiron.connect(paired.url, paired.credential),
      credential: paired.credential,
      pin: paired.pin ?? null,
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
    return {
      client: (key) => new Oneiron(call(() => native.client(key))),
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
   * credential. `request.event.cardId` must name the same card. A card the
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

  // BEGIN GENERATED FACADE VERBS
  readonly vault = {
    commitments: {
      /** Creates an authored commitment series and its due index atomically, without approving a reminder. */
      create: (input: Facade.CommitmentCreateRequest): Facade.CommitmentCreateReceipt => this.#call(() => this.#client.vaultCommitmentsCreate(input) as Facade.CommitmentCreateReceipt),
      /** Reads a commitment with its schedule, birth provenance, separate occurrence and learning times, and lifecycle receipt. */
      get: (input: Facade.CommitmentRefRequest): Facade.CommitmentView => this.#call(() => this.#client.vaultCommitmentsGet(input) as Facade.CommitmentView),
      /** Lists the materialized occurrences of a commitment series, including closed obligations. */
      instances: (input: Facade.CommitmentRefRequest): Facade.CommitmentView[] => this.#call(() => this.#client.vaultCommitmentsInstances(input) as Facade.CommitmentView[]),
      /** Observes real timer-wake reminder proposals and their run approval keys without authorizing delivery. */
      proposals: (input: Facade.CommitmentRefRequest): Facade.CommitmentWakeProposal[] => this.#call(() => this.#client.vaultCommitmentsProposals(input) as Facade.CommitmentWakeProposal[]),
      /** Explicitly confirms an obligation fulfilled with witness evidence through the existing fulfillment dispatcher. */
      fulfill: (input: Facade.CommitmentFulfillRequest): Facade.CommitmentView => this.#call(() => this.#client.vaultCommitmentsFulfill(input) as Facade.CommitmentView),
      /** Explicitly releases an obligation with witness evidence and clears its due phases in the same transaction. */
      release: (input: Facade.CommitmentCloseRequest): Facade.CommitmentView => this.#call(() => this.#client.vaultCommitmentsRelease(input) as Facade.CommitmentView),
      /** Explicitly supersedes an obligation with witness evidence and clears its due phases in the same transaction. */
      supersede: (input: Facade.CommitmentCloseRequest): Facade.CommitmentView => this.#call(() => this.#client.vaultCommitmentsSupersede(input) as Facade.CommitmentView),
    },
    reports: {
      /** The owner decides whether one publisher-routed report's exact quoted text may cross to its publisher: approve once, stop asking, or deny. */
      disclosure: (input: Facade.ReportDisclosureRequest): Facade.ReportIssue => this.#call(() => this.#client.vaultReportsDisclosure(input) as Facade.ReportIssue),
      /** The owner replaces one durable subject's maker route: the owner inbox, or one admitted publisher its feedback is delivered to. */
      route: (input: Facade.ReportRouteRequest): Facade.ReportRouteReceipt => this.#call(() => this.#client.vaultReportsRoute(input) as Facade.ReportRouteReceipt),
      /** The owner reads the content-free payload a publisher delivery for one report issue would carry now, with its quoted text only when disclosure approved it. */
      outbound: (input: Facade.ReportOutboundRequest): Facade.ReportOutboundView => this.#call(() => this.#client.vaultReportsOutbound(input) as Facade.ReportOutboundView),
    },
    diagnostics: {
      /** Lists the engine-authored diagnostic events the caller reads, by class, actor, or evidence, with the read's narrowing receipt. */
      list: (input: Facade.DiagnosticsListRequest): Facade.ScopedReadResult<Facade.DiagnosticEventView[]> => this.#call(() => this.#client.vaultDiagnosticsList(input) as Facade.ScopedReadResult<Facade.DiagnosticEventView[]>),
      /** Reads one diagnostic event the caller may read, by ref, with the read's narrowing receipt. */
      get: (input: Facade.DiagnosticsGetRequest): Facade.ScopedReadResult<Facade.DiagnosticEventView | null> => this.#call(() => this.#client.vaultDiagnosticsGet(input) as Facade.ScopedReadResult<Facade.DiagnosticEventView | null>),
    },
    coach: {
      /** Inspects one blocked report as the Coach reads it: its fenced receipt, linked diagnostic band, working set, and the repair proposal the Coach filed, through the caller's own lane. */
      inspect: (input: Facade.CoachInspectRequest): Facade.ScopedReadResult<Facade.CoachInspectionView> => this.#call(() => this.#client.vaultCoachInspect(input) as Facade.ScopedReadResult<Facade.CoachInspectionView>),
      /** Read Coach offer snapshots, their exact owner answers and later promise checks; optionally select a seat or only pending offers. */
      training_offers: Object.assign((input: Facade.OfferListRequest): Facade.OfferView[] => this.#call(() => this.#client.vaultCoachTrainingOffers(input) as Facade.OfferView[]), {
        /** Read one Coach offer snapshot with its owner answer and receipt-backed promise checks. */
        get: (input: Facade.OfferRef): Facade.OfferView | null => this.#call(() => this.#client.vaultCoachTrainingOffersGet(input) as Facade.OfferView | null),
        /** Queue one production Coach training-offer pass under the owner proof; the offer skill decides what to raise and no caller supplies an offer body. */
        trigger: (input: Facade.OfferPassRequest): Facade.OfferPassRef => this.#call(() => this.#client.vaultCoachTrainingOffersTrigger(input) as Facade.OfferPassRef),
        /** Read the production Coach offer attempt state and the exact snapshots it raised; a completed pass may raise no offer. */
        result: (input: Facade.OfferPassRef): Facade.OfferPassResult | null => this.#call(() => this.#client.vaultCoachTrainingOffersResult(input) as Facade.OfferPassResult | null),
        /** Answer the exact shown Coach snapshot: keep baseline, decline, postpone, approve switch or approve train; training still needs its separate result-swap choice. */
        answer: (input: Facade.OfferAnswerRequest): Facade.OfferAnswerRecord => this.#call(() => this.#client.vaultCoachTrainingOffersAnswer(input) as Facade.OfferAnswerRecord),
        /** Undo an approved stock switch only while its own seat still holds the switched binding; restore the previous whole binding. */
        undo: (input: Facade.OfferRef): Facade.OfferUndoReceipt => this.#call(() => this.#client.vaultCoachTrainingOffersUndo(input) as Facade.OfferUndoReceipt),
        /** Read pinned own-seat stock or training-recipe candidates, including their incumbent and explicit compute destination. */
        candidates: Object.assign((input: Facade.OfferCandidateQuery): Facade.OfferCandidateRecord[] => this.#call(() => this.#client.vaultCoachTrainingOffersCandidates(input) as Facade.OfferCandidateRecord[]), {
          /** Pin an own-seat catalog stock candidate or existing training recipe and its destination; this nominates only and never switches, downloads or trains. */
          prepare: (input: Facade.OfferCandidateSetup): Facade.OfferCandidateRecord => this.#call(() => this.#client.vaultCoachTrainingOffersCandidatesPrepare(input) as Facade.OfferCandidateRecord),
        }),
        pilots: {
          /** Prepare an eval-only pilot of a pinned seat candidate, counting its sealed cohort exposure before releasing receipt-backed cases; launch no compute or egress. */
          prepare: (input: Facade.OfferPilotPrepare): Facade.OfferPilotPrepared => this.#call(() => this.#client.vaultCoachTrainingOffersPilotsPrepare(input) as Facade.OfferPilotPrepared),
          /** Record immutable owner-evaluator pilot measurements bound to counted own-seat families; fixed code derives sufficiency and preserves unknown cost and score. */
          complete: (input: Facade.OfferPilotComplete): Facade.OfferPilot => this.#call(() => this.#client.vaultCoachTrainingOffersPilotsComplete(input) as Facade.OfferPilot),
          /** Read one counted Coach pilot, its pins, measurement receipts, one-off cost and computed sufficiency card. */
          get: (input: Facade.OfferPilotRef): Facade.OfferPilot | null => this.#call(() => this.#client.vaultCoachTrainingOffersPilotsGet(input) as Facade.OfferPilot | null),
        },
      }),
    },
    people: {
      /** One page of the people the caller reads, in handle order. */
      list: (input: Facade.PeopleListRequest): Facade.PeoplePage => this.#call(() => this.#client.vaultPeopleList(input) as Facade.PeoplePage),
      /** One person the vault knows, by their pr handle. */
      get: (input: Facade.PersonRequest): Facade.PersonRow => this.#call(() => this.#client.vaultPeopleGet(input) as Facade.PersonRow),
      /** The owner creates a distinct PERSON with declared identity hints and existing identity-evidence refs, looking before minting an opaque id without selecting or merging a namesake. */
      create: (input: Facade.PersonCreateRequest): Facade.PersonCreated => this.#call(() => this.#client.vaultPeopleCreate(input) as Facade.PersonCreated),
    },
    entities: {
      /** The owner queries the declared PERSON, ORG or PLACE identity hints for N candidates with evidence and provenance; only stored mention evidence is scored by the waterfall, and no entity is restored, linked or minted. */
      look_before_mint: (input: Facade.IdentityLookupRequest): Facade.IdentityLookup => this.#call(() => this.#client.vaultEntitiesLookBeforeMint(input) as Facade.IdentityLookup),
      /** The owner resolves an evidence-backed mention through the existing waterfall, restoring its selected archived record in place and never minting a duplicate. */
      mention: (input: Facade.EntityMentionRequest): Facade.EntityResolutionWaterfallDecision => this.#call(() => this.#client.vaultEntitiesMention(input) as Facade.EntityResolutionWaterfallDecision),
    },
    identity: {
      /** The owner reads one saved mention as unresolved, candidates or resolved, preserving the original tagger suggestion and the resolving owner evidence and provenance. */
      mention: (input: Facade.MentionProvenance): Facade.IdentityMentionView => this.#call(() => this.#client.vaultIdentityMention(input) as Facade.IdentityMentionView),
      /** The owner merges source identities into a survivor, retaining claim subjects and append-only evidence. */
      merge: (input: Facade.IdentityMergeRequest): Facade.IdentityTopologyResult => this.#call(() => this.#client.vaultIdentityMerge(input) as Facade.IdentityTopologyResult),
      /** The owner splits an identity into zero, one or many heads using an evidence-guided reassignment map. */
      split: (input: Facade.IdentitySplitRequest): Facade.IdentityTopologyResult => this.#call(() => this.#client.vaultIdentitySplit(input) as Facade.IdentityTopologyResult),
      /** The owner mints identity facets and forks assigned claims under their masks without restamping original claims. */
      facet: (input: Facade.IdentityFacetRequest): Facade.IdentityTopologyResult => this.#call(() => this.#client.vaultIdentityFacet(input) as Facade.IdentityTopologyResult),
      /** The owner asserts two identities are distinct through one symmetric claim that suppresses merge re-proposals. */
      assert_distinct: (input: Facade.IdentityAssertDistinctRequest): Facade.IdentityTopologyResult => this.#call(() => this.#client.vaultIdentityAssertDistinct(input) as Facade.IdentityTopologyResult),
      /** The owner parks a nominated merge or split candidate with no topology effects; distinct pairs suppress merge proposals. */
      propose: (input: Facade.IdentityProposeRequest): Facade.IdentityTopologyResult => this.#call(() => this.#client.vaultIdentityPropose(input) as Facade.IdentityTopologyResult),
      /** The owner undoes one current topology event by appending a counter-event under its observed revision. */
      undo: (input: Facade.IdentityUndoRequest): Facade.IdentityTopologyResult => this.#call(() => this.#client.vaultIdentityUndo(input) as Facade.IdentityTopologyResult),
      /** The owner resolves an identity to its current head set and reads shell edges, facets and evidence assignments. */
      resolve: (input: Facade.IdentityEntityRequest): Facade.IdentityResolution => this.#call(() => this.#client.vaultIdentityResolve(input) as Facade.IdentityResolution),
      events: {
        /** The owner reads one topology decision with its actor, evidence, action and current decision revision. */
        get: (input: Facade.IdentityEventRequest): Facade.IdentityTopologyReceipt => this.#call(() => this.#client.vaultIdentityEventsGet(input) as Facade.IdentityTopologyReceipt),
      },
      proposals: {
        /** The owner approves, amends then approves, or rejects a parked topology proposal under its observed revision. */
        resolve: (input: Facade.IdentityProposalResolveRequest): Facade.IdentityProposalResolutionResult => this.#call(() => this.#client.vaultIdentityProposalsResolve(input) as Facade.IdentityProposalResolutionResult),
        /** The owner reads open merge proposals and effective distinctness claims for an unordered identity pair. */
        for_pair: (input: Facade.IdentityPairRequest): Facade.IdentityPairProposals => this.#call(() => this.#client.vaultIdentityProposalsForPair(input) as Facade.IdentityPairProposals),
      },
    },
    shape: {
      /** The vault's stored seed and its live setup plane held as one document (ARCH-0070); a free read. */
      read: (input: Facade.EmptyRequest = {}): Facade.ShapeRead => this.#call(() => this.#client.vaultShapeRead(input) as Facade.ShapeRead),
      /** The difference between a seed, or the stored one, and the vault, item by item at a pinned frontier; a free read that writes nothing. */
      plan: (input: Facade.ShapePlanRequest): Facade.ShapePlan => this.#call(() => this.#client.vaultShapePlan(input) as Facade.ShapePlan),
      /** Lands a shape plan one item at a time through the vault's named doors, or resumes its apply; a widening lands only on the owner's word for that item. */
      apply: (input: Facade.ShapeApplyRequest): Facade.ShapeApplyReceipt => this.#call(() => this.#client.vaultShapeApply(input) as Facade.ShapeApplyReceipt),
    },
    companions: {
      access_requests: {
        /** The owner approves or denies one pending companion-profile request, atomically recording the answer and its exact grant. */
        answer: (input: Facade.CompanionAccessRequestAnswerRequest): Facade.CompanionAccessRequestAnswered => this.#call(() => this.#client.vaultCompanionsAccessRequestsAnswer(input) as Facade.CompanionAccessRequestAnswered),
      },
      sharing: {
        /** One contact's clearance in a companion's source vault, for the principal who controls that vault. */
        get: (input: Facade.CompanionSharingRequest): Facade.CompanionSharingView => this.#call(() => this.#client.vaultCompanionsSharingGet(input) as Facade.CompanionSharingView),
        /** The owner's standing yes to one frozen clearance offer for a companion's contact. */
        set: (input: Facade.CompanionSharingSetRequest): Facade.CompanionSharingView => this.#call(() => this.#client.vaultCompanionsSharingSet(input) as Facade.CompanionSharingView),
      },
    },
    personas: {
      /** Previews the owner's strikeable persona snapshot, with sources and its content-bound consent stamp. */
      preview: (input: Facade.PersonaSnapshotPreviewRequest): Facade.PersonaSnapshotPreview => this.#call(() => this.#client.vaultPersonasPreview(input) as Facade.PersonaSnapshotPreview),
      /** Issues the exact previewed mode-A persona copy after explicit row strikes; a changed preview refuses stale consent. */
      export: (input: Facade.PersonaSnapshotCopyRequest): Facade.PersonaSnapshotExportedCopy => this.#call(() => this.#client.vaultPersonasExport(input) as Facade.PersonaSnapshotExportedCopy),
      /** Edits an accepted persona copy into a new receipted export, preserving citations, exclusions and the already handed version. */
      edit: (input: Facade.PersonaSnapshotCopyEditRequest): Facade.PersonaSnapshotExportedCopy => this.#call(() => this.#client.vaultPersonasEdit(input) as Facade.PersonaSnapshotExportedCopy),
    },
    fanout: {
      /** Admits input-order child slots under this credential's attached live run, through the frozen fan-out approval gate and one shared parent spend tree. */
      spawn: (input: Facade.LiveRunRequest<Facade.FanoutBatchInput>): Facade.FanoutBatchView => this.#call(() => this.#client.vaultFanoutSpawn(input) as Facade.FanoutBatchView),
      /** Reads a batch launch in input slot order, with child errors, results, reservations, settled spend and released holds from its shared parent lease tree. */
      slots: (input: Facade.FanoutLaunchRequest): Facade.FanoutBatchView | null => this.#call(() => this.#client.vaultFanoutSlots(input) as Facade.FanoutBatchView | null),
      /** One held or launched fan-out by its launch ref, with the statement frozen before it launched; readable by the vault owner, its creator, or a live lead/board holder of its project, anything else reads as none. */
      launch: (input: Facade.FanoutLaunchRequest): Facade.FanoutLaunchView | null => this.#call(() => this.#client.vaultFanoutLaunch(input) as Facade.FanoutLaunchView | null),
      /** The owner rules on a held fan-out launch by the digest they saw: approve once, approve and remember under a cap, or deny, which keeps the hold visible. */
      resume: (input: Facade.FanoutResumeRequest): Facade.FanoutLaunchView => this.#call(() => this.#client.vaultFanoutResume(input) as Facade.FanoutLaunchView),
      /** A live lead or board holder of a held fan-out launch's project rules on it by the digest they saw: approve once, or deny, which keeps the hold visible; only the owner may remember. */
      resume_as: (input: Facade.FanoutResumeRequest): Facade.FanoutLaunchView => this.#call(() => this.#client.vaultFanoutResumeAs(input) as Facade.FanoutLaunchView),
      /** The owner acknowledges the width check of a fan-out that already went out, once or remembered under a cap; nothing was held, so nothing is denied. */
      ack: (input: Facade.FanoutAckRequest): Facade.FanoutLaunchView => this.#call(() => this.#client.vaultFanoutAck(input) as Facade.FanoutLaunchView),
    },
    budgets: {
      /** The owner reads a persisted spend lease, its remaining allowance and the hard ancestor that binds it. */
      lease: Object.assign((input: Facade.SpendScopeRequest): Facade.SpendLeaseView => this.#call(() => this.#client.vaultBudgetsLease(input) as Facade.SpendLeaseView), {
        /** The owner opens a persisted launch spend lease under the maximum the customer set and saw, in its declared unit. */
        open: (input: Facade.OpenSpendLeaseRequest): Facade.SpendLeaseView => this.#call(() => this.#client.vaultBudgetsLeaseOpen(input) as Facade.SpendLeaseView),
        /** The owner raises a hard lease to a shown replacement maximum; replay adds nothing twice and a child's increase stays within its ancestor's cap. */
        top_up: (input: Facade.TopUpSpendLeaseRequest): Facade.SpendLeaseView => this.#call(() => this.#client.vaultBudgetsLeaseTopUp(input) as Facade.SpendLeaseView),
      }),
      /** The owner reads a held run's notice, saved partial results, exact checkpoints and whether its existing lease permits resume. */
      hold: Object.assign((input: Facade.BudgetHoldRequest): Facade.PartialResultHold | null => this.#call(() => this.#client.vaultBudgetsHold(input) as Facade.PartialResultHold | null), {
        /** The owner resumes the same held attempts from their checkpoints after their lease has funds; no model substitution or terminal completion. */
        resume: (input: Facade.BudgetHoldRequest): Facade.PartialResultHold => this.#call(() => this.#client.vaultBudgetsHoldResume(input) as Facade.PartialResultHold),
      }),
      /** The owner observes a device-local runner budget counter without creating it, including absence after an owner restore. */
      local: (input: Facade.LocalRunnerBudgetRequest): Facade.LocalRunnerBudgetView => this.#call(() => this.#client.vaultBudgetsLocal(input) as Facade.LocalRunnerBudgetView),
      /** The owner reads a device-local runner budget counter and one page of the child reservations held against it, without creating or refilling it. */
      reservations: (input: Facade.RunnerBudgetReservationsRequest): Facade.RunnerBudgetReservationsView => this.#call(() => this.#client.vaultBudgetsReservations(input) as Facade.RunnerBudgetReservationsView),
      /** The owner reads a served run's persisted physical-rung settlement receipts, with reservation, settled units and stamped cost when priced. */
      settlements: (input: Facade.RunSettlementsRequest): Facade.RunSettlementsView => this.#call(() => this.#client.vaultBudgetsSettlements(input) as Facade.RunSettlementsView),
      /** The owner reads both RSI lines, every soft and pinned share, and whether new loop work is held. A hold reads as suspended, never as a terminal failure. */
      rsi: Object.assign((input: Facade.RsiLineRequest): Facade.RsiLineView => this.#call(() => this.#client.vaultBudgetsRsi(input) as Facade.RsiLineView), {
        /** The owner creates the vault RSI line once: its token limit, its independent exploration exposure limit, and its soft and owner-pinned shares. Reconfiguration cannot erase receipts or spend. */
        configure: (input: Facade.RsiBudgetConfig): Facade.RsiLineView => this.#call(() => this.#client.vaultBudgetsRsiConfigure(input) as Facade.RsiLineView),
        /** The owner raises one exact limiting RSI line by its units: the token limit, the exploration exposure limit, or one named share. A top-up never lowers a line and never resumes held work by itself. */
        top_up: (input: Facade.RsiTopUp): Facade.RsiLineView => this.#call(() => this.#client.vaultBudgetsRsiTopUp(input) as Facade.RsiLineView),
        /** The owner holds new RSI loop work rather than killing it; admitted reservations can still settle, and pending attempts, candidates and partial outputs stay. */
        hold: Object.assign((input: Facade.RsiLineRequest): Facade.RsiLineView => this.#call(() => this.#client.vaultBudgetsRsiHold(input) as Facade.RsiLineView), {
          /** The owner releases the RSI hold on the same line and receipts, so the same pending try continues without a new experiment or a duplicate terminal receipt. */
          resume: (input: Facade.RsiLineRequest): Facade.RsiLineView => this.#call(() => this.#client.vaultBudgetsRsiHoldResume(input) as Facade.RsiLineView),
        }),
      }),
    },
    /** Writes one whole MESSAGE atomically through the witness gate; birth supplies its immutable conversation, turn and author axes. */
    commit_message: (input: Facade.CommitMessageRequest): Facade.WitnessReceipt => this.#call(() => this.#client.vaultCommitMessage(input) as Facade.WitnessReceipt),
    /** Opens one caller-owned MESSAGE stream, with birth axes for a new message or stored axes for a continuation. */
    begin_message_stream: (input: Facade.BeginMessageStreamRequest): Facade.MessageStreamHandle => this.#call(() => this.#client.vaultBeginMessageStream(input) as Facade.MessageStreamHandle),
    /** Appends one authored delta to this actor's generation-bound stream through its existing write gate. */
    append_to_stream: (input: Facade.AppendToStreamRequest): null => this.#call(() => this.#client.vaultAppendToStream(input) as null),
    /** Publishes the current partial at once when streamed visibility allows it; atomic mode stays private. */
    flush_stream: (input: Facade.MessageStreamRequest): null => this.#call(() => this.#client.vaultFlushStream(input) as null),
    /** Commits the stream as final and releases its handle, returning the immutable terminal receipt. */
    finalize_stream: (input: Facade.MessageStreamRequest): Facade.MessageStreamReceipt => this.#call(() => this.#client.vaultFinalizeStream(input) as Facade.MessageStreamReceipt),
    /** Keeps the stream's text as one incomplete MESSAGE with cancelled finality and the caller's explicit reason. */
    cancel_stream: (input: Facade.CancelStreamRequest): Facade.MessageStreamReceipt => this.#call(() => this.#client.vaultCancelStream(input) as Facade.MessageStreamReceipt),
    /** Reads only this actor's accepted in-memory partial using its generation-bound stream handle. */
    message_stream_partial: (input: Facade.MessageStreamRequest): Facade.MessageStreamPartial => this.#call(() => this.#client.vaultMessageStreamPartial(input) as Facade.MessageStreamPartial),
    messages: {
      /** Reads a MESSAGE's completion, terminal-generation receipts and retained document history through the caller's own read lane. */
      durability: (input: Facade.MessageDurabilityRequest): Facade.ScopedReadResult<Facade.MessageDurability | null> => this.#call(() => this.#client.vaultMessagesDurability(input) as Facade.ScopedReadResult<Facade.MessageDurability | null>),
      /** Puts or removes the caller's own reaction on a message or turn; an owner-grade host also brings a provider's reaction as connector ingress. */
      react: (input: Facade.MessageReactionRequest): Facade.MessageReactionReceipt => this.#call(() => this.#client.vaultMessagesReact(input) as Facade.MessageReactionReceipt),
    },
    /**
   * Witnesses one conversational turn.
   *
   * Omitting `occurredAt` stamps the current wall clock, in Unix seconds, at
   * the call boundary.
   */
    witness: (turn: WitnessTurn): WitnessReceipt => this.#call(() => this.#client.vaultWitness(turn)),
    claims: {
      /** Admits an explicitly four-axis claim through the caller credential and existing gate, with host-authored provenance. */
      upsert: (input: Facade.ScopedClaimInput): Facade.CommitReceipt => this.#call(() => this.#client.vaultClaimsUpsert(input) as Facade.CommitReceipt),
      /** The owner reviews one proposed claim: the claim as the owner may read it, its opener and tray row, and the review_id that settles exactly this content. */
      review: (input: Facade.ClaimProposalReviewRequest): Facade.ClaimProposalReview => this.#call(() => this.#client.vaultClaimsReview(input) as Facade.ClaimProposalReview),
      /** The owner approves or rejects exactly the reviewed proposed claim through the gate and keeps its Settlement; a claim changed since its review_id is refused. */
      settle: (input: Facade.ClaimSettleRequest): Facade.ClaimSettlement => this.#call(() => this.#client.vaultClaimsSettle(input) as Facade.ClaimSettlement),
      /** Retracts one active claim: a deliberate withdrawal that preserves the record. */
      retract: (input: Facade.ClaimRefRequest): Facade.CommitReceipt => this.#call(() => this.#client.vaultClaimsRetract(input) as Facade.CommitReceipt),
      /** Lists claims by subject, predicate and lifecycle, with the read's narrowing receipt. */
      list: (input: Facade.ClaimListFilter): Facade.ScopedReadResult<Facade.ClaimView[]> => this.#call(() => this.#client.vaultClaimsList(input) as Facade.ScopedReadResult<Facade.ClaimView[]>),
      /** Demotes one active claim by one rung through the caller credential: decay its claim_of weight, weaken it to a successor at lower confidence, or mark it stale in place so retrieval stops surfacing it. */
      demote: (input: Facade.ClaimDemoteRequest): Facade.ClaimDemoteView => this.#call(() => this.#client.vaultClaimsDemote(input) as Facade.ClaimDemoteView),
      /** Lists surfaceable claims by subject, predicate and lifecycle under the caller retrieval filter met with the actor ceiling, with the read narrowing receipt. */
      list_filtered: (input: Facade.ClaimFilteredListRequest): Facade.ScopedReadResult<Facade.ClaimView[]> => this.#call(() => this.#client.vaultClaimsListFiltered(input) as Facade.ScopedReadResult<Facade.ClaimView[]>),
      /** Reads one claim as retrieval would surface it under the caller retrieval filter met with the actor ceiling, with the read narrowing receipt. */
      read_filtered: (input: Facade.ClaimFilteredReadRequest): Facade.ScopedReadResult<Facade.ClaimView | null> => this.#call(() => this.#client.vaultClaimsReadFiltered(input) as Facade.ScopedReadResult<Facade.ClaimView | null>),
      /** The supersession timeline of one claim, oldest first, with the read's narrowing receipt. */
      history: (input: Facade.ClaimRefRequest): Facade.ScopedReadResult<Facade.ClaimView[]> => this.#call(() => this.#client.vaultClaimsHistory(input) as Facade.ScopedReadResult<Facade.ClaimView[]>),
      /** Admits one imported-evidence claim through its ingest source's trust ceiling; the gate still decides. */
      admit: (input: Facade.AdmitImportedClaimInput): Facade.CommitReceipt => this.#call(() => this.#client.vaultClaimsAdmit(input) as Facade.CommitReceipt),
      /** Vets a reviewed generated-origin Auto claim or proposal through the owner Gate and signed settlement; it still contributes zero corroboration. */
      vet: (input: Facade.ClaimSettleRequest): Facade.ClaimSettlement => this.#call(() => this.#client.vaultClaimsVet(input) as Facade.ClaimSettlement),
      /** Reviews an exact generated-origin Auto claim or proposal before owner vetting, returning the content-bound review handle. */
      vetting: (input: Facade.ClaimProposalReviewRequest): Facade.ClaimProposalReview => this.#call(() => this.#client.vaultClaimsVetting(input) as Facade.ClaimProposalReview),
      /** Seeds claims through their individual gates, forced proposed, returning per claim its landed receipt or its typed refusal and refusal receipt. */
      seed: (input: Facade.ScopedCommitRequest): Facade.CommitOutcome[] => this.#call(() => this.#client.vaultClaimsSeed(input) as Facade.CommitOutcome[]),
      /** Supersedes through this credential's attached generated-writing run and its existing gates; spec is {newId,oldId,now}, never an actor or source override. */
      supersede: (input: Facade.LiveRunRequest<Facade.MemorySupersedeInput>): Facade.MemoryWriteOutput => this.#call(() => this.#client.vaultClaimsSupersede(input) as Facade.MemoryWriteOutput),
    },
    /**
   * Recalls a memory pack.
   *
   * `effort: "high"`, `"xhigh"`, or `"max"` needs a lease this package never
   * mints: an embedded client returns `LEASE_REQUIRED`; a remote one gets what
   * the server serves (reranked on its `[models]` reranker, or unreranked and
   * saying so). `effort: "call"` is call mode for live calls: light
   * effort under a hard deadline (`deadlineMs`, or the vault's call-mode
   * deadline), answering with the best results ready, marked `partial`.
   * `media` (`{ space, mime, bytesB64, kinds? }`) is embedded by the server
   * into its declared space; an embedded client returns `MODEL_UNAVAILABLE`.
   * `queryAffect` (`{ valence, arousal, dominance }`: valence in -1..1,
   * arousal and dominance in 0..1) ranks by emotion congruence, embedded and
   * remote alike; out of range it returns `BAD_REQUEST`.
   * Explicit `scope.worldRef` recalls of retained foreign worlds carry
   * `item.stale`: `staleSince` and `ageSecs` (when known), `reason` and
   * `pactEpoch`. This selection grants no read authority.
   */
    recall: (query: string, opts: RecallOptions = {}): MemoryPack => this.#call(() => this.#client.vaultRecall(query, opts.effort ?? "medium", opts.scope, opts.limit ?? 10, opts.format, opts.asOf, opts.deadlineMs, opts.media, opts.queryAffect)),
    retrieval: {
      aging: {
        /** The owner reads class-level exponential aging profiles and the trusted manifest hash; confidence never ages. */
        get: (input: Facade.EmptyRequest = {}): Facade.ClaimAgingProfilesView => this.#call(() => this.#client.vaultRetrievalAgingGet(input) as Facade.ClaimAgingProfilesView),
        /** The owner edits all class-aging profiles against the current manifest hash without rewriting confidence, lifecycle or claim bodies. */
        configure: (input: Facade.ClaimAgingProfilesConfigureRequest): Facade.ClaimAgingProfilesReceipt => this.#call(() => this.#client.vaultRetrievalAgingConfigure(input) as Facade.ClaimAgingProfilesReceipt),
      },
      weights: {
        /** The owner reads effective affect, arousal, community and semantic-edge VAD priors with the trusted manifest hash. */
        get: (input: Facade.EmptyRequest = {}): Facade.RetrievalWeightsView => this.#call(() => this.#client.vaultRetrievalWeightsGet(input) as Facade.RetrievalWeightsView),
        /** The owner sets independent retrieval priors against the current manifest hash; zero disables each prior without changing confidence or authority. */
        configure: (input: Facade.RetrievalWeightsConfigureRequest): Facade.RetrievalWeightsReceipt => this.#call(() => this.#client.vaultRetrievalWeightsConfigure(input) as Facade.RetrievalWeightsReceipt),
      },
      hyde: {
        /** The owner binds or disables a host HyDE expander for paid recall; replacing the binding cancels unanswered work. */
        configure: (input: Facade.HydeHostConfigureRequest): Facade.HydeHostConfiguration => this.#call(() => this.#client.vaultRetrievalHydeConfigure(input) as Facade.HydeHostConfiguration),
        /** The owner reads the serving host HyDE binding, grounding and bounded retry options. */
        get: (input: Facade.EmptyRequest = {}): Facade.HydeHostConfiguration => this.#call(() => this.#client.vaultRetrievalHydeGet(input) as Facade.HydeHostConfiguration),
        /** Lists pending expansion and evidence-assessment work for the same credential that called recall; free efforts enqueue nothing. */
        pending: (input: Facade.HydeHostPendingRequest): Facade.HydeHostWork[] => this.#call(() => this.#client.vaultRetrievalHydePending(input) as Facade.HydeHostWork[]),
        /** Completes one credential-bound host expansion or evidence assessment, or reports failure; late bytes are receipted and discarded. */
        complete: (input: Facade.HydeHostCompleteRequest): Facade.HydeHostReceipt => this.#call(() => this.#client.vaultRetrievalHydeComplete(input) as Facade.HydeHostReceipt),
        /** Reads one credential-bound host completion receipt, including expired work and late answers discarded at the recall deadline. */
        receipt: (input: Facade.HydeHostReceiptRequest): Facade.HydeHostReceipt | null => this.#call(() => this.#client.vaultRetrievalHydeReceipt(input) as Facade.HydeHostReceipt | null),
      },
      /** Recalls through the normal credential-bound serving pipeline as the owner, with typed opt-in turn and trace capture and the actual finalized run handle. */
      recall: (input: Facade.RecallRequest): Facade.MemoryPack => this.#call(() => this.#client.vaultRetrievalRecall(input) as Facade.MemoryPack),
      /** The owner reads finalized local retrieval runs and their independent outcome sidecars, newest first. */
      runs: (input: Facade.RetrievalRunsRequest): Facade.RetrievalRunEvidence[] => this.#call(() => this.#client.vaultRetrievalRuns(input) as Facade.RetrievalRunEvidence[]),
      /** The owner reads one finalized local serving run, its turn, policy state, trace and explicit outcomes; an unknown run reads as none. */
      run: (input: Facade.RetrievalRunRequest): Facade.RetrievalRunEvidence | null => this.#call(() => this.#client.vaultRetrievalRun(input) as Facade.RetrievalRunEvidence | null),
      /** The owner reads the independent finalized retrieval runs linked to one exact turn, in recorded order. */
      turn: (input: Facade.RetrievalTurnRequest): Facade.RetrievalRunEvidence[] => this.#call(() => this.#client.vaultRetrievalTurn(input) as Facade.RetrievalRunEvidence[]),
      outcomes: {
        /** The owner attaches an explicit observation to one local serving run; raw reward stays telemetry, never a gated training label. */
        put: (input: Facade.RetrievalOutcome): Facade.RetrievalOutcomeRecord[] => this.#call(() => this.#client.vaultRetrievalOutcomesPut(input) as Facade.RetrievalOutcomeRecord[]),
        /** The owner records a gate-attributed turn outcome for its exact contributing retrievalRunIds; the engine validates the links and shapes the reward. */
        end: (input: Facade.RetrievalEndOutcome): Facade.RetrievalRunEvidence[] => this.#call(() => this.#client.vaultRetrievalOutcomesEnd(input) as Facade.RetrievalRunEvidence[]),
      },
      /** The owner reads an opt-in trace by its vault-local keyed fork hash; hashes are never comparable across vaults. */
      trace: (input: Facade.RetrievalTraceRequest): Facade.RetrievalTrace | null => this.#call(() => this.#client.vaultRetrievalTrace(input) as Facade.RetrievalTrace | null),
      /** The owner exports finalized run evidence without query or pack text, raw frontier samples, trace keys or free-form outcome metadata. */
      export: (input: Facade.RetrievalDiagnosticRequest): Facade.RetrievalDiagnosticExport => this.#call(() => this.#client.vaultRetrievalExport(input) as Facade.RetrievalDiagnosticExport),
      /** The owner replays recorded state, ordered pack scores and trace from exact finalized runs; no fresh search, clock or outcome-derived feature is used. */
      replay: (input: Facade.RetrievalDiagnosticRequest): Facade.RetrievalDiagnosticReplay => this.#call(() => this.#client.vaultRetrievalReplay(input) as Facade.RetrievalDiagnosticReplay),
      policy: {
        /** The owner reads the served retrieval policy: active blend weights with their origins, owner pins, the learned posterior and model routing pins. */
        get: (input: Facade.EmptyRequest = {}): Facade.RetrievalPolicyView => this.#call(() => this.#client.vaultRetrievalPolicyGet(input) as Facade.RetrievalPolicyView),
        /** The owner pins one retrieval blend weight at a declared share, or clears its pin; learned updates may move only the unpinned remainder. */
        pin: (input: Facade.RetrievalPolicyPinRequest): Facade.RetrievalPolicyView => this.#call(() => this.#client.vaultRetrievalPolicyPin(input) as Facade.RetrievalPolicyView),
        /** The owner trains a retrieval-policy candidate from gate-attributed outcomes, judged on held-out runs, without serving it. */
        train: (input: Facade.RetrievalPolicyTrainRequest): Facade.RetrievalPolicyCandidate => this.#call(() => this.#client.vaultRetrievalPolicyTrain(input) as Facade.RetrievalPolicyCandidate),
        /** The owner judges candidate blend weights against the active weights on the same held-out runs the tuner never trains on. */
        evaluate: (input: Facade.RetrievalPolicyEvaluateRequest): Facade.RetrievalPolicyEvaluation => this.#call(() => this.#client.vaultRetrievalPolicyEvaluate(input) as Facade.RetrievalPolicyEvaluation),
        /** The owner admits candidate blend weights judged on the named evidence manifest; owner pins and held-out regressions refuse admission. */
        admit: (input: Facade.RetrievalPolicyAdmitRequest): Facade.RetrievalPolicyAdmitReceipt => this.#call(() => this.#client.vaultRetrievalPolicyAdmit(input) as Facade.RetrievalPolicyAdmitReceipt),
        /** The owner declares one retrieval-policy update: train, admit only a not-worse candidate, and rebuild the learned action posterior. */
        update: (input: Facade.RetrievalPolicyTrainRequest): Facade.RetrievalPolicyUpdateReceipt => this.#call(() => this.#client.vaultRetrievalPolicyUpdate(input) as Facade.RetrievalPolicyUpdateReceipt),
      },
    },
    affect: {
      annotations: {
        /** Writes one sourced TURN VAD annotation through ordinary scoped claim admission and the caller credential; the receipt states its approval. */
        put: (input: Facade.AffectAnnotationPut): Facade.CommitReceipt => this.#call(() => this.#client.vaultAffectAnnotationsPut(input) as Facade.CommitReceipt),
      },
      claims: {
        /** The owner consolidates a claim from stored TURN VAD evidence, updating only derived affect state and semantic-edge VAD through the existing engine transaction. */
        consolidate: (input: Facade.AffectClaimConsolidateRequest): Facade.AffectClaimConsolidation => this.#call(() => this.#client.vaultAffectClaimsConsolidate(input) as Facade.AffectClaimConsolidation),
      },
      coping: {
        /** Records a first coping outcome from two stored VAD-annotated turns for one person, with scoped claim admission and caller attribution; no factual claim is superseded. */
        record: (input: Facade.CopingOutcomeRecordRequest): Facade.CopingOutcomeReceipt => this.#call(() => this.#client.vaultAffectCopingRecord(input) as Facade.CopingOutcomeReceipt),
        /** Updates an active coping aggregate from its strategy turn and a later annotated turn through the existing engine transaction, preserving scope and both evidence refs. */
        update: (input: Facade.CopingOutcomeUpdateRequest): Facade.CopingOutcomeReceipt => this.#call(() => this.#client.vaultAffectCopingUpdate(input) as Facade.CopingOutcomeReceipt),
        /** Reads all admitted active coping aggregates for one person and optional exact scope, including unsuccessful outcomes and their attribution and evidence refs. */
        aggregate: (input: Facade.CopingAggregateRequest): Facade.CopingAggregate => this.#call(() => this.#client.vaultAffectCopingAggregate(input) as Facade.CopingAggregate),
      },
      wellness: {
        policy: {
          /** Reads the configured non-clinical wellness window, targets and advisory mode bands as the owner; absent policy stays absent. */
          get: (input: Facade.EmptyRequest = {}): Facade.ActionModePolicy | null => this.#call(() => this.#client.vaultAffectWellnessPolicyGet(input) as Facade.ActionModePolicy | null),
          /** Configures or clears the existing action-mode policy as the owner; no universal wellness cutoff or diagnostic label is supplied by the engine. */
          configure: (input: Facade.WellnessPolicyConfigureRequest): Facade.ActionModePolicy | null => this.#call(() => this.#client.vaultAffectWellnessPolicyConfigure(input) as Facade.ActionModePolicy | null),
        },
        /** Derives one person's non-clinical wellness projection using the existing state measurements and configured mode bands, with a routed receipt and source refs. */
        derive: (input: Facade.WellnessPersonRequest): Facade.WellnessProjection => this.#call(() => this.#client.vaultAffectWellnessDerive(input) as Facade.WellnessProjection),
        /** Reads one person's measured wellness state, configured advisory mode and coping aggregates with source refs, without refreshing or revising factual claims. */
        get: (input: Facade.WellnessPersonRequest): Facade.WellnessProjection => this.#call(() => this.#client.vaultAffectWellnessGet(input) as Facade.WellnessProjection),
      },
    },
    tagging: {
      /** Reads one turn tagging marker as pending retrying settled or failed, with the configured checkpoint, serving model, live marker and failure reason. */
      status: (input: Facade.TaggingTurnRequest): Facade.TaggingStatusView => this.#call(() => this.#client.vaultTaggingStatus(input) as Facade.TaggingStatusView),
      /** Reads the tags saved for one turn: mention spans and targets, coreference, mood, PII and other labels, and the derivation that made them. */
      tags: (input: Facade.TaggingTurnRequest): Facade.TaggingTagsView => this.#call(() => this.#client.vaultTaggingTags(input) as Facade.TaggingTagsView),
      /** Reads one turn recorded tagging traces oldest first: each attempt, checkpoint, model, try number and saved shadowed skipped or failed outcome. */
      history: (input: Facade.TaggingTurnRequest): Facade.TaggingHistoryView => this.#call(() => this.#client.vaultTaggingHistory(input) as Facade.TaggingHistoryView),
      /** Reads the saved tagger mentions naming one entity, bounded by limit and each served only while its turn reads for the caller. */
      mentions: (input: Facade.TaggingMentionsRequest): Facade.TaggingMentionsView => this.#call(() => this.#client.vaultTaggingMentions(input) as Facade.TaggingMentionsView),
    },
    /** Proposes deterministic complete-link cohorts from readable stored claims and supplied embeddings; exact subject, predicate-root, world and facet partitions never decide truth. */
    cluster: Object.assign((input: Facade.ClusterRequest): Facade.ScopedReadResult<Facade.ClusterProposal> => this.#call(() => this.#client.vaultCluster(input) as Facade.ScopedReadResult<Facade.ClusterProposal>), {
      /** Inspects a parked merge or split, its original evidence, current resolution and revision for a gated ruling; every reference must remain readable. */
      proposal: (input: Facade.ClusterProposalRequest): Facade.ScopedReadResult<Facade.ClusterProposalView> => this.#call(() => this.#client.vaultClusterProposal(input) as Facade.ScopedReadResult<Facade.ClusterProposalView>),
      /** Parks an explicit merge or split judgment with zero topology effects, under the caller's own owner proof or topology_seal Grant. */
      propose: (input: Facade.ClusterProposeRequest): Facade.ClusterTopologyReceipt => this.#call(() => this.#client.vaultClusterPropose(input) as Facade.ClusterTopologyReceipt),
      /** Applies a merge judgment through the existing topology gate, preserving claim subjects and recording its redirect shells, evidence and receipt. */
      merge: (input: Facade.ClusterMergeRequest): Facade.ClusterTopologyReceipt => this.#call(() => this.#client.vaultClusterMerge(input) as Facade.ClusterTopologyReceipt),
      /** Applies a split judgment through the existing topology gate, including zero-head retirement, evidence-guided reassignment and explicit residue. */
      split: (input: Facade.ClusterSplitRequest): Facade.ClusterTopologyReceipt => this.#call(() => this.#client.vaultClusterSplit(input) as Facade.ClusterTopologyReceipt),
      /** Approves, amends then approves, or rejects a parked merge or split under the caller's own authority, comparing its revision and recording the ruling atomically. */
      resolve_proposal: (input: Facade.ClusterResolveRequest): Facade.ClusterTopologyReceipt => this.#call(() => this.#client.vaultClusterResolveProposal(input) as Facade.ClusterTopologyReceipt),
    }),
    /** Exports the whole vault as one re-importable archive (ZIP, base64 in `archive`). */
    export: Object.assign((format?: string): MemoryExport => this.#call(() => this.#client.vaultExport({format: format}) as MemoryExport), {
      /** Exports rows selected under the caller credential and named channel, preserving the engine export fences and provenance withholding. */
      scoped: (input: Facade.ScopedExportRequest): Facade.ScopedExport => this.#call(() => this.#client.vaultExportScoped(input) as Facade.ScopedExport),
    }),
    scope: {
      /** Reads a positively stamped record position through the caller credential and existing read gate, with its narrowing receipt. */
      position: (input: Facade.RecordPositionRequest): Facade.ScopedReadResult<Facade.RecordPosition | null> => this.#call(() => this.#client.vaultScopePosition(input) as Facade.ScopedReadResult<Facade.RecordPosition | null>),
      /** Reads the caller credential ceiling as a typed ceiling, never as a record position. */
      ceiling: (input: Facade.EmptyRequest = {}): Facade.CredentialCeiling => this.#call(() => this.#client.vaultScopeCeiling(input) as Facade.CredentialCeiling),
    },
    /** Governance receipts, newest first: the gate decision ledger, or the receipts of the named kinds. */
    receipts: Object.assign((limit: number = 100, kinds?: string[]): FacadeReceipt[] => this.#call(() => this.#client.vaultReceipts(limit, kinds)), {
      /** One call receipt by ref, readable by its own actor or the vault's live owner; anything else reads as none. */
      get: (input: Facade.CallReceiptRequest): Facade.CallReceipt | null => this.#call(() => this.#client.vaultReceiptsGet(input) as Facade.CallReceipt | null),
      /** Read the frozen context of one actual reply emit, as its actor or the live vault owner; never rebuild the assembly. */
      context: (input: Facade.CallReceiptRequest): Facade.ContextEmitReceipt | null => this.#call(() => this.#client.vaultReceiptsContext(input) as Facade.ContextEmitReceipt | null),
    }),
    assets: {
      /** Lands typed text, image or audio bytes as an ASSET and optional source-bound text form, atomically under the caller's content gate. */
      ingest: (input: Facade.AssetIngestRequest): Facade.AssetIngestReceipt => this.#call(() => this.#client.vaultAssetsIngest(input) as Facade.AssetIngestReceipt),
      /** Serves an admitted ASSET in the reader's declared image, audio or text form, with a handle and committed served-form receipt refs. */
      resolve: (input: Facade.AssetResolveRequest): Facade.ScopedReadResult<Facade.AssetResolved> => this.#call(() => this.#client.vaultAssetsResolve(input) as Facade.ScopedReadResult<Facade.AssetResolved>),
    },
    search: {
      /** Searches the text index or a declared embedding space with per-kind matches and revision pins; text-index MRL reads report refinement, and explicit voice_hot skips rescore at the reduced voice limit. */
      vector: Object.assign((input: Facade.VectorSearchRequest): Facade.ScopedReadResult<Facade.VectorSearchResult> => this.#call(() => this.#client.vaultSearchVector(input) as Facade.ScopedReadResult<Facade.VectorSearchResult>), {
        /** Reads this vault open's persisted dimensions and optional MRL fast_dims prefix; graph shape is configured before open, never changed by a search. */
        config: (input: Facade.EmptyRequest = {}): Facade.ScopedReadResult<Facade.VectorSearchConfig> => this.#call(() => this.#client.vaultSearchVectorConfig(input) as Facade.ScopedReadResult<Facade.VectorSearchConfig>),
      }),
      /** Searches explicit vector, text, phonetic, temporal and PPR channels under the caller read ceiling, with optional fixed-time blend replay and per-hit score evidence. */
      hybrid: (input: Facade.HybridSearchRequest): Facade.ScopedReadResult<Facade.HybridSearchHit[]> => this.#call(() => this.#client.vaultSearchHybrid(input) as Facade.ScopedReadResult<Facade.HybridSearchHit[]>),
      /** Searches occurrence, learning or both temporal anchors under the caller's read ceiling, with sigma, adaptive widening, hard outer ranges, admitted dates and the effective request sigma and rounds. */
      temporal: (input: Facade.TemporalSearchRequest): Facade.ScopedReadResult<Facade.TemporalSearchResult> => this.#call(() => this.#client.vaultSearchTemporal(input) as Facade.ScopedReadResult<Facade.TemporalSearchResult>),
      /** BM25 text search over the engine index; surfaceable claims only. */
      bm25: (input: Facade.QueryBm25Request): Facade.ScopedReadResult<Facade.LexicalHit[]> => this.#call(() => this.#client.vaultSearchBm25(input) as Facade.ScopedReadResult<Facade.LexicalHit[]>),
    },
    images: {
      /** The full pixels behind an image's view handle (view, crop or zoom), recorded as a pull. */
      view: (request: Facade.ImageViewRequest): Facade.PulledImage => this.#call(() => {  const result = JSON.parse(this.#client.vaultImagesView(keyedJson(request))) as Facade.PulledImage; return result }),
    },
    explain: {
      /** Why one memory appeared in the caller's session: the run that served it and its place, its board tier and the run's score breakdown; none when the session was not served it or the caller cannot read it. */
      memory: (input: Facade.ExplainMemoryRequest): Facade.ExplainMemoryReply | null => this.#call(() => this.#client.vaultExplainMemory(input) as Facade.ExplainMemoryReply | null),
      /** Why a write needed approval: the gate decision behind one gate receipt, its outcome, reason codes and cited policy rows; none when the caller may not read it. */
      gate: (input: Facade.ExplainGateRequest): Facade.ExplainGateReply | null => this.#call(() => this.#client.vaultExplainGate(input) as Facade.ExplainGateReply | null),
    },
    kv: {
      /** Exact actor-owned worldless key lookup, never recall. */
      get: (request: KeyValueAddress): KeyValueItem | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultKvGet(keyedJson(request))) as WireItem | null; return result === null ? null : itemFromWire(result) }),
      /** Synchronous gated write. Review-required writes fail without changing the key. */
      put: (request: KeyValuePut): KeyValuePutReceipt => this.#call(() => { const { requestId, ...rest } = request; const result = JSON.parse(this.#client.vaultKvPut(keyedJson({ ...rest, request_id: requestId }))) as {item: WireItem; replayed: boolean; receipt_ref: string}; return {item: itemFromWire(result.item), replayed: result.replayed, receiptRef: result.receipt_ref} }),
      /** Retracts only the caller's current key; preserves claim history. */
      delete: (request: KeyValueAddress): KeyValueDeleteReceipt => this.#call(() => {  const result = JSON.parse(this.#client.vaultKvDelete(keyedJson(request))) as {existed: boolean; receipt_refs: string[]}; return {existed: result.existed, receiptRefs: result.receipt_refs} }),
      /** Exact prefix search, ordered lexically and paginated after filtering. */
      search: (request: KeyValueSearch): KeyValueItem[] => this.#call(() => { const { namespacePrefix = [], ...rest } = request; const result = JSON.parse(this.#client.vaultKvSearch(keyedJson({ ...rest, namespace_prefix: namespacePrefix }))) as WireItem[]; return result.map(item => itemFromWire(item)) }),
      /** Exact segment namespace enumeration. Empty namespaces are not retained. */
      namespaces: (request: KeyValueNamespaces): string[][] => this.#call(() => { const { maxDepth, ...rest } = request; const result = JSON.parse(this.#client.vaultKvNamespaces(keyedJson({ ...rest, max_depth: maxDepth }))) as string[][]; return result.map(item => item) }),
    },
    campaign: {
      compliance: {
        /** The owner installs cited compliance rows through the versioned amendment classifier; a loosening still waits for an exact-hash owner approval. */
        install: (input: Facade.ComplianceAmendRequest): Facade.ComplianceReceipt => this.#call(() => this.#client.vaultCampaignComplianceInstall(input) as Facade.ComplianceReceipt),
        /** Proposes cited compliance rows against the active version. Tightening activates with a notice only within the caller ceiling; loosening waits for the owner stamp. */
        amend: (input: Facade.ComplianceAmendRequest): Facade.ComplianceReceipt => this.#call(() => this.#client.vaultCampaignComplianceAmend(input) as Facade.ComplianceReceipt),
        /** The owner approves the exact pending compliance proposal hash against the active version, with a durable authority receipt. */
        approve: (input: Facade.ComplianceApprovalRequest): Facade.ComplianceReceipt => this.#call(() => this.#client.vaultCampaignComplianceApprove(input) as Facade.ComplianceReceipt),
        /** The owner rejects the exact pending compliance proposal hash without changing the effective rules. */
        reject: (input: Facade.ComplianceApprovalRequest): Facade.ComplianceReceipt => this.#call(() => this.#client.vaultCampaignComplianceReject(input) as Facade.ComplianceReceipt),
        /** The owner records cited verification dates for existing compliance rows, including an explicitly stale date, without changing requirements or freshness policy. */
        verify: (input: Facade.ComplianceVerifyRequest): Facade.ComplianceReceipt => this.#call(() => this.#client.vaultCampaignComplianceVerify(input) as Facade.ComplianceReceipt),
        /** Reads the active compliance pack, exact pending proposal, activation notices and amendment or owner-verification receipts from one snapshot. */
        result: (input: Facade.ComplianceResultRequest): Facade.ComplianceResult => this.#call(() => this.#client.vaultCampaignComplianceResult(input) as Facade.ComplianceResult),
      },
      /** Enrolls a person in a campaign the caller owns, with evidence-backed channels and sticky senders. Writes no earned stage and sends nothing. */
      enroll: (input: Facade.CampaignEnrollRequest): Facade.CampaignEnrollmentReceipt => this.#call(() => this.#client.vaultCampaignEnroll(input) as Facade.CampaignEnrollmentReceipt),
      stage: {
        /** Records earned-stage evidence under an authored ladder transition, in AUTO or propose mode. Owner-attested evidence requires the request owner proof; elapsed time earns nothing. */
        evidence: (input: Facade.CampaignStageEvidenceRequest): Facade.CampaignStageEvidenceReceipt => this.#call(() => this.#client.vaultCampaignStageEvidence(input) as Facade.CampaignStageEvidenceReceipt),
      },
      /** Immediately honors an unsubscribe with a channel-scoped enforcement claim and every suppressed membership head in one transaction. */
      unsubscribe: (input: Facade.CampaignUnsubscribeRequest): Facade.CampaignUnsubscribeReceipt => this.#call(() => this.#client.vaultCampaignUnsubscribe(input) as Facade.CampaignUnsubscribeReceipt),
      program: {
        /** Creates a campaign program (ordered steps and an optional saved-query audience) under a campaign the caller owns. */
        create: (input: Facade.CreateCampaignProgramRequest): Facade.CampaignProgramRecord => this.#call(() => this.#client.vaultCampaignProgramCreate(input) as Facade.CampaignProgramRecord),
        /** One campaign program under a campaign the caller owns, with whether its audience gets automatic intake now. */
        read: (input: Facade.CampaignProgramReadRequest): Facade.CampaignProgramReadResult => this.#call(() => this.#client.vaultCampaignProgramRead(input) as Facade.CampaignProgramReadResult),
        /** Replaces a campaign program's name, steps and audience whole under a version check; work queued at a dropped step stops. */
        update: (input: Facade.UpdateCampaignProgramRequest): Facade.CampaignProgramRecord => this.#call(() => this.#client.vaultCampaignProgramUpdate(input) as Facade.CampaignProgramRecord),
        /** Archives a campaign program: it stays readable, enrolls no one, and its queued enrollment work stops. */
        archive: (input: Facade.ArchiveCampaignProgramRequest): Facade.CampaignProgramRecord => this.#call(() => this.#client.vaultCampaignProgramArchive(input) as Facade.CampaignProgramRecord),
      },
    },
    weave: {
      /** The live weave report for the bound actor, read through its own scope and the vault's weave policy for its role. */
      report: (input: Facade.WeaveReportRequest): Facade.WeaveReportView => this.#call(() => this.#client.vaultWeaveReport(input) as Facade.WeaveReportView),
      /** One of the bound actor's saved weave digests, or the newest, under the current read policy. Its lens is a card; a server holds its frame for the card's events, an embedded handle holds none. */
      digest: Object.assign((input: Facade.WeaveDigestRequest): Facade.WeaveDigestView | null => this.#call(() => this.#client.vaultWeaveDigest(input) as Facade.WeaveDigestView | null), {
        /** Publishes the bound reader's due digest through the same live scoped lens and returns its saved period and narrowing receipt, or null when nothing is due. */
        render: (input: Facade.EmptyRequest = {}): Facade.WeaveDigestRendered | null => this.#call(() => this.#client.vaultWeaveDigestRender(input) as Facade.WeaveDigestRendered | null),
      }),
      /** Renders the caller's live weave report through the weave-report skill on the server's model, as a card whose wrong controls are its declared actions; the server holds its frame for the card's events. */
      lens: (input: Facade.WeaveReportRequest): Facade.LensFrameCard => this.#call(() => this.#client.vaultWeaveLens(input) as Facade.LensFrameCard),
      link: {
        /** A person labels a link in their own lens as wrong; the label teaches the loops and the link stays. */
        wrong: (input: Facade.WeaveWrongLinkRequest): Facade.WeaveLinkCorrectionView => this.#call(() => this.#client.vaultWeaveLinkWrong(input) as Facade.WeaveLinkCorrectionView),
        /** Reads persisted wrong-link labels for a link still admitted by the caller's live weave lens, without changing the link. */
        corrections: (input: Facade.WeaveWrongLinkRequest): Facade.WeaveLinkCorrectionView[] => this.#call(() => this.#client.vaultWeaveLinkCorrections(input) as Facade.WeaveLinkCorrectionView[]),
      },
      owner: {
        link: {
          /** The owner labels a link in the owner lens as wrong, under the owner's own credential; the label teaches the loops and the link stays. */
          wrong: (input: Facade.WeaveWrongLinkRequest): Facade.WeaveLinkCorrectionView => this.#call(() => this.#client.vaultWeaveOwnerLinkWrong(input) as Facade.WeaveLinkCorrectionView),
        },
        item: {
          /** The owner labels a claim, project or budget item in the owner lens as wrong, under the owner's own credential; the label teaches the loops and the record stays. */
          wrong: (input: Facade.WeaveWrongItemRequest): Facade.WeaveItemCorrectionView => this.#call(() => this.#client.vaultWeaveOwnerItemWrong(input) as Facade.WeaveItemCorrectionView),
        },
        digest: {
          /** Publishes the owner's due digest through the live owner lens and returns the saved period and narrowing receipt, or null when nothing is due. */
          render: (input: Facade.EmptyRequest = {}): Facade.WeaveDigestRendered | null => this.#call(() => this.#client.vaultWeaveOwnerDigestRender(input) as Facade.WeaveDigestRendered | null),
        },
      },
      item: {
        /** A person labels a claim, project or budget item in their own lens as wrong; the label teaches the loops and the record stays. */
        wrong: (input: Facade.WeaveWrongItemRequest): Facade.WeaveItemCorrectionView => this.#call(() => this.#client.vaultWeaveItemWrong(input) as Facade.WeaveItemCorrectionView),
      },
      /** Admits a generated candidate weave recipe under the owner's proof and queues its pinned execution; poll vault.consolidation.status for completion. */
      enqueue: (input: Facade.WeaveEnqueueRequest): Facade.DreamerAttemptRef => this.#call(() => this.#client.vaultWeaveEnqueue(input) as Facade.DreamerAttemptRef),
      schedules: {
        /** Lists every reader's daily or weekly weave digest schedule under the owner's proof. */
        list: (input: Facade.EmptyRequest = {}): Facade.WeaveScheduleView[] => this.#call(() => this.#client.vaultWeaveSchedulesList(input) as Facade.WeaveScheduleView[]),
        /** Sets one reader's daily or weekly digest schedule and section recipe under the owner's proof. */
        put: (input: Facade.WeaveScheduleView): Facade.WeaveScheduleView => this.#call(() => this.#client.vaultWeaveSchedulesPut(input) as Facade.WeaveScheduleView),
        /** Stops one reader's digest schedule under the owner's proof, keeping its saved periods. */
        clear: (input: Facade.WeaveReaderRef): Facade.WeaveScheduleCleared => this.#call(() => this.#client.vaultWeaveSchedulesClear(input) as Facade.WeaveScheduleCleared),
      },
    },
    inbox: {
      concerns: {
        /** Queues the Coach's real health review under the owner's proof; findings and recipients come from engine evidence, never supplied concern rows. */
        review: (input: Facade.EmptyRequest = {}): Facade.DreamerAttemptRef => this.#call(() => this.#client.vaultInboxConcernsReview(input) as Facade.DreamerAttemptRef),
      },
      /** Reads the owner's cross-identity inbox lens in impact order, optionally filtered by identity or agent, with concern groups per agent. */
      lens: (input: Facade.InboxLensRequest): Facade.InboxLensPage => this.#call(() => this.#client.vaultInboxLens(input) as Facade.InboxLensPage),
      /** Reads membership of real gate-held Dreamer consent proposals grouped by run, under the owner's proof. */
      groups: (input: Facade.InboxRunGroupsRequest): Facade.InboxGroup[] => this.#call(() => this.#client.vaultInboxGroups(input) as Facade.InboxGroup[]),
    },
    skill_hubs: {
      /** The owner registers or revises a hub source; hub trust never grants activation authority. */
      put: (input: Facade.SkillHubPutRequest): Facade.SkillHubConfigured => this.#call(() => this.#client.vaultSkillHubsPut(input) as Facade.SkillHubConfigured),
      /** Reads one configured hub as the owner. */
      get: (input: Facade.SkillHubRequest): Facade.SkillHubRecord => this.#call(() => this.#client.vaultSkillHubsGet(input) as Facade.SkillHubRecord),
      publishers: {
        /** The owner admits a foreign publisher to offer candidates from one configured hub, and nothing else. */
        admit: (input: Facade.SkillPublisherRequest): Facade.SkillPublisherAdmission => this.#call(() => this.#client.vaultSkillHubsPublishersAdmit(input) as Facade.SkillPublisherAdmission),
        /** The owner revokes the exact offer-only publisher grant; foreign hooks recheck it before running. */
        revoke: (input: Facade.SkillPublisherRequest): Facade.HubConsentReceipt => this.#call(() => this.#client.vaultSkillHubsPublishersRevoke(input) as Facade.HubConsentReceipt),
      },
      refs: {
        /** Reads one hub ref policy, pin and separate seen and trusted revisions as the owner. */
        get: (input: Facade.HubRefRequest): Facade.TrackedHubRef | null => this.#call(() => this.#client.vaultSkillHubsRefsGet(input) as Facade.TrackedHubRef | null),
        /** The owner changes one hub ref policy and pin without fetching or trusting new bytes. */
        set: (input: Facade.HubRefSetRequest): Facade.TrackedHubRef => this.#call(() => this.#client.vaultSkillHubsRefsSet(input) as Facade.TrackedHubRef),
      },
    },
    packs: {
      /** The owner fetches a pinned hub pack as its foreign publisher; code stays Candidate and hooks wait for consent. */
      install: (input: Facade.HubImportRequest): Facade.PackPutReceipt => this.#call(() => this.#client.vaultPacksInstall(input) as Facade.PackPutReceipt),
      /** The owner syncs a hub pack at its stored ref policy; wider hooks keep their old bindings until re-consent. */
      sync: (input: Facade.HubPackRequest): Facade.PackPutReceipt => this.#call(() => this.#client.vaultPacksSync(input) as Facade.PackPutReceipt),
      /** Reads an installed pack and its exact source, pin, publisher and requested powers as the owner. */
      get: (input: Facade.HubPackRequest): Facade.PackInstallReceipt | null => this.#call(() => this.#client.vaultPacksGet(input) as Facade.PackInstallReceipt | null),
      hooks: {
        /** The owner consents to the installed pack hook capabilities, including a widening update; publisher identity stays foreign. */
        bind: (input: Facade.HubHookBindRequest): Facade.EntityId[] => this.#call(() => this.#client.vaultPacksHooksBind(input) as Facade.EntityId[]),
        /** Reads live pack hook bindings and their effective read grants as the owner, excluding revoked foreign publisher grants. */
        list: (input: Facade.EmptyRequest = {}): Facade.HubHookBindingRow[] => this.#call(() => this.#client.vaultPacksHooksList(input) as Facade.HubHookBindingRow[]),
        grant: {
          /** The owner sets or changes a live hook binding's read grant; outcomes still run as the hook's author. Returns the assigned grant. */
          set: (input: Facade.HookGrantSetRequest): Facade.HookGrantView => this.#call(() => this.#client.vaultPacksHooksGrantSet(input) as Facade.HookGrantView),
          /** Reads a live hook binding's effective read grant as the owner: its manual assignment, or the author's ceiling when none was set. */
          get: (input: Facade.HookGrantRequest): Facade.HookGrantView => this.#call(() => this.#client.vaultPacksHooksGrantGet(input) as Facade.HookGrantView),
        },
        /** The owner qualifies a Candidate hub hook pack by real sandbox replay; qualification does not consent to wider hooks. */
        qualify: (input: Facade.HubHookQualifyRequest): Facade.HubHookQualificationReceipt => this.#call(() => this.#client.vaultPacksHooksQualify(input) as Facade.HubHookQualificationReceipt),
      },
      /** The owner installs a pack folder, or replaces the pack installed under its name, each file sent as text or as content_base64 bytes; the put is the consent for its hooks. */
      put: (input: Facade.PackPutRequest): Facade.PackPutReceipt => this.#call(() => this.#client.vaultPacksPut(input) as Facade.PackPutReceipt),
      connector: {
        /** Prepares an immutable connector pack admission, comparing the resolved declaration with the installed transport and drafting an ungranted slate. */
        prepare: (input: Facade.ConnectorPackPrepareRequest): Facade.ConnectorPackView => this.#call(() => this.#client.vaultPacksConnectorPrepare(input) as Facade.ConnectorPackView),
        /** Reads a connector pack source, resolved manifest, advisory evidence, qualification and owner-stampable capability rows. */
        get: (input: Facade.ConnectorPackGetRequest): Facade.ConnectorPackView => this.#call(() => this.#client.vaultPacksConnectorGet(input) as Facade.ConnectorPackView),
        /** Runs the real connector probes bound to the exact pack source and protocol; qualification grants nothing without the owner slate and actor grant. */
        qualify: (input: Facade.ConnectorPackQualifyRequest): Facade.ConnectorPackView => this.#call(() => this.#client.vaultPacksConnectorQualify(input) as Facade.ConnectorPackView),
        /** Stamps the exact connector pack manifest and grant rows once, or revokes a row; qualification stays independent. */
        accept: (input: Facade.ConnectorPackAcceptRequest): Facade.ConnectorPackView => this.#call(() => this.#client.vaultPacksConnectorAccept(input) as Facade.ConnectorPackView),
        /** Holds a connector pack at its new immutable source and protocol, carrying narrow rows and re-asking only for expanded capabilities. */
        update: (input: Facade.ConnectorPackUpdateRequest): Facade.ConnectorPackDelta => this.#call(() => this.#client.vaultPacksConnectorUpdate(input) as Facade.ConnectorPackDelta),
        grants: {
          /** Reads current per-capability authority for one actor on the reviewed connector pack source. */
          get: (input: Facade.ConnectorPackGrantsGetRequest): Facade.ConnectorPackGrants => this.#call(() => this.#client.vaultPacksConnectorGrantsGet(input) as Facade.ConnectorPackGrants),
          /** Grants declared connector pack rows to one actor through the existing owner consent gate and installed endpoint. */
          put: (input: Facade.ConnectorPackGrantsPutRequest): Facade.ConnectorPackGrants => this.#call(() => this.#client.vaultPacksConnectorGrantsPut(input) as Facade.ConnectorPackGrants),
        },
      },
      /** The owner removes an installed pack: it leaves the Active catalog and its hook bindings stop; a built-in goes back to its Candidate. */
      remove: (input: Facade.PackRemoveRequest): Facade.PackInstallReceipt => this.#call(() => this.#client.vaultPacksRemove(input) as Facade.PackInstallReceipt),
      sections: {
        /** The caller offers one typed plugin section manifest for an existing skill or a pinned hub package; it waits as a proposed install claim and registers nothing. */
        propose: (input: Facade.PluginSectionProposeRequest): Facade.PluginSectionProposal => this.#call(() => this.#client.vaultPacksSectionsPropose(input) as Facade.PluginSectionProposal),
        /** Plugin sections as they stand: install offers awaiting the owner, admitted sections with their granted manifests, and the sections installed packs project. */
        list: (input: Facade.PluginSectionListRequest): Facade.PluginSectionsView => this.#call(() => this.#client.vaultPacksSectionsList(input) as Facade.PluginSectionsView),
        /** The owner grants exactly the reviewed plugin section install: the claim settles through its review handle and the section is admitted under that same consent. */
        grant: (input: Facade.PluginSectionGrantRequest): Facade.PluginSectionGrant => this.#call(() => this.#client.vaultPacksSectionsGrant(input) as Facade.PluginSectionGrant),
        /** The owner revokes a plugin section grant by retracting its install claim; the section and its advertised verbs leave the next board rebuild. */
        revoke: (input: Facade.PluginSectionRevokeRequest): Facade.PluginSectionRevoked => this.#call(() => this.#client.vaultPacksSectionsRevoke(input) as Facade.PluginSectionRevoked),
        /** Runs one workflow-pattern suggestion pass over a pinned hub on the caller's credential: a repeating pattern nominates at most one pack as an attributed proposal. */
        suggest: (input: Facade.PluginSectionSuggestRequest): Facade.PluginSectionSuggestion => this.#call(() => this.#client.vaultPacksSectionsSuggest(input) as Facade.PluginSectionSuggestion),
        suggestions: {
          /** The owner's plugin suggestion knob: whether workflow-pattern suggestion passes may run at all. */
          get: (input: Facade.EmptyRequest = {}): Facade.PluginSuggestionsView => this.#call(() => this.#client.vaultPacksSectionsSuggestionsGet(input) as Facade.PluginSuggestionsView),
          /** The owner turns plugin suggestions on or off; off silences every later pass before any catalog is consulted. */
          set: (input: Facade.PluginSuggestionsSetRequest): Facade.PluginSuggestionsView => this.#call(() => this.#client.vaultPacksSectionsSuggestionsSet(input) as Facade.PluginSuggestionsView),
        },
      },
      setup: {
        /** The owner opens, or resumes, a pack's guided setup; opening grants nothing. */
        prepare: (input: Facade.PackSetupRequest): Facade.PackSetupReceipt => this.#call(() => this.#client.vaultPacksSetupPrepare(input) as Facade.PackSetupReceipt),
        /** A pack's guided setup as it stands, for the owner. */
        get: (input: Facade.PackSetupRequest): Facade.PackSetupReceipt => this.#call(() => this.#client.vaultPacksSetupGet(input) as Facade.PackSetupReceipt),
        /** The owner's one typed answer or card action in a pack's guided setup; a credential value never passes here. */
        answer: (input: Facade.PackSetupAnswerRequest): Facade.PackSetupReceipt => this.#call(() => this.#client.vaultPacksSetupAnswer(input) as Facade.PackSetupReceipt),
        /** Checks one pack connection with the engine's fixed read-only provider call for its declared check. */
        verify: (input: Facade.PackSetupVerifyRequest): Facade.PackSetupReceipt => this.#call(() => this.#client.vaultPacksSetupVerify(input) as Facade.PackSetupReceipt),
      },
    },
    skills: {
      /** The owner imports a pinned hub skill through scanning and publisher admission, pending its permission ask. */
      import: (input: Facade.HubImportRequest): Facade.HubSkillImported => this.#call(() => this.#client.vaultSkillsImport(input) as Facade.HubSkillImported),
      /** The owner syncs a hub skill under its ref policy; widening proposes without changing trusted capabilities. */
      sync: (input: Facade.HubSkillRequest): Facade.HubSkillSyncReceipt => this.#call(() => this.#client.vaultSkillsSync(input) as Facade.HubSkillSyncReceipt),
      /** Reads every hub source and import receipt of a skill, and its held-out admission ruling, as the owner. */
      receipts: (input: Facade.HubSkillRequest): Facade.HubSkillReceipts => this.#call(() => this.#client.vaultSkillsReceipts(input) as Facade.HubSkillReceipts),
      /** Converts selected messages through the configured refiner; user initiation approves conversion, never admission. */
      convert: (input: Facade.SkillConvertRequest): Facade.SkillConvertReceipt => this.#call(() => this.#client.vaultSkillsConvert(input) as Facade.SkillConvertReceipt),
      /** Reads skill lifecycle, exact source, provenance, source availability, scan and admission receipts, and retained fork ancestry. */
      get: (input: Facade.HubSkillRequest): Facade.SkillLibraryView => this.#call(() => this.#client.vaultSkillsGet(input) as Facade.SkillLibraryView),
      /** Lists a page of the owner skill library, including inactive skills and their retained evidence. */
      list: (input: Facade.SkillLibraryListRequest): Facade.SkillLibraryPage => this.#call(() => this.#client.vaultSkillsList(input) as Facade.SkillLibraryPage),
      /** The owner soft-retires an active skill without deleting its body, source or receipts; running callable invocations are cancelled. */
      archive: (input: Facade.HubSkillRequest): Facade.SkillLibraryView => this.#call(() => this.#client.vaultSkillsArchive(input) as Facade.SkillLibraryView),
      /** The owner restores an archived skill through the same admission gates; a hub restore prepares exact consent and reruns held-out scoring. */
      restore: (input: Facade.SkillLibraryRestoreRequest): Facade.SkillLibraryRestoreReceipt => this.#call(() => this.#client.vaultSkillsRestore(input) as Facade.SkillLibraryRestoreReceipt),
      /** The owner forks a stored skill under a new identity through the existing fork law; retained parent/version and hub ancestry remain inspectable. */
      fork: (input: Facade.SkillLibraryForkRequest): Facade.SkillLibraryView => this.#call(() => this.#client.vaultSkillsFork(input) as Facade.SkillLibraryView),
      rules: {
        /** The owner sets or clears a known-bad canonical skill hash rule, independently of advisory scanner prose. */
        set: (input: Facade.SkillHashRuleRequest): Facade.HubConsentReceipt => this.#call(() => this.#client.vaultSkillsRulesSet(input) as Facade.HubConsentReceipt),
      },
      code_auto_install: {
        /** The owner sets the code auto-install switch through its existing consent gate; the switch grants no sandbox qualification. */
        set: (input: Facade.SkillCodeAutoInstallRequest): Facade.HubConsentReceipt => this.#call(() => this.#client.vaultSkillsCodeAutoInstallSet(input) as Facade.HubConsentReceipt),
      },
      permissions: {
        /** The owner answers one imported skill permission ask at its exact hub source. */
        approve: (input: Facade.HubSkillPermissionRequest): Facade.HubConsentReceipt => this.#call(() => this.#client.vaultSkillsPermissionsApprove(input) as Facade.HubConsentReceipt),
      },
      optimize: {
        /** The owner starts one skill_optimize attempt on the Dreamer queue; a named identity or alignment skill is excluded and never enqueued. */
        start: (input: Facade.SkillOptimizeStartRequest): Facade.SkillOptimizeStartReceipt => this.#call(() => this.#client.vaultSkillsOptimizeStart(input) as Facade.SkillOptimizeStartReceipt),
        /** Reads a started skill_optimize job, its drafted proposal, the incumbent, its governance and every held-out verdict on the proposal. */
        result: (input: Facade.SkillOptimizeResultRequest): Facade.SkillOptimizeResultView => this.#call(() => this.#client.vaultSkillsOptimizeResult(input) as Facade.SkillOptimizeResultView),
        /** Submits one explicit optimizer candidate against a fixed baseline version and a real drafting attempt; ordinary held-out admission still rules. */
        propose: (input: Facade.SkillOptimizeProposeRequest): Facade.SkillOptimizeProposalReceipt => this.#call(() => this.#client.vaultSkillsOptimizePropose(input) as Facade.SkillOptimizeProposalReceipt),
        /** Judges held-out floors before any online slice, then measures the proposal on the effective goal with the registered judge and bounded live arms. */
        measure: (input: Facade.SkillOptimizeMeasureRequest): Facade.SkillOptimizeMeasurement => this.#call(() => this.#client.vaultSkillsOptimizeMeasure(input) as Facade.SkillOptimizeMeasurement),
        /** Rules on the submitted proposal through the existing held-out vector gate, floors and tradeoff ladder, without activating it. */
        score: (input: Facade.SkillOptimizeProposalRequest): Facade.SkillOptimizeResultView => this.#call(() => this.#client.vaultSkillsOptimizeScore(input) as Facade.SkillOptimizeResultView),
        /** Admits only a standing gate acceptance and supersedes its incumbent atomically, with current body, evidence, tier, goal and owner checks. */
        admit: (input: Facade.SkillOptimizeProposalRequest): Facade.SkillOptimizeResultView => this.#call(() => this.#client.vaultSkillsOptimizeAdmit(input) as Facade.SkillOptimizeResultView),
        goal: {
          /** Reads the optimizer goal identity, effective axes, revision and joined project goal claim. */
          get: (input: Facade.SkillOptimizeGoalRequest): Facade.SkillOptimizeGoalView => this.#call(() => this.#client.vaultSkillsOptimizeGoalGet(input) as Facade.SkillOptimizeGoalView),
          /** Joins a skill goal to the human project goal record, or unbinds with null; every join changes its admission revision. */
          bind: (input: Facade.SkillOptimizeGoalBindRequest): Facade.SkillOptimizeGoalRevision => this.#call(() => this.#client.vaultSkillsOptimizeGoalBind(input) as Facade.SkillOptimizeGoalRevision),
        },
        preferences: {
          /** Reads authored and learned goal tradeoff rules and the typed judgment band, without changing authority. */
          get: (input: Facade.SkillOptimizeGoalRequest): Facade.SkillTradeoffPreferences | null => this.#call(() => this.#client.vaultSkillsOptimizePreferencesGet(input) as Facade.SkillTradeoffPreferences | null),
          /** The responsible owner sets authored tradeoff rules and the typed judgment band, retaining learned picks and every admission clamp. */
          set: (input: Facade.SkillOptimizePreferencesSetRequest): Facade.SkillOptimizeGoalRevision => this.#call(() => this.#client.vaultSkillsOptimizePreferencesSet(input) as Facade.SkillOptimizeGoalRevision),
        },
        /** Lists the exact pending optimizer tradeoffs that have reached a role the caller holds, including bound typed judgment evidence. */
        tradeoff_asks: Object.assign((input: Facade.EmptyRequest = {}): Facade.SkillOptimizeTradeoffAskView[] => this.#call(() => this.#client.vaultSkillsOptimizeTradeoffAsks(input) as Facade.SkillOptimizeTradeoffAskView[]), {
          /** Approves or rejects the exact shown tradeoff; the attributed pick becomes a preference and a proposed project revision, never a Grant. */
          pick: (input: Facade.SkillOptimizeTradeoffPickRequest): Facade.SkillOptimizeResultView => this.#call(() => this.#client.vaultSkillsOptimizeTradeoffAsksPick(input) as Facade.SkillOptimizeResultView),
        }),
      },
      governance: {
        /** Reads one skill governance tier as the owner, resolved fail-closed, and whether the automated edit loop may consider it. */
        get: (input: Facade.HubSkillRequest): Facade.SkillGovernanceView => this.#call(() => this.#client.vaultSkillsGovernanceGet(input) as Facade.SkillGovernanceView),
        /** The owner marks or clears one skill governance tier; the mark changes no instruction content or version. */
        set: (input: Facade.SkillGovernanceSetRequest): Facade.SkillGovernanceView => this.#call(() => this.#client.vaultSkillsGovernanceSet(input) as Facade.SkillGovernanceView),
      },
      /** Reads a terminal pack receipt with its frozen loaded versions and actual-use attribution as the owner. */
      pack_receipt: (input: Facade.SkillPackReceiptRequest): Facade.SkillPackReceipt => this.#call(() => this.#client.vaultSkillsPackReceipt(input) as Facade.SkillPackReceipt),
      outcomes: {
        /** Projects the owner's anchored verdict through existing attributed pack outcomes; loading or calling alone never earns a reliability win. */
        project: (input: Facade.SkillPackOutcomeRequest): Facade.SkillPackOutcomeProjection => this.#call(() => this.#client.vaultSkillsOutcomesProject(input) as Facade.SkillPackOutcomeProjection),
        /** Reads the persisted anchored pack credit receipt, including its execution context, direct subjects and lineage shares, as the owner. */
        get: (input: Facade.SkillPackCreditRequest): Facade.LateCreditReceipt | null => this.#call(() => this.#client.vaultSkillsOutcomesGet(input) as Facade.LateCreditReceipt | null),
      },
      attribution: {
        /** The owner settles one amended proposal: exact replacements are recorded, the delta is measured from those ops, hunks are judged and each share routes to its consumer. */
        settle: (input: Facade.ProposalDeltaSettleRequest): Facade.ProposalDeltaSettlement => this.#call(() => this.#client.vaultSkillsAttributionSettle(input) as Facade.ProposalDeltaSettlement),
        /** The owner reads one proposal settlement by receipt: its measured delta, recorded ops, amendment evidence, judgment, preference notes and unclear rows. */
        read: (input: Facade.ProposalDeltaReadRequest): Facade.ProposalDeltaRead => this.#call(() => this.#client.vaultSkillsAttributionRead(input) as Facade.ProposalDeltaRead),
        evidence: {
          /** The owner records one attempt outcome as attribution evidence, grounded against its stamped pack receipt; recording never classifies it. */
          record: (input: Facade.AttributionEvidenceRequest): Facade.AttributionEvidenceReceipt => this.#call(() => this.#client.vaultSkillsAttributionEvidenceRecord(input) as Facade.AttributionEvidenceReceipt),
        },
        /** The owner runs one attribution pass over recorded evidence, plus the positive lane, returning the judgments and positive proposals it minted. */
        project: (input: Facade.AttributionProjectRequest): Facade.AttributionProjection => this.#call(() => this.#client.vaultSkillsAttributionProject(input) as Facade.AttributionProjection),
        /** The owner reads every persisted attribution judgment in both lanes, the projector cursor and the unclear ledger. */
        judgments: (input: Facade.AttributionListRequest): Facade.AttributionJudgmentsView => this.#call(() => this.#client.vaultSkillsAttributionJudgments(input) as Facade.AttributionJudgmentsView),
        /** The owner reads the pending skill edit proposals, preference proposals and positive skill proposals attribution has minted. */
        proposals: (input: Facade.AttributionListRequest): Facade.AttributionProposalsView => this.#call(() => this.#client.vaultSkillsAttributionProposals(input) as Facade.AttributionProposalsView),
        positive: {
          /** The owner retires one positive skill proposal once the optimizer has drafted from it or declined it. */
          retire: (input: Facade.PositiveRetireRequest): Facade.PositiveRetireReceipt => this.#call(() => this.#client.vaultSkillsAttributionPositiveRetire(input) as Facade.PositiveRetireReceipt),
        },
      },
    },
    projects: {
      goal: {
        /** What a project's goal-intake interview starts from, for a member of its home room. */
        intake: Object.assign((input: Facade.ProjectRefRequest): Facade.ProjectGoalInterviewContext => this.#call(() => this.#client.vaultProjectsGoalIntake(input) as Facade.ProjectGoalInterviewContext), {
          /** Completes the witnessed human goal-intake interview with the full confirmed record; no agent proposal can write the effective goal. */
          complete: (input: Facade.ProjectGoalIntakeCompleteRequest): Facade.ProjectGoalIntakeReceipt => this.#call(() => this.#client.vaultProjectsGoalIntakeComplete(input) as Facade.ProjectGoalIntakeReceipt),
        }),
        /** Reads the full effective goal record and its claim together; interview drafts and loop proposals never replace it. */
        get: (input: Facade.ProjectRefRequest): Facade.ProjectGoalView => this.#call(() => this.#client.vaultProjectsGoalGet(input) as Facade.ProjectGoalView),
        /** The learned goal preferences proposed for a project's goal in force and not dismissed, oldest first. */
        revisions: (input: Facade.ProjectRefRequest): Facade.ProjectGoalRevisionProposal[] => this.#call(() => this.#client.vaultProjectsGoalRevisions(input) as Facade.ProjectGoalRevisionProposal[]),
        /** The owner dismisses the proposal one tradeoff question made for a project's goal; false for an identical retry. */
        dismiss: (input: Facade.ProjectGoalDismissRequest): Facade.ProjectGoalDismissReceipt => this.#call(() => this.#client.vaultProjectsGoalDismiss(input) as Facade.ProjectGoalDismissReceipt),
      },
      /** The drafting agent proposes a project card on a source message; the card writes no project and confers no authority. */
      propose: (input: Facade.ProjectProposalRequest): Facade.ProjectProposalCard => this.#call(() => this.#client.vaultProjectsPropose(input) as Facade.ProjectProposalCard),
      /** The project cards shown in a conversation, each with its state. */
      proposals: (input: Facade.ProjectConversationRequest): Facade.ProjectCardRecord[] => this.#call(() => this.#client.vaultProjectsProposals(input) as Facade.ProjectCardRecord[]),
      /** The card's person dismisses a project card so it never mints; false when it was dismissed already. */
      dismiss_card: (input: Facade.ProjectCardRequest): Facade.ProjectCardDismissal => this.#call(() => this.#client.vaultProjectsDismissCard(input) as Facade.ProjectCardDismissal),
      /** The owner's tap that confirms a host-held project card; only the host's own door can complete it. */
      confirm: (input: Facade.ProjectCardConfirmRequest): Facade.ProjectMintReceipt => this.#call(() => this.#client.vaultProjectsConfirm(input) as Facade.ProjectMintReceipt),
      roster: {
        /** Writes an existing project's signed roster as the bound caller, filing joins for the newly seated subjects it stands for and an invitation for each unrelated person, who accepts through vault.rooms.consent. */
        write: (input: Facade.ProjectRosterWriteRequest): Facade.ProjectRosterWriteOutcome => this.#call(() => this.#client.vaultProjectsRosterWrite(input) as Facade.ProjectRosterWriteOutcome),
      },
      /** Asks the A/B tradeoff question pending on a skill proposal on a project TASK, as a visible turn in its home room. */
      route_tradeoff: (input: Facade.ProjectTradeoffRouteRequest): Facade.TaskAskReceipt => this.#call(() => this.#client.vaultProjectsRouteTradeoff(input) as Facade.TaskAskReceipt),
    },
    connectors: {
      proxy: {
        /** The owner admits the OpenAI memory proxy for one paired actor, stamping its read and remember slate and activating its connector key. */
        admit: (input: Facade.ProxyConnectorAdmitRequest): Facade.ProxyConnectorRegistration => this.#call(() => this.#client.vaultConnectorsProxyAdmit(input) as Facade.ProxyConnectorRegistration),
        /** The owner withdraws only the proxy remember grant at the reviewed key and slate revision; read access, stored memories and the connector remain intact. */
        revoke_write: (input: Facade.ProxyConnectorRevokeWriteRequest): Facade.ProxyConnectorRegistration => this.#call(() => this.#client.vaultConnectorsProxyRevokeWrite(input) as Facade.ProxyConnectorRegistration),
      },
      subscriptions: {
        /** The owner subscribes an agent to the messages a built-in channel (slack or line) routes to it, so each one wakes the agent to answer. */
        put: (input: Facade.ChannelSubscriptionRequest): Facade.ChannelMessageSubscription => this.#call(() => this.#client.vaultConnectorsSubscriptionsPut(input) as Facade.ChannelMessageSubscription),
        /** An agent's connector event subscriptions, standing and revoked, for the owner. */
        list: (input: Facade.ChannelSubscriptionsRequest): Facade.ChannelSubscriptions => this.#call(() => this.#client.vaultConnectorsSubscriptionsList(input) as Facade.ChannelSubscriptions),
        /** The owner stops one connector event subscription; the agent's key for the channel stays. */
        revoke: (input: Facade.ChannelSubscriptionRevokeRequest): Facade.ChannelSubscriptionRevoked => this.#call(() => this.#client.vaultConnectorsSubscriptionsRevoke(input) as Facade.ChannelSubscriptionRevoked),
      },
    },
    authority: {
      /** One page of the dated authority log audit, for the owner: grants, revokes and confirms. On a vault that adopted a checkpoint image a page can also carry cold, checkpoint-attested rows it does not store, with no clock or kind. */
      audit: (input: Facade.AuthorityAuditQuery): Facade.AuthorityAuditPage => this.#call(() => this.#client.vaultAuthorityAudit(input) as Facade.AuthorityAuditPage),
      history: {
        /** Exports the full original signed authority history, including quarantined forks, as base64 envelopes for the owner. No signing secret leaves. */
        export: (input: Facade.EmptyRequest = {}): Facade.SignedAuthorityHistory => this.#call(() => this.#client.vaultAuthorityHistoryExport(input) as Facade.SignedAuthorityHistory),
        /** Imports original base64 signed authority envelopes atomically for the owner, preserving bytes and refolding locally. Invalid signatures, foreign genesis and missing parents write nothing. */
        import: (input: Facade.SignedAuthorityHistory): Facade.AuthorityHistoryImported => this.#call(() => this.#client.vaultAuthorityHistoryImport(input) as Facade.AuthorityHistoryImported),
      },
      /** Every saved authority handoff fork alarm, for the owner. */
      handoff_alarms: Object.assign((input: Facade.EmptyRequest = {}): Facade.AuthorityHandoffAlarm[] => this.#call(() => this.#client.vaultAuthorityHandoffAlarms(input) as Facade.AuthorityHandoffAlarm[]), {
        /** The owner acknowledges one saved handoff fork alarm. */
        acknowledge: (input: Facade.HandoffAlarmRequest): Facade.AuthorityHandoffAlarm => this.#call(() => this.#client.vaultAuthorityHandoffAlarmsAcknowledge(input) as Facade.AuthorityHandoffAlarm),
      }),
    },
    wire_health: {
      thresholds: {
        /** The owner reads the serving host's per-verb and per-actor wire detection thresholds and their window; crossings ask a health question, never refuse for rate. */
        get: (input: Facade.EmptyRequest): Facade.WireThresholds => this.#call(() => this.#client.vaultWireHealthThresholdsGet(input) as Facade.WireThresholds),
        /** The owner replaces the serving host's positive wire detection thresholds and window, receiving the previous and installed policy without adding a rate refusal. */
        set: (input: Facade.WireThresholds): Facade.WireThresholdsReceipt => this.#call(() => this.#client.vaultWireHealthThresholdsSet(input) as Facade.WireThresholdsReceipt),
      },
    },
    slim: {
      /** Reads the serving host idle policy: the long outbound wait, no exit on idle and lazy heap rebuild. */
      policy: (input: Facade.EmptyRequest): Facade.SlimIdlePolicy => this.#call(() => this.#client.vaultSlimPolicy(input) as Facade.SlimIdlePolicy),
      /** Observes FULL or SLIM atomically with this process id and the retained journaled resume pointer, without waking the vault. */
      state: (input: Facade.EmptyRequest): Facade.SlimStateSnapshot => this.#call(() => this.#client.vaultSlimState(input) as Facade.SlimStateSnapshot),
      /** Reads a saved model checkpoint or outbound intent by its retained identity, including after FULL or restart, without reissuing it. */
      resume_step: (input: Facade.SlimResumeStepRequest): Facade.SavedResumeStep => this.#call(() => this.#client.vaultSlimResumeStep(input) as Facade.SavedResumeStep),
      /** Drops rebuildable heap in process and returns the completed engine transition, drop counts or typed refusal; one journaled outbound step is required. */
      drop_heavy: (input: Facade.SlimDropRequest): Facade.SlimDropReceipt => this.#call(() => this.#client.vaultSlimDropHeavy(input) as Facade.SlimDropReceipt),
      /** Resumes logical FULL in the same process and returns its completion receipt; indexes rebuild lazily and no saved outbound step is reissued. */
      resume: (input: Facade.EmptyRequest): Facade.SlimResumeReceipt => this.#call(() => this.#client.vaultSlimResume(input) as Facade.SlimResumeReceipt),
    },
    mesh: {
      /** The newest path receipts this machine's paired-machine mesh left, newest first and bounded: direct or relayed, admitted, refused or failed, for the owner. */
      path_receipts: (input: Facade.MeshPathReceiptsRequest): Facade.MeshPathReceipt[] => this.#call(() => this.#client.vaultMeshPathReceipts(input) as Facade.MeshPathReceipt[]),
    },
    inspection: {
      /** Resolves an inspection handle for the caller; unreadable, missing and wrong-kind targets all answer with no item. */
      resolve: (input: Facade.InspectionResolveRequest): Facade.InspectionResolved => this.#call(() => this.#client.vaultInspectionResolve(input) as Facade.InspectionResolved),
    },
    shared: {
      /** Starts a shared vault's delete_vault act, returned as a typed pending act. */
      propose_delete: (input: Facade.SharedVaultRequest): Facade.PendingAuthorityAct => this.#call(() => this.#client.vaultSharedProposeDelete(input) as Facade.PendingAuthorityAct),
      /** Starts a shared vault's transfer_ownership act: a live Owner hands the vault to another person. */
      propose_transfer: (input: Facade.SharedTransferRequest): Facade.PendingAuthorityAct => this.#call(() => this.#client.vaultSharedProposeTransfer(input) as Facade.PendingAuthorityAct),
      /** Starts a shared vault's remove_owner act, with its export-first answer. */
      propose_remove_owner: (input: Facade.SharedRemoveOwnerRequest): Facade.PendingAuthorityAct => this.#call(() => this.#client.vaultSharedProposeRemoveOwner(input) as Facade.PendingAuthorityAct),
      /** A live Owner runs a matured shared-vault act and gets its receipt. */
      execute: (input: Facade.SharedActRequest): Facade.SharedActExecuted => this.#call(() => this.#client.vaultSharedExecute(input) as Facade.SharedActExecuted),
      /** One shared-act or membership receipt its reader was told about, by id. */
      receipt: (input: Facade.SharedReceiptRequest): Facade.SharedActExecutionReceipt => this.#call(() => this.#client.vaultSharedReceipt(input) as Facade.SharedActExecutionReceipt),
      /** The reader's own outcome notices for a shared vault. */
      outcomes: (input: Facade.SharedVaultRequest): Facade.SharedActOutcome[] => this.#call(() => this.#client.vaultSharedOutcomes(input) as Facade.SharedActOutcome[]),
      /** The executed delete-the-vault act, if any. */
      deletion: (input: Facade.EmptyRequest = {}): Facade.SharedVaultDeletion | null => this.#call(() => this.#client.vaultSharedDeletion(input) as Facade.SharedVaultDeletion | null),
      /** A holder of a pending shared act's objector role objects inside its veto window. */
      object: (input: Facade.SharedActRequest): Facade.PendingAuthorityAct => this.#call(() => this.#client.vaultSharedObject(input) as Facade.PendingAuthorityAct),
      /** The holder withdraws their objection; past the deadline the last withdrawal releases the act. */
      withdraw_objection: (input: Facade.SharedActRequest): Facade.PendingAuthorityAct => this.#call(() => this.#client.vaultSharedWithdrawObjection(input) as Facade.PendingAuthorityAct),
      /** The caller's own notices of shared acts started in the vault. */
      started: (input: Facade.SharedVaultRequest): Facade.PendingActStarted[] => this.#call(() => this.#client.vaultSharedStarted(input) as Facade.PendingActStarted[]),
      /** The caller's own notices of shared acts whose veto window has passed. */
      matured: (input: Facade.SharedVaultRequest): Facade.PendingActMatured[] => this.#call(() => this.#client.vaultSharedMatured(input) as Facade.PendingActMatured[]),
      /** A Member requests, or an Admin proposes, that the Owners erase a record; it erases nothing. */
      erase_ask: (input: Facade.SharedEraseAskRequest): Facade.SharedEraseAsk => this.#call(() => this.#client.vaultSharedEraseAsk(input) as Facade.SharedEraseAsk),
      /** The erase asks the caller may see: every ask for an Owner, their own for anyone else. */
      erase_asks: (input: Facade.SharedVaultRequest): Facade.SharedEraseAsk[] => this.#call(() => this.#client.vaultSharedEraseAsks(input) as Facade.SharedEraseAsk[]),
      /** An Owner closes an open erase ask, as erased (naming its erase act) or declined. */
      close_erase_ask: (input: Facade.SharedEraseAskCloseRequest): Facade.SharedEraseAsk => this.#call(() => this.#client.vaultSharedCloseEraseAsk(input) as Facade.SharedEraseAsk),
      policy: {
        /** A live Owner reads every shared-act policy row of a shared vault: the rows its kind ships, the vault's own rows, the row each act resolves to, and the policy_hash a change binds. */
        get: (input: Facade.SharedVaultRequest): Facade.SharedActPoliciesView => this.#call(() => this.#client.vaultSharedPolicyGet(input) as Facade.SharedActPoliciesView),
        /** A live policy editor proposes one shared-act policy row change against the policy_hash they read; it applies only when every live editor approves it, and one no vetoes it. */
        propose: (input: Facade.SharedActPolicyProposeRequest): Facade.SharedActPolicyChange => this.#call(() => this.#client.vaultSharedPolicyPropose(input) as Facade.SharedActPolicyChange),
        /** A live policy editor approves or vetoes a pending shared-act policy change under their own credential; the last approval of the live editor set writes the row. */
        answer: (input: Facade.SharedActPolicyAnswerRequest): Facade.SharedActPolicyChange => this.#call(() => this.#client.vaultSharedPolicyAnswer(input) as Facade.SharedActPolicyChange),
        /** A live Owner reads one shared-act policy change: its row, approvals, veto, state and the live editors it still waits on. */
        change: (input: Facade.SharedActPolicyChangeRequest): Facade.SharedActPolicyChange => this.#call(() => this.#client.vaultSharedPolicyChange(input) as Facade.SharedActPolicyChange),
      },
    },
    org_admin: {
      /** The owner fixes an organization's Admin identities and closed named-power set once; no root or private-vault power can be configured. */
      configure: (input: Facade.OrgAdminConfigureRequest): Facade.OrgAdminConfigured => this.#call(() => this.#client.vaultOrgAdminConfigure(input) as Facade.OrgAdminConfigured),
      /** The caller reads only the organization's fixed named Admin powers that their own credential carries. */
      powers: (input: Facade.OrgAdminPowersRequest): Facade.OrgAdminPowers => this.#call(() => this.#client.vaultOrgAdminPowers(input) as Facade.OrgAdminPowers),
    },
    members: {
      /** An Admin resets only a non-root shared project's signed access roster through the existing project-proof gate; it never changes a personal root or grants an unsigned override. */
      reset_project_access: (input: Facade.SharedProjectAccessResetRequest): Facade.SharedProjectAccessReset => this.#call(() => this.#client.vaultMembersResetProjectAccess(input) as Facade.SharedProjectAccessReset),
      /** A live parent Admin or Owner mints one explicit scope narrowing for a holder, bounded by policy and a server-clock expiry of at most 90 days; the Delegate cannot delegate onward. */
      delegate: (input: Facade.FederationDelegateRequest): Facade.FederationMemberGrant => this.#call(() => this.#client.vaultMembersDelegate(input) as Facade.FederationMemberGrant),
      /** Read a member's visible role grants, scopes, expiry and person/relationship through the caller's own scoped read; relationship labels confer no additional authority. */
      projection: (input: Facade.SharedMemberRequest): Facade.MemberProjection => this.#call(() => this.#client.vaultMembersProjection(input) as Facade.MemberProjection),
      /** An Admin invites a live person into a shared vault at a non-root role; they join when they accept. Given the invitee's own device key, the host also mints the invitee a slip good only for this invitation while it is pending. */
      add: (input: Facade.SharedMemberAddRequest): Facade.SharedMemberInvited => this.#call(() => this.#client.vaultMembersAdd(input) as Facade.SharedMemberInvited),
      /** An Admin mints a pending invitation's slip for the public key the invitee generated on their own device: a founding invitation's, or one whose slip was lost. */
      invitation_slip: (input: Facade.InvitationSlipRequest): Facade.InvitationSlip => this.#call(() => this.#client.vaultMembersInvitationSlip(input) as Facade.InvitationSlip),
      /** An Admin assigns another non-root role to a member who is not an Owner. */
      change: (input: Facade.SharedMemberRoleRequest): Facade.SharedActExecutionReceipt => this.#call(() => this.#client.vaultMembersChange(input) as Facade.SharedActExecutionReceipt),
      /** An Admin removes one member from a shared vault. */
      remove: (input: Facade.SharedMemberRequest): Facade.SharedActExecutionReceipt => this.#call(() => this.#client.vaultMembersRemove(input) as Facade.SharedActExecutionReceipt),
      /** A member leaves a shared vault under their own proof; an Owner leaves through remove_owner instead. */
      leave: (input: Facade.SharedVaultRequest): Facade.SharedActExecutionReceipt => this.#call(() => this.#client.vaultMembersLeave(input) as Facade.SharedActExecutionReceipt),
      /** The caller's own pending invitations into a shared vault. */
      invitations: (input: Facade.SharedVaultRequest): Facade.SharedInvitation[] => this.#call(() => this.#client.vaultMembersInvitations(input) as Facade.SharedInvitation[]),
      /** The invitee accepts their own invitation and joins the shared vault at its role. */
      accept: (input: Facade.SharedInvitationRequest): Facade.SharedActExecutionReceipt => this.#call(() => this.#client.vaultMembersAccept(input) as Facade.SharedActExecutionReceipt),
      /** The invitee declines their own invitation; nothing is granted. */
      decline: (input: Facade.SharedInvitationRequest): Facade.SharedActExecutionReceipt => this.#call(() => this.#client.vaultMembersDecline(input) as Facade.SharedActExecutionReceipt),
      /** An Admin with the add_member power takes back a pending invitation. */
      withdraw_invitation: (input: Facade.SharedInvitationWithdrawRequest): Facade.SharedActExecutionReceipt => this.#call(() => this.#client.vaultMembersWithdrawInvitation(input) as Facade.SharedActExecutionReceipt),
    },
    federation: {
      coreference: {
        /** The owner atomically links two people with proposed or confirmed identity status, without pooling their claims or granting reads. */
        link: (input: Facade.CoreferenceLinkRequest): Facade.CoreferenceLinkReceipt => this.#call(() => this.#client.vaultFederationCoreferenceLink(input) as Facade.CoreferenceLinkReceipt),
        /** The owner atomically confirms cross-vault identity without changing either person or their claims. */
        confirm: (input: Facade.CoreferencePairRequest): Facade.CoreferenceLinkReceipt => this.#call(() => this.#client.vaultFederationCoreferenceConfirm(input) as Facade.CoreferenceLinkReceipt),
        /** The owner consents to exporting an existing identity link into exactly one named federation pact. */
        share_consent: (input: Facade.CoreferenceShareConsentRequest): Facade.CoreferenceShareConsentReceipt => this.#call(() => this.#client.vaultFederationCoreferenceShareConsent(input) as Facade.CoreferenceShareConsentReceipt),
        /** The owner atomically removes both identity-link orientations and retracts link metadata while retaining the original claims. */
        unlink: (input: Facade.CoreferencePairRequest): Facade.CoreferenceUnlinkReceipt => this.#call(() => this.#client.vaultFederationCoreferenceUnlink(input) as Facade.CoreferenceUnlinkReceipt),
      },
      burst: {
        /** The owner reads one peer's named or observed baseline, relative rate and streak, and current vault-size context. */
        baseline: (input: Facade.FederationBurstPeerRequest): Facade.FederationBurstBaselineState => this.#call(() => this.#client.vaultFederationBurstBaseline(input) as Facade.FederationBurstBaselineState),
        /** The owner reads one grant-bound peer's relative-burst outcome policy. */
        policy: Object.assign((input: Facade.FederationBurstPeerRequest): Facade.FederationBurstPolicy => this.#call(() => this.#client.vaultFederationBurstPolicy(input) as Facade.FederationBurstPolicy), {
          /** The owner sets a named baseline and allow, isolate-and-propose or defer routing for one peer without changing its grant. */
          set: (input: Facade.FederationBurstPolicySetRequest): Facade.FederationBurstPolicy => this.#call(() => this.#client.vaultFederationBurstPolicySet(input) as Facade.FederationBurstPolicy),
        }),
        /** The owner admits a peer host signed Connect delivery through current federation admission and receives its discriminated burst receipt. */
        ingress: (input: Facade.ConnectDelivery): Facade.FederationBurstReceipt => this.#call(() => this.#client.vaultFederationBurstIngress(input) as Facade.FederationBurstReceipt),
        /** The owner reads an authenticated batch original disposition, named baseline context and current durable replay state. */
        disposition: (input: Facade.FederationBurstReplayRequest): Facade.FederationBurstReceipt => this.#call(() => this.#client.vaultFederationBurstDisposition(input) as Facade.FederationBurstReceipt),
        /** The owner reads retained peer review bundles, coalesced once per peer and kept after replay or rejection. */
        review: Object.assign((input: Facade.EmptyRequest): Facade.FederationBurstReviewBundle[] => this.#call(() => this.#client.vaultFederationBurstReview(input) as Facade.FederationBurstReviewBundle[]), {
          /** The owner releases a bundle's burst hold for current-grant replay without importing evidence or widening authority. */
          release: (input: Facade.FederationBurstReviewRequest): Facade.FederationBurstReviewReceipt => this.#call(() => this.#client.vaultFederationBurstReviewRelease(input) as Facade.FederationBurstReviewReceipt),
          /** The owner rejects a bundle's pending batches while retaining its review evidence and terminal dispositions. */
          reject: (input: Facade.FederationBurstReviewRequest): Facade.FederationBurstReviewReceipt => this.#call(() => this.#client.vaultFederationBurstReviewReject(input) as Facade.FederationBurstReviewReceipt),
        }),
        /** The owner retries one retained authenticated batch through its current grant and federation admission without another burst debit. */
        replay: (input: Facade.FederationBurstReplayRequest): Facade.FederationBurstReceipt => this.#call(() => this.#client.vaultFederationBurstReplay(input) as Facade.FederationBurstReceipt),
      },
      connect: {
        /** The owner reads this vault identity and the host key used for reciprocal Connect consent. */
        identity: (input: Facade.EmptyRequest): Facade.ConnectIdentity => this.#call(() => this.#client.vaultFederationConnectIdentity(input) as Facade.ConnectIdentity),
        grants: {
          /** The owner mints an inert Connect guest grant inside the named local-world ceiling. */
          mint: (input: Facade.MintConnectGrant): Facade.ConnectGrant => this.#call(() => this.#client.vaultFederationConnectGrantsMint(input) as Facade.ConnectGrant),
        },
        /** The owner asks the host to sign one disclosed Connect half without activating it. */
        offer: (input: Facade.OfferConnect): Facade.Offer => this.#call(() => this.#client.vaultFederationConnectOffer(input) as Facade.Offer),
        /** The owner accepts the peer host signed Connect half and receives the matching host counter-half. */
        accept: (input: Facade.AcceptConnect): Facade.ConnectAccepted => this.#call(() => this.#client.vaultFederationConnectAccept(input) as Facade.ConnectAccepted),
        /** The owner narrows the current outbound scope without breaking the reciprocal relationship. */
        narrow: (input: Facade.NarrowConnect): Facade.ConnectPactReceipt => this.#call(() => this.#client.vaultFederationConnectNarrow(input) as Facade.ConnectPactReceipt),
        rescope: {
          /** The owner discloses both directions at a new epoch and asks the host to sign a reciprocal re-scope proposal. */
          offer: (input: Facade.RescopeConnect): Facade.RescopeOffer => this.#call(() => this.#client.vaultFederationConnectRescopeOffer(input) as Facade.RescopeOffer),
          /** The owner accepts the peer host signed re-scope and receives the matching signed counter-half. */
          accept: (input: Facade.AcceptRescopeConnect): Facade.ConnectRescoped => this.#call(() => this.#client.vaultFederationConnectRescopeAccept(input) as Facade.ConnectRescoped),
        },
        /** The owner unilaterally ends both directions of a pact without claiming to erase the peer retained copy. */
        disconnect: (input: Facade.ConnectPactRequest): Facade.ConnectDisconnected => this.#call(() => this.#client.vaultFederationConnectDisconnect(input) as Facade.ConnectDisconnected),
        /** The owner exports one grant-filtered named-world update signed by the host for its live pact and epoch. */
        export: (input: Facade.ConnectExportRequest): Facade.ConnectDelivery => this.#call(() => this.#client.vaultFederationConnectExport(input) as Facade.ConnectDelivery),
        /** The owner admits a peer host signed update through guest admission into the retained foreign-world vault. */
        rejoin: (input: Facade.ConnectDelivery): Facade.ConnectRejoined => this.#call(() => this.#client.vaultFederationConnectRejoin(input) as Facade.ConnectRejoined),
      },
    },
    trusted_contacts: {
      /** The vault owner names another live person of the vault as their trusted contact, reached on one outbound channel verb, with an ask-first dial; naming again replaces it and needs the contact's consent again. */
      name: (input: Facade.TrustedContactNameRequest): Facade.TrustedContact => this.#call(() => this.#client.vaultTrustedContactsName(input) as Facade.TrustedContact),
      /** A live person lists every trusted-contact relation they are a side of: those they named and those naming them, under their own credential. */
      list: (input: Facade.TrustedContactsRequest): Facade.TrustedContact[] => this.#call(() => this.#client.vaultTrustedContactsList(input) as Facade.TrustedContact[]),
      /** The named contact, a live person under their own credential, accepts the naming version they were shown and attests they are an adult; the relation is live only after this. */
      consent: (input: Facade.TrustedContactConsentRequest): Facade.TrustedContact => this.#call(() => this.#client.vaultTrustedContactsConsent(input) as Facade.TrustedContact),
      /** Either side of a trusted-contact relation ends it under their own credential; no notice staged from it is sent after this returns, and its open asks close. */
      revoke: (input: Facade.TrustedContactRevokeRequest): Facade.TrustedContact => this.#call(() => this.#client.vaultTrustedContactsRevoke(input) as Facade.TrustedContact),
      dial: {
        /** The vault owner changes whether they are asked before their trusted contact is reached (ask_first or just_call); the contact's consent stands. */
        set: (input: Facade.TrustedContactDialRequest): Facade.TrustedContact => this.#call(() => this.#client.vaultTrustedContactsDialSet(input) as Facade.TrustedContact),
      },
      tier: {
        /** The vault owner names the trusted-contact tier (concern or imminent) of one RouteToHelp policy row; a row never named is a concern. */
        set: (input: Facade.TrustedContactTierRequest): Facade.TrustedContactTierSet => this.#call(() => this.#client.vaultTrustedContactsTierSet(input) as Facade.TrustedContactTierSet),
      },
      concern: {
        /** The vault owner reads their open asks to reach a trusted contact, each raised by a RouteToHelp the policy gate settled. */
        asks: (input: Facade.TrustedContactAsksRequest): Facade.TrustedContactAsk[] => this.#call(() => this.#client.vaultTrustedContactsConcernAsks(input) as Facade.TrustedContactAsk[]),
        /** The vault owner answers one open ask, once: a yes stages the fact-of-concern notice (staged, not delivered) and returns the notices that tell the person and the model; a no or a superseded ask stages nothing. */
        authorize: (input: Facade.TrustedContactAuthorizeRequest): Facade.TrustedContactAuthorization => this.#call(() => this.#client.vaultTrustedContactsConcernAuthorize(input) as Facade.TrustedContactAuthorization),
        /** The owner's policy gate reads one message the caller reads, fresh; a RouteToHelp asks the owner or stages a just-call notice, and the answer carries only the fact of concern, the gate receipt, open asks and notices. */
        propose: (input: Facade.TrustedContactConcernRequest): Facade.TrustedContactConcernProposal => this.#call(() => this.#client.vaultTrustedContactsConcernPropose(input) as Facade.TrustedContactConcernProposal),
        /** The caller sends the next staged fact-of-concern notice it is the stored sender of, as itself, through the consent-checked outbound dispatch; null when none is eligible, never another sender's notice. */
        deliver: (input: Facade.TrustedContactDeliverRequest): Facade.TrustedContactDeliveryReceipt | null => this.#call(() => this.#client.vaultTrustedContactsConcernDeliver(input) as Facade.TrustedContactDeliveryReceipt | null),
      },
    },
    guests: {
      /** The owner shares a locally authored named-world document through its live guest grant as a filtered signed envelope bound to the pact epoch. */
      share: (input: Facade.GuestDocumentShareRequest): Facade.GuestDocumentEnvelope => this.#call(() => this.#client.vaultGuestsShare(input) as Facade.GuestDocumentEnvelope),
      /** The guest fetches its actual filtered signed document envelope under its own live grant-bound credential over HTTP or the held socket. */
      export_envelope: (input: Facade.GuestDocumentShareRequest): Facade.GuestDocumentEnvelope => this.#call(() => this.#client.vaultGuestsExportEnvelope(input) as Facade.GuestDocumentEnvelope),
      /** The owner attempts a document re-share through the same local-world-only guest door; received foreign worlds and base are refused. */
      reshare: (input: Facade.GuestDocumentShareRequest): Facade.GuestDocumentEnvelope => this.#call(() => this.#client.vaultGuestsReshare(input) as Facade.GuestDocumentEnvelope),
      revoke: (input: Facade.GuestRevokeRequest): Facade.GuestRevokeResponse => this.#call(() => this.#client.vaultGuestsRevoke(input) as Facade.GuestRevokeResponse),
      /** The owner mints an Ask or active Connect guest capability slip bound to its live grant and the public key generated by the guest on their own device, with an optional signed comm cap (below vault, owners only). */
      mint_slip: (input: Facade.GuestSlipMintRequest): Facade.GuestSlipMinted => this.#call(() => this.#client.vaultGuestsMintSlip(input) as Facade.GuestSlipMinted),
    },
    support_grants: {
      /** The owner mints our support person or agent a time-limited, revocable grant, bound to that party's own key, inside explicit bounds. */
      mint: (input: Facade.SupportGrantMintRequest): Facade.SupportGrantMintAnswer => this.#call(() => this.#client.vaultSupportGrantsMint(input) as Facade.SupportGrantMintAnswer),
      /** The owner lists the vault's support grants, newest first, with each one's bounds, deadline, status and revoke command. */
      list: (input: Facade.SupportGrantListRequest): Facade.SupportGrantList => this.#call(() => this.#client.vaultSupportGrantsList(input) as Facade.SupportGrantList),
      /** The owner revokes one support grant; what support already read is not recalled. */
      revoke: (input: Facade.SupportGrantRevokeRequest): Facade.SupportGrantRevokeAnswer => this.#call(() => this.#client.vaultSupportGrantsRevoke(input) as Facade.SupportGrantRevokeAnswer),
    },
    residence: {
      /** Switches one of the owner's machines between opened and all residence; that machine's own sync connection applies it. A machine this host does not reach answers state queued, naming the directive. */
      mode: (input: Facade.ResidenceModeRequest): Facade.ResidenceModeAnswer => this.#call(() => this.#client.vaultResidenceMode(input) as Facade.ResidenceModeAnswer),
      /** Opens one item on the named machine and reports local or home residence; a NOTE includes typed text, its version and requested stable anchors. A machine this host does not reach answers state queued, naming the directive. */
      open: (input: Facade.ResidenceOpenRequest): Facade.ResidenceOpenAnswer => this.#call(() => this.#client.vaultResidenceOpen(input) as Facade.ResidenceOpenAnswer),
      /** The thin index one of the owner's machines holds, window by window: what exists, never a body. A machine this host does not reach answers state queued, naming the directive. */
      index: (input: Facade.ResidenceMachineRequest): Facade.ResidenceIndexAnswer => this.#call(() => this.#client.vaultResidenceIndex(input) as Facade.ResidenceIndexAnswer),
      /** Drops the opened-item caches one of the owner's machines last touched before a time. A machine this host does not reach answers state queued, naming the directive. */
      prune: (input: Facade.ResidencePruneRequest): Facade.ResidencePruneAnswer => this.#call(() => this.#client.vaultResidencePrune(input) as Facade.ResidencePruneAnswer),
      /** The owner reads the residence directives this replica holds and each machine's result as received here; a null result means not received here, not that the machine is idle. */
      directives: (input: Facade.ResidenceDirectivesRequest): Facade.ResidenceDirectiveView[] => this.#call(() => this.#client.vaultResidenceDirectives(input) as Facade.ResidenceDirectiveView[]),
    },
    off_record: {
      /** The vault's owner, or a person or agent who then manages it with the owner, enters an off-record session alone, off record or anonymous; nothing of it reaches the vault unless the owner promotes or saves it. */
      start: (input: Facade.OffRecordStartRequest): Facade.OffRecordSessionView => this.#call(() => this.#client.vaultOffRecordStart(input) as Facade.OffRecordSessionView),
      /** The session's creator or the vault's owner reads one live off-record session: its mode, backend, entry time, promoted turns and whether it is closing; a room's member reads what their membership shows. */
      status: (input: Facade.OffRecordSessionRequest): Facade.OffRecordSessionView => this.#call(() => this.#client.vaultOffRecordStatus(input) as Facade.OffRecordSessionView),
      /** The session's creator or the vault's owner witnesses one turn into an off-record session, or a member into a room's; it stays in the room until promoted or dropped at close. */
      witness: (input: Facade.OffRecordWitnessRequest): Facade.WitnessReceipt => this.#call(() => this.#client.vaultOffRecordWitness(input) as Facade.WitnessReceipt),
      /** The session's creator or the vault's owner closes an off-record session without saving it: its turns, writes, receipts and spilled outputs are dropped, and promoted turns stay. */
      discard: (input: Facade.OffRecordSessionRequest): Facade.OffRecordClosed => this.#call(() => this.#client.vaultOffRecordDiscard(input) as Facade.OffRecordClosed),
      /** The session's creator or the vault's owner recalls over an off-record session and the vault together, on their own credential: rows the room holds and vault rows alike. */
      recall: (input: Facade.OffRecordRecallRequest): Facade.MemoryPack => this.#call(() => this.#client.vaultOffRecordRecall(input) as Facade.MemoryPack),
      notes: {
        /** The session's creator or the vault's owner writes one NOTE into an off-record session through its handle; it lands in the room, never in the vault, and close drops it. */
        create: (input: Facade.OffRecordNoteRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultOffRecordNotesCreate(input) as Facade.EntityRefReceipt),
      },
      claims: {
        /** The session's creator or the vault's owner admits one claim into an off-record session through its handle and the gate; it lands in the room beside the vault heads, and close drops it. */
        upsert: (input: Facade.OffRecordClaimRequest): Facade.CommitReceipt => this.#call(() => this.#client.vaultOffRecordClaimsUpsert(input) as Facade.CommitReceipt),
      },
      rooms: {
        /** Reads a room's off-record notices and waiting save suggestions as the caller's membership shows them, without the talk. */
        status: (input: Facade.OffRecordRoomRequest): Facade.OffRecordRoomView => this.#call(() => this.#client.vaultOffRecordRoomsStatus(input) as Facade.OffRecordRoomView),
        /** A person starts an off-record stretch in a room they belong to, on their own credential. */
        start: (input: Facade.OffRecordRoomStartRequest): Facade.OffRecordRoomView => this.#call(() => this.#client.vaultOffRecordRoomsStart(input) as Facade.OffRecordRoomView),
        /** Witnesses a turn into a room's off-record stretch as the caller, under their live membership and the current saving grant. */
        witness: (input: Facade.OffRecordRoomWitnessRequest): Facade.WitnessReceipt => this.#call(() => this.#client.vaultOffRecordRoomsWitness(input) as Facade.WitnessReceipt),
        /** A holder of this vault's write grant saves the visible whole talk so far into this vault, on their own credential. */
        save: (input: Facade.OffRecordRoomRequest): Facade.OffRecordRoomSaved => this.#call(() => this.#client.vaultOffRecordRoomsSave(input) as Facade.OffRecordRoomSaved),
        /** A holder puts a room's stretch on record for later turns while their vault write grant and room membership stay live. */
        save_from_here: (input: Facade.OffRecordRoomRequest): Facade.OffRecordRoomView => this.#call(() => this.#client.vaultOffRecordRoomsSaveFromHere(input) as Facade.OffRecordRoomView),
        /** A person exports only their visible room talk as a JSON attachment, posts a content-free notice and writes no vault. */
        export: (input: Facade.OffRecordRoomRequest): Facade.OffRecordRoomExport => this.#call(() => this.#client.vaultOffRecordRoomsExport(input) as Facade.OffRecordRoomExport),
        /** An agent suggests saving a room's off-record talk on a write or propose credential; nothing is saved until a holder confirms. */
        suggest_save: (input: Facade.OffRecordRoomRequest): Facade.OffRecordRoomView => this.#call(() => this.#client.vaultOffRecordRoomsSuggestSave(input) as Facade.OffRecordRoomView),
        /** A holder confirms the room's waiting save suggestions with their own save of the visible whole talk; refuses when none waits. */
        confirm_save: (input: Facade.OffRecordRoomRequest): Facade.OffRecordRoomSaved => this.#call(() => this.#client.vaultOffRecordRoomsConfirmSave(input) as Facade.OffRecordRoomSaved),
        /** A holder declines the room's waiting save suggestions, posts a content-free notice and saves nothing; refuses when none waits. */
        decline_save: (input: Facade.OffRecordRoomRequest): Facade.OffRecordRoomView => this.#call(() => this.#client.vaultOffRecordRoomsDeclineSave(input) as Facade.OffRecordRoomView),
      },
    },
    records: {
      /** What erasing one record would take: the brief grants it revokes, the records holding the same bytes and the LFS chunks it shares, with the digest erase_confirm takes back. */
      erase_preview: (input: Facade.RecordEraseRequest): Facade.RecordErasePreview => this.#call(() => this.#client.vaultRecordsErasePreview(input) as Facade.RecordErasePreview),
      /** Erase the record the caller previewed, once its preview still has the digest they confirmed; in a shared vault a held record starts its own erase act instead. */
      erase_confirm: (input: Facade.RecordEraseConfirmRequest): Facade.RecordEraseOutcome => this.#call(() => this.#client.vaultRecordsEraseConfirm(input) as Facade.RecordEraseOutcome),
      /** Read a redaction receipt's recorded historical-sweep deadline and linked completion as the owner; never starts a sweep. */
      erase_sweep: (input: Facade.RecordEraseSweepRequest): Facade.RecordEraseSweep | null => this.#call(() => this.#client.vaultRecordsEraseSweep(input) as Facade.RecordEraseSweep | null),
    },
    research: {
      /** The owner enqueues an experiment child through ordinary agent dispatch under an unpruned campaign parent; record its actual candidate afterward with research.fork or research.weave. */
      create_child: (input: Facade.ResearchChildWire): Facade.ResearchChildReceipt => this.#call(() => this.#client.vaultResearchCreateChild(input) as Facade.ResearchChildReceipt),
      /** Reads the complete retained campaign record, including every pruned, buggy and woven candidate, original search and held-out evidence, selection rounds and promotion receipts, under the controller gate. */
      archive: Object.assign((input: Facade.ResearchArchiveWire): Facade.ResearchArchive => this.#call(() => this.#client.vaultResearchArchive(input) as Facade.ResearchArchive), {
        /** Installs one immutable campaign output descriptor from a receipted Coach proposal under the current human goal; categorical axes and embedding clusters share the engine validator. */
        install: (input: Facade.CampaignArchiveInstall): Facade.CampaignArchiveView => this.#call(() => this.#client.vaultResearchArchiveInstall(input) as Facade.CampaignArchiveView),
        /** Records original placement and quality receipts for one output revision; categorical judgment or pinned embedding placement competes only within its own cell. */
        record: (input: Facade.CampaignArchiveOutput): Facade.CampaignArchiveView => this.#call(() => this.#client.vaultResearchArchiveRecord(input) as Facade.CampaignArchiveView),
        /** Reads the installed campaign output descriptor and every original placement and scoring receipt, including losing outputs, under the research controller gate. */
        get: (input: Facade.CampaignArchiveRequest): Facade.CampaignArchiveRecord => this.#call(() => this.#client.vaultResearchArchiveGet(input) as Facade.CampaignArchiveRecord),
        /** Rebuilds one best output per cell under the immutable descriptor revision and reports whether bunching warrants a new campaign proposal. */
        best: (input: Facade.CampaignArchiveRequest): Facade.CampaignArchiveView => this.#call(() => this.#client.vaultResearchArchiveBest(input) as Facade.CampaignArchiveView),
        /** Installs a receipted descriptor proposal in a new bound campaign when the old archive is bunched; the old descriptor, goal and cell winners remain unchanged. */
        repropose: (input: Facade.CampaignArchiveReproposal): Facade.CampaignArchiveView => this.#call(() => this.#client.vaultResearchArchiveRepropose(input) as Facade.CampaignArchiveView),
        /** Pins the incumbent and candidate replay output refs and projects the human goal coverage floor; promotion rechecks these receipts and rejects any lost incumbent cell. */
        coverage: (input: Facade.CampaignArchiveCoverage): Facade.CampaignArchiveAdmission => this.#call(() => this.#client.vaultResearchArchiveCoverage(input) as Facade.CampaignArchiveAdmission),
      }),
      /** Binds an autoresearch campaign to its existing root attempt: its ruler, selection policy, cohort, budget share and prior ladder, once. The owner or the agent running that root calls it. */
      bind: (input: Facade.ResearchBindWire): Facade.ResearchBinding => this.#call(() => this.#client.vaultResearchBind(input) as Facade.ResearchBinding),
      /** Records a variation or debug child the campaign's controller enqueued under a measured or buggy parent. */
      fork: (input: Facade.ResearchForkWire): Facade.ExperimentNode => this.#call(() => this.#client.vaultResearchFork(input) as Facade.ExperimentNode),
      /** Records a crossover child of several parents whose candidate landed as a claim through the gate, once a held-out win turned merge crossover on. */
      weave: (input: Facade.ResearchWeaveWire): Facade.ExperimentNode => this.#call(() => this.#client.vaultResearchWeave(input) as Facade.ExperimentNode),
      /** Records a node's search-split evidence, its selection signal, once. */
      measure_search: (input: Facade.ResearchSearchWire): Facade.ExperimentNode => this.#call(() => this.#client.vaultResearchMeasureSearch(input) as Facade.ExperimentNode),
      /** Records a node's held-out evidence, once; only the promotion basis reads it. */
      measure_held_out: (input: Facade.ResearchHeldOutWire): Facade.ExperimentNode => this.#call(() => this.#client.vaultResearchMeasureHeldOut(input) as Facade.ExperimentNode),
      /** The owner scores one arm of a bound claim-authoring campaign on one split under its bound config; the blind taste questions go through the host's decision ladder, and the report is returned, not stored. */
      evaluate_split: (input: Facade.CampaignSplitWire): Facade.CampaignSplitReport => this.#call(() => this.#client.vaultResearchEvaluateSplit(input) as Facade.CampaignSplitReport),
      /** Marks a node buggy: it stays as evidence and takes debug children. */
      mark_invalid: (input: Facade.ResearchInvalidWire): Facade.ExperimentNode => this.#call(() => this.#client.vaultResearchMarkInvalid(input) as Facade.ExperimentNode),
      /** Stops exploring a branch for a stated cause; its attempts, claims and outputs stay. A stop names the caller. */
      prune: (input: Facade.ResearchPruneWire): Facade.ExperimentNode => this.#call(() => this.#client.vaultResearchPrune(input) as Facade.ExperimentNode),
      /** Runs one selection round through the trusted selection floor and records it; only the owner can say the goal is met. */
      select: (input: Facade.ResearchSelectWire): Facade.SelectionReceipt => this.#call(() => this.#client.vaultResearchSelect(input) as Facade.SelectionReceipt),
      /** Decides a candidate's held-out promotion basis against the incumbent, once. */
      promotion_basis: (input: Facade.ResearchBasisWire): Facade.PromotionBasis => this.#call(() => this.#client.vaultResearchPromotionBasis(input) as Facade.PromotionBasis),
      /** Spends a Promote candidate's one sealed confirmation and releases the campaign's sealed cohort to the controller's referee, counted as a serving. */
      reserve_confirmation: (input: Facade.ResearchCandidateWire): Facade.EvalRelease => this.#call(() => this.#client.vaultResearchReserveConfirmation(input) as Facade.EvalRelease),
      /** Settles a candidate on the sealed referee's scores of it and the incumbent: a strict win, a not-worse sufficiency card and, for a skill, the gate's accepted verdict make it the incumbent. */
      promote: (input: Facade.ResearchPromoteWire): Facade.CampaignPromotionReceipt => this.#call(() => this.#client.vaultResearchPromote(input) as Facade.CampaignPromotionReceipt),
      /** Reserves token work for the campaign on the RSI line under its share, and returns the reservation's id. */
      reserve_work: (input: Facade.ResearchWorkWire): Facade.EntityId => this.#call(() => this.#client.vaultResearchReserveWork(input) as Facade.EntityId),
      /** Settles a work reservation at its actual spend. */
      settle_work: (input: Facade.ResearchSettleWire): Facade.ResearchReservation => this.#call(() => this.#client.vaultResearchSettleWork(input) as Facade.ResearchReservation),
      /** Refunds a work reservation nothing was spent on. */
      refund_work: (input: Facade.ResearchRefundWire): Facade.ResearchReservation => this.#call(() => this.#client.vaultResearchRefundWork(input) as Facade.ResearchReservation),
      /** Reserves exploration exposure for the campaign on its own exposure-denominated RSI line, independently of token work, and returns the reservation's id. Settle or refund it through settle_work and refund_work. */
      reserve_exploration: (input: Facade.ResearchExplorationWire): Facade.EntityId => this.#call(() => this.#client.vaultResearchReserveExploration(input) as Facade.EntityId),
      /** Reads the campaign's lease, every reservation it holds or held with its settlement and soft-share overdraft receipt, and the vault RSI lines behind them, including the observable hold state. */
      budget: (input: Facade.ResearchArchiveWire): Facade.ResearchBudgetView => this.#call(() => this.#client.vaultResearchBudget(input) as Facade.ResearchBudgetView),
      /** Records an estimator version's held-out selection benchmark against the DGM parent formula, once per version; a win of at least 30 cases lets its information gain rank parents. */
      record_benchmark: (input: Facade.ResearchBenchmarkWire): Facade.SelectionBenchmark => this.#call(() => this.#client.vaultResearchRecordBenchmark(input) as Facade.SelectionBenchmark),
    },
    evals: {
      /** The owner reads the metadata-only eval-authoring inventory: real receipt families, grounded case candidates, date-cut cohorts and exposure counts. Pin its built_at and digest for cohort setup. */
      inventory: (input: Facade.EvalInventoryWire): Facade.EvalAuthoringInventory => this.#call(() => this.#client.vaultEvalsInventory(input) as Facade.EvalAuthoringInventory),
      /** Read date-cut cohorts, the fixed reference, retirement decisions, exposure counts and near-copy audits; similarity flags review only. */
      cohorts: Object.assign((input: Facade.EvalSeatRequest): Facade.EvalCohortView[] => this.#call(() => this.#client.vaultEvalsCohorts(input) as Facade.EvalCohortView[]), {
        /** The owner sets up sealed cohorts from a pinned real inventory through the existing family, case and audited cut doors. Reports refused decisions; never serves sealed content or fabricates labels or skill provenance. */
        setup: (input: Facade.EvalCohortSetup): Facade.EvalAuthoringReport => this.#call(() => this.#client.vaultEvalsCohortsSetup(input) as Facade.EvalAuthoringReport),
        /** Count a candidate, query or promotion serving before releasing its sealed cohort in the same owner-validated transaction; retired cohorts refuse. */
        open: (input: Facade.EvalCohortOpenRequest): Facade.EvalRelease => this.#call(() => this.#client.vaultEvalsCohortsOpen(input) as Facade.EvalRelease),
      }),
      /** Queue the production Coach eval-authoring pass, coalescing with nightly work; the caller supplies no plan, skill provenance or lease. */
      author_now: (input: Facade.EvalAuthorNowRequest): Facade.EvalAuthoringRef => this.#call(() => this.#client.vaultEvalsAuthorNow(input) as Facade.EvalAuthoringRef),
      authoring: {
        /** Read the eval-authoring host attempt's actual state and terminal error; a completed pass may author nothing. */
        result: (input: Facade.EvalAuthoringRef): Facade.EvalAuthoringResult | null => this.#call(() => this.#client.vaultEvalsAuthoringResult(input) as Facade.EvalAuthoringResult | null),
      },
      /** Read a seat's family purposes, source roots, derivative lineage and dates, including retirement and training eligibility, without sealed labels. */
      families: Object.assign((input: Facade.EvalSeatRequest): Facade.EvalFamilyView[] => this.#call(() => this.#client.vaultEvalsFamilies(input) as Facade.EvalFamilyView[]), {
        /** Assign source roots their fixed eval family and purpose before deriving cases; conflicting families, purposes or seats refuse. */
        assign: (input: Facade.EvalFamilyAssignRequest): Facade.SourceFamily => this.#call(() => this.#client.vaultEvalsFamiliesAssign(input) as Facade.SourceFamily),
      }),
      /** Read development or judge-audit eval cases; sealed confirmation refuses and retired cohorts read as development, never training. */
      cases: Object.assign((input: Facade.EvalCasesRequest): Facade.EvalCase[] => this.#call(() => this.#client.vaultEvalsCases(input) as Facade.EvalCase[]), {
        /** Record a receipt, repair, paraphrase, summary, translation, synthetic or rubric case through the shared family-inheritance guard; no labels are invented. */
        record: (input: Facade.EvalCaseDraft): Facade.EvalCase => this.#call(() => this.#client.vaultEvalsCasesRecord(input) as Facade.EvalCase),
      }),
      /** Read a cohort's individual exposure ledger and independent candidate, query and promotion counts; unknown cohorts refuse. */
      exposure: (input: Facade.EvalCohortRef): Facade.EvalExposureLedger => this.#call(() => this.#client.vaultEvalsExposure(input) as Facade.EvalExposureLedger),
      /** Compute the existing sufficiency card from explicit family-grouped measurements; unknown never approves, creates a label ask or deploys. */
      sufficiency: (input: Facade.SufficiencyInput): Facade.SufficiencyCard => this.#call(() => this.#client.vaultEvalsSufficiency(input) as Facade.SufficiencyCard),
      labels: {
        /** Read only unanswered eval-label asks for this owner, optionally by seat or blocked decision, with scoped cases and quoted human minutes; create no standing label session. */
        blocked: (input: Facade.EvalBlockedLabelsRequest): Facade.EvalLabelAsk[] => this.#call(() => this.#client.vaultEvalsLabelsBlocked(input) as Facade.EvalLabelAsk[]),
        /** Record either option of the responsible owner's existing eval-label ask once; the same pick repeats safely and a conflicting second pick refuses. */
        pick: (input: Facade.EvalLabelPickRequest): Facade.EvalCase => this.#call(() => this.#client.vaultEvalsLabelsPick(input) as Facade.EvalCase),
      },
    },
    cleanup: {
      /** The owner runs one archive-cleanup pass under the current posture; propose-first opens a proposal and archives nothing. */
      run: (input: Facade.CleanupRunRequest): Facade.CleanupRunView => this.#call(() => this.#client.vaultCleanupRun(input) as Facade.CleanupRunView),
    },
    legal_holds: {
      /** The owner places a customer legal hold on the named records or gate partitions. */
      place: (input: Facade.LegalHoldPlaceRequest): Facade.LegalHold => this.#call(() => this.#client.vaultLegalHoldsPlace(input) as Facade.LegalHold),
      /** Adds targets to one of the owner's standing customer legal holds. */
      widen: (input: Facade.LegalHoldWidenRequest): Facade.LegalHold => this.#call(() => this.#client.vaultLegalHoldsWiden(input) as Facade.LegalHold),
      /** Every legal hold the owner may see. */
      list: (input: Facade.EmptyRequest = {}): Facade.LegalHold[] => this.#call(() => this.#client.vaultLegalHoldsList(input) as Facade.LegalHold[]),
      /** The owner-visible legal hold log, oldest first. */
      log: (input: Facade.EmptyRequest = {}): Facade.LegalHoldEvent[] => this.#call(() => this.#client.vaultLegalHoldsLog(input) as Facade.LegalHoldEvent[]),
      /** The owner's one confirm that lifts or narrows the customer holds on the named records and erases them. */
      lift_and_erase: (input: Facade.LegalHoldLiftAndEraseRequest): Facade.LegalHoldLiftAndErased => this.#call(() => this.#client.vaultLegalHoldsLiftAndErase(input) as Facade.LegalHoldLiftAndErased),
    },
    courtesy_delete: {
      /** The owner asks a former peer to drop what an ended pact delivered, and queues the signed ask for delivery. */
      send: (input: Facade.CourtesyDeleteSendRequest): Facade.CourtesyDeleteSent => this.#call(() => this.#client.vaultCourtesyDeleteSend(input) as Facade.CourtesyDeleteSent),
      /** Every courtesy delete ask this vault sent, with its delivery status, for the owner. */
      sent: (input: Facade.EmptyRequest = {}): Facade.CourtesyDeleteSent[] => this.#call(() => this.#client.vaultCourtesyDeleteSent(input) as Facade.CourtesyDeleteSent[]),
      /** Every courtesy delete ask a former peer sent, with each named world's stale stamp and the owner's answer. */
      incoming: (input: Facade.EmptyRequest = {}): Facade.CourtesyDeleteIncoming[] => this.#call(() => this.#client.vaultCourtesyDeleteIncoming(input) as Facade.CourtesyDeleteIncoming[]),
      /** The owner answers one incoming courtesy delete ask from the menu, and sends the answer back when reply_to names where. */
      answer: (input: Facade.CourtesyDeleteAnswerRequest): Facade.CourtesyDeleteIncoming => this.#call(() => this.#client.vaultCourtesyDeleteAnswer(input) as Facade.CourtesyDeleteIncoming),
    },
    embedding_spaces: {
      /** Every declared embedding space, the text index, the space each kind slot reads, every move and the probe count per kind. */
      list: (input: Facade.EmptyRequest = {}): Facade.EmbeddingSpacesView => this.#call(() => this.#client.vaultEmbeddingSpacesList(input) as Facade.EmbeddingSpacesView),
      /** Declares or widens one embedding space: id, dimensions, accepts, query_towers and optional evidence floors. */
      declare: (input: Facade.EmbeddingSpaceDeclareRequest): Facade.EmbeddingSpacesView => this.#call(() => this.#client.vaultEmbeddingSpacesDeclare(input) as Facade.EmbeddingSpacesView),
      /** Binds one kind slot to a declared space, or returns it to its default when no space is named. */
      bind: (input: Facade.EmbeddingSpaceBindRequest): Facade.EmbeddingSpacesView => this.#call(() => this.#client.vaultEmbeddingSpacesBind(input) as Facade.EmbeddingSpacesView),
      /** Binds every kind slot the space accepts, text included, to that one space. */
      one_space: (input: Facade.EmbeddingSpaceRequest): Facade.EmbeddingSpacesView => this.#call(() => this.#client.vaultEmbeddingSpacesOneSpace(input) as Facade.EmbeddingSpacesView),
      /** Drops a declared space that no slot binds and no open move names, with its vector rows. */
      retire: (input: Facade.EmbeddingSpaceRequest): Facade.EmbeddingSpacesView => this.#call(() => this.#client.vaultEmbeddingSpacesRetire(input) as Facade.EmbeddingSpacesView),
      /** Starts moving every kind slot the incumbent serves (the text index when none is named) to the candidate space. */
      move: (input: Facade.EmbeddingSpaceMoveRequest): Facade.SpaceMove => this.#call(() => this.#client.vaultEmbeddingSpacesMove(input) as Facade.SpaceMove),
      /** Runs an embedding space move probes now through both spaces and acts on the reading; it can take minutes. */
      move_check: (input: Facade.EmbeddingSpaceCandidateRequest): Facade.EmbeddingSpaceMoveChecked => this.#call(() => this.#client.vaultEmbeddingSpacesMoveCheck(input) as Facade.EmbeddingSpaceMoveChecked),
      /** The owner says yes to a full candidate over a check that did not read not worse; it swaps in. */
      move_approve: (input: Facade.EmbeddingSpaceCandidateRequest): Facade.EmbeddingSpacesView => this.#call(() => this.#client.vaultEmbeddingSpacesMoveApprove(input) as Facade.EmbeddingSpacesView),
      /** Binds a swapped-in move incumbent again. */
      move_undo: (input: Facade.EmbeddingSpaceCandidateRequest): Facade.EmbeddingSpacesView => this.#call(() => this.#client.vaultEmbeddingSpacesMoveUndo(input) as Facade.EmbeddingSpacesView),
      /** Ends an open embedding space move with no swap. */
      move_abandon: (input: Facade.EmbeddingSpaceCandidateRequest): Facade.EmbeddingSpacesView => this.#call(() => this.#client.vaultEmbeddingSpacesMoveAbandon(input) as Facade.EmbeddingSpacesView),
      probes: {
        /** Every stored embedding space probe with its id. */
        list: (input: Facade.EmptyRequest = {}): Facade.EmbeddingSpaceProbes => this.#call(() => this.#client.vaultEmbeddingSpacesProbesList(input) as Facade.EmbeddingSpaceProbes),
        /** Stores one retrieval probe the owner or another model wrote: kind, query, family, targets and author. */
        put: (input: Facade.EmbeddingSpaceProbePutRequest): Facade.EmbeddingSpaceProbe => this.#call(() => this.#client.vaultEmbeddingSpacesProbesPut(input) as Facade.EmbeddingSpaceProbe),
        /** Removes one stored embedding space probe by its id. */
        delete: (input: Facade.EmbeddingSpaceProbeDeleteRequest): Facade.EmbeddingSpaceProbeDeleted => this.#call(() => this.#client.vaultEmbeddingSpacesProbesDelete(input) as Facade.EmbeddingSpaceProbeDeleted),
      },
    },
    policy: {
      owner: {
        /** The owner reads the content-policy configuration, default manifest hash and effective off/on state. */
        get: (input: Facade.EmptyRequest = {}): Facade.OwnerPolicyConfigurationView => this.#call(() => this.#client.vaultPolicyOwnerGet(input) as Facade.OwnerPolicyConfigurationView),
        /** The owner configures or toggles content policy against the current manifest hash without changing other policy tables. */
        configure: (input: Facade.OwnerPolicyConfigureRequest): Facade.OwnerPolicyConfigurationReceipt => this.#call(() => this.#client.vaultPolicyOwnerConfigure(input) as Facade.OwnerPolicyConfigurationReceipt),
        row: {
          /** The owner adds, edits or removes a scoped content-policy row through its existing holder-governed writer and receives its change receipt. */
          change: (input: Facade.PolicyRowChangeRequest): Facade.PolicyRowReceipt => this.#call(() => this.#client.vaultPolicyOwnerRowChange(input) as Facade.PolicyRowReceipt),
        },
      },
      outbound: {
        /** Decide an outbound candidate under owner policy with system notices and hash-only receipts; Warn and Skipped preserve its exact bytes. */
        decide: (input: Facade.PolicyOutboundRequest): Facade.PolicyModelEnforcement => this.#call(() => this.#client.vaultPolicyOutboundDecide(input) as Facade.PolicyModelEnforcement),
      },
      relay: {
        /** Decide bytes carried by the host-bound attested relay under its own legal policy; outages halt with a service notice and local-model offer. */
        decide: (input: Facade.PolicyOutboundRequest): Facade.HostedRelayDecision => this.#call(() => this.#client.vaultPolicyRelayDecide(input) as Facade.HostedRelayDecision),
      },
    },
    consent: {
      /** The owner approves exactly one engine-emitted effect digest; no standing grant is created. */
      approve_once: (input: Facade.ApproveOnceRequest): Facade.ConsentActReceipt => this.#call(() => this.#client.vaultConsentApproveOnce(input) as Facade.ConsentActReceipt),
      /** The owner denies exactly one engine-emitted effect digest and records the refusal without granting authority. */
      deny: (input: Facade.DenyConsentRequest): Facade.ConsentActReceipt => this.#call(() => this.#client.vaultConsentDeny(input) as Facade.ConsentActReceipt),
      /** The owner creates a bounded standing action or disclosure grant, with no stored expiry; a wider bound is a new decision. */
      create_standing_grant: (input: Facade.CreateStandingGrantRequest): Facade.ConsentActReceipt => this.#call(() => this.#client.vaultConsentCreateStandingGrant(input) as Facade.ConsentActReceipt),
      /** The owner reads the unified action and disclosure grant registry, including revoke commands and optionally revoked grants. */
      registry: (input: Facade.ConsentRegistryQuery): Facade.ConsentRegistry => this.#call(() => this.#client.vaultConsentRegistry(input) as Facade.ConsentRegistry),
      /** The owner immediately revokes a standing consent grant by the reference its receipt or registry emitted. */
      revoke: (input: Facade.RevokeGrantRequest): Facade.ConsentActReceipt => this.#call(() => this.#client.vaultConsentRevoke(input) as Facade.ConsentActReceipt),
      /** The owner previews the exact actor, classes, envelope and project or thread of a scoped bypass; this warning grants nothing. */
      bypass_grant_warning: (input: Facade.BypassGrantWarningRequest): Facade.BypassGrantWarningView => this.#call(() => this.#client.vaultConsentBypassGrantWarning(input) as Facade.BypassGrantWarningView),
      /** The owner explicitly acknowledges a scoped bypass warning and atomically creates one receipted standing bypass per class. */
      create_bypass_grant: (input: Facade.CreateBypassGrantRequest): Facade.ConsentActReceipt[] => this.#call(() => this.#client.vaultConsentCreateBypassGrant(input) as Facade.ConsentActReceipt[]),
      /** The owner reads live scoped bypass states and their complete bounds, newest first; vault.consent.revoke ends each grant. */
      active_bypass_grants: (input: Facade.ActiveBypassGrantsRequest): Facade.BypassActiveState[] => this.#call(() => this.#client.vaultConsentActiveBypassGrants(input) as Facade.BypassActiveState[]),
      /** The owner reads the existing Gate receipts for effects covered by one bypass grant, including after its revocation. */
      bypassed_effect_receipts: (input: Facade.BypassedEffectReceiptsRequest): Facade.BypassedEffectReceipt[] => this.#call(() => this.#client.vaultConsentBypassedEffectReceipts(input) as Facade.BypassedEffectReceipt[]),
      graduation: {
        /** Reads runtime consent-graduation policy rows and the effective row for an optional exact scope. */
        policy: Object.assign((input: Facade.GraduationPolicyRequest): Facade.GraduationPolicies => this.#call(() => this.#client.vaultConsentGraduationPolicy(input) as Facade.GraduationPolicies), {
          /** The owner sets a scope-pattern streak, posterior guard and two snooze backoffs; zero-second backoff is supported. */
          set: (input: Facade.GraduationPolicySetRequest): Facade.GraduationChanged => this.#call(() => this.#client.vaultConsentGraduationPolicySet(input) as Facade.GraduationChanged),
          /** The owner clears one runtime graduation policy row; scopes fall back to the next matching policy. */
          clear: (input: Facade.GraduationPolicyClearRequest): Facade.GraduationChanged => this.#call(() => this.#client.vaultConsentGraduationPolicyClear(input) as Facade.GraduationChanged),
        }),
        /** Reads one exact graduation scope outcome history and current consent posture. */
        stats: (input: Facade.GraduationScopeRequest): Facade.GraduationStats | null => this.#call(() => this.#client.vaultConsentGraduationStats(input) as Facade.GraduationStats | null),
        /** The owner records an untouched, amended or rejected proposal ruling, receipted and folded through the existing ramp. */
        outcome: (input: Facade.GraduationOutcomeRequest): Facade.GraduationStats => this.#call(() => this.#client.vaultConsentGraduationOutcome(input) as Facade.GraduationStats),
        /** Reads earned, unsuppressed graduation offers with thresholds, streaks and before/after reach; reading grants nothing. */
        offers: (input: Facade.EmptyRequest): Facade.GraduationOffer[] => this.#call(() => this.#client.vaultConsentGraduationOffers(input) as Facade.GraduationOffer[]),
        /** The owner answers auto, not-now or manual_pinned; only auto mints the existing standing grant, and not-now resets the streak. */
        answer: (input: Facade.GraduationAnswerRequest): Facade.GraduationAnswerReceipt => this.#call(() => this.#client.vaultConsentGraduationAnswer(input) as Facade.GraduationAnswerReceipt),
        /** Reads the owner trust table: scope, counts, effective threshold, snooze or manual pin, live grant and offer reach. */
        trust_table: (input: Facade.EmptyRequest): Facade.GraduationTrustRow[] => this.#call(() => this.#client.vaultConsentGraduationTrustTable(input) as Facade.GraduationTrustRow[]),
        settings: {
          /** The owner reopens a pinned or snoozed graduation scope in settings; no grant is created. */
          unpin: (input: Facade.GraduationScopeRequest): Facade.GraduationChanged => this.#call(() => this.#client.vaultConsentGraduationSettingsUnpin(input) as Facade.GraduationChanged),
        },
        /** The owner demotes an exact scope to propose, revoking its live grant and recording the existing durable demotion receipt. */
        demote: (input: Facade.GraduationDemoteRequest): Facade.GraduationChanged => this.#call(() => this.#client.vaultConsentGraduationDemote(input) as Facade.GraduationChanged),
      },
    },
    gate: {
      policy: {
        /** The owner reads Gate policy envelopes, actor ceilings, source permits and checker references, including inert contributions. */
        get: (input: Facade.PolicyManifestRead): Facade.PolicyManifestsView => this.#call(() => this.#client.vaultGatePolicyGet(input) as Facade.PolicyManifestsView),
        /** The owner installs or edits typed Gate write axes, preserving other tables and meeting independently installed contributions. */
        put: (input: Facade.PolicyManifestPut): Facade.PolicyManifestReceipt => this.#call(() => this.#client.vaultGatePolicyPut(input) as Facade.PolicyManifestReceipt),
        /** Propose a Gate policy under the caller's own authority; even a tighter contribution remains untrusted and inert. */
        propose: (input: Facade.PolicyManifestPropose): Facade.PolicyManifestReceipt => this.#call(() => this.#client.vaultGatePolicyPropose(input) as Facade.PolicyManifestReceipt),
      },
      checker: {
        /** The owner reads the calibrated checker verdict role from the vault model manifest. */
        get: (input: Facade.EmptyRequest = {}): Facade.GateCheckerView => this.#call(() => this.#client.vaultGateCheckerGet(input) as Facade.GateCheckerView),
        /** The owner sets the calibrated checker model, slot, confidence floor and shadow or enforce mode without changing other model bindings. */
        set: (input: Facade.GateCheckerSet): Facade.GateCheckerReceipt => this.#call(() => this.#client.vaultGateCheckerSet(input) as Facade.GateCheckerReceipt),
      },
    },
    learning: {
      /** The owner reads a measured learning cell, its explicit prior, derived UNTESTED mark, projector heads and anchored evidence; borrowed provenance stays separate from own runs. */
      read: (input: Facade.LearningReadRequest): Facade.LearningCellView => this.#call(() => this.#client.vaultLearningRead(input) as Facade.LearningCellView),
      /** The owner observes the stored projection receipt for an anchored attempt outcome; an absent receipt means projection has not committed, never a successful empty projection. */
      projection: (input: Facade.LearningProjectionRequest): Facade.LearningProjectionView => this.#call(() => this.#client.vaultLearningProjection(input) as Facade.LearningProjectionView),
    },
    seal: {
      /** Confess an attempt's objectives without changing any score; named flaws and uncertainty create durable directed rechecks. */
      confess: (input: Facade.AttemptConfession): Facade.SealReceiptView => this.#call(() => this.#client.vaultSealConfess(input) as Facade.SealReceiptView),
      /** Draw a passing sealed attempt once at the current audit rate, saving the rate and selection before any checker runs. */
      audit: (input: Facade.SealAttemptRequest): Facade.SealReceiptView => this.#call(() => this.#client.vaultSealAudit(input) as Facade.SealReceiptView),
      /** Read a sealed attempt, its stamped audit draw, directed and random check completions, weighted findings and separate honesty reward. */
      receipt: (input: Facade.SealAttemptRequest): Facade.SealReceiptView | null => this.#call(() => this.#client.vaultSealReceipt(input) as Facade.SealReceiptView | null),
      /** Read pending directed rechecks and random audits, optionally for one attempt, without executing a checker. */
      pending: (input: Facade.SealPendingRequest): Facade.SealCheckRequest[] => this.#call(() => this.#client.vaultSealPending(input) as Facade.SealCheckRequest[]),
      /** Queue the existing Coach seal checker under its ordinary lease, Grant and budget; the returned job never grants extra authority. */
      run: (input: Facade.SealRunRequest): Facade.SealRunReceipt => this.#call(() => this.#client.vaultSealRun(input) as Facade.SealRunReceipt),
      /** Attest an independent external seal check as the owner; admit immutable findings and project them using the request's stamped rate. */
      complete: (input: Facade.SealCompleteRequest): Facade.SealReceiptView => this.#call(() => this.#client.vaultSealComplete(input) as Facade.SealReceiptView),
    },
    settings: {
      /** The owner reads the learned-setting catalog, each knob's value now, and the owner's seed and pin rows at the vault, a project or a task type. */
      learning: Object.assign((input: Facade.LearningSettingsRequest): Facade.LearningSettingsView => this.#call(() => this.#client.vaultSettingsLearning(input) as Facade.LearningSettingsView), {
        /** The owner lays one seed or pin on a learned setting at the vault, a project or a task type, replacing the row of the same key, mode and scope. */
        put: (input: Facade.LearningSettingPut): Facade.LearningSettingsView => this.#call(() => this.#client.vaultSettingsLearningPut(input) as Facade.LearningSettingsView),
        /** The owner clears one learned-setting row of a key, mode and scope. */
        clear: (input: Facade.LearningSettingClear): Facade.LearningSettingsView => this.#call(() => this.#client.vaultSettingsLearningClear(input) as Facade.LearningSettingsView),
      }),
      wake_policy: {
        /** The owner sets the dreamer's wake policy: the app's dreamer.wake_policy.set action, run as the caller under the owner's proof. */
        set: (input: Facade.WakePolicySetRequest): Facade.PolicyActionOutcome => this.#call(() => this.#client.vaultSettingsWakePolicySet(input) as Facade.PolicyActionOutcome),
      },
      /** Reads the per-purpose inference defaults: the app's inference.defaults.read action, which needs the caller's Auto ceiling. */
      inference_defaults: Object.assign((input: Facade.EmptyRequest = {}): Facade.PolicyActionOutcome => this.#call(() => this.#client.vaultSettingsInferenceDefaults(input) as Facade.PolicyActionOutcome), {
        /** Replaces the whole per-purpose inference default table: the app's inference.defaults.replace action, which needs the caller's Auto ceiling. */
        replace: (input: Facade.InferenceDefaultsReplaceRequest): Facade.PolicyActionOutcome => this.#call(() => this.#client.vaultSettingsInferenceDefaultsReplace(input) as Facade.PolicyActionOutcome),
      }),
    },
    secrets: {
      /** The owner reads the historical secret lift sweep: the run in progress, the last receipt and the open lift proposals by cause. With close, one proposal closes first with the owner's reason and a receipt; with start, a run is queued. */
      lift_history: (input: Facade.SecretLiftRequest): Facade.SecretLiftStatus => this.#call(() => this.#client.vaultSecretsLiftHistory(input) as Facade.SecretLiftStatus),
    },
    /** The owner lists the context-widen proposals agents raised, newest first, or only those pending, approved or declined. */
    widen_proposals: Object.assign((input: Facade.WidenProposalsRequest): Facade.WidenProposalsView => this.#call(() => this.#client.vaultWidenProposals(input) as Facade.WidenProposalsView), {
      /** The owner, as the board above, approves one context-widen proposal: the parent's context widens and the child is enqueued. */
      approve: (input: Facade.WidenProposalAnswer): Facade.WidenProposalView => this.#call(() => this.#client.vaultWidenProposalsApprove(input) as Facade.WidenProposalView),
      /** The owner, as the board above, declines one context-widen proposal for good; the decline stays on record. */
      decline: (input: Facade.WidenProposalAnswer): Facade.WidenProposalView => this.#call(() => this.#client.vaultWidenProposalsDecline(input) as Facade.WidenProposalView),
    }),
    /** The owner lists the craft notes residents' dreaming proposed about themselves that wait on a verdict, newest first, or one resident's, each with the content hash an answer pins. */
    craft_candidates: Object.assign((input: Facade.CraftCandidatesRequest): Facade.CraftCandidatesView => this.#call(() => this.#client.vaultCraftCandidates(input) as Facade.CraftCandidatesView), {
      /** The owner approves or rejects one craft candidate, bound to the content hash its card showed: an Approved or Rejected row supersedes it, with one receipt. The same answer again returns the first. */
      answer: (input: Facade.CraftCandidateAnswer): Facade.CraftVerdictView => this.#call(() => this.#client.vaultCraftCandidatesAnswer(input) as Facade.CraftVerdictView),
    }),
    lenses: {
      /** Stores one frozen compiled lens tree for a pack slot as this actor's proposal; it mounts only once the owner selects it. */
      propose: (input: Facade.LensProposeRequest): Facade.LensProposalReceipt => this.#call(() => this.#client.vaultLensesPropose(input) as Facade.LensProposalReceipt),
      /** The owner selects a proposed lens revision for its pack slot. */
      activate: (input: Facade.LensActivateRequest): Facade.LensActivationReceipt => this.#call(() => this.#client.vaultLensesActivate(input) as Facade.LensActivationReceipt),
      /** The owner clears a pack slot's selected lens; the pack, its skill and the proposal stay. */
      deactivate: (input: Facade.LensDeactivateRequest): Facade.LensActivationReceipt => this.#call(() => this.#client.vaultLensesDeactivate(input) as Facade.LensActivationReceipt),
      /** One page of the vault's lens proposals, each with its slot state from the owner's current selection. A credential narrowed to some worlds or facets sees only the proposals whose slot skill and pack source it reads, without their trees. */
      list: (input: Facade.LensListRequest): Facade.LensListPage => this.#call(() => this.#client.vaultLensesList(input) as Facade.LensListPage),
      /** Selects a rendered atom or Unicode-scalar span under the caller's live key and holds its read handle on that card. */
      select: (input: Facade.LensSelectRequest): Facade.LensSelection => this.#call(() => this.#client.vaultLensesSelect(input) as Facade.LensSelection),
      /** Re-proves a host-issued selection on the caller's held card and reads its source with its pinned cursor span. */
      resolve: (input: Facade.LensSelectionResolveRequest): Facade.LensSelectionResolved => this.#call(() => this.#client.vaultLensesResolve(input) as Facade.LensSelectionResolved),
      result_set: {
        /** Re-proves the ticked rows or rendered predicate and their selected handles, then dispatches the declared result-set action through the caller's existing gate. */
        action: (input: Facade.LensResultSetActionRequest): Facade.LensResultSetActionResult => this.#call(() => this.#client.vaultLensesResultSetAction(input) as Facade.LensResultSetActionResult),
      },
      /** Composes the default vault lens from the named sources, read under the caller's own scope, as a card. A server holds its frame for the card's events; an embedded handle holds none, so its events need a server. */
      default: (input: Facade.LensDefaultRequest): Facade.ScopedReadResult<Facade.LensFrameCard> => this.#call(() => this.#client.vaultLensesDefault(input) as Facade.ScopedReadResult<Facade.LensFrameCard>),
    },
    disclosure: {
      /** An agent files a clearance offer for one contact, waiting on the owner's answer until it lapses. */
      offer: (input: Facade.DisclosureOfferRequest): Facade.DisclosureOffered => this.#call(() => this.#client.vaultDisclosureOffer(input) as Facade.DisclosureOffered),
    },
    shares: {
      /** The handle's actor issues a share: the brief, its recipient, the most the view may show and the text that travels. */
      create: (input: Facade.ShareCreateRequest): Facade.ShareCreated => this.#call(() => this.#client.vaultSharesCreate(input) as Facade.ShareCreated),
      revoke: (input: Facade.ShareRevokeRequest): Facade.ShareRevokeReceipt => this.#call(() => this.#client.vaultSharesRevoke(input) as Facade.ShareRevokeReceipt),
      view: (input: Facade.ShareViewRequest): Facade.ScopedReadResult<Facade.SharedBriefView | null> => this.#call(() => this.#client.vaultSharesView(input) as Facade.ScopedReadResult<Facade.SharedBriefView | null>),
    },
    hooks: {
      /** The owner replays a fact hook over past facts on the hook sandbox, as a dry run where nothing lands. */
      replay: (input: Facade.HooksReplayRequest): Facade.HookReplayRow[] => this.#call(() => this.#client.vaultHooksReplay(input) as Facade.HookReplayRow[]),
      regen: {
        /** List, as the authenticated owner, the hook bindings of the vault's own packs whose verb table or sandbox contract changed since their last good body passed, with no regen waiting. Runs no regen. */
        due: (input: Facade.EmptyRequest = {}): Facade.EntityId[] => this.#call(() => this.#client.vaultHooksRegenDue(input) as Facade.EntityId[]),
        /** Read one hook binding's regen record as the authenticated owner: its last good body hash, contract stamp, intent and pending decision, with the candidate_hash an adoption names. Null for a binding bound under no record. Changes nothing. */
        get: (input: Facade.HookRegenBindingRequest): Facade.HookRegenView | null => this.#call(() => this.#client.vaultHooksRegenGet(input) as Facade.HookRegenView | null),
        /** Adopt, as the authenticated owner and as their stamp, the regen candidate pending on one hook binding, named by the candidate_hash vault.hooks.regen.get shows. Answers the pack put receipt; only an installed put advances the record. */
        adopt: (input: Facade.HookRegenAdoptRequest): Facade.PackPutReceipt => this.#call(() => this.#client.vaultHooksRegenAdopt(input) as Facade.PackPutReceipt),
      },
    },
    artifacts: {
      /** Computes the exact publication approval digest for the existing owner approve-once door; it grants nothing. */
      publish_approval: (input: Facade.ArtifactPublishRequest): Facade.ArtifactPublishApproval => this.#call(() => this.#client.vaultArtifactsPublishApproval(input) as Facade.ArtifactPublishApproval),
      /** Publishes one immutable code fork or numbered blob export with an explicit audience through the existing Gate, returning its pointer and durable receipt ref. */
      publish: (input: Facade.ArtifactPublishRequest): Facade.ArtifactPublishView => this.#call(() => this.#client.vaultArtifactsPublish(input) as Facade.ArtifactPublishView),
      /** Repoints one artifact channel to an exact immutable export through the publication Gate; use a new publish id, and earlier receipts survive. */
      repoint: (input: Facade.ArtifactPublishRequest): Facade.ArtifactPublishView => this.#call(() => this.#client.vaultArtifactsRepoint(input) as Facade.ArtifactPublishView),
      /** Reads the current artifact channel pin and audience under the owner credential; null when absent or withheld. */
      pointer: (input: Facade.ArtifactPointerRequest): Facade.ArtifactPointer | null => this.#call(() => this.#client.vaultArtifactsPointer(input) as Facade.ArtifactPointer | null),
      /** Removes one artifact channel pointer without deleting its immutable export or earlier publication receipts. */
      unpublish: (input: Facade.ArtifactPointerRequest): Facade.ArtifactUnpublished => this.#call(() => this.#client.vaultArtifactsUnpublish(input) as Facade.ArtifactUnpublished),
      /** Mints a serving-only link token and its digest tier; publication still requires a separate exact Gate authorization. */
      link_token: (input: Facade.EmptyRequest): Facade.ArtifactLinkToken => this.#call(() => this.#client.vaultArtifactsLinkToken(input) as Facade.ArtifactLinkToken),
      live_preview: {
        /** Opens a draft-labelled, owner-private live preview only for the exact process, port and lease already declared by the trusted session runtime. */
        register: (input: Facade.ArtifactPreviewRegisterRequest): Facade.ArtifactPreviewView => this.#call(() => this.#client.vaultArtifactsLivePreviewRegister(input) as Facade.ArtifactPreviewView),
        /** Reads a live draft endpoint and a caller-specific preview URL as the owner or a named invitee; uninvited callers are refused. */
        read: (input: Facade.ArtifactPreviewRequest): Facade.ArtifactPreviewView | null => this.#call(() => this.#client.vaultArtifactsLivePreviewRead(input) as Facade.ArtifactPreviewView | null),
        /** Closes one owner-private preview lease, invalidating its old URLs, streams and upgrades without changing any published artifact pin. */
        close: (input: Facade.ArtifactPreviewRequest): Facade.ArtifactPreviewClosed => this.#call(() => this.#client.vaultArtifactsLivePreviewClose(input) as Facade.ArtifactPreviewClosed),
        /** Invites one named principal to a private live preview under the lease owner proof; no public audience is created. */
        invite: (input: Facade.ArtifactPreviewInviteRequest): Facade.ArtifactPreviewInvitation => this.#call(() => this.#client.vaultArtifactsLivePreviewInvite(input) as Facade.ArtifactPreviewInvitation),
        /** Revokes one private preview invitation and its personal credentials, including active streams. */
        revoke_invite: (input: Facade.ArtifactPreviewInviteRequest): Facade.ArtifactPreviewInvitation => this.#call(() => this.#client.vaultArtifactsLivePreviewRevokeInvite(input) as Facade.ArtifactPreviewInvitation),
        /** Mints a revocable sharing URL for one private live preview, replacing any earlier sharing URL; no artifact is published. */
        share: (input: Facade.ArtifactPreviewRequest): Facade.ArtifactPreviewShare => this.#call(() => this.#client.vaultArtifactsLivePreviewShare(input) as Facade.ArtifactPreviewShare),
        /** Revokes the private preview sharing URL and streams that used it while preserving separate owner and invitee credentials. */
        revoke_share: (input: Facade.ArtifactPreviewRequest): Facade.ArtifactPreviewShare => this.#call(() => this.#client.vaultArtifactsLivePreviewRevokeShare(input) as Facade.ArtifactPreviewShare),
      },
      /** One artifact's kind, head and versions, each with its made_by and born-from. */
      view: (request: Facade.ArtifactRefRequest): Facade.ArtifactView | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsView(keyedJson(request))) as Facade.ArtifactView | null; return result === null ? null : result }),
      /** Inspects real DOCX blocks, XLSX cells and PPTX shapes in one version; other kinds explicitly report no annotation unit adapter. */
      units: (input: Facade.ArtifactUnitsRequest): Facade.ArtifactUnitsView => this.#call(() => this.#client.vaultArtifactsUnits(input) as Facade.ArtifactUnitsView),
      anchors: {
        /** Pins an exact readable locator and quote in an artifact version; opening a thread makes the pin durable. */
        pin: (input: Facade.AnnotationPinRequest): Facade.AnnotationAnchorView => this.#call(() => this.#client.vaultArtifactsAnchorsPin(input) as Facade.AnnotationAnchorView),
      },
      threads: {
        /** Opens an anchored thread with its first comment as the caller, retaining its exact version, locator and quote. */
        open: (input: Facade.AnnotationThreadOpenRequest): Facade.AnnotationThreadView => this.#call(() => this.#client.vaultArtifactsThreadsOpen(input) as Facade.AnnotationThreadView),
        /** Appends a comment as the caller; returns its first stored part, with every part available through threads.read. */
        comment: (input: Facade.AnnotationCommentRequest): Facade.AnnotationCommentView => this.#call(() => this.#client.vaultArtifactsThreadsComment(input) as Facade.AnnotationCommentView),
        /** Reads a thread, its opening quote, current anchor, explicit pinned, mapped or drifted disposition, comments and assignment. */
        read: (input: Facade.AnnotationThreadRequest): Facade.AnnotationThreadView | null => this.#call(() => this.#client.vaultArtifactsThreadsRead(input) as Facade.AnnotationThreadView | null),
        /** Lists an artifact's readable threads with their opening pins, current anchors, drift, comments and assignments. */
        list: (input: Facade.ArtifactRefRequest): Facade.AnnotationThreadView[] => this.#call(() => this.#client.vaultArtifactsThreadsList(input) as Facade.AnnotationThreadView[]),
        /** Assigns an anchored thread into a durable task brief with its anchor and transcript; an agent-definition assignee dispatches through the engine. */
        assign: (input: Facade.AnnotationAssignRequest): Facade.AnnotationBriefView => this.#call(() => this.#client.vaultArtifactsThreadsAssign(input) as Facade.AnnotationBriefView),
        /** Opens or resolves a thread through its existing claim gate, preserving its anchor, comments and drift. */
        state: (input: Facade.AnnotationStateRequest): Facade.AnnotationThreadView => this.#call(() => this.#client.vaultArtifactsThreadsState(input) as Facade.AnnotationThreadView),
      },
      /** One version's export file (base64), with its pinned name and media type. */
      export: (request: Facade.ArtifactExportRequest): Facade.ArtifactExportFile | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsExport(keyedJson(request))) as Facade.ArtifactExportFile | null; return result === null ? null : result }),
      /** The artifacts and versions a task, ask, run, skill or agent run produced. */
      born_from: (request: Facade.BornFromRequest): Facade.BornFromView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBornFrom(keyedJson(request))) as Facade.BornFromView; return result }),
      /** The proposals waiting beside one artifact for Keep or Discard. */
      proposals: (request: Facade.ArtifactRefRequest): Facade.PendingProposalView[] => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsProposals(keyedJson(request))) as Facade.PendingProposalView[]; return result.map(item => item) }),
      /** The organ calls held beside one artifact until one of your nodes can run them, each with why it waits. */
      waits: (request: Facade.ArtifactRefRequest): Facade.OrganWaitView[] => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsWaits(keyedJson(request))) as Facade.OrganWaitView[]; return result.map(item => item) }),
      /** Lets one held organ call go, by its run ref, under the consent a Discard needs. */
      release_wait: (request: Facade.ProposalSettleRequest): Facade.ReleasedWait => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsReleaseWait(keyedJson(request))) as Facade.ReleasedWait; return result }),
      /** Reviews an artifact's slides through the host's decision ladder and holds the comments as one proposal for Keep. */
      review_slides: (request: Facade.SlideReviewSubmit): Facade.SlideReviewOutcome => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsReviewSlides(keyedJson(request))) as Facade.SlideReviewOutcome; return result }),
      /** Asks one typed question over an artifact's sheet rows, paragraphs or folder items through the host's decision ladder and holds the answers as one proposal for Keep or Discard. */
      ask: (input: Facade.ArtifactAskSubmit): Facade.ArtifactAskOutcome => this.#call(() => this.#client.vaultArtifactsAsk(input) as Facade.ArtifactAskOutcome),
      /** Proposes a closed typed deck outline as a brief NOTE for the person to keep or decline. */
      propose_outline: (input: Facade.DeckOutlineProposeRequest): Facade.DeckOutlineView => this.#call(() => this.#client.vaultArtifactsProposeOutline(input) as Facade.DeckOutlineView),
      /** Reads a typed deck outline, its current NOTE frontier, its keep and its freshness. */
      outline: (input: Facade.DeckOutlineRefRequest): Facade.DeckOutlineView => this.#call(() => this.#client.vaultArtifactsOutline(input) as Facade.DeckOutlineView),
      /** The owner keeps the exact outline frontier, freezing its version and content hash. */
      keep_outline: (input: Facade.DeckOutlineSettleRequest): Facade.KeptOutline => this.#call(() => this.#client.vaultArtifactsKeepOutline(input) as Facade.KeptOutline),
      /** The owner declines the exact outline frontier, clearing its keep and design directions. */
      decline_outline: (input: Facade.DeckOutlineSettleRequest): Facade.DeckOutlineDeclined => this.#call(() => this.#client.vaultArtifactsDeclineOutline(input) as Facade.DeckOutlineDeclined),
      /** Compiles one to three template directions from the exact fresh keep into validated plans or typed design decisions. */
      design_deck: (input: Facade.DeckDesignRequest): Facade.DeckDesignView => this.#call(() => this.#client.vaultArtifactsDesignDeck(input) as Facade.DeckDesignView),
      /** Emits one checked deck from a fresh kept outline and a planned template, retaining born-from and unverified fit. */
      create_deck: (input: Facade.DeckEmissionRequest): Facade.DeckEmissionOutcome => this.#call(() => this.#client.vaultArtifactsCreateDeck(input) as Facade.DeckEmissionOutcome),
      /** Inspects one PPTX version for native edit targets and comment identities without minting ids. */
      inspect_deck: (input: Facade.DeckInspectRequest): Facade.DeckInspectionView => this.#call(() => this.#client.vaultArtifactsInspectDeck(input) as Facade.DeckInspectionView),
      /** Runs one native deck transaction over the head and holds the proposal for Keep. */
      propose_deck: (request: Facade.DeckProposeRequest): Facade.DeckProposeOutcome => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsProposeDeck(keyedJson(request))) as Facade.DeckProposeOutcome; return result }),
      /** Offers one native organ result as the artifact's next version, held for Keep. */
      propose_output: (request: Facade.NativeOutputRequest): Facade.PendingProposalView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsProposeOutput(keyedJson(request))) as Facade.PendingProposalView; return result }),
      /** Keeps one waiting proposal as a new version, once, with its receipt. */
      keep: (request: Facade.ProposalSettleRequest): Facade.KeptProposal => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsKeep(keyedJson(request))) as Facade.KeptProposal; return result }),
      /** Discards one waiting proposal, once, with its receipt. */
      discard: (request: Facade.ProposalSettleRequest): Facade.DiscardedProposal => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsDiscard(keyedJson(request))) as Facade.DiscardedProposal; return result }),
      /** Undoes one Keep with a new version; the settle stays consumed. */
      undo: (request: Facade.ProposalSettleRequest): Facade.UndoneKeep => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsUndo(keyedJson(request))) as Facade.UndoneKeep; return result }),
      /** Creates an artifact with its first version, as the caller: a person's upload, or an agent's version naming its run. */
      create: (input: Facade.ArtifactCreateRequest): Facade.ArtifactView | null => this.#call(() => this.#client.vaultArtifactsCreate(input) as Facade.ArtifactView | null),
      /** Registers one blob artifact; its bytes ride vault.artifacts.append. */
      put: (input: Facade.BlobArtifactInput): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultArtifactsPut(input) as Facade.EntityRefReceipt),
      body: {
        /** Imports one office version as the artifact's live body. */
        import: (request: Facade.OfficeBodyImportRequest): Facade.OfficeBodyHead => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyImport(keyedJson(request))) as Facade.OfficeBodyHead; return result }),
        /** An artifact's live body head, or null. */
        head: (request: Facade.OfficeBodyArtifactRequest): Facade.OfficeBodyHead | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyHead(keyedJson(request))) as Facade.OfficeBodyHead | null; return result === null ? null : result }),
        /** Reads a DOCX or XLSX live body, at its head or an earlier frontier. */
        read: (request: Facade.OfficeBodyReadRequest): Facade.OfficeBodyView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyRead(keyedJson(request))) as Facade.OfficeBodyView; return result }),
        /** Every commit receipt of a live body, in commit order, or one actor's. */
        commits: (request: Facade.OfficeBodyCommitsRequest): Facade.OfficeBodyCommitView[] => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyCommits(keyedJson(request))) as Facade.OfficeBodyCommitView[]; return result.map(item => item) }),
        /** A person's typed operations on the live body. */
        edit: (request: Facade.OfficeBodyEditRequest): Facade.OfficeBodyEdit => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyEdit(keyedJson(request))) as Facade.OfficeBodyEdit; return result }),
        fork: {
          /** Opens a fork of the live body for machine work. */
          open: (request: Facade.OfficeBodyForkOpenRequest): Facade.OfficeBodyFork => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyForkOpen(keyedJson(request))) as Facade.OfficeBodyFork; return result }),
          /** The opener's typed operations on its fork. */
          edit: (request: Facade.OfficeBodyForkEditRequest): Facade.OfficeBodyEdit => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyForkEdit(keyedJson(request))) as Facade.OfficeBodyEdit; return result }),
          /** A fork's three-way diff against the live head. */
          diff: (request: Facade.OfficeBodyForkRequest): Facade.OfficeBodyDiff => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyForkDiff(keyedJson(request))) as Facade.OfficeBodyDiff; return result }),
          /** Lands one reviewed fork on an answer. */
          merge: (request: Facade.OfficeBodyForkMergeRequest): Facade.OfficeBodyDiff => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyForkMerge(keyedJson(request))) as Facade.OfficeBodyDiff; return result }),
          /** Abandons an open fork's unlanded work. */
          discard: (request: Facade.OfficeBodyForkRequest): Facade.OfficeBodyFork => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyForkDiscard(keyedJson(request))) as Facade.OfficeBodyFork; return result }),
        },
        proposal: {
          /** An office proposal: its members, answers and settlement. */
          read: (request: Facade.OfficeBodyProposalRequest): Facade.OfficeBodyProposal => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyProposalRead(keyedJson(request))) as Facade.OfficeBodyProposal; return result }),
          /** Accepts or rejects an office proposal's reviewed forks. */
          settle: (request: Facade.OfficeBodyProposalSettleRequest): Facade.OfficeBodyProposal => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyProposalSettle(keyedJson(request))) as Facade.OfficeBodyProposal; return result }),
        },
        /** Exports the live body as the artifact's next version. */
        export: (request: Facade.OfficeBodyExportVerbRequest): Facade.OfficeBodyExportView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyExport(keyedJson(request))) as Facade.OfficeBodyExportView; return result }),
        /** The workbook an XLSX export would land now, recalculated. */
        preview: (request: Facade.OfficeBodyPreviewRequest): Facade.XlsxPreview => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyPreview(keyedJson(request))) as Facade.XlsxPreview; return result }),
        deck: {
          /** A deck fork's merge preflight against the live head. */
          review: (request: Facade.OfficeBodyForkRequest): Facade.DeckReviewView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyDeckReview(keyedJson(request))) as Facade.DeckReviewView; return result }),
          /** A person lands a reviewed deck fork. */
          merge: (request: Facade.DeckForkMergeRequest): Facade.LandingReceipt => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyDeckMerge(keyedJson(request))) as Facade.LandingReceipt; return result }),
          /** Projects a deck, landing it as the next version when its export gate is open. */
          export: (request: Facade.DeckExportRequest): Facade.DeckExportView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyDeckExport(keyedJson(request))) as Facade.DeckExportView; return result }),
          /** The deck export gate for a profile. */
          gate: (request: Facade.DeckGateRequest): Facade.DeckGateView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyDeckGate(keyedJson(request))) as Facade.DeckGateView; return result }),
          /** Records the deck oracle's receipt for its export profile. */
          oracle: (request: Facade.DeckOracleRequest): Facade.DeckGateView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyDeckOracle(keyedJson(request))) as Facade.DeckGateView; return result }),
          /** The asked slides of a deck's head or a fork's merge candidate, drawn by the host's review renderer (provisional). */
          preview: (request: Facade.DeckPreviewRequest): Facade.DeckPreview => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBodyDeckPreview(keyedJson(request))) as Facade.DeckPreview; return result }),
        },
      },
      /** Appends one version of bytes to a blob artifact's append-only chain. */
      append: (input: Facade.AppendBlobVersionRequest): Facade.BlobVersionView => this.#call(() => this.#client.vaultArtifactsAppend(input) as Facade.BlobVersionView),
      /** Reads one version of a blob artifact's bytes. */
      read: (input: Facade.ReadBlobVersionRequest): Facade.BlobContent | null => this.#call(() => this.#client.vaultArtifactsRead(input) as Facade.BlobContent | null),
    },
    code: {
      /** The semantic changes between two tested states of one code file, each with the operations that made it. */
      diff: (request: Facade.CodeDiffRequest): Facade.CodeDiffView | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultCodeDiff(keyedJson(request))) as Facade.CodeDiffView | null; return result === null ? null : result }),
      /** Every unit of one tested code file state, blamed by the operations that wrote it. */
      blame: (request: Facade.CodeStateRequest): Facade.CodeBlameView | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultCodeBlame(keyedJson(request))) as Facade.CodeBlameView | null; return result === null ? null : result }),
      /** One repo proposal's semantic change from its base, under the provenance it was proposed with. */
      proposal_view: (request: Facade.CodeProposalViewRequest): Facade.CodeProposalView | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultCodeProposalView(keyedJson(request))) as Facade.CodeProposalView | null; return result === null ? null : result }),
      symbols: {
        /** Declare the current repository symbols a task will touch, held by the caller until host time plus ttl_seconds. Owner only. An overlap waits behind the tasks it names, never refused; it grants no write, approval or landing. */
        declare: (input: Facade.CodeSymbolsDeclareRequest): Facade.CodeSymbolsDeclared => this.#call(() => this.#client.vaultCodeSymbolsDeclare(input) as Facade.CodeSymbolsDeclared),
        /** Renew the live symbol declaration the caller holds for one task by its declared lifetime. Owner only. */
        renew: (input: Facade.CodeSymbolsTaskRequest): Facade.CodeSymbolLeaseView => this.#call(() => this.#client.vaultCodeSymbolsRenew(input) as Facade.CodeSymbolLeaseView),
        /** Release the symbol declaration the caller holds for one task. Owner only. Keyed by task and holder with no epoch fence; it applies, approves and schedules nothing. */
        release: (input: Facade.CodeSymbolsTaskRequest): Facade.CodeSymbolsReleased => this.#call(() => this.#client.vaultCodeSymbolsRelease(input) as Facade.CodeSymbolsReleased),
        /** Find Rust symbol definitions by exact name within one pinned code snapshot. Owner only. Definitions only: no calls, imports or refs relation, and no other language. */
        definitions: (input: Facade.CodeSnapshotDefinitionsRequest): Facade.CodeSnapshotDefinitionsView => this.#call(() => this.#client.vaultCodeSymbolsDefinitions(input) as Facade.CodeSnapshotDefinitionsView),
      },
      /** Stage one file change of a repository as a Proposed proposal with its retained base, under the review lens catalog the owner sends. Owner only. The engine mints the proposal id; nothing is approved, queued or landed. */
      proposal_submit: (input: Facade.CodeProposalSubmitRequest): Facade.CodeProposalSubmitted => this.#call(() => this.#client.vaultCodeProposalSubmit(input) as Facade.CodeProposalSubmitted),
      /** Record a real Git overlap between two stored one-file proposals at the same retained base, with both trees, paths and a linked reconciliation task. Owner only; neither branch moves. */
      conflict_record: (input: Facade.CodeConflictRecordRequest): Facade.CodeConflictView => this.#call(() => this.#client.vaultCodeConflictRecord(input) as Facade.CodeConflictView),
      /** Read open repository conflicts and their durable resolution claims, including each reconciliation task. Owner only. */
      conflict_view: (input: Facade.CodeConflictViewRequest): Facade.CodeConflictHistory => this.#call(() => this.#client.vaultCodeConflictView(input) as Facade.CodeConflictHistory),
      /** Stage a one-file resolution of an active repository conflict as another Proposed proposal, preserving its original proposals and reconciliation task. Owner only; nothing lands. */
      proposal_resolve: (input: Facade.CodeProposalResolveRequest): Facade.CodeProposalSubmitted => this.#call(() => this.#client.vaultCodeProposalResolve(input) as Facade.CodeProposalSubmitted),
      /** Record the authenticated owner's immutable critic opinion on one proposal lens. Independent reviewers only; this is no contract-check execution receipt. */
      proposal_review: (input: Facade.CodeProposalReviewRequest): Facade.CodeProposalSettlementView => this.#call(() => this.#client.vaultCodeProposalReview(input) as Facade.CodeProposalSettlementView),
      /** Approve or reject one reviewed code proposal as an independent owner, retaining a decision receipt. Approval still needs unanimous critics and never advances head; only the tested merge queue lands it. */
      proposal_settle: (input: Facade.CodeProposalSettleRequest): Facade.CodeProposalSettlementView => this.#call(() => this.#client.vaultCodeProposalSettle(input) as Facade.CodeProposalSettlementView),
      /** Read a code proposal's review decision receipt and execution lineage, including its conflict, original proposals, reconciliation task and resolution claim. Owner only. */
      proposal_settlement: (input: Facade.CodeProposalSettlementRequest): Facade.CodeProposalSettlementView => this.#call(() => this.#client.vaultCodeProposalSettlement(input) as Facade.CodeProposalSettlementView),
      /** Read the durable mutation log of one repository in sequence order: prepared, applied and failed mutations. Owner only. It is not a proposal queue and holds no pending proposal. */
      oplog: (input: Facade.CodeRepoRequest): Facade.CodeMutationLog => this.#call(() => this.#client.vaultCodeOplog(input) as Facade.CodeMutationLog),
      /** Read the tally this vault keeps of its own durable executor turns one model needed wire healing for, by full provider/name@revision id, zero when absent. Owner only. A routing signal, not a run correction receipt or repair policy. */
      model_heal_count: (input: Facade.CodeRunModelHealCountRequest): Facade.CodeRunModelHealCountView => this.#call(() => this.#client.vaultCodeModelHealCount(input) as Facade.CodeRunModelHealCountView),
      waits: {
        /** Answer one sealed code consent wait as the authenticated owner, on the word the owner gave on its ask. First answer wins; the held effect meets its own current gate once. No raw reply, grant or consumption is taken. */
        resolve: (input: Facade.CodeWaitResolveRequest): Facade.CodeWaitReceiptView => this.#call(() => this.#client.vaultCodeWaitsResolve(input) as Facade.CodeWaitReceiptView),
        /** Read one code consent wait as the authenticated owner: its held effect, answer, settlement and replay consumption receipts. Never answers, resumes or sends. Null for an unknown, unsealed or withheld wait. */
        receipt: (input: Facade.CodeWaitReceiptRequest): Facade.CodeWaitReceiptView | null => this.#call(() => this.#client.vaultCodeWaitsReceipt(input) as Facade.CodeWaitReceiptView | null),
      },
      /** Every file changed between two trees of a repository, unit by unit, with the operations that wrote each. */
      repo_diff: (request: Facade.CodeRepoDiffRequest): Facade.CodeRepoDiffView | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultCodeRepoDiff(keyedJson(request))) as Facade.CodeRepoDiffView | null; return result === null ? null : result }),
      /** Export one already-finalized and reviewed document revision through the existing origin publication protocol. */
      export: (input: Facade.CodeExportRequest): Facade.CodeExportResult => this.#call(() => this.#client.vaultCodeExport(input) as Facade.CodeExportResult),
      origin: {
        authority: {
          /** Read one served origin authority and this host identity under the owner credential. */
          get: (input: Facade.OriginRepoRequest): Facade.OriginAuthorityView => this.#call(() => this.#client.vaultCodeOriginAuthorityGet(input) as Facade.OriginAuthorityView),
          /** Cut over one existing served origin under the owner proof and expected authority epoch. */
          set: (input: Facade.OriginAuthoritySetRequest): Facade.OriginAuthorityView => this.#call(() => this.#client.vaultCodeOriginAuthoritySet(input) as Facade.OriginAuthorityView),
        },
        /** Read durable publication records for one served repository ref and commit without synthesizing a push acknowledgement. */
        publications: (input: Facade.OriginPublicationsRequest): Facade.OriginPublicationsView => this.#call(() => this.#client.vaultCodeOriginPublications(input) as Facade.OriginPublicationsView),
      },
      checkout: {
        /** Materialize an existing live owner checkout with lease-bound origin remotes and no upstream credential. */
        bind: (input: Facade.CheckoutDoorBindRequest): Facade.CheckoutDoorBinding => this.#call(() => this.#client.vaultCodeCheckoutBind(input) as Facade.CheckoutDoorBinding),
        /** Claim the caller's checkout on an assigned task, with a bounded TTL and declared idempotence. */
        claim: (input: Facade.CheckoutClaimInput): Facade.CheckoutLeaseView => this.#call(() => this.#client.vaultCodeCheckoutClaim(input) as Facade.CheckoutLeaseView),
        /** Read checkout custody and vault-clock expiry as a task party, without claiming or renewing it. */
        get: (input: Facade.CheckoutGetInput): Facade.CheckoutLeaseView => this.#call(() => this.#client.vaultCodeCheckoutGet(input) as Facade.CheckoutLeaseView),
        /** Renew the caller's still-live checkout under its exact holder and epoch fence. */
        renew: (input: Facade.CheckoutRenewInput): Facade.CheckoutLeaseView => this.#call(() => this.#client.vaultCodeCheckoutRenew(input) as Facade.CheckoutLeaseView),
        /** Reclaim an expired declared-idempotent build or verify checkout as an authorized successor at the named epoch. */
        reclaim: (input: Facade.CheckoutReclaimInput): Facade.CheckoutLeaseView => this.#call(() => this.#client.vaultCodeCheckoutReclaim(input) as Facade.CheckoutLeaseView),
        /** Explicitly take over a checkout as its task owner, including effect work, at the named epoch. */
        takeover: (input: Facade.CheckoutTakeoverInput): Facade.CheckoutLeaseView => this.#call(() => this.#client.vaultCodeCheckoutTakeover(input) as Facade.CheckoutLeaseView),
        /** Publish a stored candidate result for checkout settlement under the caller's live epoch; this does not export a Git head. */
        publish: (input: Facade.CheckoutPublishInput): Facade.CheckoutPublished => this.#call(() => this.#client.vaultCodeCheckoutPublish(input) as Facade.CheckoutPublished),
        /** Consume one published checkout result at its epoch as select, apply, release or discard; an identical retry returns its receipt. */
        settle: (input: Facade.CheckoutSettleInput): Facade.CheckoutSettled => this.#call(() => this.#client.vaultCodeCheckoutSettle(input) as Facade.CheckoutSettled),
        /** Collect the caller's checkout only with a matching durable pushed-head receipt and clear custody; retain dirty or uncertain trees. */
        teardown: (input: Facade.CheckoutTeardownInput): Facade.CheckoutTornDown => this.#call(() => this.#client.vaultCodeCheckoutTeardown(input) as Facade.CheckoutTornDown),
      },
      views: {
        /** Materialize a private linked working view from verified tested file frontiers in the authenticated owner account. */
        materialize: (input: Facade.CodeViewMaterializeRequest): Facade.CodeWorkingView => this.#call(() => this.#client.vaultCodeViewsMaterialize(input) as Facade.CodeWorkingView),
        /** Read one working view and its immutable tested base under the authenticated owner account. */
        get: (input: Facade.CodeViewRequest): Facade.CodeWorkingView => this.#call(() => this.#client.vaultCodeViewsGet(input) as Facade.CodeWorkingView),
        /** Read the current bytes of one selected input in the authenticated owner working view. */
        read: (input: Facade.CodeViewReadRequest): Facade.CodeViewFileBytes => this.#call(() => this.#client.vaultCodeViewsRead(input) as Facade.CodeViewFileBytes),
        /** Freeze current view input identities and return the REAPI action digest with its exact command bytes and input root digest. */
        action: (input: Facade.CodeViewActionRequest): Facade.CodeViewAction => this.#call(() => this.#client.vaultCodeViewsAction(input) as Facade.CodeViewAction),
        /** Run a pinned native owner build or verify leg, reusing clean account-local results and retaining secret-consuming exhaust as tainted. */
        build: (input: Facade.CodeViewBuildRequest): Facade.CodeCacheOutcome => this.#call(() => this.#client.vaultCodeViewsBuild(input) as Facade.CodeCacheOutcome),
      },
      cache: {
        /** Read one clean immutable account-local build result by action key without executing a command. */
        get: (input: Facade.CodeCacheReadRequest): Facade.CodeCacheOutcome => this.#call(() => this.#client.vaultCodeCacheGet(input) as Facade.CodeCacheOutcome),
        /** Reuse an authorized clean action result into another matching working view without dispatching a cold build. */
        reuse: (input: Facade.CodeViewBuildRequest): Facade.CodeCacheOutcome => this.#call(() => this.#client.vaultCodeCacheReuse(input) as Facade.CodeCacheOutcome),
      },
      snapshots: {
        /** Import one committed Git tree, by an absolute folder on the serving host and a full 40-hex commit, as a custody-filtered snapshot. Owner only. It registers no repository, whitelist, membership or receipt. */
        ingest: (input: Facade.CodeSnapshotIngestRequest): Facade.CodeSnapshotView => this.#call(() => this.#client.vaultCodeSnapshotsIngest(input) as Facade.CodeSnapshotView),
        /** Read the file manifest of one code snapshot, pinned by its imported artifact and fork hash. Owner only. Files carry blob hashes, not document versions, and the scope key is an index key, not a grant. */
        get: (input: Facade.CodeSnapshotRequest): Facade.CodeSnapshotView | null => this.#call(() => this.#client.vaultCodeSnapshotsGet(input) as Facade.CodeSnapshotView | null),
        /** Read one UTF-8 file and its SHA-256 from the frozen blobs of a pinned code snapshot, never from the folder on disk. Owner only. */
        read: (input: Facade.CodeSnapshotReadRequest): Facade.CodeSnapshotPinnedFile | null => this.#call(() => this.#client.vaultCodeSnapshotsRead(input) as Facade.CodeSnapshotPinnedFile | null),
      },
      merge_queue: {
        /** Queue stored repository proposals as one batch on the queue green commit, one to six per call, with no batching window. Owner only. The proposals keep their own bytes and reviews; nothing is checked or landed. */
        enqueue: (input: Facade.MergeQueueEnqueueRequest): Facade.MergeQueueBatchView => this.#call(() => this.#client.vaultCodeMergeQueueEnqueue(input) as Facade.MergeQueueBatchView),
        /** Materialize every nonempty subset of one queued batch as a journaled detached speculative worktree. Owner only. Head and green do not move. */
        stage: (input: Facade.MergeQueueBatchRequest): Facade.MergeQueueBatchView => this.#call(() => this.#client.vaultCodeMergeQueueStage(input) as Facade.MergeQueueBatchView),
        /** Read the queue head and green Git commits, the named batches in request order and the stored contract verdicts they name. Owner only. It never recovers or settles, and a verdict is no check execution receipt. */
        observe: (input: Facade.MergeQueueObserveRequest): Facade.MergeQueueObservation => this.#call(() => this.#client.vaultCodeMergeQueueObserve(input) as Facade.MergeQueueObservation),
        /** Queue the proposals a diagnosed red batch did not quarantine as a new batch, keeping the red batch and its quarantine. Owner only. No durable parent or child link is written. */
        requeue_survivors: (input: Facade.MergeQueueBatchRequest): Facade.MergeQueueRequeueView => this.#call(() => this.#client.vaultCodeMergeQueueRequeueSurvivors(input) as Facade.MergeQueueRequeueView),
        /** Advance the fast-tested head by one ready batch through reviewed-stack admission alone. Owner only. Each proposal still needs unanimous critic approval and exact bytes and base; the owner proof approves nothing. */
        land_reviewed: (input: Facade.MergeQueueBatchRequest): Facade.MergeQueueBatchView => this.#call(() => this.#client.vaultCodeMergeQueueLandReviewed(input) as Facade.MergeQueueBatchView),
        /** Settle stored slow results in landing order: green advances past passing ones, and a red one rolls the ungreen suffix back. Owner only. The caller names no commit or result. */
        settle_slow: (input: Facade.MergeQueueRepoRequest): Facade.MergeQueuePointersView => this.#call(() => this.#client.vaultCodeMergeQueueSettleSlow(input) as Facade.MergeQueuePointersView),
        /** Reconcile an interrupted landing or rollback with its persisted mutation receipts. Owner only. Unreceipted divergence refuses; nothing is approved or rebased. */
        recover: (input: Facade.MergeQueueRepoRequest): Facade.MergeQueuePointersView => this.#call(() => this.#client.vaultCodeMergeQueueRecover(input) as Facade.MergeQueuePointersView),
      },
    },
    results: {
      /** The owner inspects retained result occurrences, incomplete body descriptors and recorded producing-run effects without entering the run. */
      status: (input: Facade.ResultRunRequest): Facade.ResultRunStatus => this.#call(() => this.#client.vaultResultsStatus(input) as Facade.ResultRunStatus),
      /** The owner reopens retained result status after restart; it never resumes the producer or replays an effect to regenerate output. */
      recover: (input: Facade.ResultRunRequest): Facade.ResultRunStatus => this.#call(() => this.#client.vaultResultsRecover(input) as Facade.ResultRunStatus),
      /** The owner reads one exact retained result occurrence card under its current taint and source-row fence, never by content authority alone. */
      read: (input: Facade.ResultOccurrenceRequest): Facade.ResultReadView => this.#call(() => this.#client.vaultResultsRead(input) as Facade.ResultReadView),
      /** The owner reads a typed byte or line range of one exact result occurrence, with bounded continuations and current taint withholding. */
      slice: (input: Facade.ResultSliceRequest): Facade.ResultSliceView => this.#call(() => this.#client.vaultResultsSlice(input) as Facade.ResultSliceView),
    },
    agents: {
      /** The owner creates an inert custom agent composition with an optional per-domain refusal dial, caller-derived authorship and existing fork/ceiling gates; no attempt is dispatched. */
      create: (input: Facade.AgentDefinitionCreateRequest): Facade.AgentDefinitionView => this.#call(() => this.#client.vaultAgentsCreate(input) as Facade.AgentDefinitionView),
      /** The owner reads one saved agent composition, including its declared refusal dial, version and approval state. */
      get: (input: Facade.AgentDefinitionRequest): Facade.AgentDefinitionView => this.#call(() => this.#client.vaultAgentsGet(input) as Facade.AgentDefinitionView),
      /** The owner edits the expected definition version and optional refusal dial through the existing immutable-field and ceiling gates; refusal decisions read the live dial. */
      update: (input: Facade.AgentDefinitionUpdateRequest): Facade.AgentDefinitionView => this.#call(() => this.#client.vaultAgentsUpdate(input) as Facade.AgentDefinitionView),
      dreaming: {
        /** The owner reads one agent's dreaming choice: its stored mode, the mode in force and its own dreaming model slot. */
        get: (input: Facade.AgentDreamingRequest): Facade.AgentDreamingView => this.#call(() => this.#client.vaultAgentsDreamingGet(input) as Facade.AgentDreamingView),
        /** The owner sets one agent's dreaming choice on the revision read: its own model, the vault weaver's, or off; sharing a model never shares its diary. */
        set: (input: Facade.AgentDreamingSetRequest): Facade.AgentDreamingView => this.#call(() => this.#client.vaultAgentsDreamingSet(input) as Facade.AgentDreamingView),
      },
      /** The owner launches one reserved planned agent or team under an intent key on this host's planner: the type placed, the plan frozen at the root, then queued; the same key answers what it kept. */
      spawn: Object.assign((input: Facade.SpawnIntentRequest): Facade.SpawnIntentReply => this.#call(() => this.#client.vaultAgentsSpawn(input) as Facade.SpawnIntentReply), {
        /** The owner reads one spawned agent's stored observations by its attempt: its type stamp and frozen plan, the team actually launched, its seat route, critic artifacts and receipt-backed learning. */
        get: (input: Facade.PlannedSpawnRead): Facade.PlannedSpawnObservation => this.#call(() => this.#client.vaultAgentsSpawnGet(input) as Facade.PlannedSpawnObservation),
      }),
      /** The agent's travelling AgentPack folder (files base64) and what stayed home. */
      export_pack: (request: Facade.AgentPackExportRequest): Facade.AgentPackExport => this.#call(() => {  const result = JSON.parse(this.#client.vaultAgentsExportPack(keyedJson(request))) as Facade.AgentPackExport; return result }),
    },
    standing_blocks: {
      /** The owner configures one agent's standing block in one world with its name and token floor; reopening the same pair answers the stored handle. */
      configure: (input: Facade.StandingBlockConfigureRequest): Facade.StandingBlockView => this.#call(() => this.#client.vaultStandingBlocksConfigure(input) as Facade.StandingBlockView),
      /** The owner gives a configured standing block a new name and token floor; an unconfigured pair is refused, never implicitly opened. */
      reconfigure: (input: Facade.StandingBlockConfigureRequest): Facade.StandingBlockView => this.#call(() => this.#client.vaultStandingBlocksReconfigure(input) as Facade.StandingBlockView),
      /** The owner reads one agent's configured standing block in one world: its handle, name and token floor. */
      get: (input: Facade.StandingBlockRequest): Facade.StandingBlockView => this.#call(() => this.#client.vaultStandingBlocksGet(input) as Facade.StandingBlockView),
      /** The owner lists every standing block configured for one agent, one per world, in world order. */
      list: (input: Facade.StandingBlocksRequest): Facade.StandingBlockView[] => this.#call(() => this.#client.vaultStandingBlocksList(input) as Facade.StandingBlockView[]),
    },
    workflows: {
      /** The owner saves an ordered composition of live AGENT_DEF steps at a new WORKFLOW id at revision 1; an occupied id is refused and no attempt is dispatched. */
      save: (input: Facade.WorkflowSaveRequest): Facade.WorkflowView => this.#call(() => this.#client.vaultWorkflowsSave(input) as Facade.WorkflowView),
      /** The owner reads one saved workflow, its steps, revision and fork lineage. */
      get: (input: Facade.WorkflowRequest): Facade.WorkflowView => this.#call(() => this.#client.vaultWorkflowsGet(input) as Facade.WorkflowView),
      /** The owner edits exactly the workflow revision they read; the door assigns the next revision and keeps fork lineage, and runs already admitted keep their captured steps. */
      update: (input: Facade.WorkflowUpdateRequest): Facade.WorkflowView => this.#call(() => this.#client.vaultWorkflowsUpdate(input) as Facade.WorkflowView),
      /** The owner starts one root run of a saved workflow under a briefing through the ordinary dispatch admission for every step; each step's definition revision, scope and ceiling are captured, and a retried intent key returns the same run. */
      dispatch: (input: Facade.WorkflowDispatchRequest): Facade.WorkflowRunView => this.#call(() => this.#client.vaultWorkflowsDispatch(input) as Facade.WorkflowRunView),
      /** The owner reads one workflow run by its root attempt: the captured step definitions, the active step attempt and each settled step's attempt and result. */
      status: (input: Facade.WorkflowRunRequest): Facade.WorkflowRunView => this.#call(() => this.#client.vaultWorkflowsStatus(input) as Facade.WorkflowRunView),
    },
    task_types: {
      /** The owner stores an authored task-type tree on an open team-shape fork, as a candidate; the receipt says whether it is in force. */
      pin: (input: Facade.TaskTypeTreePin): Facade.TaskTypeTreePinReceipt => this.#call(() => this.#client.vaultTaskTypesPin(input) as Facade.TaskTypeTreePinReceipt),
      /** The owner reads the task-type tree in force, or one kept tree version, for the vault or a project. */
      get: (input: Facade.TaskTypeTreeRead): Facade.TaskTypeTreeReadReply => this.#call(() => this.#client.vaultTaskTypesGet(input) as Facade.TaskTypeTreeReadReply),
    },
    tasks: {
      /** The owner force-stops every live branch of one TASK, unrefusably: each running attempt is cancelled, its live step stops, and the reply carries every branch's landing and cancellation receipts. */
      cancel_force: (input: Facade.CancelForceRequest): Facade.CancelForceReceipt => this.#call(() => this.#client.vaultTasksCancelForce(input) as Facade.CancelForceReceipt),
      linear: {
        /** One TASK's Linear issue mapping: its link, watermarks, unresolved conflicts, opt-out, mapping and dirty revisions, and its newest mirror events. */
        mapping: Object.assign((input: Facade.LinearMappingRequest): Facade.LinearMappingView => this.#call(() => this.#client.vaultTasksLinearMapping(input) as Facade.LinearMappingView), {
          /** Links, unlinks or mirrors again one TASK's Linear issue, by the TASK's owner at the mapping revision the caller read, under an intent key. */
          edit: (input: Facade.LinearMappingEdit): Facade.LinearMappingEditReceipt => this.#call(() => this.#client.vaultTasksLinearMappingEdit(input) as Facade.LinearMappingEditReceipt),
        }),
        /** One TASK's stored Linear mirror events, newest first: webhook deliveries, sent pushes, mapping and title edits, with their external evidence and receipts. */
        provenance: (input: Facade.LinearProvenanceRequest): Facade.LinearProvenancePage => this.#call(() => this.#client.vaultTasksLinearProvenance(input) as Facade.LinearProvenancePage),
      },
    },
    runs: {
      branches: {
        /** The owner reads every branch of one TASK: its lifecycle state, run status, result, typed asks and signals, and its landing, saved partial-result (resume point) and cancellation receipts. */
        get: (input: Facade.RunBranchesRequest): Facade.RunBranchesView => this.#call(() => this.#client.vaultRunsBranchesGet(input) as Facade.RunBranchesView),
      },
      /** Reads one committed model step of a Dreamer attempt by its job reference and step hash: the completion claim, the run identity it recorded and the stored response, without calling a model, spending a lease or admitting work. */
      step: (input: Facade.SettledStepRequest): Facade.SettledStepView | null => this.#call(() => this.#client.vaultRunsStep(input) as Facade.SettledStepView | null),
      /** Reads one page of a code run's committed step checkpoints and the stored replies its parked calls resumed with, without attaching, resuming or dispatching the run. */
      checkpoint: (input: Facade.CheckpointReadRequest): Facade.CheckpointView | null => this.#call(() => this.#client.vaultRunsCheckpoint(input) as Facade.CheckpointView | null),
      /** The owner reviews an explicit cross-kind set of existing changes, including child-job changes, with a content-bound review id and a derived explainer. */
      review: (input: Facade.RunReviewRequest): Facade.RunReview => this.#call(() => this.#client.vaultRunsReview(input) as Facade.RunReview),
      /** The owner approves or rejects the exact reviewed set through each kind's existing gate and keeps its ProposalOutcome and run revert handle. */
      settle: (input: Facade.RunSettleRequest): Facade.RunSettlement => this.#call(() => this.#client.vaultRunsSettle(input) as Facade.RunSettlement),
      /** The owner reads the durable cross-kind ProposalOutcome of one reviewed job and its revert handle. */
      settlement: (input: Facade.RunSettlementRequest): Facade.RunSettlement => this.#call(() => this.#client.vaultRunsSettlement(input) as Facade.RunSettlement),
    },
    consults: {
      /** The owner reads one consult TASK: its deadline and terminal register (how it ended, its result, the evidence or abstention reason, the ladder outcome and any counter TASK), as refs, never bodies. */
      get: (input: Facade.ConsultReadRequest): Facade.ConsultInspection => this.#call(() => this.#client.vaultConsultsGet(input) as Facade.ConsultInspection),
    },
    workspace: {
      /** The caller establishes a workspace preset and companion policy through its existing owner or workspace-settings power; no member or companion is minted. */
      establish: (input: Facade.WorkspacePresetRequest): Facade.WorkspacePresetReceipt => this.#call(() => this.#client.vaultWorkspaceEstablish(input) as Facade.WorkspacePresetReceipt),
      members: {
        /** A holder of the workspace AddMember power runs resumable member and companion onboarding. Bringing an existing companion requires the member's own caller proof; mailbox enrollment is separate. */
        onboard: (input: Facade.WorkspaceMemberOnboardRequest): Facade.MemberOnboardingOutcome => this.#call(() => this.#client.vaultWorkspaceMembersOnboard(input) as Facade.MemberOnboardingOutcome),
      },
      /** The owner reads the workspace house and companion roster with their actor, subject and facet refs. */
      roster: (input: Facade.WorkspaceRosterRequest): Facade.WorkspaceRosterEntry[] => this.#call(() => this.#client.vaultWorkspaceRoster(input) as Facade.WorkspaceRosterEntry[]),
      work_companion: {
        /** A workspace's work_companion policy, readable by every member it governs. */
        get: (input: Facade.WorkspaceRefRequest): Facade.WorkCompanionPolicy => this.#call(() => this.#client.vaultWorkspaceWorkCompanionGet(input) as Facade.WorkCompanionPolicy),
        /** The owner, or an Admin holding the workspace-settings power, sets a workspace's work_companion policy in person. */
        set: (input: Facade.WorkCompanionSetRequest): Facade.WorkCompanionPolicy => this.#call(() => this.#client.vaultWorkspaceWorkCompanionSet(input) as Facade.WorkCompanionPolicy),
      },
    },
    critic: {
      /** Reviews one document, design or proposed claim through the host's decision ladder, one lens at a time, and writes the verdict as the caller; nothing is applied to the target. */
      review: (input: Facade.CriticReviewSubmit): Facade.CriticReviewOutcome => this.#call(() => this.#client.vaultCriticReview(input) as Facade.CriticReviewOutcome),
    },
    rooms: {
      /** The caller's rooms its own grants admit; inside a room turn, only that room. */
      list: (): Facade.RoomEntry[] => this.#call(() => this.#client.vaultRoomsList({}) as Facade.RoomEntry[]),
      /** One page of the turns in a room this reader may read. */
      messages: (roomRef: string, after?: string, limit?: number): Facade.RoomPage => this.#call(() => this.#client.vaultRoomsMessages({room_ref: roomRef, after, limit}) as Facade.RoomPage),
      /** One page of who took part in a room or one of its threads, each with its causes and whether it may take part now. */
      participants: (input: Facade.ParticipantsRequest): Facade.ParticipantsPage => this.#call(() => this.#client.vaultRoomsParticipants(input) as Facade.ParticipantsPage),
      /** The standalone rendered view of a room's threads. */
      render: (roomRef: string): string[] => this.#call(() => this.#client.vaultRoomsRender({room_ref: roomRef}) as string[]),
      /** One page of a room's threads. */
      find: (roomRef: string, after?: string, limit?: number): Facade.RoomThreadPage => this.#call(() => this.#client.vaultRoomsFind({room_ref: roomRef, after, limit}) as Facade.RoomThreadPage),
      /** One thread of a room by its turn, even when every list omits it. */
      get: (roomRef: string, turnRef: string): Facade.RoomThread | null => this.#call(() => this.#client.vaultRoomsGet({room_ref: roomRef, turn_ref: turnRef}) as Facade.RoomThread | null),
      /** One trunk turn of a room, with the completed TASK result headers that hang under it. */
      trunk: (roomRef: string, turnRef: string): Facade.RoomTrunk => this.#call(() => this.#client.vaultRoomsTrunk({room_ref: roomRef, turn_ref: turnRef}) as Facade.RoomTrunk),
      /** One page of a thread's quote replies, grouped by the message they quote, in reply order. */
      reply_strips: (input: Facade.ReplyStripsRequest): Facade.ReplyStripsPage => this.#call(() => this.#client.vaultRoomsReplyStrips(input) as Facade.ReplyStripsPage),
      /** Claims one turn addressed to the caller for it to answer: claimed, held by another, or not addressed. */
      claim: (roomRef: string, turnRef: string): Facade.RoomClaimOutcome => this.#call(() => this.#client.vaultRoomsClaim({room_ref: roomRef, turn_ref: turnRef}) as Facade.RoomClaimOutcome),
      /** Speaks through the witness gate; on a new thread root, thread_audience explicitly limits readers to named room members and cannot be changed later. */
      speak: (input: Facade.WitnessTurn): Facade.WitnessReceipt => this.#call(() => this.#client.vaultRoomsSpeak(input) as Facade.WitnessReceipt),
      /** Files and decides a request to take part in a room or one of its threads. */
      join: (input: Facade.JoinRequest): Facade.JoinOutcome => this.#call(() => this.#client.vaultRoomsJoin(input) as Facade.JoinOutcome),
      /** The vault's owner invites a person into an ordinary room: files her join with the owner's admission yes, which holds until she answers yes through vault.rooms.consent. */
      invite: (input: Facade.JoinRequest): Facade.JoinOutcome => this.#call(() => this.#client.vaultRoomsInvite(input) as Facade.JoinOutcome),
      /** One party's answer to a join that waits on it, after which the join is decided again. */
      consent: (input: Facade.ConsentAnswer): Facade.JoinOutcome => this.#call(() => this.#client.vaultRoomsConsent(input) as Facade.JoinOutcome),
      /** Publishes an agent's offer card to join a room or one of its threads, with an optional fixed deadline for a room-wide card. */
      offer: Object.assign((input: Facade.OfferDraft): Facade.OfferCard => this.#call(() => this.#client.vaultRoomsOffer(input) as Facade.OfferCard), {
        /** The room's host answers an offer card: join, or not now. */
        answer: (input: Facade.OfferSettleOfferAnswerRequest): Facade.OfferSettlement => this.#call(() => this.#client.vaultRoomsOfferAnswer(input) as Facade.OfferSettlement),
        /** Someone in the room casts an advisory join or not-now vote on an open room-wide offer card, which keeps it open; only the host's answer admits. */
        vote: (input: Facade.OfferVoteRequest): Facade.OfferCard => this.#call(() => this.#client.vaultRoomsOfferVote(input) as Facade.OfferCard),
        /** The room's owner or delegated host reopens its aged-out room-wide offer card. */
        reopen: (input: Facade.OfferReopenRequest): Facade.OfferCard => this.#call(() => this.#client.vaultRoomsOfferReopen(input) as Facade.OfferCard),
      }),
      /** One page of the current offer cards in a room or one of its threads. */
      offers: (input: Facade.OffersRequest): Facade.OffersPage => this.#call(() => this.#client.vaultRoomsOffers(input) as Facade.OffersPage),
      /** Who hosts a room now, and the caller's own speaking role there. */
      host: Object.assign((input: Facade.RoomHostRequest): Facade.RoomStanding => this.#call(() => this.#client.vaultRoomsHost(input) as Facade.RoomStanding), {
        /** Pins an agent as a room's host, or clears the stored host, pin or handoff. */
        pin: (input: Facade.RoomHostPin): Facade.RoomStanding => this.#call(() => this.#client.vaultRoomsHostPin(input) as Facade.RoomStanding),
        /** The room's current host hands the hosting duty to another agent that may host. */
        hand: (input: Facade.RoomHostHand): Facade.RoomStanding => this.#call(() => this.#client.vaultRoomsHostHand(input) as Facade.RoomStanding),
      }),
      /** A room's effective sharing scope and why it is clamped, for a member of the room. */
      sharing: (input: Facade.RoomRefRequest): Facade.RoomSharingView => this.#call(() => this.#client.vaultRoomsSharing(input) as Facade.RoomSharingView),
    },
    conversations: {
      turn: {
        /** Queues generation that resumes an incomplete assistant reply from exactly its saved text. */
        continue: (input: Facade.TurnActionRequest): Facade.TurnActionReceipt => this.#call(() => this.#client.vaultConversationsTurnContinue(input) as Facade.TurnActionReceipt),
        /** Queues a new answer to the user turn an assistant turn answered; the old reply stays. */
        retry: (input: Facade.TurnActionRequest): Facade.TurnActionReceipt => this.#call(() => this.#client.vaultConversationsTurnRetry(input) as Facade.TurnActionReceipt),
      },
      /** Creates a conversation; a body naming members also authors its membership ledger, creator and role grants as the caller. */
      create: (input: Facade.ConversationCreateInput): Facade.CoreEntityWriteReceipt => this.#call(() => this.#client.vaultConversationsCreate(input) as Facade.CoreEntityWriteReceipt),
      turns: {
        /** Puts one TURN under a conversation, with its text index and checked ChildOf edge, in one batch; the host lands the turn once. */
        create: (input: Facade.ConversationTurnCreateInput): Facade.CoreEntityWriteReceipt => this.#call(() => this.#client.vaultConversationsTurnsCreate(input) as Facade.CoreEntityWriteReceipt),
      },
      records: {
        /** Appends one TURN to a conversation's DAG, bylined the caller, with its topology in one transaction; the host lands the turn once. */
        append: (input: Facade.DagRecordAppendInput): Facade.DagRecordAppendReceipt => this.#call(() => this.#client.vaultConversationsRecordsAppend(input) as Facade.DagRecordAppendReceipt),
      },
    },
    models: {
      catalog: {
        /** Refreshes priced model catalog rows and external-score diffs under an immutable revision; changes no role binding. */
        refresh: (input: Facade.ModelCatalogRefresh): Facade.ModelCatalogRevision => this.#call(() => this.#client.vaultModelsCatalogRefresh(input) as Facade.ModelCatalogRevision),
        /** Reads a pinned model catalog revision with its prices, backend offers and score evidence. */
        get: (input: Facade.ModelCatalogGet): Facade.ModelCatalogRevision => this.#call(() => this.#client.vaultModelsCatalogGet(input) as Facade.ModelCatalogRevision),
        /** Diffs two immutable model catalog revisions, including prices, scores and retired offers. */
        diff: (input: Facade.ModelCatalogDiffRequest): Facade.ModelCatalogDiff => this.#call(() => this.#client.vaultModelsCatalogDiff(input) as Facade.ModelCatalogDiff),
      },
      trials: {
        /** Nominates a question-specific held-out trial at a catalog revision using the caller own labels; external scores grant no authority. */
        nominate: (input: Facade.ModelTrialNominate): Facade.ModelTrialView => this.#call(() => this.#client.vaultModelsTrialsNominate(input) as Facade.ModelTrialView),
        /** Reads a retained held-out trial, its catalog revision, independent labels and measured cost. */
        get: (input: Facade.ModelTrialRef): Facade.ModelTrialView => this.#call(() => this.#client.vaultModelsTrialsGet(input) as Facade.ModelTrialView),
        /** Approves exploration for a held-out model trial only; leaves its role binding unchanged. */
        approve: (input: Facade.ModelTrialRef): Facade.ModelTrialView => this.#call(() => this.#client.vaultModelsTrialsApprove(input) as Facade.ModelTrialView),
        /** Runs both pinned backend arms through decide and normal inference leases on the original held-out source frontier; records real usage and cost. */
        run: (input: Facade.ModelTrialRef): Facade.ModelTrialView => this.#call(() => this.#client.vaultModelsTrialsRun(input) as Facade.ModelTrialView),
        /** Completes a measured model trial with a sufficiency card bound to its exact set and measurements; only produces an offer. */
        complete: (input: Facade.ModelTrialComplete): Facade.ModelTrialView => this.#call(() => this.#client.vaultModelsTrialsComplete(input) as Facade.ModelTrialView),
      },
      bindings: {
        /** Proposes a role model change from a sufficient held-out trial, retaining catalog revision and real trial cost without activating it. */
        propose: (input: Facade.ModelBindingPropose): Facade.ModelBindingProposal => this.#call(() => this.#client.vaultModelsBindingsPropose(input) as Facade.ModelBindingProposal),
        /** Reads an owner-reviewed model role-binding proposal and its pinned trial evidence. */
        get: (input: Facade.ModelBindingProposalRef): Facade.ModelBindingProposal => this.#call(() => this.#client.vaultModelsBindingsGet(input) as Facade.ModelBindingProposal),
        /** Reads the currently active manifest binding for a model role. */
        read: (input: Facade.ModelBindingRead): Facade.ModelBinding => this.#call(() => this.#client.vaultModelsBindingsRead(input) as Facade.ModelBinding),
        /** Accepts a pending model role-binding proposal as the owner after transaction-local incumbent, catalog and trial checks. */
        accept: (input: Facade.ModelBindingAccept): Facade.ModelBindingProposal => this.#call(() => this.#client.vaultModelsBindingsAccept(input) as Facade.ModelBindingProposal),
        /** Denies a pending model role-binding proposal as the owner without changing the incumbent manifest binding. */
        deny: (input: Facade.ModelBindingProposalRef): Facade.ModelBindingProposal => this.#call(() => this.#client.vaultModelsBindingsDeny(input) as Facade.ModelBindingProposal),
      },
    },
    voices: {
      packs: {
        /** The owner banks one immutable reference pack of their own voice: the first captured or designed pack makes its identity, a captured pack cites their current render grant, and a retry of the same pack is a no-op. */
        put: (input: Facade.VoiceBankPackPutRequest): Facade.VoiceBankPackReceipt => this.#call(() => this.#client.vaultVoicesPacksPut(input) as Facade.VoiceBankPackReceipt),
      },
      /** The owner records their render decision on their own voice: a grant names the farthest locality its refs may reach; a withdrawal drops each target clone, deleted at its vendor best effort, and keeps the packs. */
      render_consent: (input: Facade.VoiceRenderConsentRequest): Facade.VoiceRenderConsentReceipt => this.#call(() => this.#client.vaultVoicesRenderConsent(input) as Facade.VoiceRenderConsentReceipt),
      targets: {
        /** The owner's own voice cloned at a configured hosted target from its banked refs, or that target's current clone. The render consent must reach the target's locality before any provider call. */
        provision: (input: Facade.VoiceTargetProvisionRequest): Facade.VoiceTargetReceipt => this.#call(() => this.#client.vaultVoicesTargetsProvision(input) as Facade.VoiceTargetReceipt),
        /** The owner drops a target's clone of their own voice, deleted at its vendor best effort. The identity and its packs stay. */
        evict: (input: Facade.VoiceTargetEvictRequest): Facade.VoiceTargetEvictReceipt => this.#call(() => this.#client.vaultVoicesTargetsEvict(input) as Facade.VoiceTargetEvictReceipt),
      },
      /** The owner inspects their own voice as the bank holds it for one configured hosted target: identity, pack metadata without audio or transcripts, the current render decision and the target's current clone. */
      inspect: (input: Facade.VoiceBankInspectRequest): Facade.VoiceBankInspection => this.#call(() => this.#client.vaultVoicesInspect(input) as Facade.VoiceBankInspection),
    },
    graph: {
      ask: (input: Facade.GraphAskRequest): Facade.GraphAskOutcome => this.#call(() => this.#client.vaultGraphAsk(input) as Facade.GraphAskOutcome),
    },
    questions: {
      create: (input: Facade.QuestionCreateRequest): Facade.QuestionRecord => this.#call(() => this.#client.vaultQuestionsCreate(input) as Facade.QuestionRecord),
      edit: (input: Facade.QuestionEditRequest): Facade.QuestionRecord => this.#call(() => this.#client.vaultQuestionsEdit(input) as Facade.QuestionRecord),
      pause: (input: Facade.QuestionPauseRequest): Facade.QuestionPaused => this.#call(() => this.#client.vaultQuestionsPause(input) as Facade.QuestionPaused),
      backfill: (input: Facade.QuestionBackfillRequest): Facade.ScheduledBackfill => this.#call(() => this.#client.vaultQuestionsBackfill(input) as Facade.ScheduledBackfill),
      read: (input: Facade.QuestionReadRequest): Facade.QuestionRecord | null => this.#call(() => this.#client.vaultQuestionsRead(input) as Facade.QuestionRecord | null),
      answers: (input: Facade.QuestionAnswersRequest): Facade.QuestionAnswer[] => this.#call(() => this.#client.vaultQuestionsAnswers(input) as Facade.QuestionAnswer[]),
      /** Refreshes the caller's standing question by hand, now, over every unit its current version covers, on the host's ladder as the standing pump answers it. */
      refresh: (input: Facade.QuestionRefreshRequest): Facade.AnswerRecord[] => this.#call(() => this.#client.vaultQuestionsRefresh(input) as Facade.AnswerRecord[]),
      /** Reads the caller's standing question outcome labels and calibration pairs, each pairing an answer prediction and probability with its mapped label. */
      outcomes: Object.assign((input: Facade.QuestionOutcomesRequest): Facade.QuestionOutcomes => this.#call(() => this.#client.vaultQuestionsOutcomes(input) as Facade.QuestionOutcomes), {
        /** Projects the caller's standing question bound outcomes over current facts, idempotently binding each admissible fact in an answer horizon as its label. */
        project: (input: Facade.QuestionOutcomesProjectRequest): Facade.QuestionOutcomesProjected => this.#call(() => this.#client.vaultQuestionsOutcomesProject(input) as Facade.QuestionOutcomesProjected),
      }),
      /** Reads the caller's standing question scheduling head: its current version, paused state, last refresh and any failed-refresh hold. */
      schedule: (input: Facade.QuestionScheduleRequest): Facade.QuestionScheduleHead | null => this.#call(() => this.#client.vaultQuestionsSchedule(input) as Facade.QuestionScheduleHead | null),
    },
    decisions: {
      bands: {
        /** The owner reads a question version's effective band on the running host; an unlearned row stays shadow at the supplied seed and version zero. */
        read: (input: Facade.DecisionBandReadRequest): Facade.LearnedBand => this.#call(() => this.#client.vaultDecisionsBandsRead(input) as Facade.LearnedBand),
        /** The owner declares a question version's learned band in shadow mode on the running host, advancing its band version for that reversibility. */
        learn: (input: Facade.DecisionBandLearnRequest): Facade.LearnedBand => this.#call(() => this.#client.vaultDecisionsBandsLearn(input) as Facade.LearnedBand),
        /** The owner enforces an already learned question-version and reversibility band on the running host without widening any decision dial or authority. */
        enforce: (input: Facade.DecisionBandEnforceRequest): Facade.LearnedBand => this.#call(() => this.#client.vaultDecisionsBandsEnforce(input) as Facade.LearnedBand),
      },
      asks: {
        answer: (input: Facade.DecisionAskAnswerRequest): Facade.DecisionAsk => this.#call(() => this.#client.vaultDecisionsAsksAnswer(input) as Facade.DecisionAsk),
        climb: (input: Facade.DecisionAskClimbRequest): Facade.ResolvedRole | null => this.#call(() => this.#client.vaultDecisionsAsksClimb(input) as Facade.ResolvedRole | null),
      },
    },
    /** Commits claims through the gate, each element its own write; each answers its landed receipt, or its typed refusal and refusal receipt when nothing of it persisted. */
    commit: (input: Facade.ScopedCommitRequest): Facade.CommitOutcome[] => this.#call(() => this.#client.vaultCommit(input) as Facade.CommitOutcome[]),
    /** Commits one claim through the gate, the same as vault.claims.upsert. */
    remember: (input: Facade.ClaimInput): Facade.CommitReceipt => this.#call(() => this.#client.vaultRemember(input) as Facade.CommitReceipt),
    /** Retracts claims by exact claim or by subject and predicate; never a hard delete. */
    forget: (input: Facade.ForgetRequest): Facade.CommitReceipt[] => this.#call(() => this.#client.vaultForget(input) as Facade.CommitReceipt[]),
    booking: {
      /** Lists ranked public slots on a live published booking page as the caller, through the shared booking admission and solver without exposing busy sources. */
      availability: (input: Facade.BookingAvailabilityRequest): Facade.BookingOperationResponse => this.#call(() => this.#client.vaultBookingAvailability(input) as Facade.BookingOperationResponse),
      /** Holds or confirms a real slot on a live published booking page as the caller, through the shared admission and home-node lifecycle with opaque session-bound tokens. */
      book: (input: Facade.BookingBookRequest): Facade.BookingOperationResponse => this.#call(() => this.#client.vaultBookingBook(input) as Facade.BookingOperationResponse),
      /** Moves a booking on a live published page using its reschedule token, preserving EVENT and UID and replaying without another passport revision. */
      reschedule: (input: Facade.BookingRescheduleRequest): Facade.BookingOperationResponse => this.#call(() => this.#client.vaultBookingReschedule(input) as Facade.BookingOperationResponse),
      /** Cancels a booking on a live published page using its cancel token, preserving EVENT and UID and replaying without another passport revision. */
      cancel: (input: Facade.BookingCancelRequest): Facade.BookingOperationResponse => this.#call(() => this.#client.vaultBookingCancel(input) as Facade.BookingOperationResponse),
      /** Parses one scheduling constraint on a live published booking page as the caller, returning public slot controls, an email continuation or a deflect; this never holds or confirms a booking. */
      constraint_turn: (input: Facade.BookingConstraintTurnRequest): Facade.BookingConstraintTurnResponse => this.#call(() => this.#client.vaultBookingConstraintTurn(input) as Facade.BookingConstraintTurnResponse),
      /** The owner discovers the opaque token for an existing configured booking page; this does not publish the page or grant booking authority. */
      page_token: (input: Facade.BookingPageTokenRequest): Facade.BookingPageTokenResponse => this.#call(() => this.#client.vaultBookingPageToken(input) as Facade.BookingPageTokenResponse),
    },
    calendar: {
      passports: {
        /** Reads the admitted passport head for one EVENT, system and UID through the caller scoped-read gate, including sequence, semantic hash, direction and presence. */
        read: (input: Facade.CalendarPassportReadRequest): Facade.ScopedReadResult<Facade.CalendarPassportRevision | null> => this.#call(() => this.#client.vaultCalendarPassportsRead(input) as Facade.ScopedReadResult<Facade.CalendarPassportRevision | null>),
        /** Reads recorded passport revisions oldest first for one EVENT, system and UID, retaining explicit approval and lifecycle under the caller recorded-read gate. */
        history: (input: Facade.CalendarPassportReadRequest): Facade.ScopedReadResult<Facade.CalendarPassportRevision[]> => this.#call(() => this.#client.vaultCalendarPassportsHistory(input) as Facade.ScopedReadResult<Facade.CalendarPassportRevision[]>),
      },
      /** Creates a native or evidence-linked dreamer EVENT as the caller, with atomic projector-recorded origin and engine-stamped recorded time. */
      create: (input: Facade.CalendarEventCreateRequest): Facade.CalendarEventCreated => this.#call(() => this.#client.vaultCalendarCreate(input) as Facade.CalendarEventCreated),
      ics: {
        /** The owner imports one exact uploaded ICS version through the existing UID diff and imported-claim gate; the receipt exposes pending claim refs without granting consent. */
        import: (input: Facade.CalendarIcsImportRequest): Facade.CalendarIcsImportReceipt => this.#call(() => this.#client.vaultCalendarIcsImport(input) as Facade.CalendarIcsImportReceipt),
      },
      /** Expands an admitted stored master inside an inclusive UTC window under the caller's read scope, preserving UID and original-start identities and masking detached exceptions. */
      occurrences: (input: Facade.CalendarOccurrencesRequest): Facade.ScopedReadResult<Facade.CalendarOccurrenceView[]> => this.#call(() => this.#client.vaultCalendarOccurrences(input) as Facade.ScopedReadResult<Facade.CalendarOccurrenceView[]>),
      instances: {
        /** The owner applies one uploaded detached-instance amendment matching its UID, original start and new interval, through the import gate without changing other instances. */
        move: (input: Facade.CalendarInstanceMoveRequest): Facade.CalendarIcsImportReceipt => this.#call(() => this.#client.vaultCalendarInstancesMove(input) as Facade.CalendarIcsImportReceipt),
      },
      /** Reads one calendar EVENT under the caller's scoped read, with its mandatory narrowing receipt. */
      read: (input: Facade.CalendarReadRequest): Facade.ScopedReadResult<Facade.CalendarEventView | null> => this.#call(() => this.#client.vaultCalendarRead(input) as Facade.ScopedReadResult<Facade.CalendarEventView | null>),
      /** Searches calendar EVENTs by calendar, inclusive UTC range and name under the caller's scoped read, with its mandatory narrowing receipt. */
      search: (input: Facade.CalendarSearchRequest): Facade.ScopedReadResult<Facade.CalendarEventView[]> => this.#call(() => this.#client.vaultCalendarSearch(input) as Facade.ScopedReadResult<Facade.CalendarEventView[]>),
      /** Projects source-redacted busy occupancy over an inclusive UTC range under the caller's scoped read, as half-open intervals with a mandatory narrowing receipt. */
      freebusy: (input: Facade.CalendarFreebusyRequest): Facade.ScopedReadResult<Facade.CalendarFreebusyDto> => this.#call(() => this.#client.vaultCalendarFreebusy(input) as Facade.ScopedReadResult<Facade.CalendarFreebusyDto>),
      /** Builds a fresh caller-scoped meeting PrepPack with commitments first and a 250-word ceiling, or deliberately returns no pack. */
      prep: (input: Facade.CalendarMeetingRequest): Facade.ScopedReadResult<Facade.PrepPack | null> => this.#call(() => this.#client.vaultCalendarPrep(input) as Facade.ScopedReadResult<Facade.PrepPack | null>),
      /** Reads the caller-visible meeting outcome and its recorded basis; silence projects to unknown and never to held or no_show. */
      event_outcome: (input: Facade.CalendarMeetingRequest): Facade.ScopedReadResult<Facade.CalendarEventOutcome | null> => this.#call(() => this.#client.vaultCalendarEventOutcome(input) as Facade.ScopedReadResult<Facade.CalendarEventOutcome | null>),
      check_in: {
        /** Observes whether a meeting check-in is due under owner proof, live evidence and the engine clock, without advancing time or recording an outcome. */
        due: (input: Facade.CalendarMeetingRequest): Facade.ScopedReadResult<Facade.CalendarCheckInDue | null> => this.#call(() => this.#client.vaultCalendarCheckInDue(input) as Facade.ScopedReadResult<Facade.CalendarCheckInDue | null>),
        /** The owner answers a due check-in as held, no_show or rescheduled; the caller cannot assert machine evidence or replace it. */
        answer: (input: Facade.CalendarCheckInRequest): Facade.CalendarCheckInReceipt => this.#call(() => this.#client.vaultCalendarCheckInAnswer(input) as Facade.CalendarCheckInReceipt),
      },
      outcome_policy: {
        /** Reads the owner-configured post-meeting grace policy, including the default 1800 seconds when no override exists. */
        get: (input: Facade.EmptyRequest = {}): Facade.CalendarOutcomePolicy => this.#call(() => this.#client.vaultCalendarOutcomePolicyGet(input) as Facade.CalendarOutcomePolicy),
        /** Sets the post-meeting grace in real seconds under owner proof, without changing event times or minting attendance evidence. */
        set: (input: Facade.CalendarOutcomePolicy): Facade.CalendarOutcomePolicy => this.#call(() => this.#client.vaultCalendarOutcomePolicySet(input) as Facade.CalendarOutcomePolicy),
      },
      transcript: {
        /** Ingests verified uploaded UTF-8 transcript bytes as a closed SESSION with ordered TURNs; an optional meeting link earns a machine outcome through the caller gate. */
        ingest: (input: Facade.TranscriptFileDropInput): Facade.TranscriptIngestOutcome => this.#call(() => this.#client.vaultCalendarTranscriptIngest(input) as Facade.TranscriptIngestOutcome),
      },
    },
    /** Deletes one entity under a named reason; an owner verb that only a verified human may call. */
    delete: (input: Facade.SafeDeleteRequest): Facade.DeleteReceipt => this.#call(() => this.#client.vaultDelete(input) as Facade.DeleteReceipt),
    writes: {
      critical_confirm: {
        /** The owner reads a candidate's exact critical confirmation, with its nonce, effect digest, policy frontier and deadline. */
        pending: (input: Facade.CriticalWriteConfirmPendingRequest): Facade.CriticalWriteConfirmPending | null => this.#call(() => this.#client.vaultWritesCriticalConfirmPending(input) as Facade.CriticalWriteConfirmPending | null),
        /** The owner clears exactly the nonce and frontier-bound critical claim confirmation and receives its fold-verified signed receipt. */
        clear: (input: Facade.CriticalWriteConfirmRequest): Facade.CriticalWriteConfirmSettlement => this.#call(() => this.#client.vaultWritesCriticalConfirmClear(input) as Facade.CriticalWriteConfirmSettlement),
        /** The owner declines exactly the nonce and frontier-bound critical claim confirmation and receives its fold-verified signed receipt. */
        decline: (input: Facade.CriticalWriteConfirmRequest): Facade.CriticalWriteConfirmSettlement => this.#call(() => this.#client.vaultWritesCriticalConfirmDecline(input) as Facade.CriticalWriteConfirmSettlement),
        /** The owner reads a critical confirmation's existing signed authority receipt without settling or rewriting the claim. */
        receipt: (input: Facade.CriticalWriteConfirmReceiptRequest): Facade.CriticalWriteConfirmReceipt => this.#call(() => this.#client.vaultWritesCriticalConfirmReceipt(input) as Facade.CriticalWriteConfirmReceipt),
      },
      /** Gated writes parked for consent, newest first. */
      pending: (input: Facade.ReceiptsRequest): Facade.PendingWrite[] => this.#call(() => this.#client.vaultWritesPending(input) as Facade.PendingWrite[]),
    },
    /** Hydrates short refs or hex ids to full entity views, with the read's receipt. */
    hydrate: (input: Facade.HydrateRequest): Facade.ScopedReadResult<Facade.EntityView[]> => this.#call(() => this.#client.vaultHydrate(input) as Facade.ScopedReadResult<Facade.EntityView[]>),
    /** Reads one entity as a typed view, or none when absent or withheld; the receipt says which. */
    get: (input: Facade.EntityRequest): Facade.ScopedReadResult<Facade.EntityView | null> => this.#call(() => this.#client.vaultGet(input) as Facade.ScopedReadResult<Facade.EntityView | null>),
    refs: {
      /** The bounded preview of one record ref, read through the caller's own scope; unreadable and missing look the same. */
      resolve: (input: Facade.ResolveRecordRefRequest): Facade.ScopedReadResult<Facade.RecordRefPreview> => this.#call(() => this.#client.vaultRefsResolve(input) as Facade.ScopedReadResult<Facade.RecordRefPreview>),
      /** A text, the texts a read surface returned, or a turn's readable messages, as typed spans whose record links resolve under the caller's own read. */
      links: (input: Facade.RecordLinksRequest): Facade.RecordLinks => this.#call(() => this.#client.vaultRefsLinks(input) as Facade.RecordLinks),
    },
    vectors: {
      /** Supplies one full-width vector for a readable record as the authenticated owner; the existing write gate checks model, transform, width, revision staging and graph updates atomically. */
      put: (input: Facade.VectorPutRequest): Facade.VectorPutReceipt => this.#call(() => this.#client.vaultVectorsPut(input) as Facade.VectorPutReceipt),
    },
    /** The weighted-edge neighbourhood of one entity, filtered by edge kind and minimum weight. */
    neighbors: (input: Facade.NeighborsRequest): Facade.ScopedReadResult<Facade.NeighborHit[]> => this.#call(() => this.#client.vaultNeighbors(input) as Facade.ScopedReadResult<Facade.NeighborHit[]>),
    structural: {
      /** Puts one structural record with its text-index fields and outgoing edges, in one atomic batch; claims go through commit. */
      put: (input: Facade.StructuralPutInput): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultStructuralPut(input) as Facade.EntityRefReceipt),
    },
    habits: {
      /** Appends one immutable check-in under a Habit TASK. */
      checkin: (input: Facade.HabitCheckinInput): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultHabitsCheckin(input) as Facade.EntityRefReceipt),
    },
    productivity: {
      /** Creates one inert Goal, Milestone or Habit TASK under an optional checked parent; an illegal nesting refuses the whole write. */
      create: (input: Facade.ProductivityCreateRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultProductivityCreate(input) as Facade.EntityRefReceipt),
      /** The role-labelled TASK tree under one root, read through the caller's lane, with each Habit's derived streak counters. */
      tree: (input: Facade.ProductivityTreeRequest): Facade.ScopedReadResult<Facade.ProductivityTree | null> => this.#call(() => this.#client.vaultProductivityTree(input) as Facade.ScopedReadResult<Facade.ProductivityTree | null>),
    },
    esign: {
      /** Drafts a signing document on PDF artifacts the caller already holds, as the caller; sending it is its own gated act. */
      create: (input: Facade.EsignCreateRequest): Facade.EsignDraftView => this.#call(() => this.#client.vaultEsignCreate(input) as Facade.EsignDraftView),
      /** Reads one signing document as its trail folds: its status, recipients, filled fields and its hash-chained audit trail. */
      get: (input: Facade.EsignGetRequest): Facade.EsignDocumentView => this.#call(() => this.#client.vaultEsignGet(input) as Facade.EsignDocumentView),
      links: {
        /** The vault owner mints the signing links of a drafted document and receives each new one once, to deliver to its recipient. */
        issue: (input: Facade.EsignLinksIssueRequest): Facade.EsignLinksView => this.#call(() => this.#client.vaultEsignLinksIssue(input) as Facade.EsignLinksView),
      },
      /** Sends a drafted signing document to its recipients through the outbound gate, as the caller; an agent sends only within its principal envelope. */
      send_for_signature: (input: Facade.EsignDispatchRequest): Facade.EsignDispatchView => this.#call(() => this.#client.vaultEsignSendForSignature(input) as Facade.EsignDispatchView),
      /** Reminds the recipients whose turn it is to sign a pending document, through the outbound gate, as the caller. */
      remind: (input: Facade.EsignDispatchRequest): Facade.EsignDispatchView => this.#call(() => this.#client.vaultEsignRemind(input) as Facade.EsignDispatchView),
      /** Withdraws a drafted or pending signing document unsealed and tells its recipients why, through the outbound gate, as the caller. */
      void: (input: Facade.EsignVoidRequest): Facade.EsignDispatchView => this.#call(() => this.#client.vaultEsignVoid(input) as Facade.EsignDispatchView),
      signing: {
        /** One recipient ceremony act under the signing capability in the body: load the page, save a field, complete with consent, or reject; an agent caller makes Complete an automated sign act. */
        act: (input: Facade.EsignSigningRequest): Facade.SigningOutcome => this.#call(() => this.#client.vaultEsignSigningAct(input) as Facade.SigningOutcome),
        /** One ceremony item under its signing capability, as base64 PDF bytes: the pinned original while signing, the hash-checked sealed output after sealing. */
        pdf: (input: Facade.EsignSigningPdfRequest): Facade.EsignSigningPdfView => this.#call(() => this.#client.vaultEsignSigningPdf(input) as Facade.EsignSigningPdfView),
        /** Stores one signature image bound to the signing capability recipient and answers the ref a signature field value names. */
        image: (input: Facade.EsignSigningImageRequest): Facade.EsignSigningImageView => this.#call(() => this.#client.vaultEsignSigningImage(input) as Facade.EsignSigningImageView),
        /** Reads back one stored signature image under the signing capability that uploaded it, as base64 bytes. */
        signature: (input: Facade.EsignSigningSignatureRequest): Facade.EsignSigningSignatureView => this.#call(() => this.#client.vaultEsignSigningSignature(input) as Facade.EsignSigningSignatureView),
      },
      seal: {
        /** Where one signing document seal task stands: its folded status, every seal attempt receipt the queue holds for it, and its sealed manifest once one attempt sealed it. */
        get: (input: Facade.EsignSealGetRequest): Facade.EsignSealView => this.#call(() => this.#client.vaultEsignSealGet(input) as Facade.EsignSealView),
      },
    },
    /** Commits up to 256 core entity puts atomically, at the grade of the credential that sent them; an embedded handle commits below owner grade. */
    batch: (input: Facade.CoreBatchWriteInput): Facade.CoreBatchWriteReceipt => this.#call(() => this.#client.vaultBatch(input) as Facade.CoreBatchWriteReceipt),
    consolidation: {
      /** Enqueues one consolidation attempt and returns its durable job reference. */
      enqueue: (input: Facade.ConsolidationEnqueueRequest): Facade.DreamerAttemptRef => this.#call(() => this.#client.vaultConsolidationEnqueue(input) as Facade.DreamerAttemptRef),
      /** Reads the status of one consolidation attempt by its durable job reference. */
      status: (input: Facade.ConsolidationStatusRequest): Facade.DreamerAttemptView | null => this.#call(() => this.#client.vaultConsolidationStatus(input) as Facade.DreamerAttemptView | null),
      home: {
        /** The owner reads the elected MACRO home this node's runner holds and this install's own sync client id, without electing, minting or waking anything. */
        get: (input: Facade.EmptyRequest = {}): Facade.ConsolidationHomeView => this.#call(() => this.#client.vaultConsolidationHomeGet(input) as Facade.ConsolidationHomeView),
      },
      /** The owner reads one consolidation job's retry chain back to its root and a page of its committed step refs, without resuming, leasing or calling a model. */
      lineage: (input: Facade.ConsolidationLineageRequest): Facade.ConsolidationLineageView | null => this.#call(() => this.#client.vaultConsolidationLineage(input) as Facade.ConsolidationLineageView | null),
      /** Promotes typed generated candidates in an admitted Dreamer attempt through its host-stamped writer and checker, returning retained evidence and refusals. */
      promote: (input: Facade.ConsolidationPromoteRequest): Facade.ConsolidationPromotion => this.#call(() => this.#client.vaultConsolidationPromote(input) as Facade.ConsolidationPromotion),
      /** Pins reference-only evidence for six-axis consolidation buckets at one owner-scoped ledger revision. Hashes, lineage taint and source eligibility are derived by the root, never accepted from children. */
      pin: (input: Facade.ConsolidationPinRequest): Facade.ConsolidationRootAccounting => this.#call(() => this.#client.vaultConsolidationPin(input) as Facade.ConsolidationRootAccounting),
      /** Records immutable child judgements and reference sets against an existing root pin, in any completion order, and accounts source-plus-hash corroboration without merging projects. Does not settle claims. */
      frontier: (input: Facade.ConsolidationFrontierRequest): Facade.ConsolidationRootAccounting => this.#call(() => this.#client.vaultConsolidationFrontier(input) as Facade.ConsolidationRootAccounting),
      /** Reads the original root revision, source hashes, ancestor and edge provenance taint, zero-signal exclusions and per-bucket corroboration accounting under current owner read authority. */
      accounting: (input: Facade.ConsolidationAccountingRequest): Facade.ConsolidationRootAccounting => this.#call(() => this.#client.vaultConsolidationAccounting(input) as Facade.ConsolidationRootAccounting),
      /** Reads exact generated-claim evidence, source lineage and separate consolidation, corroboration and effector-evidence eligibility as the owner. */
      evidence: (input: Facade.ConsolidationEvidenceRequest): Facade.ScopedReadResult<Facade.ConsolidationEvidenceSource[]> => this.#call(() => this.#client.vaultConsolidationEvidence(input) as Facade.ScopedReadResult<Facade.ConsolidationEvidenceSource[]>),
    },
    sieve: {
      /** Read the original TURN identity, sieve reading digest, evidence cursor and owed/continuing state as the owner. */
      evidence: Object.assign((input: Facade.SieveEvidenceRequest): Facade.SieveEvidenceView => this.#call(() => this.#client.vaultSieveEvidence(input) as Facade.SieveEvidenceView), {
        /** Replay the same stored TURN through its owed sieve read under the owner proof; preserve every ingress identity and let the existing digest check decide whether evidence changed. */
        replay: (input: Facade.SieveEvidenceRequest): Facade.SieveEvidenceView => this.#call(() => this.#client.vaultSieveEvidenceReplay(input) as Facade.SieveEvidenceView),
      }),
      /** Read the shared Dreamer/Coach wake policy, the production scheduler cadence receipt and pending recipe evidence ranges; do not tick, enqueue or call a model. */
      cadence: (input: Facade.WakeCadenceRequest): Facade.WakeCadenceView => this.#call(() => this.#client.vaultSieveCadence(input) as Facade.WakeCadenceView),
      /** Page shared-scheduler root receipts and all Dreamer/Coach descendants, including exact conclusion identities, authority receipts, terminal states and durable parks. */
      settlements: Object.assign((input: Facade.WakeSettlementsRequest): Facade.WakeSettlementsPage => this.#call(() => this.#client.vaultSieveSettlements(input) as Facade.WakeSettlementsPage), {
        /** Read one shared-scheduler root and its complete descendant settlement; a completed dispatcher never implies its children completed. */
        get: (input: Facade.WakeSettlementRequest): Facade.WakeSettlementView | null => this.#call(() => this.#client.vaultSieveSettlementsGet(input) as Facade.WakeSettlementView | null),
      }),
      /** The owner reads one ordered page of the sieve interest queue: span handles, source and range refs, kind, score and the rungs still owed. */
      queue: (input: Facade.SievePageRequest): Facade.SieveQueuePage => this.#call(() => this.#client.vaultSieveQueue(input) as Facade.SieveQueuePage),
      /** The owner reads the sieve retained original span readings, which spending never removes, for a later weave over evidence. */
      retained: (input: Facade.SievePageRequest): Facade.SieveRetainedPage => this.#call(() => this.#client.vaultSieveRetained(input) as Facade.SieveRetainedPage),
      /** The owner reads consumed-span receipts: each span nightly spending consumed once, its source ref and the attempt that spent it. */
      receipts: (input: Facade.SievePageRequest): Facade.SieveReceiptsPage => this.#call(() => this.#client.vaultSieveReceipts(input) as Facade.SieveReceiptsPage),
      /** The owner reads the sieve policy row: how much one pass reads, each kind interest, rule confidences and the uncertain band. */
      policy: Object.assign((input: Facade.SievePolicyRequest): Facade.SievePolicy => this.#call(() => this.#client.vaultSievePolicy(input) as Facade.SievePolicy), {
        /** The owner replaces the sieve policy row; the new row scores spans read after it and queued spans keep the score they were given. */
        set: (input: Facade.SievePolicySetRequest): Facade.SievePolicy => this.#call(() => this.#client.vaultSievePolicySet(input) as Facade.SievePolicy),
      }),
      /** The owner reads the wake recipe policy row: per-receipt span and child budgets, rung retry and the sampled audit settings. */
      recipe_policy: Object.assign((input: Facade.SievePolicyRequest): Facade.WakeRecipePolicy => this.#call(() => this.#client.vaultSieveRecipePolicy(input) as Facade.WakeRecipePolicy), {
        /** The owner replaces the wake recipe policy row; unspent interest stays queued and only later receipts spend under the new budgets. */
        set: (input: Facade.SieveRecipePolicySetRequest): Facade.WakeRecipePolicy => this.#call(() => this.#client.vaultSieveRecipePolicySet(input) as Facade.WakeRecipePolicy),
      }),
      /** The owner reads one wake-budget lease counter without creating it: total, remaining and reserved units by its budget id. */
      lease: Object.assign((input: Facade.SieveLeaseRequest): Facade.SieveLeaseView => this.#call(() => this.#client.vaultSieveLease(input) as Facade.SieveLeaseView), {
        /** The owner refills one wake-budget lease to a replacement total; spent and reserved units keep their claim and replay adds nothing twice. */
        refill: (input: Facade.SieveLeaseRefillRequest): Facade.SieveLeaseView => this.#call(() => this.#client.vaultSieveLeaseRefill(input) as Facade.SieveLeaseView),
      }),
    },
    memory: {
      /** Queues typed extraction of witnessed turns on the configured production Dreamer role; returns durable partition job refs, never caller-authored candidates. */
      signal_extraction: Object.assign((input: Facade.SignalExtractionRequest): Facade.SignalExtractionTicket => this.#call(() => this.#client.vaultMemorySignalExtraction(input) as Facade.SignalExtractionTicket), {
        /** Reads extraction completion, accepted claims, generated prospective queries and parent-verified source ranges and MESSAGE revisions as the owner may read them. */
        result: (input: Facade.SignalExtractionResultRequest): Facade.SignalExtractionResult | null => this.#call(() => this.#client.vaultMemorySignalExtractionResult(input) as Facade.SignalExtractionResult | null),
      }),
    },
    channel_identities: {
      /** Provision an engine-held channel address, handle or shared presence through the existing lifecycle gate. */
      provision: (input: Facade.ChannelIdentityProvisionRequest): Facade.ChannelIdentityLifecycleReceipt => this.#call(() => this.#client.vaultChannelIdentitiesProvision(input) as Facade.ChannelIdentityLifecycleReceipt),
      /** Bind a requested identity or an existing delegated account with transaction-verified custody. */
      bind: (input: Facade.ChannelIdentityBindRequest): Facade.ChannelIdentityLifecycleReceipt => this.#call(() => this.#client.vaultChannelIdentitiesBind(input) as Facade.ChannelIdentityLifecycleReceipt),
      /** Record owner-confirmed fulfillment of a pending channel identity; delegated custody is revalidated. */
      fulfill: (input: Facade.ChannelIdentityRequest): Facade.ChannelIdentityLifecycleReceipt => this.#call(() => this.#client.vaultChannelIdentitiesFulfill(input) as Facade.ChannelIdentityLifecycleReceipt),
      /** Rotate an engine-held channel identity through its lifecycle gate; delegated accounts cannot rotate. */
      rotate: (input: Facade.ChannelIdentityRequest): Facade.ChannelIdentityLifecycleReceipt => this.#call(() => this.#client.vaultChannelIdentitiesRotate(input) as Facade.ChannelIdentityLifecycleReceipt),
      /** Release a channel identity through its lifecycle gate, retaining engine-held addresses under the never-recycle rule. */
      release: (input: Facade.ChannelIdentityReleaseRequest): Facade.ChannelIdentityLifecycleReceipt => this.#call(() => this.#client.vaultChannelIdentitiesRelease(input) as Facade.ChannelIdentityLifecycleReceipt),
      /** Read and receipt the gated inbound routing disposition of a channel identity, including retirement holds. */
      route_inbound: (input: Facade.ChannelIdentityRequest): Facade.ChannelIdentityLifecycleReceipt => this.#call(() => this.#client.vaultChannelIdentitiesRouteInbound(input) as Facade.ChannelIdentityLifecycleReceipt),
      /** Read live channel identity facts, custody, lifecycle and outbound capability without granting permission to send. */
      get: (input: Facade.ChannelIdentityRequest): Facade.ChannelIdentityView => this.#call(() => this.#client.vaultChannelIdentitiesGet(input) as Facade.ChannelIdentityView),
      selection: {
        /** Read the compiled relationship selection law and authenticated writer provenance. */
        rules: (input: Facade.EmptyRequest): Facade.ChannelIdentitySelectionRuleSet => this.#call(() => this.#client.vaultChannelIdentitiesSelectionRules(input) as Facade.ChannelIdentitySelectionRuleSet),
        /** Amend relationship selection rules at an expected revision as the authenticated owner or an authorized agent writer. */
        update: (input: Facade.ChannelSelectionUpdateRequest): Facade.ChannelIdentitySelectionRuleSet => this.#call(() => this.#client.vaultChannelIdentitiesSelectionUpdate(input) as Facade.ChannelIdentitySelectionRuleSet),
      },
      /** Select a live channel identity under relationship rules, retaining an existing thread passport mask. */
      select: (input: Facade.ChannelSelectionRequest): Facade.ChannelSelectionView => this.#call(() => this.#client.vaultChannelIdentitiesSelect(input) as Facade.ChannelSelectionView),
      passports: {
        /** Read one receiving identity and Message-ID passport through the caller credential. */
        get: (input: Facade.ThreadPassportRequest): Facade.ThreadPassportLookup => this.#call(() => this.#client.vaultChannelIdentitiesPassportsGet(input) as Facade.ThreadPassportLookup),
        /** Read canonical thread passports and the sticky identity, actor and facet mask. */
        list: (input: Facade.ThreadPassportsRequest): Facade.ThreadPassportsView => this.#call(() => this.#client.vaultChannelIdentitiesPassportsList(input) as Facade.ThreadPassportsView),
      },
    },
    delivery_window: {
      policy: {
        /** The owner writes one typed interrupt-only delivery-window policy through the gated claim writer. */
        put: (input: Facade.DeliveryWindowPolicyPutRequest): Facade.CommitReceipt => this.#call(() => this.#client.vaultDeliveryWindowPolicyPut(input) as Facade.CommitReceipt),
        /** Read typed delivery-window policy rows with approval, source, lifecycle and validity provenance. */
        list: (input: Facade.DeliveryWindowPolicyRequest): Facade.DeliveryWindowPolicies => this.#call(() => this.#client.vaultDeliveryWindowPolicyList(input) as Facade.DeliveryWindowPolicies),
        /** The owner retracts a delivery-window policy through the existing claim lifecycle door. */
        retract: (input: Facade.DeliveryWindowPolicyRetractRequest): Facade.CommitReceipt => this.#call(() => this.#client.vaultDeliveryWindowPolicyRetract(input) as Facade.CommitReceipt),
      },
      /** Preview live delivery-window policy with the engine evaluator; the preview does not authorize or release an effect. */
      evaluate: (input: Facade.DeliveryWindowEvaluateRequest): Facade.DeliveryWindowPreview => this.#call(() => this.#client.vaultDeliveryWindowEvaluate(input) as Facade.DeliveryWindowPreview),
    },
    summaries: {
      /** Declares a readable source scope; only the configured Dreamer writes and source-links the SUMMARY birth. */
      create: (request: Facade.SummaryCreateRequest): Facade.SummaryQueued => this.#call(() => this.#client.vaultSummariesCreate(request) as Facade.SummaryQueued),
      /** Reads SUMMARY text, keep, derivation, covers and stable edit anchors in one caller-scoped snapshot. */
      read: (request: Facade.SummaryReadRequest): Facade.ScopedReadResult<Facade.SummaryReadView | null> => this.#call(() => this.#client.vaultSummariesRead(request) as Facade.ScopedReadResult<Facade.SummaryReadView | null>),
      /** Reads the calling principal's own summary declaration and its retained completion or failure. */
      status: (request: Facade.SummaryStatusRequest): Facade.ScopeSummaryStatus => this.#call(() => this.#client.vaultSummariesStatus(request) as Facade.ScopeSummaryStatus),
      /** Edits the SUMMARY keep memo at the exact frontier read, under the caller's owner proof or entity-bound text grant. */
      keep: (request: Facade.SummaryKeepRequest): Facade.SummaryKeepResult => this.#call(() => this.#client.vaultSummariesKeep(request) as Facade.SummaryKeepResult),
      /** Applies attributed anchored SUMMARY edits through existing grants; ungranted edits remain a typed review proposal. */
      edit: (request: Facade.SummaryEditRequest): Facade.SummaryProposalView => this.#call(() => this.#client.vaultSummariesEdit(request) as Facade.SummaryProposalView),
      /** Applies generated anchored SUMMARY operations after a keep fence and source admission; durable receipts name the sources read. */
      patch: (request: Facade.SummaryPatchRequest): Facade.SummaryMutationResult => this.#call(() => this.#client.vaultSummariesPatch(request) as Facade.SummaryMutationResult),
      /** Retains generated SUMMARY text as a source-linked rewrite fork after reading keep; no head moves without explicit switch. */
      regenerate: (request: Facade.SummaryRegenerateRequest): Facade.SummaryMutationResult => this.#call(() => this.#client.vaultSummariesRegenerate(request) as Facade.SummaryMutationResult),
      proposals: {
        /** Reads a SUMMARY proposal's fork provenance, retained text and durable receipts only when every member is readable. */
        read: (request: Facade.SummaryProposalRequest): Facade.SummaryProposalView => this.#call(() => this.#client.vaultSummariesProposalsRead(request) as Facade.SummaryProposalView),
        /** Merges the complete SUMMARY proposal under existing entity grants, preserving concurrent head edits and durable receipts. */
        merge: (request: Facade.SummaryProposalRequest): Facade.SummaryProposalView => this.#call(() => this.#client.vaultSummariesProposalsMerge(request) as Facade.SummaryProposalView),
        /** Explicitly switches the complete SUMMARY proposal under existing entity grants; a stale causal base refuses the entire set. */
        switch: (request: Facade.SummaryProposalRequest): Facade.SummaryProposalView => this.#call(() => this.#client.vaultSummariesProposalsSwitch(request) as Facade.SummaryProposalView),
        /** Rejects the complete SUMMARY proposal under existing entity grants, dropping pending fork text without moving live heads. */
        reject: (request: Facade.SummaryProposalRequest): Facade.SummaryProposalView => this.#call(() => this.#client.vaultSummariesProposalsReject(request) as Facade.SummaryProposalView),
      },
    },
    notes: {
      /** A verified person stamps the brief kind policy seed; it grants no sharing or extraction authority. */
      bless_brief_kind: (input: Facade.EmptyRequest = {}): Facade.BriefKindStamp => this.#call(() => this.#client.vaultNotesBlessBriefKind(input) as Facade.BriefKindStamp),
      /** Authors markdown with supporting claim citations, capturing source NOTE pins and rechecking their live read authority in the brief write transaction. */
      author_brief: (input: Facade.AuthorBriefRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultNotesAuthorBrief(input) as Facade.EntityRefReceipt),
      /** Follows returned share and claim references under the caller live read scope; revocation stops resolution and hidden citations disclose no quote or lifecycle. */
      follow_citation: (input: Facade.BriefCitationFollowRequest): Facade.ScopedReadResult<Facade.SharedBriefCitation | null> => this.#call(() => this.#client.vaultNotesFollowCitation(input) as Facade.ScopedReadResult<Facade.SharedBriefCitation | null>),
      /** Creates a NOTE of a registered kind, its first authored text as its birth. */
      create: (input: Facade.CreateNoteRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultNotesCreate(input) as Facade.EntityRefReceipt),
      /** Appends an opinion/take NOTE about a subject or claim, attributed to the bound caller without changing the target. */
      author_take: (input: Facade.AuthorTakeRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultNotesAuthorTake(input) as Facade.EntityRefReceipt),
      /** Creates a NOTE of a registered kind from an existing entity. */
      from_entity: (input: Facade.CreateNoteFromEntityRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultNotesFromEntity(input) as Facade.EntityRefReceipt),
      /** Reads live NOTE text or one retained NoteVersion, acquiring stable edit anchors in the same scoped snapshot. */
      read: (input: Facade.NoteReadRequest): Facade.ScopedReadResult<Facade.NoteReadView | null> => this.#call(() => this.#client.vaultNotesRead(input) as Facade.ScopedReadResult<Facade.NoteReadView | null>),
      /** Reads authenticated NOTE operation identities and actors with the retained history boundary; hidden or purged history is never invented. */
      history: (input: Facade.NoteAccessRequest): Facade.ScopedReadResult<Facade.NoteHistoryView | null> => this.#call(() => this.#client.vaultNotesHistory(input) as Facade.ScopedReadResult<Facade.NoteHistoryView | null>),
      /** Forks one NOTE at the exact live-head version the caller read, retaining its edits or rewrite without moving the live head. */
      fork: (input: Facade.NoteForkRequest): Facade.NoteForkView => this.#call(() => this.#client.vaultNotesFork(input) as Facade.NoteForkView),
      forks: {
        /** Reads a NOTE fork and its retained pending text through the same scoped, reason-logged read as the live NOTE. */
        read: (input: Facade.NoteForkReadRequest): Facade.ScopedReadResult<Facade.NoteForkView | null> => this.#call(() => this.#client.vaultNotesForksRead(input) as Facade.ScopedReadResult<Facade.NoteForkView | null>),
      },
      proposals: {
        /** Opens one explicit set of NOTE forks with its shared explainer; the engine routes each member under the caller's own existing grants. */
        open: (input: Facade.NoteProposalOpenRequest): Facade.NoteProposalView => this.#call(() => this.#client.vaultNotesProposalsOpen(input) as Facade.NoteProposalView),
        /** Reads an entire NOTE proposal set, its pending fork text, explainer and head-move receipts only when every member is readable. */
        read: (input: Facade.NoteProposalRequest): Facade.NoteProposalView => this.#call(() => this.#client.vaultNotesProposalsRead(input) as Facade.NoteProposalView),
        /** Accepts the complete NOTE proposal set by merge under the caller's existing NOTE grants, retaining concurrent head edits and durable receipts. */
        merge: (input: Facade.NoteProposalRequest): Facade.NoteProposalView => this.#call(() => this.#client.vaultNotesProposalsMerge(input) as Facade.NoteProposalView),
        /** Accepts the complete NOTE proposal set by explicit switch under the caller's existing NOTE grants, recording every head move. */
        switch: (input: Facade.NoteProposalRequest): Facade.NoteProposalView => this.#call(() => this.#client.vaultNotesProposalsSwitch(input) as Facade.NoteProposalView),
        /** Rejects the complete NOTE proposal set under the caller's existing NOTE grants, dropping pending text without changing live heads. */
        reject: (input: Facade.NoteProposalRequest): Facade.NoteProposalView => this.#call(() => this.#client.vaultNotesProposalsReject(input) as Facade.NoteProposalView),
      },
      /** Reads NOTE birth, current version, fork parent and frontier links, proposal membership, verdicts and durable head-move receipts. */
      version_tree: (input: Facade.NoteAccessRequest): Facade.ScopedReadResult<Facade.NoteVersionTree | null> => this.#call(() => this.#client.vaultNotesVersionTree(input) as Facade.ScopedReadResult<Facade.NoteVersionTree | null>),
      /** The owner explicitly erases a NOTE's safe history, or opens its shared-vault erase veto window; no grant names this action. */
      history_purge: (input: Facade.NoteHistoryPurgeRequest): Facade.NoteHistoryPurgeOutcome => this.#call(() => this.#client.vaultNotesHistoryPurge(input) as Facade.NoteHistoryPurgeOutcome),
      /** Executes the exact history erase this owner started after its veto window closes without objection; retries return its durable receipt. */
      history_purge_execute: (input: Facade.NoteHistoryPurgeExecuteRequest): Facade.NoteHistoryPurgeReceipt => this.#call(() => this.#client.vaultNotesHistoryPurgeExecute(input) as Facade.NoteHistoryPurgeReceipt),
      /** The owner reads a NOTE's durable history-purge receipts, including each requested and retained causal frontier. */
      history_purge_receipts: (input: Facade.NoteHistoryPurgeRequest): Facade.NoteHistoryPurgeReceipt[] => this.#call(() => this.#client.vaultNotesHistoryPurgeReceipts(input) as Facade.NoteHistoryPurgeReceipt[]),
      editor: {
        /** Binds a live NOTE editor to the caller and returns its typed text and base version; close the binding when the editor leaves. */
        bind: (input: Facade.NoteAccessRequest): Facade.ScopedReadResult<Facade.NoteEditorBinding | null> => this.#call(() => this.#client.vaultNotesEditorBind(input) as Facade.ScopedReadResult<Facade.NoteEditorBinding | null>),
        /** Closes one live NOTE editor held by this caller; a binding id alone grants no authority. */
        close: (input: Facade.NoteEditorCloseRequest): Facade.NoteEditorClosed => this.#call(() => this.#client.vaultNotesEditorClose(input) as Facade.NoteEditorClosed),
      },
      /** Edits one NOTE in a transaction-local document; a rejected edit leaves nothing pending. */
      edit: (input: Facade.EditNoteRequest): Facade.NoteEditOutcome => this.#call(() => this.#client.vaultNotesEdit(input) as Facade.NoteEditOutcome),
      /** Seals one NOTE: its document freezes, and a later edit opens a fork. */
      seal: (request: Facade.NoteRefRequest): Facade.NoteSeal => this.#call(() => {  const result = JSON.parse(this.#client.vaultNotesSeal(keyedJson(request))) as Facade.NoteSeal; return result }),
      /** Where one NOTE stands (active, sealed, archived or tombstoned) and its seal. */
      lifecycle: (request: Facade.NoteRefRequest): Facade.NoteLifecycleView => this.#call(() => {  const result = JSON.parse(this.#client.vaultNotesLifecycle(keyedJson(request))) as Facade.NoteLifecycleView; return result }),
      /** Sets the defaults one NOTE overrides over its kind's; empty overrides clear them. */
      set_overrides: (request: Facade.SetNoteOverridesRequest): Facade.NoteDefaultsView => this.#call(() => {  const result = JSON.parse(this.#client.vaultNotesSetOverrides(keyedJson(request))) as Facade.NoteDefaultsView; return result }),
      /** One NOTE's overrides and the defaults its gates read after them. */
      defaults: (request: Facade.NoteRefRequest): Facade.NoteDefaultsView => this.#call(() => {  const result = JSON.parse(this.#client.vaultNotesDefaults(keyedJson(request))) as Facade.NoteDefaultsView; return result }),
    },
    /** The owner compensates all or selected changes of a settled run, preserving later work and listing every change not undone and why. */
    revert_run: (input: Facade.RevertRunRequest): Facade.RevertRunOutcome => this.#call(() => this.#client.vaultRevertRun(input) as Facade.RevertRunOutcome),
  }
  /** Fetches one HTTP(S) page through the renderer ladder and retains its source as Imported evidence with Proposed claims; never walks links. */
  fetch(input: Facade.WebFetchRequest): Facade.FetchResult { return this.#call(() => this.#client.fetch(input) as Facade.FetchResult) }
  /** Crawls from one seed under an explicit attempted-page budget, same-origin by default; retains Imported evidence and Proposed claims, and returns failures and completion. */
  crawl(input: Facade.WebCrawlRequest): Facade.CrawlResult { return this.#call(() => this.#client.crawl(input) as Facade.CrawlResult) }
  /** Files one feedback report on a skill or run: its subject, category and evidence; the host supplies the actor. */
  report(input: Facade.ReportRequest): Facade.ReportReceipt { return this.#call(() => this.#client.report(input) as Facade.ReportReceipt) }
  readonly feedback = {
    /** The owner previews the exact feedback bundle one report issue would send to its publisher: its subject, digest, destination and approval. */
    preview: (input: Facade.FeedbackPreviewRequest): Facade.FeedbackSubjectPreview => this.#call(() => this.#client.feedbackPreview(input) as Facade.FeedbackSubjectPreview),
    /** The owner sends exactly the previewed feedback bundle for one report issue to its publisher, once, through the ordinary outbound gate. */
    send: (input: Facade.FeedbackSendSubjectRequest): Facade.FeedbackSubjectSent => this.#call(() => this.#client.feedbackSend(input) as Facade.FeedbackSubjectSent),
  }
  readonly self = {
    focus: {
      /** Takes every wake queued for the attached run's board STREAM connection, each re-read under this credential at delivery. */
      wakes: (input: Facade.LiveRunRequest<Facade.BoardWakeRequest>): Facade.BoardWakeReply => this.#call(() => this.#client.selfFocusWakes(input) as Facade.BoardWakeReply),
      scratchpad: {
        /** Searches the bound actor's whole session scratchpad, live or sealed, for the lines holding every query word, folded lines in full. */
        recall: (input: Facade.ScratchpadRecallRequest): Facade.ScratchpadRecallReply => this.#call(() => this.#client.selfFocusScratchpadRecall(input) as Facade.ScratchpadRecallReply),
        /** Appends one line, with an optional keep or scratch mark and pin, to the bound actor's session scratchpad; the session's first line opens the pad, and a sealed pad is refused. */
        append: (input: Facade.ScratchpadAppendRequest): Facade.ScratchpadWriteReply => this.#call(() => this.#client.selfFocusScratchpadAppend(input) as Facade.ScratchpadWriteReply),
        /** Seals the bound actor's session scratchpad, ending the run's pad; a session with no pad answers no pad. */
        seal: (input: Facade.ScratchpadSealRequest): Facade.ScratchpadWriteReply => this.#call(() => this.#client.selfFocusScratchpadSeal(input) as Facade.ScratchpadWriteReply),
      },
      /** Re-renders the attached run's context board as one STREAM frame, at the frame epoch the caller last saw. */
      refresh: (input: Facade.LiveRunRequest<Facade.BoardRefreshRequest>): Facade.BoardFrameReply => this.#call(() => this.#client.selfFocusRefresh(input) as Facade.BoardFrameReply),
      /** Subscribes the attached run's board STREAM connection to the named scopes, inside its credential ceiling. */
      subscribe: (input: Facade.LiveRunRequest<Facade.BoardSubscriptionRequest>): Facade.BoardSubscriptionReply => this.#call(() => this.#client.selfFocusSubscribe(input) as Facade.BoardSubscriptionReply),
      /** Unsubscribes the attached run's board STREAM connection from the named scopes. */
      unsubscribe: (input: Facade.LiveRunRequest<Facade.BoardSubscriptionRequest>): Facade.BoardSubscriptionReply => this.#call(() => this.#client.selfFocusUnsubscribe(input) as Facade.BoardSubscriptionReply),
    },
    memory: {
      /** Writes one private entry in the bound actor's own diary, as an actor-private NOTE. */
      diary: Object.assign((input: Facade.DiaryEntryRequest): Facade.DiaryEntryReceipt => this.#call(() => this.#client.selfMemoryDiary(input) as Facade.DiaryEntryReceipt), {
        /** This agent's diary read log: who read its diary and why, newest first, and the reasons its review holds. */
        reads: (input: Facade.DiaryReadsRequest): Facade.DiaryReadsView => this.#call(() => this.#client.selfMemoryDiaryReads(input) as Facade.DiaryReadsView),
        /** This agent's yes or no to a reader's reason for reading its diary; only the diary's own agent answers. */
        review: (input: Facade.DiaryReviewAnswer): Facade.DiaryReadRequest => this.#call(() => this.#client.selfMemoryDiaryReview(input) as Facade.DiaryReadRequest),
        /** Reads an agent's diary under the caller's diary.read grants, stating a reason the agent sees in its read log. */
        query: (input: Facade.DiaryQueryRequest): Facade.DiaryQueryOutcome => this.#call(() => this.#client.selfMemoryDiaryQuery(input) as Facade.DiaryQueryOutcome),
      }),
    },
    standing: {
      /** This agent's configured standing block in one world: its handle, name and token floor. */
      get: (input: Facade.OwnStandingBlockRequest): Facade.StandingBlockView => this.#call(() => this.#client.selfStandingGet(input) as Facade.StandingBlockView),
      /** Every standing block configured for this agent, one per world, in world order. */
      list: (input: Facade.EmptyRequest = {}): Facade.StandingBlockView[] => this.#call(() => this.#client.selfStandingList(input) as Facade.StandingBlockView[]),
      /** This agent proposes one persona field's new text for its standing block, as a Generated claim its gate settles; compiled text is never edited. */
      edit: (input: Facade.StandingBlockEditRequest): Facade.StandingBlockEditReceipt => this.#call(() => this.#client.selfStandingEdit(input) as Facade.StandingBlockEditReceipt),
    },
    identity: {
      /** The owner answers an identity choice with supporting evidence refs; the original mention and verified owner resolution provenance are retained atomically. */
      answer: (input: Facade.IdentityAnswerEvidenceRequest): Facade.IdentitySettled => this.#call(() => this.#client.selfIdentityAnswer(input) as Facade.IdentitySettled),
      /** Before acting on a person known only by a name, settles who that name is from its newest saved mention, or opens an ask. */
      settle: (input: Facade.IdentityActNowRequest): Facade.IdentityActNow => this.#call(() => this.#client.selfIdentitySettle(input) as Facade.IdentityActNow),
    },
    inbox: {
      /** Lists one page of notifications delivered to the bound actor, without marking them. */
      list: (input: Facade.InboxListRequest): Facade.NotificationPage => this.#call(() => this.#client.selfInboxList(input) as Facade.NotificationPage),
      /** Marks one delivered notification seen or acknowledged for the bound actor. */
      mark: (input: Facade.InboxMarkRequest): Facade.NotificationRow => this.#call(() => this.#client.selfInboxMark(input) as Facade.NotificationRow),
      concern: Object.assign((input: Facade.ConcernCardRequest): Facade.AgentHealthCardView => this.#call(() => this.#client.selfInboxConcern(input) as Facade.AgentHealthCardView), {
        outcome: (input: Facade.ConcernOutcomeRequest): Facade.ConcernCardSummary => this.#call(() => this.#client.selfInboxConcernOutcome(input) as Facade.ConcernCardSummary),
        move: (input: Facade.ConcernMoveRequest): Facade.ConcernMoveOutcome => this.#call(() => this.#client.selfInboxConcernMove(input) as Facade.ConcernMoveOutcome),
      }),
      /** Reads the bound actor's own identity inbox slice in impact order, with optional identity filtering and concern groups; not a delivered-notification page. */
      lens: (input: Facade.InboxLensRequest): Facade.InboxLensPage => this.#call(() => this.#client.selfInboxLens(input) as Facade.InboxLensPage),
    },
    /** Sends one message to a person in the Direct room the caller's person and theirs share, making the room on first use. */
    message: (input: Facade.MessagePersonRequest): Facade.MessagePersonReceipt => this.#call(() => this.#client.selfMessage(input) as Facade.MessagePersonReceipt),
    grants: {
      /** Asks a person for access on the caller's behalf; the request grants nothing until the vault owner approves it. */
      ask: (input: Facade.GrantAskRequest): Facade.GrantAskReceipt => this.#call(() => this.#client.selfGrantsAsk(input) as Facade.GrantAskReceipt),
    },
    /** The caller's own dispatched attempt: its persisted spend allowance, landing reserve, checkpoint and saved hold, without substituting a token meter for money. */
    budget: Object.assign((input: Facade.SelfBudgetRequest): Facade.AgentBudgetView => this.#call(() => this.#client.selfBudget(input) as Facade.AgentBudgetView), {
      /** The worker parks its own dispatched attempt at its budget hold with its lease fence and exact checkpoint; the same run keeps its partial results and resumes later. */
      land: (input: Facade.BudgetLandRequest): Facade.PartialResultHold => this.#call(() => this.#client.selfBudgetLand(input) as Facade.PartialResultHold),
    }),
    credential: {
      /** Appends a holder-signed caveat to the caller's own slip, optionally transferring it to a recipient public key. Existing caveats and live parent authority remain binding; no actor or grant is minted. */
      attenuate: (input: Facade.CredentialAttenuationRequest): Facade.CredentialAttenuated => this.#call(() => this.#client.selfCredentialAttenuate(input) as Facade.CredentialAttenuated),
    },
    admission: {
      /** Reads the durable queued, held or terminal receipt of one typed call under its invocation id, as its own actor; never submits or replays work. */
      status: (input: Facade.AdmissionStatusRequest): Facade.AdmissionReceipt | null => this.#call(() => this.#client.selfAdmissionStatus(input) as Facade.AdmissionReceipt | null),
      /** Reconciles an exact authored set of invocation ids against the caller actor durable admission receipts in one snapshot, without duplicate outcomes or replay. */
      receipts: (input: Facade.AdmissionReceiptsRequest): Facade.AdmissionReceipt[] => this.#call(() => this.#client.selfAdmissionReceipts(input) as Facade.AdmissionReceipt[]),
    },
    off_record: {
      /** The session's creator or the vault's owner runs one entry of a durable code-mode run bound to an off-record session; its rows and spilled outputs stay in the room until close. */
      execute: (input: Facade.OffRecordExecuteRequest): Facade.OffRecordExecuted => this.#call(() => this.#client.selfOffRecordExecute(input) as Facade.OffRecordExecuted),
    },
    consent: {
      graduation: {
        /** The bound actor transparently gives up only its own ramp scope authority, with the existing durable demotion receipt. */
        demote: (input: Facade.GraduationScopeRequest): Facade.GraduationChanged => this.#call(() => this.#client.selfConsentGraduationDemote(input) as Facade.GraduationChanged),
      },
    },
    /** Hands a secret to one trusted operation by its handle, under the owner's binding; answers what the operation got back, never the value. */
    use: (input: Facade.SecretUseRequest): Facade.SecretUseAnswer => this.#call(() => this.#client.selfUse(input) as Facade.SecretUseAnswer),
    secrets: {
      /** Mints a value-free grant on a secret for this credential's attached run, to one purpose: an operation or connector (door), a host destination (leased) or a declared file (local); the answer never holds the value. */
      materialize: (input: Facade.LiveRunRequest<Facade.SecretGrantMintRequest>): Facade.SecretGrantView => this.#call(() => this.#client.selfSecretsMaterialize(input) as Facade.SecretGrantView),
      /** Renews a grant the attached run holds: a fresh grant at the secret's current generation in its place, never a longer life for bytes already handed out. */
      renew: (input: Facade.LiveRunRequest<Facade.SecretGrantRenewRequest>): Facade.SecretGrantView => this.#call(() => this.#client.selfSecretsRenew(input) as Facade.SecretGrantView),
      /** Tears down a grant the attached run holds, whatever its state: revokes it and its lease, removes its file or clears its destination, and says what the cleanup found. */
      teardown: (input: Facade.LiveRunRequest<Facade.SecretGrantTeardownRequest>): Facade.SecretGrantView => this.#call(() => this.#client.selfSecretsTeardown(input) as Facade.SecretGrantView),
      /** Hands the secret a door grant redeems to one trusted operation or connector call, for the attached run; a grant minted before a rotation refuses until renewed, and the answer never holds the value. */
      use: (input: Facade.LiveRunRequest<Facade.SecretGrantUseRequest>): Facade.SecretUseAnswer => this.#call(() => this.#client.selfSecretsUse(input) as Facade.SecretUseAnswer),
    },
    skills: {
      /** An agent saves a skill it wrote, SKILL.md and scripts together; it lands as a proposed candidate and nothing activates it. */
      save: (input: Facade.SkillSaveRequest): Facade.SkillAuthoringReceipt => this.#call(() => this.#client.selfSkillsSave(input) as Facade.SkillAuthoringReceipt),
      /** An agent forks a stored skill under its own identity, keeping its import ancestry. */
      fork: (input: Facade.SkillForkRequest): Facade.SkillAuthoringReceipt => this.#call(() => this.#client.selfSkillsFork(input) as Facade.SkillAuthoringReceipt),
      /** Every loadable callable helper skill and its call contract: what it takes and returns. */
      callables: (input: Facade.EmptyRequest = {}): Facade.CallableCardView[] => this.#call(() => this.#client.selfSkillsCallables(input) as Facade.CallableCardView[]),
      /** Runs a callable skill on this credential's attached leased run with its existing sandbox and gates; the result follows the stored return contract, while anchored outcomes settle separately. */
      call: (input: Facade.LiveRunRequest<Facade.SkillCallInput>): unknown => this.#call(() => this.#client.selfSkillsCall(input) as unknown),
    },
    decisions: {
      asks: (input: Facade.EmptyRequest = {}): Facade.DecisionAsk[] => this.#call(() => this.#client.selfDecisionsAsks(input) as Facade.DecisionAsk[]),
    },
    run: {
      /** Attaches the caller's own credential to its leased live run and returns the handle required by the public fold and history calls. */
      attach: (input: Facade.RunAttachRequest): Facade.RunAttached => this.#call(() => this.#client.selfRunAttach(input) as Facade.RunAttached),
    },
    /** Lists the attached run's landed folds, pending marks and outstanding compact ask. */
    folds: Object.assign((input: Facade.FoldRunRequest): Facade.FoldReply<Facade.FoldList> => this.#call(() => this.#client.selfFolds(input) as Facade.FoldReply<Facade.FoldList>), {
      /** Reads one pending mark or landed fold of the attached run, with its Generated stub, source ids and retained result handles. */
      describe: (input: Facade.FoldUnfoldRequest): Facade.FoldReply<Facade.FoldDescription> => this.#call(() => this.#client.selfFoldsDescribe(input) as Facade.FoldReply<Facade.FoldDescription>),
    }),
    /** Reads checkpointed raw steps and landed fold and epoch boundaries of the attached run; a cleared ask alone never proves compaction settled. */
    history: (input: Facade.FoldHistoryRequest): Facade.FoldHistory => this.#call(() => this.#client.selfHistory(input) as Facade.FoldHistory),
    browser: {
      /** Opens a URL in the attached run's own browser session and observes the page; a long page's observation comes in pages, read on with observe and its next cursor. */
      open: (input: Facade.LiveRunRequest<Facade.OpenInput>): Facade.ObservationPage => this.#call(() => this.#client.selfBrowserOpen(input) as Facade.ObservationPage),
      /** Observes the current page of the attached run's browser session, in pages read on with observe and an answer's next cursor; the verbs follow a tab an act opens, or a closed tab's opener, and name the move as switched. */
      observe: (input: Facade.LiveRunRequest<Facade.ObserveInput>): Facade.ObservationPage => this.#call(() => this.#client.selfBrowserObserve(input) as Facade.ObservationPage),
      /** Finds the page rows whose role and name match, in pages: an answer with next goes on, and find with that cursor reads the next page. */
      find: (input: Facade.LiveRunRequest<Facade.FindInput>): Facade.FindOutput => this.#call(() => this.#client.selfBrowserFind(input) as Facade.FindOutput),
      /** Clicks one page target and observes the result; a long page's observation comes in pages, read on with observe and its next cursor. */
      click: (input: Facade.LiveRunRequest<Facade.ClickInput>): Facade.ObservationPage => this.#call(() => this.#client.selfBrowserClick(input) as Facade.ObservationPage),
      /** Clicks a point of a held screenshot, mapped onto the viewport; a long page's observation comes in pages, read on with observe and its next cursor. */
      click_at: (input: Facade.LiveRunRequest<Facade.PointInput>): Facade.ObservationPage => this.#call(() => this.#client.selfBrowserClickAt(input) as Facade.ObservationPage),
      /** Types text into one page target and observes the result; a long page's observation comes in pages, read on with observe and its next cursor. */
      type: (input: Facade.LiveRunRequest<Facade.TypeInput>): Facade.ObservationPage => this.#call(() => this.#client.selfBrowserType(input) as Facade.ObservationPage),
      /** Picks the option of a select element by its label, text or value; a long page's observation comes in pages, read on with observe and its next cursor. */
      select: (input: Facade.LiveRunRequest<Facade.SelectInput>): Facade.ObservationPage => this.#call(() => this.#client.selfBrowserSelect(input) as Facade.ObservationPage),
      /** Waits until a page row its refs name, or else some row matching a role and name, is there; many rows come in pages, read on with find and its next cursor. */
      wait_for: (input: Facade.LiveRunRequest<Facade.WaitForInput>): Facade.WaitForOutput => this.#call(() => this.#client.selfBrowserWaitFor(input) as Facade.WaitForOutput),
      /** Checks that a page row is present or absent, and holds a given value. */
      expect: (input: Facade.LiveRunRequest<Facade.ExpectInput>): Facade.ExpectOutput => this.#call(() => this.#client.selfBrowserExpect(input) as Facade.ExpectOutput),
      /** Takes a screenshot the session holds, by image ref and never captioned. */
      screenshot: (input: Facade.LiveRunRequest<Facade.ScreenshotInput>): Facade.ScreenshotOutput => this.#call(() => this.#client.selfBrowserScreenshot(input) as Facade.ScreenshotOutput),
      /** Reads back a held image by its ref. */
      view: (input: Facade.LiveRunRequest<Facade.ViewInput>): Facade.ImageOutput => this.#call(() => this.#client.selfBrowserView(input) as Facade.ImageOutput),
      /** Crops a held image to a rectangle. */
      crop: (input: Facade.LiveRunRequest<Facade.CropInput>): Facade.ImageOutput => this.#call(() => this.#client.selfBrowserCrop(input) as Facade.ImageOutput),
      /** Zooms into a rectangle of a held image. */
      zoom: (input: Facade.LiveRunRequest<Facade.ZoomInput>): Facade.ImageOutput => this.#call(() => this.#client.selfBrowserZoom(input) as Facade.ImageOutput),
      /** Runs one batched program of browser steps for a subgoal, stopping at the first step that fails; a long last observation comes in pages, read on with observe and the batch's next cursor. */
      batch: (input: Facade.LiveRunRequest<Facade.BatchInput>): Facade.BatchOutput => this.#call(() => this.#client.selfBrowserBatch(input) as Facade.BatchOutput),
      library: {
        /** The replay library's programs for a site, or for the attached run's open page's site. */
        find: (input: Facade.LiveRunRequest<Facade.LibraryFindInput>): Facade.LibraryFindOutput => this.#call(() => this.#client.selfBrowserLibraryFind(input) as Facade.LibraryFindOutput),
        /** Offers a solved run's program to the replay library of the attached run's browser session; it joins only once a no-model replay meets its postcondition. */
        propose: (input: Facade.LiveRunRequest<Facade.ProposeInput>): Facade.ProposeOutput => this.#call(() => this.#client.selfBrowserLibraryPropose(input) as Facade.ProposeOutput),
        /** Takes a program out of the replay library of the attached run's browser session for every later run, and returns the card it had. */
        retire: (input: Facade.LiveRunRequest<Facade.LibraryRetireInput>): Facade.LibraryRetireOutput => this.#call(() => this.#client.selfBrowserLibraryRetire(input) as Facade.LibraryRetireOutput),
        /** The programs retires took out of the replay library for a site, or for the attached run's open page's site, the newest first, each with when and why. */
        retired: (input: Facade.LiveRunRequest<Facade.LibraryRetiredInput>): Facade.LibraryRetiredOutput => this.#call(() => this.#client.selfBrowserLibraryRetired(input) as Facade.LibraryRetiredOutput),
        /** Runs a replay library program live with its arguments in the attached run's browser session; a missed postcondition goes back to the planner. */
        run: (input: Facade.LiveRunRequest<Facade.LibraryRunInput>): Facade.LibraryRunOutput => this.#call(() => this.#client.selfBrowserLibraryRun(input) as Facade.LibraryRunOutput),
      },
      /** Asks a person to take the browser over, saying why (to sign in or pay inside the same page); until they hand it back, every browser verb refuses browser_taken_over, and the answer after carries the takeover's record. */
      handover: (input: Facade.LiveRunRequest<Facade.HandoverInput>): Facade.HandoverOutput => this.#call(() => this.#client.selfBrowserHandover(input) as Facade.HandoverOutput),
    },
    /** Marks a span of the attached run as pending; compaction leaves its raw steps untouched until a batch lands. */
    fold: (input: Facade.FoldMarkRequest): Facade.FoldReply<Facade.FoldMarked> => this.#call(() => this.#client.selfFold(input) as Facade.FoldReply<Facade.FoldMarked>),
    /** Asks the attached run to fold its pending marks in one batch at its next step boundary; read self.history for landed folds and epochs. */
    compact: (input: Facade.FoldCompactRequest): Facade.FoldReply<Facade.FoldCompactAsked> => this.#call(() => this.#client.selfCompact(input) as Facade.FoldReply<Facade.FoldCompactAsked>),
    /** Appends a fold of the attached run after its current tail, without replacing the earlier stub. */
    unfold: (input: Facade.FoldUnfoldRequest): Facade.FoldReply<Facade.FoldUnfolded> => this.#call(() => this.#client.selfUnfold(input) as Facade.FoldReply<Facade.FoldUnfolded>),
    /** Files this credential's attached agent run's own blocked report: a closed category and its detail as the fenced, untrusted leaf of a witnessed receipt for the Coach's Issues job; it grants nothing and completes no task. */
    report_blocked: (input: Facade.LiveRunRequest<Facade.ReportBlockedInput>): Facade.ReportBlockedOutput => this.#call(() => this.#client.selfReportBlocked(input) as Facade.ReportBlockedOutput),
    agents: {
      /** Spawns a child under the leased parent attached to this credential; spec states the need, work and narrowing, never the parent identity. */
      spawn: (input: Facade.LiveRunRequest<Facade.AgentSpawnInput>): Facade.AgentSpawnOutput => this.#call(() => this.#client.selfAgentsSpawn(input) as Facade.AgentSpawnOutput),
    },
    leader: {
      /** Splits the attached leader run into a subproject inside its own TASK wrapper; spec may name only the child leader and a narrower scope. */
      split: (input: Facade.LiveRunRequest<Facade.LeaderSplitInput>): Facade.LeaderSplitOutput => this.#call(() => this.#client.selfLeaderSplit(input) as Facade.LeaderSplitOutput),
    },
  }
  /** Cancels one task under the ladder's `auto` default. The receipt says what stopped and what became a proposal instead. */
  cancel(taskRef: string): TaskCancelReceipt { return this.#call(() => this.#client.cancel({task_ref: taskRef}) as TaskCancelReceipt) }
  /** The TASK's spawner nudges its live run; a resend with the same key answers the first receipt. */
  steer(input: Facade.SteerRequest): Facade.SteerReceipt { return this.#call(() => this.#client.steer(input) as Facade.SteerReceipt) }
  /** Describes one task's card, or the whole TASKS section when no task is named. */
  describe(taskRef?: string): TaskDescription { return this.#call(() => this.#client.describe({task_ref: taskRef}) as TaskDescription) }
  readonly tasks = {
    /** Mints one TASK and its realizing attempt when the actor's ceiling permits, or parks it as a proposal; an intent key with a typed brief posts it through the task highway. */
    create: (input: Facade.TaskCreateRequest): Facade.TaskCreateReceipt => this.#call(() => this.#client.tasksCreate(input) as Facade.TaskCreateReceipt),
    /** Cuts an epic TASK into a wave of TASKs through a planner agent, as one planning attempt: under the asking run's own lease, or the owner's root wave. */
    wave: (input: Facade.TaskWaveRequest): Facade.TaskWaveReceipt => this.#call(() => this.#client.tasksWave(input) as Facade.TaskWaveReceipt),
    /** Reports task progress, blocked work or a durable result through the task highway; without a report, acknowledges a failed TASK. */
    update: (input: Facade.TaskUpdateRequest): Facade.TaskUpdateReceipt => this.#call(() => this.#client.tasksUpdate(input) as Facade.TaskUpdateReceipt),
    /** Accepts one TASK addressed to the caller through the task highway under the caller's intent key; the attempt handle it answers fences the caller's reports. */
    accept: (input: Facade.TaskAccept): Facade.TaskCallReceipt => this.#call(() => this.#client.tasksAccept(input) as Facade.TaskCallReceipt),
    /** Admits one person's word on an ask; the word is evidence, never approval. */
    answer: (handle: TaskAskHandle, word: TaskAskWord): Facade.TaskAskAnswer => this.#call(() => this.#client.tasksAnswer({handle, word}) as Facade.TaskAskAnswer),
    /** Owner-scoped calibration pairs for an ask: each prediction against the outcome it was bound to. */
    outcomes: (handle: TaskAskHandle): Facade.CalibrationPair[] => this.#call(() => this.#client.tasksOutcomes(handle) as Facade.CalibrationPair[]),
    /** Applies this credential's attached agent run refusal dial to its own TASK, with a durable reason; the live lease supplies the actor and TASK and the engine owns replay. */
    refuse: (input: Facade.LiveRunRequest<Facade.TaskRefuseInput>): Facade.TaskRefuseOutput => this.#call(() => this.#client.tasksRefuse(input) as Facade.TaskRefuseOutput),
  }
  readonly ai = {
    chat: {
      /** Recalls scoped memory, injects it as data, forwards a buffered OpenAI chat call and proposes the exchange under the paired connector's own ceiling. */
      completions: (input: Facade.ChatCompletionRequest): Facade.ChatCompletionResponse => this.#call(() => this.#client.aiChatCompletions(input) as Facade.ChatCompletionResponse),
    },
    steps: {
      /** Submit or resume one owner-bound durable model step with declared transport attempts, deterministic fallback and a schema-validated JSON result. */
      submit: (input: Facade.ModelStepSubmit): Facade.ModelStepReceipt => this.#call(() => this.#client.aiStepsSubmit(input) as Facade.ModelStepReceipt),
      /** Read the owner-bound model-step checkpoints and persisted terminal result without calling a model or spending another lease. */
      receipt: (input: Facade.ModelStepReceiptRequest): Facade.ModelStepReceipt => this.#call(() => this.#client.aiStepsReceipt(input) as Facade.ModelStepReceipt),
    },
    /** Generate one context-bearing reply from the caller's scoped conversation, standing prefix and reader profile through an exact configured model; return durable emit-context receipt refs. */
    reply: (input: Facade.AiReplyRequest): Facade.AiReply => this.#call(() => this.#client.aiReply(input) as Facade.AiReply),
    voice: {
      asr: {
        /** Opens one credential-bound utterance for host-enriched ASR speculative recall, with fixed scope, at most four fires and a call-mode deadline. */
        open: (input: Facade.AsrOpenRequest): Facade.AsrSession => this.#call(() => this.#client.aiVoiceAsrOpen(input) as Facade.AsrSession),
        /** Observes an ASR hypothesis and host enrichment; returns the engine signature-change decision, actual fire budget, scoped candidates and a per-fire receipt. */
        hypothesis: (input: Facade.AsrHypothesisRequest): Facade.AsrHypothesisReceipt => this.#call(() => this.#client.aiVoiceAsrHypothesis(input) as Facade.AsrHypothesisReceipt),
        /** Consumes an ASR utterance, promoting its compatible last fire with receipt linkage or running one full finalize pass with warm-fill and honest partial reporting. */
        finalize: (input: Facade.AsrHypothesisRequest): Facade.AsrFinalReceipt => this.#call(() => this.#client.aiVoiceAsrFinalize(input) as Facade.AsrFinalReceipt),
        /** Closes an unfinished ASR utterance under its opening credential and releases its warm candidates without a final retrieval. */
        close: (input: Facade.AsrCloseRequest): Facade.AsrClosed => this.#call(() => this.#client.aiVoiceAsrClose(input) as Facade.AsrClosed),
      },
      /** Opens an owner-bound live media session on the configured voice routes, using the caller credential, room audience and existing budget gates. */
      start: (input: Facade.LiveVoiceStartRequest): Facade.LiveVoiceSession => this.#call(() => this.#client.aiVoiceStart(input) as Facade.LiveVoiceSession),
      /** Feeds one utterance of PCM16LE with client VAD to the live voice host; sustained speech retires old output through the shared cancellation path. */
      audio: (input: Facade.LiveVoiceAudioRequest): Facade.LiveVoiceProcessed => this.#call(() => this.#client.aiVoiceAudio(input) as Facade.LiveVoiceProcessed),
      /** Reads ordered utterance and epoch events, PCM, flushes, playout stops, safeguard receipts and notices; advancing the cursor releases consumed events. */
      events: (input: Facade.LiveVoiceEventsRequest): Facade.LiveVoiceEvents => this.#call(() => this.#client.aiVoiceEvents(input) as Facade.LiveVoiceEvents),
      /** Acknowledges the exact playout-end or playout-stop event of one session epoch after client playback or flush has completed. */
      ack: (input: Facade.LiveVoiceAckRequest): Facade.LiveVoiceProcessed => this.#call(() => this.#client.aiVoiceAck(input) as Facade.LiveVoiceProcessed),
      /** Observes actual voice-brain run settlements and a terminal boundary after producer teardown, epoch retirement, TTS cancel and client playout acknowledgment. */
      usage: (input: Facade.LiveVoiceUsageRequest): Facade.LiveVoiceUsage => this.#call(() => this.#client.aiVoiceUsage(input) as Facade.LiveVoiceUsage),
      /** Calls a connector under the caller grant and carries its delivered result, marked foreign, into the next voice utterance for parallel sentence safeguards. */
      tool: (input: Facade.LiveVoiceToolRequest): Facade.LiveVoiceToolReply => this.#call(() => this.#client.aiVoiceTool(input) as Facade.LiveVoiceToolReply),
      /** Ends live voice through the shared cancellation path; keeps the session available for final playout acknowledgment and usage observation. */
      end: (input: Facade.LiveVoiceSessionRequest): Facade.LiveVoiceProcessed => this.#call(() => this.#client.aiVoiceEnd(input) as Facade.LiveVoiceProcessed),
      /** Ends and releases a live voice session and its retained events; read terminal usage and acknowledge playout before closing. */
      close: (input: Facade.LiveVoiceSessionRequest): Facade.LiveVoiceProcessed => this.#call(() => this.#client.aiVoiceClose(input) as Facade.LiveVoiceProcessed),
    },
    /** One standalone memory-free turn on the house configuration or a plain model, with ephemeral policy notices; use the HTTP SDK, not a recorded MCP or code-mode call. */
    anonymous_chat: (input: Facade.AnonymousChatRequest): Facade.AnonymousChatResponse => this.#call(() => this.#client.aiAnonymousChat(input) as Facade.AnonymousChatResponse),
    /** The model rows the caller could call now: where each runs, what it takes, its price and rates, and what its meter has left. */
    options: (input: Facade.AiOptionsRequest): Facade.AiOptions => this.#call(() => this.#client.aiOptions(input) as Facade.AiOptions),
    /** One image out of the host's image model; reference images make it an edit. */
    image: (input: Facade.AiCallRequest): Facade.AiAnswer => this.#call(() => this.#client.aiImage(input) as Facade.AiAnswer),
    /** Speech audio out of text, from the host's speech model. */
    speech: (input: Facade.AiCallRequest): Facade.AiAnswer => this.#call(() => this.#client.aiSpeech(input) as Facade.AiAnswer),
    /** Text out of speech audio, from the host's transcription model. */
    transcribe: (input: Facade.AiCallRequest): Facade.AiAnswer => this.#call(() => this.#client.aiTranscribe(input) as Facade.AiAnswer),
    /** One embedding vector per input text, from the host's embedding model. */
    embed: (input: Facade.AiCallRequest): Facade.AiAnswer => this.#call(() => this.#client.aiEmbed(input) as Facade.AiAnswer),
    /** Starts a video render as a provider job and answers with its ticket. */
    video: Object.assign((input: Facade.AiCallRequest): Facade.AiVideoTicket => this.#call(() => this.#client.aiVideo(input) as Facade.AiVideoTicket), {
      /** Where a video job stands; a finished one answers with its clip on every poll until ai.video.cancel deletes it. */
      poll: (input: Facade.AiVideoJobRequest): Facade.AiVideoJob => this.#call(() => this.#client.aiVideoPoll(input) as Facade.AiVideoJob),
      /** Stops a video job at its provider. */
      cancel: (input: Facade.AiVideoJobRequest): Facade.AiVideoCancelled => this.#call(() => this.#client.aiVideoCancel(input) as Facade.AiVideoCancelled),
    }),
    /** The caller's own typed question through the host's decision ladder: yes or no, one of its options, a score in the caller's range, or a box or point in an image, answered with a probability and a decision receipt. */
    verdict: (input: Facade.AiVerdictRequest): Facade.AiVerdict => this.#call(() => this.#client.aiVerdict(input) as Facade.AiVerdict),
  }
  /** Asks for a secret's value for the model, by its handle and why; answers a pending reveal that reveal.wait collects. */
  readonly reveal = Object.assign((input: Facade.RevealRequest): Facade.RevealPending => this.#call(() => this.#client.reveal(input) as Facade.RevealPending), {
    /** Where a reveal stands: pending, denied, expired or granted; the first granted answer carries the value, later ones the receipt. */
    wait: (input: Facade.RevealWaitRequest): Facade.RevealWaitAnswer => this.#call(() => this.#client.revealWait(input) as Facade.RevealWaitAnswer),
    /** What a secret handle names, where it was found and what a reveal of it would do now; never the value. */
    describe: (input: Facade.RevealDescribeRequest): Facade.RevealHandleCard => this.#call(() => this.#client.revealDescribe(input) as Facade.RevealHandleCard),
  })
  readonly host = {
    /** Compacts a conversation window on the configured cheap backend, preserving add-only hook pins through the existing gate and keyframe mint. */
    compact: (input: Facade.HostCompactRequest): Facade.HostCompactResult => this.#call(() => this.#client.hostCompact(input) as Facade.HostCompactResult),
    /** Schedules the host wake through its typed trigger; pre-hook Skip keeps its reason and Timer includes the engine maintenance lanes. */
    wake: (input: Facade.HostWakeRequest): Facade.HostWakeResult => this.#call(() => this.#client.hostWake(input) as Facade.HostWakeResult),
    budget: {
      /** Notifies a spent durable budget seat under Suspend, retaining the original line, root payer, cap and accounting for hook follow-up work. */
      hit: (input: Facade.HostBudgetHitRequest): Facade.HostBudgetHitResult => this.#call(() => this.#client.hostBudgetHit(input) as Facade.HostBudgetHitResult),
    },
  }
  /** Open the caller-scoped live graph or a retained repository snapshot, resolving a snapshot id to its exact fork hash. */
  mount(input: Facade.GraphFsMountRequest): Facade.GraphFsMounted { return this.#call(() => this.#client.mount(input) as Facade.GraphFsMounted) }
  readonly graph_fs = {
    /** List one directory at the mounted reference under the caller read gate, with a sealed continuation. */
    readdir: (input: Facade.GraphFsPathRequest): Facade.GraphFsDirectoryView => this.#call(() => this.#client.graphFsReaddir(input) as Facade.GraphFsDirectoryView),
    /** Read a bounded page of file bytes at the mounted reference, with its encoding and sealed continuation. */
    read_file: (input: Facade.GraphFsPathRequest): Facade.GraphFsOutput => this.#call(() => this.#client.graphFsReadFile(input) as Facade.GraphFsOutput),
    /** Resolve a visible graph link at the mounted reference without following a host filesystem link. */
    read_link: (input: Facade.GraphFsLinkRequest): Facade.GraphFsLinkView => this.#call(() => this.#client.graphFsReadLink(input) as Facade.GraphFsLinkView),
    /** List names at the mounted reference, using the live temporal index when requested. */
    ls: (input: Facade.GraphFsLsRequest): Facade.GraphFsOutput => this.#call(() => this.#client.graphFsLs(input) as Facade.GraphFsOutput),
    /** Walk visible paths at the mounted reference, or push a live newer-than query into the temporal index. */
    find: (input: Facade.GraphFsFindRequest): Facade.GraphFsOutput => this.#call(() => this.#client.graphFsFind(input) as Facade.GraphFsOutput),
    /** Search visible mounted file bytes, using the live claim text index for supported recursive patterns. */
    grep: (input: Facade.GraphFsGrepRequest): Facade.GraphFsOutput => this.#call(() => this.#client.graphFsGrep(input) as Facade.GraphFsOutput),
    /** Read a bounded page of mounted file bytes as UTF-8 or base64 without changing its reference. */
    cat: (input: Facade.GraphFsPathRequest): Facade.GraphFsOutput => this.#call(() => this.#client.graphFsCat(input) as Facade.GraphFsOutput),
    /** Read the first requested lines at the mounted reference with bounded output and a sealed continuation. */
    head: (input: Facade.GraphFsHeadRequest): Facade.GraphFsOutput => this.#call(() => this.#client.graphFsHead(input) as Facade.GraphFsOutput),
    /** Count lines, words and bytes of a visible file at the mounted reference. */
    wc: (input: Facade.GraphFsLinkRequest): Facade.GraphFsOutput => this.#call(() => this.#client.graphFsWc(input) as Facade.GraphFsOutput),
  }
  /** Run foreign JavaScript with only scoped record snapshots and inert, receipted proposals in the existing isolated tier; no host writes, credentials or network grant are lent. */
  execute_code(input: Facade.ForeignCodeRunRequest): Facade.ForeignCodeRunResult { return this.#call(() => this.#client.executeCode(input) as Facade.ForeignCodeRunResult) }
  /** Read-only ask routing or attributed partial answers. */
  can(request: TaskCanAskRequest): TaskAskPreflight { return this.#call(() => {  const result = JSON.parse(this.#client.can(keyedJson(request))) as TaskAskPreflight; return result }) }
  /** Read-only ask routing or attributed partial answers. */
  peek(request: TaskAskHandle): TaskAskPersonEvidence[] { return this.#call(() => {  const result = JSON.parse(this.#client.peek(keyedJson(request))) as TaskAskPersonEvidence[]; return result.map(item => item) }) }
  /** Asks people or an authority a typed question and returns at admission with the ask's handle. */
  ask(...args: [spec: TaskAskSpec] | [who: TaskAskWho | undefined, what: TaskAskQuestion, until?: number | null, defaultBranch?: TaskAskDefault]): TaskAskReceipt { return this.#call(() => { const input: TaskAskSpec | TaskAskShort = args.length === 1 ? args[0] : {who: typeof args[0] === "string" ? {people: [args[0]]} : Array.isArray(args[0]) ? {people: args[0]} : args[0], what: args[1], until: args[2], default: args[3]}; return this.#client.ask(input) as TaskAskReceipt }) }
  /** Waits on an ask at a step with no other work: pending, changed, ready with its result, or a park for code mode. */
  wait(handle: TaskAskHandle, stepKey = "sdk.wait"): Facade.TaskAskWait { return this.#call(() => this.#client.wait({handle, step_key: stepKey}) as Facade.TaskAskWait) }
  readonly connector = {
    /** Every live catalogued connector whose name or summary matches the query. */
    list: (input: Facade.ConnectorListRequest): Facade.ConnectorEntry[] => this.#call(() => this.#client.connectorList(input) as Facade.ConnectorEntry[]),
    /** One catalogued connector by name, removed ones included. */
    status: (input: Facade.ConnectorNameRequest): Facade.ConnectorView | null => this.#call(() => this.#client.connectorStatus(input) as Facade.ConnectorView | null),
    /** Calls one tool of one catalogued connector under the caller's own grant and gate; the tool's reply comes back as foreign data. */
    call: (input: Facade.ConnectorCallRequest): Facade.ConnectorCallReply => this.#call(() => this.#client.connectorCall(input) as Facade.ConnectorCallReply),
    /** One catalogued connector tool's approved input schema, as the caller's own grant resolves it. */
    schema: (input: Facade.ConnectorSchemaRequest): Facade.ConnectorSchemaReply => this.#call(() => this.#client.connectorSchema(input) as Facade.ConnectorSchemaReply),
    /** Where one held connector.call stands, by the call_ref its held or pending_delivery reply named: still pending, or the reply it settled with. Only the actor that made the call and the vault's owner read it. */
    call_status: (input: Facade.ConnectorCallStatusRequest): Facade.ConnectorCallStatus => this.#call(() => this.#client.connectorCallStatus(input) as Facade.ConnectorCallStatus),
    outbound: {
      /** Schedules one send through a granted outbound connector, gated and held for delivery. */
      schedule: (input: Facade.OutboundScheduleRequest): Facade.OutboundIntentReceipt => this.#call(() => this.#client.connectorOutboundSchedule(input) as Facade.OutboundIntentReceipt),
    },
  }
  readonly calendar = {
    /** Schedules an iMIP REQUEST or CANCEL through the caller-bound outbound gate, preserving UID, SEQUENCE, vault-only hygiene and delivery dedupe. */
    invite: (input: Facade.CalendarInviteSurfaceInput): Facade.OutboundIntentReceipt => this.#call(() => this.#client.calendarInvite(input) as Facade.OutboundIntentReceipt),
    ics: {
      /** Installs one owner-authorized secret-ref ICS feed per system with the existing bounded poll cadence; configuration grants no import consent. */
      configure: (input: Facade.CalendarIcsFeedConfigureRequest): Facade.CalendarIcsFeedRegistration => this.#call(() => this.#client.calendarIcsConfigure(input) as Facade.CalendarIcsFeedRegistration),
      /** Fetches the installed ICS feed through secret custody and the existing imported-claim gate, returning a durable completion barrier and cursor; failed or truncated fetches never mean absence. */
      poll: (input: Facade.CalendarIcsFeedRequest): Facade.CalendarIcsPollCompletion => this.#call(() => this.#client.calendarIcsPoll(input) as Facade.CalendarIcsPollCompletion),
      /** Reads the installed ICS configuration, real cursor and last public poll completion under owner proof, never the secret URL. */
      status: (input: Facade.CalendarIcsFeedRequest): Facade.CalendarIcsFeedStatus | null => this.#call(() => this.#client.calendarIcsStatus(input) as Facade.CalendarIcsFeedStatus | null),
    },
    connector: {
      /** Installs one CalDAV seat under owner proof, with a custody reference, discovery endpoint and nonzero bounded poll cadence. */
      configure: (input: Facade.CalendarConnectorConfigureRequest): Facade.CalendarConnectorRegistration => this.#call(() => this.#client.calendarConnectorConfigure(input) as Facade.CalendarConnectorRegistration),
      /** Reads a configured CalDAV seat, its real provider cursor, kill switch and last sync observation under owner proof. */
      get: (input: Facade.CalendarConnectorRequest): Facade.CalendarConnectorRegistration | null => this.#call(() => this.#client.calendarConnectorGet(input) as Facade.CalendarConnectorRegistration | null),
      /** Pulls the configured CalDAV seat through the existing import gate and echo law, returning the real cursor and sync counters under owner proof. */
      pull: (input: Facade.CalendarConnectorRequest): Facade.CalendarSyncOutcome => this.#call(() => this.#client.calendarConnectorPull(input) as Facade.CalendarSyncOutcome),
      /** Writes a readable EVENT to the owner-installed CalDAV seat through the durable conditional-write outbox, never a blind overwrite. */
      write: (input: Facade.CalendarConnectorWriteRequest): Facade.RemoteWriteReceipt => this.#call(() => this.#client.calendarConnectorWrite(input) as Facade.RemoteWriteReceipt),
      /** Kills a CalDAV seat under owner proof, revoking its advertised verbs and stopping further polling and writes without erasing calendar evidence. */
      kill: (input: Facade.CalendarConnectorKillRequest): Facade.CalendarConnectorRegistration => this.#call(() => this.#client.calendarConnectorKill(input) as Facade.CalendarConnectorRegistration),
    },
    imip: {
      /** Installs the host iMIP mail submission endpoint and custody name under owner proof; this configuration grants no invite consent or sending identity. */
      configure: (input: Facade.CalendarImipTransportConfig): Facade.CalendarImipTransportConfig => this.#call(() => this.#client.calendarImipConfigure(input) as Facade.CalendarImipTransportConfig),
      /** Reads the installed host iMIP submission endpoint and custody name under owner proof, never its credential value. */
      get: (input: Facade.EmptyRequest = {}): Facade.CalendarImipTransportConfig | null => this.#call(() => this.#client.calendarImipGet(input) as Facade.CalendarImipTransportConfig | null),
    },
  }

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
export type { HookStop } from "./error.js"
export type * from "./types.js"
export type * as Facade from "./facade-types.js"

export type { OutcomeBinding, CalibrationPair, TaskAssignee, ConsultPayloadRef, TaskAskOptionId, TaskAskTarget, TaskAskWho, TaskAskShort, TaskAskLadderPrediction, TaskAskQuestion, TaskAskElectorate, TaskAskNeed, TaskAskDecide, TaskAskDefault, TaskAskDisagree, TaskAskClass, TaskAskSpec, TaskAskHandle, TaskAskReceipt, TaskCanAskRequest, TaskAskPreflight, TaskAskPreflightRecipient, TaskAskPersonKind, TaskAskPersonEvidence, TaskAskWord, TaskAskAnswer, TaskAskCoverage, TaskAskDecision, TaskAskFallback, TaskAskEffectAuthorization, TaskAskEvidence, TaskAskSettlement, TaskAskResult, TaskAskStatus, TaskAskWait, TaskCancelReceipt, TaskDescription } from "./agent-verbs.js"
