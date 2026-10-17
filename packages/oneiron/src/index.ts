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
import { NativeClient } from "./native.js"
import type * as Facade from "./facade-types.js"
import type { CalibrationPair, TaskAskAnswer, TaskAskDefault, TaskAskHandle, TaskAskPersonEvidence, TaskAskPreflight, TaskAskQuestion, TaskAskReceipt, TaskAskShort, TaskAskSpec, TaskAskWait, TaskAskWho, TaskAskWord, TaskCancelReceipt, TaskCanAskRequest, TaskDescription } from "./agent-verbs.js"

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
  MemoryExport,
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

  // BEGIN GENERATED FACADE VERBS
  report(input: Record<string, unknown>): unknown { return this.#call(() => this.#client.report(input) as unknown) }
  readonly self = {
    memory: {
      diary: Object.assign((input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfMemoryDiary(input) as unknown), {
        reads: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfMemoryDiaryReads(input) as unknown),
        review: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfMemoryDiaryReview(input) as unknown),
        query: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfMemoryDiaryQuery(input) as unknown),
      }),
    },
    identity: {
      answer: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfIdentityAnswer(input) as unknown),
      settle: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfIdentitySettle(input) as unknown),
    },
    message: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfMessage(input) as unknown),
    grants: {
      ask: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfGrantsAsk(input) as unknown),
    },
    skills: {
      save: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfSkillsSave(input) as unknown),
      fork: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfSkillsFork(input) as unknown),
      callables: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.selfSkillsCallables(input) as unknown),
    },
  }
  readonly vault = {
    people: {
      list: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultPeopleList(input) as unknown),
      get: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultPeopleGet(input) as unknown),
    },
    /**
   * Witnesses one conversational turn.
   *
   * Omitting `occurredAt` stamps the current wall clock, in Unix seconds, at
   * the call boundary.
   */
    witness: (turn: WitnessTurn): WitnessReceipt => this.#call(() => this.#client.vaultWitness(turn)),
    claims: {
      /** Upserts one claim. The consent gate, not this call, decides approval. */
      upsert: (claim: ClaimInput): CommitReceipt => this.#call(() => this.#client.vaultClaimsUpsert(claim)),
      retract: (input: Facade.ClaimRefRequest): Facade.CommitReceipt => this.#call(() => this.#client.vaultClaimsRetract(input) as Facade.CommitReceipt),
      list: (input: Facade.ClaimListFilter): {value: (Facade.ClaimView)[]; narrowing: unknown} => this.#call(() => this.#client.vaultClaimsList(input) as {value: (Facade.ClaimView)[]; narrowing: unknown}),
      history: (input: Facade.ClaimRefRequest): {value: (Facade.ClaimView)[]; narrowing: unknown} => this.#call(() => this.#client.vaultClaimsHistory(input) as {value: (Facade.ClaimView)[]; narrowing: unknown}),
      admit: (input: Facade.AdmitImportedClaimInput): Facade.CommitReceipt => this.#call(() => this.#client.vaultClaimsAdmit(input) as Facade.CommitReceipt),
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
   */
    recall: (query: string, opts: RecallOptions = {}): MemoryPack => this.#call(() => this.#client.vaultRecall(query, opts.effort ?? "medium", opts.scope, opts.limit ?? 10, opts.format, opts.asOf, opts.deadlineMs)),
    /** Exports the whole vault as one re-importable archive (ZIP, base64 in `archive`). */
    export: (format?: string): MemoryExport => this.#call(() => this.#client.vaultExport({format: format}) as MemoryExport),
    /** Governance receipts, newest first. */
    receipts: Object.assign((limit: number = 100): FacadeReceipt[] => this.#call(() => this.#client.vaultReceipts(limit)), {
      get: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultReceiptsGet(input) as unknown),
    }),
    images: {
      /** The full pixels behind an image's view handle (view, crop or zoom), recorded as a pull. */
      view: (request: ImageViewRequest): PulledImage => this.#call(() => {  const result = JSON.parse(this.#client.vaultImagesView(keyedJson(request))) as PulledImage; return result }),
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
    weave: {
      report: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultWeaveReport(input) as unknown),
      digest: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultWeaveDigest(input) as unknown),
      lens: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultWeaveLens(input) as unknown),
      link: {
        wrong: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultWeaveLinkWrong(input) as unknown),
      },
    },
    packs: {
      put: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultPacksPut(input) as unknown),
      setup: {
        prepare: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultPacksSetupPrepare(input) as unknown),
        get: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultPacksSetupGet(input) as unknown),
        answer: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultPacksSetupAnswer(input) as unknown),
        verify: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultPacksSetupVerify(input) as unknown),
      },
    },
    authority: {
      audit: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultAuthorityAudit(input) as unknown),
      handoff_alarms: Object.assign((input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultAuthorityHandoffAlarms(input) as unknown), {
        acknowledge: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultAuthorityHandoffAlarmsAcknowledge(input) as unknown),
      }),
    },
    inspection: {
      resolve: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultInspectionResolve(input) as unknown),
    },
    shared: {
      propose_delete: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharedProposeDelete(input) as unknown),
      propose_transfer: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharedProposeTransfer(input) as unknown),
      propose_remove_owner: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharedProposeRemoveOwner(input) as unknown),
      execute: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharedExecute(input) as unknown),
      receipt: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharedReceipt(input) as unknown),
      outcomes: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharedOutcomes(input) as unknown),
      deletion: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharedDeletion(input) as unknown),
    },
    members: {
      add: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultMembersAdd(input) as unknown),
      change: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultMembersChange(input) as unknown),
      remove: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultMembersRemove(input) as unknown),
      leave: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultMembersLeave(input) as unknown),
    },
    guests: {
      revoke: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultGuestsRevoke(input) as unknown),
    },
    legal_holds: {
      place: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLegalHoldsPlace(input) as unknown),
      widen: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLegalHoldsWiden(input) as unknown),
      list: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLegalHoldsList(input) as unknown),
      log: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLegalHoldsLog(input) as unknown),
      lift_and_erase: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLegalHoldsLiftAndErase(input) as unknown),
    },
    lenses: {
      propose: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLensesPropose(input) as unknown),
      activate: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLensesActivate(input) as unknown),
      deactivate: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLensesDeactivate(input) as unknown),
      list: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLensesList(input) as unknown),
      default: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultLensesDefault(input) as unknown),
    },
    disclosure: {
      offer: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultDisclosureOffer(input) as unknown),
    },
    shares: {
      create: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharesCreate(input) as unknown),
      revoke: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharesRevoke(input) as unknown),
      view: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultSharesView(input) as unknown),
    },
    hooks: {
      replay: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultHooksReplay(input) as unknown),
    },
    artifacts: {
      /** One artifact's kind, head and versions, each with its made_by and born-from. */
      view: (request: ArtifactRefRequest): ArtifactView | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsView(keyedJson(request))) as ArtifactView | null; return result === null ? null : result }),
      /** One version's export file (base64), with its pinned name and media type. */
      export: (request: ArtifactExportRequest): ArtifactExportFile | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsExport(keyedJson(request))) as ArtifactExportFile | null; return result === null ? null : result }),
      /** The artifacts and versions a task, ask, run, skill or agent run produced. */
      born_from: (request: BornFromRequest): BornFromView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsBornFrom(keyedJson(request))) as BornFromView; return result }),
      /** The proposals waiting beside one artifact for Keep or Discard. */
      proposals: (request: ArtifactRefRequest): PendingProposalView[] => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsProposals(keyedJson(request))) as PendingProposalView[]; return result.map(item => item) }),
      /** The organ calls held beside one artifact until one of your nodes can run them, each with why it waits. */
      waits: (request: ArtifactRefRequest): OrganWaitView[] => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsWaits(keyedJson(request))) as OrganWaitView[]; return result.map(item => item) }),
      /** Lets one held organ call go, by its run ref, under the consent a Discard needs. */
      release_wait: (request: ProposalSettleRequest): ReleasedWait => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsReleaseWait(keyedJson(request))) as ReleasedWait; return result }),
      /** Reviews an artifact's slides through the host's decision ladder and holds the comments as one proposal for Keep. */
      review_slides: (request: SlideReviewSubmit): SlideReviewOutcome => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsReviewSlides(keyedJson(request))) as SlideReviewOutcome; return result }),
      /** Runs one native deck transaction over the head and holds the proposal for Keep. */
      propose_deck: (request: DeckProposeRequest): DeckProposeOutcome => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsProposeDeck(keyedJson(request))) as DeckProposeOutcome; return result }),
      /** Offers one native organ result as the artifact's next version, held for Keep. */
      propose_output: (request: NativeOutputRequest): PendingProposalView => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsProposeOutput(keyedJson(request))) as PendingProposalView; return result }),
      /** Keeps one waiting proposal as a new version, once, with its receipt. */
      keep: (request: ProposalSettleRequest): KeptProposal => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsKeep(keyedJson(request))) as KeptProposal; return result }),
      /** Discards one waiting proposal, once, with its receipt. */
      discard: (request: ProposalSettleRequest): DiscardedProposal => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsDiscard(keyedJson(request))) as DiscardedProposal; return result }),
      /** Undoes one Keep with a new version; the settle stays consumed. */
      undo: (request: ProposalSettleRequest): UndoneKeep => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsUndo(keyedJson(request))) as UndoneKeep; return result }),
      put: (input: Facade.BlobArtifactInput): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultArtifactsPut(input) as Facade.EntityRefReceipt),
      append: (input: Facade.AppendBlobVersionRequest): Facade.BlobVersionView => this.#call(() => this.#client.vaultArtifactsAppend(input) as Facade.BlobVersionView),
      read: (input: Facade.ReadBlobVersionRequest): Facade.BlobContent | null => this.#call(() => this.#client.vaultArtifactsRead(input) as Facade.BlobContent | null),
    },
    rooms: {
      list: (): unknown[] => this.#call(() => this.#client.vaultRoomsList({}) as unknown[]),
      messages: (roomRef: string, after?: string, limit?: number): {rows: unknown[]; next_after: string | null} => this.#call(() => this.#client.vaultRoomsMessages({room_ref: roomRef, after, limit}) as {rows: unknown[]; next_after: string | null}),
      participants: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsParticipants(input) as unknown),
      render: (roomRef: string): string[] => this.#call(() => this.#client.vaultRoomsRender({room_ref: roomRef}) as string[]),
      find: (roomRef: string, after?: string, limit?: number): {rows: unknown[]; next_after: string | null} => this.#call(() => this.#client.vaultRoomsFind({room_ref: roomRef, after, limit}) as {rows: unknown[]; next_after: string | null}),
      get: (roomRef: string, turnRef: string): unknown => this.#call(() => this.#client.vaultRoomsGet({room_ref: roomRef, turn_ref: turnRef}) as unknown),
      trunk: (roomRef: string, turnRef: string): unknown => this.#call(() => this.#client.vaultRoomsTrunk({room_ref: roomRef, turn_ref: turnRef}) as unknown),
      reply_strips: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsReplyStrips(input) as unknown),
      claim: (roomRef: string, turnRef: string): unknown => this.#call(() => this.#client.vaultRoomsClaim({room_ref: roomRef, turn_ref: turnRef}) as unknown),
      speak: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsSpeak(input) as unknown),
      join: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsJoin(input) as unknown),
      consent: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsConsent(input) as unknown),
      offer: Object.assign((input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsOffer(input) as unknown), {
        answer: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsOfferAnswer(input) as unknown),
      }),
      offers: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsOffers(input) as unknown),
      host: Object.assign((input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsHost(input) as unknown), {
        pin: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsHostPin(input) as unknown),
        hand: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsHostHand(input) as unknown),
      }),
      sharing: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRoomsSharing(input) as unknown),
    },
    projects: {
      propose: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultProjectsPropose(input) as unknown),
      proposals: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultProjectsProposals(input) as unknown),
      dismiss_card: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultProjectsDismissCard(input) as unknown),
      confirm: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultProjectsConfirm(input) as unknown),
      goal: {
        intake: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultProjectsGoalIntake(input) as unknown),
        revisions: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultProjectsGoalRevisions(input) as unknown),
        dismiss: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultProjectsGoalDismiss(input) as unknown),
      },
      route_tradeoff: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultProjectsRouteTradeoff(input) as unknown),
    },
    conversations: {
      turn: {
        continue: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultConversationsTurnContinue(input) as unknown),
        retry: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultConversationsTurnRetry(input) as unknown),
      },
    },
    companions: {
      sharing: {
        get: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultCompanionsSharingGet(input) as unknown),
        set: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultCompanionsSharingSet(input) as unknown),
      },
    },
    workspace: {
      work_companion: {
        get: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultWorkspaceWorkCompanionGet(input) as unknown),
        set: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultWorkspaceWorkCompanionSet(input) as unknown),
      },
    },
    graph: {
      ask: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultGraphAsk(input) as unknown),
    },
    questions: {
      create: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultQuestionsCreate(input) as unknown),
      edit: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultQuestionsEdit(input) as unknown),
      pause: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultQuestionsPause(input) as unknown),
      read: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultQuestionsRead(input) as unknown),
      answers: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultQuestionsAnswers(input) as unknown),
    },
    commit: (input: Facade.CommitRequest): (Facade.CommitReceipt)[] => this.#call(() => this.#client.vaultCommit(input) as (Facade.CommitReceipt)[]),
    remember: (input: Facade.ClaimInput): Facade.CommitReceipt => this.#call(() => this.#client.vaultRemember(input) as Facade.CommitReceipt),
    forget: (input: Facade.ForgetRequest): (Facade.CommitReceipt)[] => this.#call(() => this.#client.vaultForget(input) as (Facade.CommitReceipt)[]),
    delete: (input: Facade.SafeDeleteRequest): Facade.DeleteReceipt => this.#call(() => this.#client.vaultDelete(input) as Facade.DeleteReceipt),
    writes: {
      pending: (input: Facade.ReceiptsRequest): (Facade.PendingWrite)[] => this.#call(() => this.#client.vaultWritesPending(input) as (Facade.PendingWrite)[]),
    },
    hydrate: (input: Facade.HydrateRequest): {value: (Facade.EntityView)[]; narrowing: unknown} => this.#call(() => this.#client.vaultHydrate(input) as {value: (Facade.EntityView)[]; narrowing: unknown}),
    get: (input: Facade.EntityRequest): {value: Facade.EntityView | null; narrowing: unknown} => this.#call(() => this.#client.vaultGet(input) as {value: Facade.EntityView | null; narrowing: unknown}),
    refs: {
      resolve: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRefsResolve(input) as unknown),
      links: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.vaultRefsLinks(input) as unknown),
    },
    search: {
      bm25: (input: Facade.QueryBm25Request): {value: (Facade.LexicalHit)[]; narrowing: unknown} => this.#call(() => this.#client.vaultSearchBm25(input) as {value: (Facade.LexicalHit)[]; narrowing: unknown}),
    },
    neighbors: (input: Facade.NeighborsRequest): {value: (Facade.NeighborHit)[]; narrowing: unknown} => this.#call(() => this.#client.vaultNeighbors(input) as {value: (Facade.NeighborHit)[]; narrowing: unknown}),
    structural: {
      put: (input: Facade.StructuralPutInput): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultStructuralPut(input) as Facade.EntityRefReceipt),
    },
    habits: {
      checkin: (input: Facade.HabitCheckinInput): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultHabitsCheckin(input) as Facade.EntityRefReceipt),
    },
    notes: {
      create: (input: Facade.CreateNoteRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultNotesCreate(input) as Facade.EntityRefReceipt),
      from_entity: (input: Facade.CreateNoteFromEntityRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultNotesFromEntity(input) as Facade.EntityRefReceipt),
      edit: (input: Facade.EditNoteRequest): unknown => this.#call(() => this.#client.vaultNotesEdit(input) as unknown),
    },
  }
  /** Cancels one task under the ladder's `auto` default. The receipt says what stopped and what became a proposal instead. */
  cancel(taskRef: string): TaskCancelReceipt { return this.#call(() => this.#client.cancel({task_ref: taskRef}) as TaskCancelReceipt) }
  steer(input: Record<string, unknown>): unknown { return this.#call(() => this.#client.steer(input) as unknown) }
  /** Describes one task's card, or the whole TASKS section when no task is named. */
  describe(taskRef?: string): TaskDescription { return this.#call(() => this.#client.describe({task_ref: taskRef}) as TaskDescription) }
  readonly tasks = {
    create: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.tasksCreate(input) as unknown),
    update: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.tasksUpdate(input) as unknown),
    answer: (handle: TaskAskHandle, word: TaskAskWord): TaskAskAnswer => this.#call(() => this.#client.tasksAnswer({handle, word}) as TaskAskAnswer),
    outcomes: (handle: TaskAskHandle): CalibrationPair[] => this.#call(() => this.#client.tasksOutcomes(handle) as CalibrationPair[]),
  }
  /** Read-only ask routing or attributed partial answers. */
  can(request: TaskCanAskRequest): TaskAskPreflight { return this.#call(() => {  const result = JSON.parse(this.#client.can(keyedJson(request))) as TaskAskPreflight; return result }) }
  /** Read-only ask routing or attributed partial answers. */
  peek(request: TaskAskHandle): TaskAskPersonEvidence[] { return this.#call(() => {  const result = JSON.parse(this.#client.peek(keyedJson(request))) as TaskAskPersonEvidence[]; return result.map(item => item) }) }
  ask(...args: [spec: TaskAskSpec] | [who: TaskAskWho | undefined, what: TaskAskQuestion, until?: number | null, defaultBranch?: TaskAskDefault]): TaskAskReceipt { return this.#call(() => { const input: TaskAskSpec | TaskAskShort = args.length === 1 ? args[0] : {who: typeof args[0] === "string" ? {people: [args[0]]} : Array.isArray(args[0]) ? {people: args[0]} : args[0], what: args[1], until: args[2], default: args[3]}; return this.#client.ask(input) as TaskAskReceipt }) }
  wait(handle: TaskAskHandle, stepKey = "sdk.wait"): TaskAskWait { return this.#call(() => this.#client.wait({handle, step_key: stepKey}) as TaskAskWait) }
  readonly ai = {
    options: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.aiOptions(input) as unknown),
    image: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.aiImage(input) as unknown),
    speech: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.aiSpeech(input) as unknown),
    transcribe: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.aiTranscribe(input) as unknown),
    embed: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.aiEmbed(input) as unknown),
    video: Object.assign((input: Record<string, unknown>): unknown => this.#call(() => this.#client.aiVideo(input) as unknown), {
      poll: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.aiVideoPoll(input) as unknown),
      cancel: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.aiVideoCancel(input) as unknown),
    }),
    verdict: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.aiVerdict(input) as unknown),
  }
  readonly connector = {
    list: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.connectorList(input) as unknown),
    status: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.connectorStatus(input) as unknown),
    outbound: {
      schedule: (input: Record<string, unknown>): unknown => this.#call(() => this.#client.connectorOutboundSchedule(input) as unknown),
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
export type * from "./types.js"
export type * as Facade from "./facade-types.js"

export type { OutcomeBinding, CalibrationPair, TaskAssignee, ConsultPayloadRef, TaskAskOptionId, TaskAskTarget, TaskAskWho, TaskAskShort, TaskAskLadderPrediction, TaskAskQuestion, TaskAskElectorate, TaskAskNeed, TaskAskDecide, TaskAskDefault, TaskAskDisagree, TaskAskClass, TaskAskSpec, TaskAskHandle, TaskAskReceipt, TaskCanAskRequest, TaskAskPreflight, TaskAskPreflightRecipient, TaskAskPersonKind, TaskAskPersonEvidence, TaskAskWord, TaskAskAnswer, TaskAskCoverage, TaskAskDecision, TaskAskFallback, TaskAskEffectAuthorization, TaskAskEvidence, TaskAskSettlement, TaskAskResult, TaskAskStatus, TaskAskWait, TaskCancelReceipt, TaskDescription } from "./agent-verbs.js"
