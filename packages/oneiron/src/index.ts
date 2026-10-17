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

  // BEGIN GENERATED FACADE VERBS
  /** Files one feedback report on a skill or run: its subject, category and evidence; the host supplies the actor. */
  report(input: Facade.ReportRequest): Facade.ReportReceipt { return this.#call(() => this.#client.report(input) as Facade.ReportReceipt) }
  readonly self = {
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
    identity: {
      /** A vault owner's tap on an identity choice card: who a person named in their conversations is. */
      answer: (input: Facade.IdentityAnswerRequest): Facade.IdentitySettled => this.#call(() => this.#client.selfIdentityAnswer(input) as Facade.IdentitySettled),
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
    },
    /** Sends one message to a person in the Direct room the caller's person and theirs share, making the room on first use. */
    message: (input: Facade.MessagePersonRequest): Facade.MessagePersonReceipt => this.#call(() => this.#client.selfMessage(input) as Facade.MessagePersonReceipt),
    grants: {
      /** Asks a person for access on the caller's behalf; the request grants nothing until the vault owner approves it. */
      ask: (input: Facade.GrantAskRequest): Facade.GrantAskReceipt => this.#call(() => this.#client.selfGrantsAsk(input) as Facade.GrantAskReceipt),
    },
    skills: {
      /** An agent saves a skill it wrote, SKILL.md and scripts together; it lands as a proposed candidate and nothing activates it. */
      save: (input: Facade.SkillSaveRequest): Facade.SkillAuthoringReceipt => this.#call(() => this.#client.selfSkillsSave(input) as Facade.SkillAuthoringReceipt),
      /** An agent forks a stored skill under its own identity, keeping its import ancestry. */
      fork: (input: Facade.SkillForkRequest): Facade.SkillAuthoringReceipt => this.#call(() => this.#client.selfSkillsFork(input) as Facade.SkillAuthoringReceipt),
      /** Every loadable callable helper skill and its call contract: what it takes and returns. */
      callables: (input: Facade.EmptyRequest = {}): Facade.CallableCardView[] => this.#call(() => this.#client.selfSkillsCallables(input) as Facade.CallableCardView[]),
    },
    decisions: {
      asks: (input: Facade.EmptyRequest = {}): Facade.DecisionAsk[] => this.#call(() => this.#client.selfDecisionsAsks(input) as Facade.DecisionAsk[]),
    },
  }
  readonly vault = {
    people: {
      /** One page of the people the caller reads, in handle order. */
      list: (input: Facade.PeopleListRequest): Facade.PeoplePage => this.#call(() => this.#client.vaultPeopleList(input) as Facade.PeoplePage),
      /** One person the vault knows, by their pr handle. */
      get: (input: Facade.PersonRequest): Facade.PersonRow => this.#call(() => this.#client.vaultPeopleGet(input) as Facade.PersonRow),
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
      /** Retracts one active claim: a deliberate withdrawal that preserves the record. */
      retract: (input: Facade.ClaimRefRequest): Facade.CommitReceipt => this.#call(() => this.#client.vaultClaimsRetract(input) as Facade.CommitReceipt),
      /** Lists claims by subject, predicate and lifecycle, with the read's narrowing receipt. */
      list: (input: Facade.ClaimListFilter): Facade.ScopedReadResult<Facade.ClaimView[]> => this.#call(() => this.#client.vaultClaimsList(input) as Facade.ScopedReadResult<Facade.ClaimView[]>),
      /** The supersession timeline of one claim, oldest first, with the read's narrowing receipt. */
      history: (input: Facade.ClaimRefRequest): Facade.ScopedReadResult<Facade.ClaimView[]> => this.#call(() => this.#client.vaultClaimsHistory(input) as Facade.ScopedReadResult<Facade.ClaimView[]>),
      /** Admits one imported-evidence claim through its ingest source's trust ceiling; the gate still decides. */
      admit: (input: Facade.AdmitImportedClaimInput): Facade.CommitReceipt => this.#call(() => this.#client.vaultClaimsAdmit(input) as Facade.CommitReceipt),
      /** Seeds claims through their individual gates, forced proposed, returning one receipt per claim. */
      seed: (input: Facade.CommitRequest): Facade.CommitReceipt[] => this.#call(() => this.#client.vaultClaimsSeed(input) as Facade.CommitReceipt[]),
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
      /** One call receipt by ref, readable by its own actor or the vault's live owner; anything else reads as none. */
      get: (input: Facade.CallReceiptRequest): Facade.CallReceipt | null => this.#call(() => this.#client.vaultReceiptsGet(input) as Facade.CallReceipt | null),
    }),
    images: {
      /** The full pixels behind an image's view handle (view, crop or zoom), recorded as a pull. */
      view: (request: Facade.ImageViewRequest): Facade.PulledImage => this.#call(() => {  const result = JSON.parse(this.#client.vaultImagesView(keyedJson(request))) as Facade.PulledImage; return result }),
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
      /** The live weave report for the bound actor, read through its own scope and the vault's weave policy for its role. */
      report: (input: Facade.WeaveReportRequest): Facade.WeaveReportView => this.#call(() => this.#client.vaultWeaveReport(input) as Facade.WeaveReportView),
      /** One of the bound actor's saved weave digests, or the newest, under the current read policy. */
      digest: (input: Facade.WeaveDigestRequest): Facade.WeaveDigestView | null => this.#call(() => this.#client.vaultWeaveDigest(input) as Facade.WeaveDigestView | null),
      lens: (input: Facade.WeaveReportRequest): Facade.GeneratedLens => this.#call(() => this.#client.vaultWeaveLens(input) as Facade.GeneratedLens),
      link: {
        /** A person labels a link in their own lens as wrong; the label teaches the loops and the link stays. */
        wrong: (input: Facade.WeaveWrongLinkRequest): Facade.WeaveLinkCorrectionView => this.#call(() => this.#client.vaultWeaveLinkWrong(input) as Facade.WeaveLinkCorrectionView),
      },
    },
    packs: {
      /** The owner installs a pack folder, or replaces the pack installed under its name; the put is the consent for its hooks. */
      put: (input: Facade.PackPutRequest): Facade.PackPutReceipt => this.#call(() => this.#client.vaultPacksPut(input) as Facade.PackPutReceipt),
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
    authority: {
      /** One page of the dated authority log audit: grants, revokes and confirms, for the owner. */
      audit: (input: Facade.AuthorityAuditQuery): Facade.AuthorityAuditPage => this.#call(() => this.#client.vaultAuthorityAudit(input) as Facade.AuthorityAuditPage),
      /** Every saved authority handoff fork alarm, for the owner. */
      handoff_alarms: Object.assign((input: Facade.EmptyRequest = {}): Facade.AuthorityHandoffAlarm[] => this.#call(() => this.#client.vaultAuthorityHandoffAlarms(input) as Facade.AuthorityHandoffAlarm[]), {
        /** The owner acknowledges one saved handoff fork alarm. */
        acknowledge: (input: Facade.HandoffAlarmRequest): Facade.AuthorityHandoffAlarm => this.#call(() => this.#client.vaultAuthorityHandoffAlarmsAcknowledge(input) as Facade.AuthorityHandoffAlarm),
      }),
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
    },
    members: {
      /** An Admin invites a live person into a shared vault at a non-root role; they join when they accept. */
      add: (input: Facade.SharedMemberAddRequest): Facade.SharedActExecutionReceipt => this.#call(() => this.#client.vaultMembersAdd(input) as Facade.SharedActExecutionReceipt),
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
    guests: {
      revoke: (input: Facade.GuestRevokeRequest): Facade.GuestRevokeResponse => this.#call(() => this.#client.vaultGuestsRevoke(input) as Facade.GuestRevokeResponse),
      /** The owner mints an ask guest's capability slip, bound to its grant, for the public key the guest generated on their own device. */
      mint_slip: (input: Facade.GuestSlipMintRequest): Facade.GuestSlipMinted => this.#call(() => this.#client.vaultGuestsMintSlip(input) as Facade.GuestSlipMinted),
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
    settings: {
      /** The owner reads the learned-setting catalog, each knob's value now, and the owner's seed and pin rows at the vault, a project or a task type. */
      learning: Object.assign((input: Facade.LearningSettingsRequest): Facade.LearningSettingsView => this.#call(() => this.#client.vaultSettingsLearning(input) as Facade.LearningSettingsView), {
        /** The owner lays one seed or pin on a learned setting at the vault, a project or a task type, replacing the row of the same key, mode and scope. */
        put: (input: Facade.LearningSettingPut): Facade.LearningSettingsView => this.#call(() => this.#client.vaultSettingsLearningPut(input) as Facade.LearningSettingsView),
        /** The owner clears one learned-setting row of a key, mode and scope. */
        clear: (input: Facade.LearningSettingClear): Facade.LearningSettingsView => this.#call(() => this.#client.vaultSettingsLearningClear(input) as Facade.LearningSettingsView),
      }),
    },
    lenses: {
      /** Stores one frozen compiled lens tree for a pack slot as this actor's proposal; it mounts only once the owner selects it. */
      propose: (input: Facade.LensProposeRequest): Facade.LensProposalReceipt => this.#call(() => this.#client.vaultLensesPropose(input) as Facade.LensProposalReceipt),
      /** The owner selects a proposed lens revision for its pack slot. */
      activate: (input: Facade.LensActivateRequest): Facade.LensActivationReceipt => this.#call(() => this.#client.vaultLensesActivate(input) as Facade.LensActivationReceipt),
      /** The owner clears a pack slot's selected lens; the pack, its skill and the proposal stay. */
      deactivate: (input: Facade.LensDeactivateRequest): Facade.LensActivationReceipt => this.#call(() => this.#client.vaultLensesDeactivate(input) as Facade.LensActivationReceipt),
      /** One page of the vault's lens proposals, each with its slot state from the owner's current selection. */
      list: (input: Facade.LensListRequest): Facade.LensListPage => this.#call(() => this.#client.vaultLensesList(input) as Facade.LensListPage),
      /** Composes the default vault lens from the named sources, read under the caller's own scope. */
      default: (input: Facade.LensDefaultRequest): Facade.ScopedReadResult<Facade.GeneratedLens> => this.#call(() => this.#client.vaultLensesDefault(input) as Facade.ScopedReadResult<Facade.GeneratedLens>),
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
    },
    artifacts: {
      /** One artifact's kind, head and versions, each with its made_by and born-from. */
      view: (request: Facade.ArtifactRefRequest): Facade.ArtifactView | null => this.#call(() => {  const result = JSON.parse(this.#client.vaultArtifactsView(keyedJson(request))) as Facade.ArtifactView | null; return result === null ? null : result }),
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
      /** Registers one blob artifact; its bytes ride vault.artifacts.append. */
      put: (input: Facade.BlobArtifactInput): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultArtifactsPut(input) as Facade.EntityRefReceipt),
      /** Appends one version of bytes to a blob artifact's append-only chain. */
      append: (input: Facade.AppendBlobVersionRequest): Facade.BlobVersionView => this.#call(() => this.#client.vaultArtifactsAppend(input) as Facade.BlobVersionView),
      /** Reads one version of a blob artifact's bytes. */
      read: (input: Facade.ReadBlobVersionRequest): Facade.BlobContent | null => this.#call(() => this.#client.vaultArtifactsRead(input) as Facade.BlobContent | null),
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
      /** Speaks one turn into the current room turn's room, through the normal witness gate. */
      speak: (input: Facade.WitnessTurn): Facade.WitnessReceipt => this.#call(() => this.#client.vaultRoomsSpeak(input) as Facade.WitnessReceipt),
      /** Files and decides a request to take part in a room or one of its threads. */
      join: (input: Facade.JoinRequest): Facade.JoinOutcome => this.#call(() => this.#client.vaultRoomsJoin(input) as Facade.JoinOutcome),
      /** One party's answer to a join that waits on it, after which the join is decided again. */
      consent: (input: Facade.ConsentAnswer): Facade.JoinOutcome => this.#call(() => this.#client.vaultRoomsConsent(input) as Facade.JoinOutcome),
      /** Publishes an agent's offer card to join a room or one of its threads, with an optional fixed deadline for a room-wide card. */
      offer: Object.assign((input: Facade.OfferDraft): Facade.OfferCard => this.#call(() => this.#client.vaultRoomsOffer(input) as Facade.OfferCard), {
        /** The room's host answers an offer card: join, or not now. */
        answer: (input: Facade.OfferAnswerRequest): Facade.OfferSettlement => this.#call(() => this.#client.vaultRoomsOfferAnswer(input) as Facade.OfferSettlement),
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
    projects: {
      /** The drafting agent proposes a project card on a source message; the card writes no project and confers no authority. */
      propose: (input: Facade.ProjectProposalRequest): Facade.ProjectProposalCard => this.#call(() => this.#client.vaultProjectsPropose(input) as Facade.ProjectProposalCard),
      /** The project cards shown in a conversation, each with its state. */
      proposals: (input: Facade.ProjectConversationRequest): Facade.ProjectCardRecord[] => this.#call(() => this.#client.vaultProjectsProposals(input) as Facade.ProjectCardRecord[]),
      /** The card's person dismisses a project card so it never mints; false when it was dismissed already. */
      dismiss_card: (input: Facade.ProjectCardRequest): Facade.ProjectCardDismissal => this.#call(() => this.#client.vaultProjectsDismissCard(input) as Facade.ProjectCardDismissal),
      /** The owner's tap that confirms a host-held project card; only the host's own door can complete it. */
      confirm: (input: Facade.ProjectCardConfirmRequest): Facade.ProjectMintReceipt => this.#call(() => this.#client.vaultProjectsConfirm(input) as Facade.ProjectMintReceipt),
      goal: {
        /** What a project's goal-intake interview starts from, for a member of its home room. */
        intake: (input: Facade.ProjectRefRequest): Facade.ProjectGoalInterviewContext => this.#call(() => this.#client.vaultProjectsGoalIntake(input) as Facade.ProjectGoalInterviewContext),
        /** The learned goal preferences proposed for a project's goal in force and not dismissed, oldest first. */
        revisions: (input: Facade.ProjectRefRequest): Facade.ProjectGoalRevisionProposal[] => this.#call(() => this.#client.vaultProjectsGoalRevisions(input) as Facade.ProjectGoalRevisionProposal[]),
        /** The owner dismisses the proposal one tradeoff question made for a project's goal; false for an identical retry. */
        dismiss: (input: Facade.ProjectGoalDismissRequest): Facade.ProjectGoalDismissReceipt => this.#call(() => this.#client.vaultProjectsGoalDismiss(input) as Facade.ProjectGoalDismissReceipt),
      },
      /** Asks the A/B tradeoff question pending on a skill proposal on a project TASK, as a visible turn in its home room. */
      route_tradeoff: (input: Facade.ProjectTradeoffRouteRequest): Facade.TaskAskReceipt => this.#call(() => this.#client.vaultProjectsRouteTradeoff(input) as Facade.TaskAskReceipt),
    },
    conversations: {
      turn: {
        /** Queues generation that resumes an incomplete assistant reply from exactly its saved text. */
        continue: (input: Facade.TurnActionRequest): Facade.TurnActionReceipt => this.#call(() => this.#client.vaultConversationsTurnContinue(input) as Facade.TurnActionReceipt),
        /** Queues a new answer to the user turn an assistant turn answered; the old reply stays. */
        retry: (input: Facade.TurnActionRequest): Facade.TurnActionReceipt => this.#call(() => this.#client.vaultConversationsTurnRetry(input) as Facade.TurnActionReceipt),
      },
    },
    companions: {
      sharing: {
        /** One contact's clearance in a companion's source vault, for the principal who controls that vault. */
        get: (input: Facade.CompanionSharingRequest): Facade.CompanionSharingView => this.#call(() => this.#client.vaultCompanionsSharingGet(input) as Facade.CompanionSharingView),
        /** The owner's standing yes to one frozen clearance offer for a companion's contact. */
        set: (input: Facade.CompanionSharingSetRequest): Facade.CompanionSharingView => this.#call(() => this.#client.vaultCompanionsSharingSet(input) as Facade.CompanionSharingView),
      },
    },
    workspace: {
      work_companion: {
        /** A workspace's work_companion policy, readable by every member it governs. */
        get: (input: Facade.WorkspaceRefRequest): Facade.WorkCompanionPolicy => this.#call(() => this.#client.vaultWorkspaceWorkCompanionGet(input) as Facade.WorkCompanionPolicy),
        /** The owner sets a workspace's work_companion policy in person. */
        set: (input: Facade.WorkCompanionSetRequest): Facade.WorkCompanionPolicy => this.#call(() => this.#client.vaultWorkspaceWorkCompanionSet(input) as Facade.WorkCompanionPolicy),
      },
    },
    graph: {
      ask: (input: Facade.GraphAskRequest): Facade.GraphAskOutcome => this.#call(() => this.#client.vaultGraphAsk(input) as Facade.GraphAskOutcome),
    },
    questions: {
      create: (input: Facade.QuestionCreateRequest): Facade.QuestionRecord => this.#call(() => this.#client.vaultQuestionsCreate(input) as Facade.QuestionRecord),
      edit: (input: Facade.QuestionEditRequest): Facade.QuestionRecord => this.#call(() => this.#client.vaultQuestionsEdit(input) as Facade.QuestionRecord),
      pause: (input: Facade.QuestionPauseRequest): Facade.QuestionPaused => this.#call(() => this.#client.vaultQuestionsPause(input) as Facade.QuestionPaused),
      read: (input: Facade.QuestionReadRequest): Facade.QuestionRecord | null => this.#call(() => this.#client.vaultQuestionsRead(input) as Facade.QuestionRecord | null),
      answers: (input: Facade.QuestionAnswersRequest): Facade.AnswerRecord[] => this.#call(() => this.#client.vaultQuestionsAnswers(input) as Facade.AnswerRecord[]),
    },
    decisions: {
      asks: {
        answer: (input: Facade.DecisionAskAnswerRequest): Facade.DecisionAsk => this.#call(() => this.#client.vaultDecisionsAsksAnswer(input) as Facade.DecisionAsk),
        climb: (input: Facade.DecisionAskClimbRequest): Facade.ResolvedRole | null => this.#call(() => this.#client.vaultDecisionsAsksClimb(input) as Facade.ResolvedRole | null),
      },
    },
    /** Commits claims through the gate, each element decided on its own; rejected elements come back rejected and do not persist. */
    commit: (input: Facade.CommitRequest): Facade.CommitReceipt[] => this.#call(() => this.#client.vaultCommit(input) as Facade.CommitReceipt[]),
    /** Commits one claim through the gate, the same as vault.claims.upsert. */
    remember: (input: Facade.ClaimInput): Facade.CommitReceipt => this.#call(() => this.#client.vaultRemember(input) as Facade.CommitReceipt),
    /** Retracts claims by exact claim or by subject and predicate; never a hard delete. */
    forget: (input: Facade.ForgetRequest): Facade.CommitReceipt[] => this.#call(() => this.#client.vaultForget(input) as Facade.CommitReceipt[]),
    /** Deletes one entity under a named reason; an owner verb that only a verified human may call. */
    delete: (input: Facade.SafeDeleteRequest): Facade.DeleteReceipt => this.#call(() => this.#client.vaultDelete(input) as Facade.DeleteReceipt),
    writes: {
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
      /** A text, or a turn's readable messages, as typed spans whose record links resolve under the caller's own read. */
      links: (input: Facade.RecordLinksRequest): Facade.RecordLinks => this.#call(() => this.#client.vaultRefsLinks(input) as Facade.RecordLinks),
    },
    search: {
      /** BM25 text search over the engine index; surfaceable claims only. */
      bm25: (input: Facade.QueryBm25Request): Facade.ScopedReadResult<Facade.LexicalHit[]> => this.#call(() => this.#client.vaultSearchBm25(input) as Facade.ScopedReadResult<Facade.LexicalHit[]>),
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
    consolidation: {
      /** Enqueues one consolidation attempt and returns its durable job reference. */
      enqueue: (input: Facade.ConsolidationEnqueueRequest): Facade.DreamerAttemptRef => this.#call(() => this.#client.vaultConsolidationEnqueue(input) as Facade.DreamerAttemptRef),
      /** Reads the status of one consolidation attempt by its durable job reference. */
      status: (input: Facade.ConsolidationStatusRequest): Facade.DreamerAttemptView | null => this.#call(() => this.#client.vaultConsolidationStatus(input) as Facade.DreamerAttemptView | null),
    },
    notes: {
      /** Creates a NOTE of a registered kind, its first authored text as its birth. */
      create: (input: Facade.CreateNoteRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultNotesCreate(input) as Facade.EntityRefReceipt),
      /** Creates a NOTE of a registered kind from an existing entity. */
      from_entity: (input: Facade.CreateNoteFromEntityRequest): Facade.EntityRefReceipt => this.#call(() => this.#client.vaultNotesFromEntity(input) as Facade.EntityRefReceipt),
      /** Edits one NOTE in a transaction-local document; a rejected edit leaves nothing pending. */
      edit: (input: Facade.EditNoteRequest): Facade.NoteEditOutcome => this.#call(() => this.#client.vaultNotesEdit(input) as Facade.NoteEditOutcome),
    },
  }
  /** Cancels one task under the ladder's `auto` default. The receipt says what stopped and what became a proposal instead. */
  cancel(taskRef: string): TaskCancelReceipt { return this.#call(() => this.#client.cancel({task_ref: taskRef}) as TaskCancelReceipt) }
  /** The TASK's spawner nudges its live run; a resend with the same key answers the first receipt. */
  steer(input: Facade.SteerRequest): Facade.SteerReceipt { return this.#call(() => this.#client.steer(input) as Facade.SteerReceipt) }
  /** Describes one task's card, or the whole TASKS section when no task is named. */
  describe(taskRef?: string): TaskDescription { return this.#call(() => this.#client.describe({task_ref: taskRef}) as TaskDescription) }
  readonly tasks = {
    /** Mints one TASK and its realizing attempt when the actor's ceiling permits, or parks it as a proposal. */
    create: (input: Facade.TaskCreateRequest): Facade.TaskCreateReceipt => this.#call(() => this.#client.tasksCreate(input) as Facade.TaskCreateReceipt),
    /** Records the owner's acknowledgement of a failed TASK; any other task stays as it was. */
    update: (input: Facade.TaskUpdateRequest): Facade.TaskUpdateReceipt => this.#call(() => this.#client.tasksUpdate(input) as Facade.TaskUpdateReceipt),
    /** Admits one person's word on an ask; the word is evidence, never approval. */
    answer: (handle: TaskAskHandle, word: TaskAskWord): Facade.TaskAskAnswer => this.#call(() => this.#client.tasksAnswer({handle, word}) as Facade.TaskAskAnswer),
    /** Owner-scoped calibration pairs for an ask: each prediction against the outcome it was bound to. */
    outcomes: (handle: TaskAskHandle): Facade.CalibrationPair[] => this.#call(() => this.#client.tasksOutcomes(handle) as Facade.CalibrationPair[]),
  }
  /** Read-only ask routing or attributed partial answers. */
  can(request: TaskCanAskRequest): TaskAskPreflight { return this.#call(() => {  const result = JSON.parse(this.#client.can(keyedJson(request))) as TaskAskPreflight; return result }) }
  /** Read-only ask routing or attributed partial answers. */
  peek(request: TaskAskHandle): TaskAskPersonEvidence[] { return this.#call(() => {  const result = JSON.parse(this.#client.peek(keyedJson(request))) as TaskAskPersonEvidence[]; return result.map(item => item) }) }
  /** Asks people or an authority a typed question and returns at admission with the ask's handle. */
  ask(...args: [spec: TaskAskSpec] | [who: TaskAskWho | undefined, what: TaskAskQuestion, until?: number | null, defaultBranch?: TaskAskDefault]): TaskAskReceipt { return this.#call(() => { const input: TaskAskSpec | TaskAskShort = args.length === 1 ? args[0] : {who: typeof args[0] === "string" ? {people: [args[0]]} : Array.isArray(args[0]) ? {people: args[0]} : args[0], what: args[1], until: args[2], default: args[3]}; return this.#client.ask(input) as TaskAskReceipt }) }
  /** Waits on an ask at a step with no other work: pending, changed, ready with its result, or a park for code mode. */
  wait(handle: TaskAskHandle, stepKey = "sdk.wait"): Facade.TaskAskWait { return this.#call(() => this.#client.wait({handle, step_key: stepKey}) as Facade.TaskAskWait) }
  readonly ai = {
    /** The model rows an ai call could use: where each runs, what it takes, its rates, and what the media meter has left. */
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
      /** Where a video job stands; a finished one answers with its clip, once. */
      poll: (input: Facade.AiVideoJobRequest): Facade.AiVideoJob => this.#call(() => this.#client.aiVideoPoll(input) as Facade.AiVideoJob),
      /** Stops a video job at its provider. */
      cancel: (input: Facade.AiVideoJobRequest): Facade.AiVideoCancelled => this.#call(() => this.#client.aiVideoCancel(input) as Facade.AiVideoCancelled),
    }),
    /** The caller's own typed question through the host's decision ladder, answered with a probability and a decision receipt. */
    verdict: (input: Facade.AiVerdictRequest): Facade.AiVerdict => this.#call(() => this.#client.aiVerdict(input) as Facade.AiVerdict),
  }
  readonly connector = {
    /** Every live catalogued connector whose name or summary matches the query. */
    list: (input: Facade.ConnectorListRequest): Facade.ConnectorEntry[] => this.#call(() => this.#client.connectorList(input) as Facade.ConnectorEntry[]),
    /** One catalogued connector by name, removed ones included. */
    status: (input: Facade.ConnectorNameRequest): Facade.ConnectorView | null => this.#call(() => this.#client.connectorStatus(input) as Facade.ConnectorView | null),
    outbound: {
      /** Schedules one send through a granted outbound connector, gated and held for delivery. */
      schedule: (input: Facade.OutboundScheduleRequest): Facade.OutboundIntentReceipt => this.#call(() => this.#client.connectorOutboundSchedule(input) as Facade.OutboundIntentReceipt),
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
