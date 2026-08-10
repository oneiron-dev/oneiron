// Compile probe for the generated UniFFI Swift bindings of the WIRE head
// contract.
//
// This file is never run. Every reference lives inside an uncalled function
// so `swift build` type-checks the entire generated surface — both
// constructors, actor rebinding, all 27 pinned verbs, every DTO's full
// memberwise initializer, and the three-field error shape — without
// executing the definition-only entrypoints. The top-level body stays
// empty on purpose: it prints no success marker and opens no vault.
//
// Any export rename, DTO field drift, optionality change, or width change
// breaks this build by construction. That, plus the Rust contract tests, is
// the whole job of this package; it is not a quickstart and wires no
// product.

import Foundation
import OneironUniFFI

// MARK: Constructors and actor rebinding

func constructorsCompile() throws {
    _ = try Oneiron.open(path: nil, options: nil)
    _ = try Oneiron.open(
        path: "/nonexistent/compile-only",
        options: OpenOptions(dimensions: 512)
    )
    _ = try Oneiron.connect(url: "https://example.invalid", key: "compile-only")
}

func actorRebindingCompiles(client: Oneiron) throws {
    let scoped: Oneiron = try client.asActor(actorKey: "human:compile-only")
    _ = scoped
}

// MARK: Tier 0

func tierZeroCompiles(client: Oneiron) throws {
    let author = WitnessAuthor.user
    let message = WitnessMessage(
        id: nil,
        author: author,
        messageType: "note",
        content: "compile-only",
        metadata: WireJson(canonicalJson: "{}"),
        isVisible: true,
        order: 0
    )
    let _: String = message.content
    let turn = WitnessTurn(
        conversationRef: "conversation:compile-only",
        turnRef: nil,
        messages: [message],
        occurredAt: nil
    )
    let _: String = turn.conversationRef

    let _: WitnessReceipt = try client.witness(turn: turn)

    let scope = RecallScope(worldRef: nil, facet: nil)
    let _: String? = scope.facet
    let pack: MemoryPack = try client.recall(
        query: "compile-only",
        effort: .standard,
        scope: scope,
        limit: 10,
        format: nil
    )
    let _: UInt32 = pack.packVersion

    let _: [FacadeReceipt] = try client.receipts(limit: 10)

    let witnessReceipt = WitnessReceipt(
        turnShortId: "turn:compile-only",
        messageShortIds: ["message:compile-only"],
        receiptRef: "receipt:compile-only"
    )
    let _: [String] = witnessReceipt.messageShortIds
}

// MARK: Claims

func claimsCompile(client: Oneiron) throws {
    let claim = ClaimInput(
        id: nil,
        predicate: "compile.only",
        subjectRef: "entity:compile-only",
        value: WireJson(canonicalJson: "\"compile-only\""),
        confidence: 0.9,
        source: "compile-only",
        worldRef: nil,
        scope: nil,
        validFrom: nil,
        validTo: nil,
        occurredAt: nil,
        learnedAt: nil,
        salience: 0.5
    )
    let _: String = claim.predicate

    let _: [CommitReceipt] = try client.commit(claims: [claim])
    let _: CommitReceipt = try client.claimUpsert(claim: claim)
    let _: CommitReceipt = try client.remember(claim: claim)
    let _: CommitReceipt = try client.claimRetract(claimRef: "claim:compile-only")
    let _: [CommitReceipt] = try client.seedClaims(claims: [claim])

    let selector = ForgetSelector(
        shortRef: "claim:compile-only",
        subjectRef: nil,
        predicate: nil
    )
    let _: String? = selector.shortRef
    let _: [CommitReceipt] = try client.forget(selector: selector)

    let filter = ClaimListFilter(
        subjectRef: "entity:compile-only",
        predicate: "compile.only",
        lifecycle: nil,
        limit: 10
    )
    let _: UInt32 = filter.limit
    let _: [ClaimView] = try client.claimList(filter: filter)
    let _: [ClaimView] = try client.claimHistory(claimRef: "claim:compile-only")

    let receipt = CommitReceipt(
        claimShortId: "claim:compile-only",
        approval: "auto",
        supersededShortId: nil,
        receiptRef: "receipt:compile-only"
    )
    let _: String = receipt.receiptRef

    let view = ClaimView(
        claimRef: "claim:compile-only",
        shortRef: "claim:compile-only",
        predicate: "compile.only",
        subjectRef: "entity:compile-only",
        value: WireJson(canonicalJson: "\"compile-only\""),
        confidence: 0.9,
        approval: "auto",
        lifecycle: "active",
        source: "compile-only",
        worldRef: nil,
        scope: nil,
        validFrom: nil,
        validTo: nil,
        salience: nil,
        stale: false
    )
    let _: Bool = view.stale
}

// MARK: Deletion and consent

func deletionAndConsentCompile(client: Oneiron) throws {
    let _: DeleteReceipt = try client.safeDelete(
        entityRef: "entity:compile-only",
        reason: .userDelete
    )
    let _: [PendingWrite] = try client.pendingWrites(limit: 10)

    let deletion = DeleteReceipt(
        existed: true,
        reason: "user_delete",
        receiptRef: nil
    )
    let _: Bool = deletion.existed

    let pending = PendingWrite(
        claimRef: "claim:compile-only",
        decisionRef: "decision:compile-only",
        createdAt: 0,
        reasonCodes: ["compile-only"],
        dreamerRunId: nil
    )
    let _: Int64 = pending.createdAt

    let facadeReceipt = FacadeReceipt(
        receiptRef: "receipt:compile-only",
        outcome: "approved",
        createdAt: 0,
        reasonCodes: ["compile-only"],
        actorClass: "human",
        actorRef: nil,
        contentKind: "claim",
        claimRef: "claim:compile-only"
    )
    let _: String = facadeReceipt.actorClass
}

// MARK: Reads and graph

func readsCompile(client: Oneiron) throws {
    let _: [EntityView] = try client.hydrate(refs: ["entity:compile-only"])
    let _: EntityView? = try client.getEntity(entityRef: "entity:compile-only")
    let _: [LexicalHit] = try client.queryBm25(query: "compile-only", limit: 10)

    let opts = NeighborOpts(edgeKind: "compile_only", minWeight: 0.5, limit: 10)
    let _: Float? = opts.minWeight
    let _: [NeighborHit] = try client.neighbors(
        entityRef: "entity:compile-only",
        opts: opts
    )

    let entity = EntityView(
        idHex: "00000000000000000000000000000000",
        shortRef: "entity:compile-only",
        kind: "concept",
        occurredStart: 0,
        occurredEnd: 0,
        learnedAt: 0,
        body: nil
    )
    let _: String = entity.idHex

    let hit = LexicalHit(
        shortId: "entity:compile-only",
        kind: "concept",
        score: 0.5,
        snippet: "compile-only"
    )
    let _: Float = hit.score

    let neighbor = NeighborHit(
        shortId: "entity:compile-only",
        kind: "concept",
        edgeKind: "compile_only",
        weight: 1.0,
        direction: "outgoing"
    )
    let _: String = neighbor.direction
}

// MARK: Structural writes

func structuralCompile(client: Oneiron) throws {
    let field = TextIndexField(field: "title", value: "compile-only")
    let _: String = field.value
    let edge = StructuralEdgeSpec(
        edgeKind: "compile_only",
        targetRef: "entity:compile-only",
        weight: 0.25
    )
    let _: Float? = edge.weight
    let put = StructuralPutInput(
        id: nil,
        kind: "concept",
        body: WireJson(canonicalJson: "{}"),
        textFields: [field],
        edges: [edge],
        occurredAt: nil,
        learnedAt: nil
    )
    let _: String = put.kind
    let _: EntityRefReceipt = try client.putStructural(input: put)

    let receipt = EntityRefReceipt(
        entityRef: "entity:compile-only",
        idHex: "00000000000000000000000000000000",
        receiptRef: "receipt:compile-only"
    )
    let _: String = receipt.entityRef
}

// MARK: Specialized facade inputs

func specializedInputsCompile(client: Oneiron) throws {
    let checkin = HabitCheckinInput(
        habitRef: "task:compile-only",
        id: nil,
        data: nil,
        occurredAt: nil,
        learnedAt: nil
    )
    let _: String = checkin.habitRef
    let _: EntityRefReceipt = try client.putHabitCheckin(input: checkin)

    let companion = CompanionRecordInput(
        id: nil,
        ownerRef: "person:compile-only",
        personaRef: "persona:compile-only",
        value: WireJson(canonicalJson: "{}"),
        source: "compile-only",
        retiredAt: nil,
        learnedAt: 0
    )
    let _: String = companion.personaRef
    let _: EntityRefReceipt = try client.putCompanionRecord(input: companion)

    let imported = AdmitImportedClaimInput(
        sourceId: "compile-only",
        sourceRecordId: "compile-only",
        id: nil,
        subjectRef: "entity:compile-only",
        predicate: "compile.only",
        value: WireJson(canonicalJson: "\"compile-only\""),
        occurredAt: nil,
        learnedAt: nil
    )
    let _: String = imported.sourceId
    let _: CommitReceipt = try client.admitImportedClaim(input: imported)
}

// MARK: Blob bytes

func blobBytesCompile(client: Oneiron) throws {
    let artifact = BlobArtifactInput(
        id: nil,
        name: "compile-only",
        mediaType: "application/octet-stream",
        occurredAt: nil,
        learnedAt: nil
    )
    let _: String = artifact.mediaType
    let _: EntityRefReceipt = try client.putBlobArtifact(input: artifact)

    let appended: BlobVersionView = try client.appendBlobVersion(
        artifactRef: "artifact:compile-only",
        content: Data([0x00, 0x01]),
        runRef: nil,
        occurredAt: nil,
        learnedAt: nil
    )
    let read: Data? = try client.readBlobVersion(
        artifactRef: "artifact:compile-only",
        version: 1
    )
    _ = (appended, read)

    let view = BlobVersionView(
        artifactRef: "artifact:compile-only",
        version: 1,
        contentHashHex: "00",
        claimRef: "claim:compile-only",
        createdAt: 0
    )
    let _: UInt64 = view.version
}

// MARK: Recall DTO shape

func recallDtosCompile() {
    let provenance = MemoryProvenance(
        source: "compile-only",
        sourceRevisionIds: ["revision:compile-only"],
        evidenceTurnIds: ["turn:compile-only"]
    )
    let _: [String] = provenance.evidenceTurnIds
    let item = MemoryItem(
        shortId: "claim:compile-only",
        kind: "claim",
        predicate: "compile.only",
        valueText: "compile-only",
        confidence: 0.9,
        hedgeBucket: "confident",
        provenance: provenance,
        world: nil,
        facet: nil,
        salience: 0.5
    )
    let _: String = item.hedgeBucket
    let honesty = ScopeHonesty(outOfScopeWorlds: ["world:compile-only"])
    let _: [String] = honesty.outOfScopeWorlds
    let meta = RetrievalMeta(
        sparse: true,
        totalCandidates: 1,
        claimsReturned: 1,
        deepPending: nil
    )
    let _: UInt64 = meta.totalCandidates
    let pack = MemoryPack(
        items: [item],
        scopeHonesty: honesty,
        retrievalMeta: meta,
        packVersion: 1,
        rendered: "compile-only"
    )
    let _: String? = pack.rendered
    let options = OpenOptions(dimensions: nil)
    let _: UInt32? = options.dimensions
    let opaque = WireJson(canonicalJson: "{\"compile\":true}")
    let _: String = opaque.canonicalJson
}

// MARK: Dreamer jobs

func dreamerJobsCompile(client: Oneiron) throws {
    let enqueue = ConsolidationJobInput(
        scope: "compile-only",
        input: WireJson(canonicalJson: "{}"),
        runId: nil,
        dedupeKey: "compile-only",
        now: nil
    )
    let _: String = enqueue.scope
    let _: DreamerJobRef = try client.enqueueConsolidation(input: enqueue)
    let _: DreamerJobView? = try client.dreamerJobStatus(
        jobRef: "job:compile-only"
    )

    let ref = DreamerJobRef(
        jobRef: "job:compile-only",
        state: "queued",
        existing: false
    )
    let _: Bool = ref.existing
    let view = DreamerJobView(
        jobRef: "job:compile-only",
        state: "queued",
        kind: "consolidation",
        leaseOwner: nil,
        attemptCount: 0,
        runId: nil,
        lastError: nil,
        createdAt: 0,
        updatedAt: 0
    )
    let _: UInt32 = view.attemptCount
}

// MARK: Outbound (scheduling only)

func outboundCompile(client: Oneiron) throws {
    let draft = OutboundDraftInput(
        verb: "compile_only",
        channel: "compile-only",
        target: "compile-only",
        onBehalfOf: nil,
        contentRef: nil,
        idempotencyKey: "compile-only",
        dedupeKey: "compile-only",
        trigger: "compile-only",
        triggerRef: "compile-only",
        jobRef: nil,
        occurredAt: nil
    )
    let _: String = draft.trigger
    let _: OutboundIntentReceipt = try client.scheduleOutbound(draft: draft)

    let intent = OutboundIntentReceipt(
        intentRef: "intent:compile-only",
        outcome: "scheduled",
        gateOutcome: "approved",
        gateDecisionRef: "receipt:compile-only",
        gateReasonCodes: ["compile-only"],
        deduped: false
    )
    let _: Bool = intent.deduped
}

// MARK: Closed vocabularies and the error shape

func closedVocabulariesCompile() {
    for effort in [Effort.minimal, .standard, .deep] {
        switch effort {
        case .minimal, .standard, .deep:
            break
        }
    }
    for author in [WitnessAuthor.user, .companion, .system] {
        switch author {
        case .user, .companion, .system:
            break
        }
    }
    for reason in [SafeDeleteReason.userDelete, .userHardDelete, .gdprDelete, .policyDelete] {
        switch reason {
        case .userDelete, .userHardDelete, .gdprDelete, .policyDelete:
            break
        }
    }
}

/// Compile-time shape check of the generated error: one variant, three
/// fields, `suggestions` never dropped. This is not a runtime thrown-error
/// test; the live Swift throw path is first-consumer scope.
func errorShapeCompiles() {
    do {
        _ = try Oneiron.open(path: nil, options: nil)
    } catch OneironError.Failure(let code, let message, let suggestions) {
        let _: String = code
        let _: String = message
        let _: [String] = suggestions
    } catch {
        let _: any Error = error
    }
}
