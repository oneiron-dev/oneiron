package org.oneiron

/**
 * One stored edge ([EmbeddedVault.edgesOut], [EmbeddedVault.edgesIn]): [src] to [target], both
 * 32-character hex entity ids, of the wire [kind], with its [weight], its creation time
 * [createdAt], and its [vad] (valence, arousal, dominance) when it carries one.
 */
class VaultEdge(
    val src: String,
    val kind: Int,
    val target: String,
    val weight: Float,
    val createdAt: Long,
    val vad: FloatArray?,
)

/** One search hit ([EmbeddedVault.searchVector], [EmbeddedVault.searchText]): the hex entity [id] and its [score]. */
class ScoredEntity(val id: String, val score: Float)

/** One [EmbeddedVault.subtree] entry: a descendant's hex [id] and its [depth] below the root. */
class SubtreeEntry(val id: String, val depth: Int)

/**
 * One embedded core vault. Each instance owns its native environment, or a share of an engine's.
 * A plain vault writes as the host; one from [bound] writes as the caller it names (OF-063):
 * its [put], [delete], [putEdge] and [putVector] run that caller's doors. Reads are the same on
 * every vault. Refusals throw `IllegalStateException`.
 */
class EmbeddedVault private constructor() : AutoCloseable {
    private var nativeHandle: Long = 0
    private var closed = false

    /** Opens the vault at [path] on its own, with no server. */
    constructor(path: String) : this() { synchronized(this) { openNative(path) } }

    /** The vault [engine] serves: the same open vault, never opened again. */
    internal constructor(engine: EmbeddedEngine) : this() { synchronized(this) { shareNative(engine) } }

    private constructor(source: EmbeddedVault, actorKey: String?, session: String?) : this() {
        synchronized(this) { bindNative(source, actorKey, session) }
    }

    /**
     * A NEW vault over this same open vault whose writes run as one caller (OF-063): the
     * principal [actorKey] names (`human:<ref>`, `agent:<ref>` or `system:<ref>`), or the
     * embedded owner when it is null, inside the off-record session [session] names, or outside
     * any when it is null. This vault is unchanged; close the new one on its own.
     */
    @Synchronized
    fun bound(actorKey: String? = null, session: String? = null): EmbeddedVault {
        check(!closed) { "vault is closed" }
        return EmbeddedVault(this, actorKey, session)
    }

    @Synchronized
    fun put(id: String, kind: Int, occurredSeconds: Long, body: ByteArray) {
        check(!closed) { "vault is closed" }
        putNative(id, kind, occurredSeconds, body)
    }

    @Synchronized
    fun get(id: String): ByteArray? {
        check(!closed) { "vault is closed" }
        return getNative(id)
    }

    /**
     * Deletes the entity [id] names and answers whether one was there. A bound vault deletes
     * as its caller through the `vault.delete` door: owner-only, and an id naming no record
     * throws.
     */
    @Synchronized
    fun delete(id: String): Boolean {
        check(!closed) { "vault is closed" }
        return deleteNative(id)
    }

    /** Stores the directed edge [src] to [target] of the wire edge [kind]. */
    @Synchronized
    fun putEdge(src: String, kind: Int, target: String, weight: Float) {
        check(!closed) { "vault is closed" }
        putEdgeNative(src, kind, target, weight)
    }

    /** The edges out of [src]. */
    @Synchronized
    fun edgesOut(src: String): Array<VaultEdge> {
        check(!closed) { "vault is closed" }
        return edgesNative(src, false)
    }

    /** The edges into [target]. */
    @Synchronized
    fun edgesIn(target: String): Array<VaultEdge> {
        check(!closed) { "vault is closed" }
        return edgesNative(target, true)
    }

    /** Stores [id]'s embedding; its length must be the vault's dimensions. */
    @Synchronized
    fun putVector(id: String, vector: FloatArray) {
        check(!closed) { "vault is closed" }
        putVectorNative(id, vector)
    }

    /** The [limit] (at most 1000) entities nearest [query], best first. */
    @Synchronized
    fun searchVector(query: FloatArray, limit: Int = 10): Array<ScoredEntity> {
        check(!closed) { "vault is closed" }
        return searchVectorNative(query, limit)
    }

    /**
     * A context pack over [text] and [vector] as UTF-8 in [format] (`json` when null or unknown;
     * `yaml`, `toon`, `markdown`, `plaintext`), at most [limit] (at most 1000) items, as the C
     * ABI's `oneiron_vault_context_pack` packs it.
     */
    @Synchronized
    fun contextPack(
        text: String? = null,
        vector: FloatArray? = null,
        limit: Int = 10,
        format: String? = null,
    ): String {
        check(!closed) { "vault is closed" }
        return contextPackNative(text, vector, limit, format)
    }

    /** The [limit] (at most 1000) best BM25 text matches for [query], best first. */
    @Synchronized
    fun searchText(query: String, limit: Int = 10): Array<ScoredEntity> {
        check(!closed) { "vault is closed" }
        return searchTextNative(query, limit)
    }

    /** The hex ids [src]'s wire [kind] edges point to, only of entity type [targetType] when given. */
    @Synchronized
    fun targets(src: String, kind: Int, targetType: Int? = null): Array<String> {
        check(!closed) { "vault is closed" }
        return targetsNative(src, kind, targetType != null, targetType ?: 0)
    }

    /** The hex ids whose wire [kind] edges point to [target], only of entity type [sourceType] when given. */
    @Synchronized
    fun sources(target: String, kind: Int, sourceType: Int? = null): Array<String> {
        check(!closed) { "vault is closed" }
        return sourcesNative(target, kind, sourceType != null, sourceType ?: 0)
    }

    /** [root]'s `ChildOf` descendants, at most [maxDepth] levels down, each with its depth. */
    @Synchronized
    fun subtree(root: String, maxDepth: Int): Array<SubtreeEntry> {
        check(!closed) { "vault is closed" }
        return subtreeNative(root, maxDepth)
    }

    /** [node]'s `ChildOf` ancestors, as hex ids. */
    @Synchronized
    fun ancestors(node: String): Array<String> {
        check(!closed) { "vault is closed" }
        return ancestorsNative(node)
    }

    @Synchronized
    override fun close() {
        if (!closed) { closeNative(); closed = true }
    }

    private external fun openNative(path: String)
    private external fun shareNative(engine: EmbeddedEngine)
    private external fun bindNative(source: EmbeddedVault, actorKey: String?, session: String?)
    private external fun putNative(id: String, kind: Int, occurredSeconds: Long, body: ByteArray)
    private external fun getNative(id: String): ByteArray?
    private external fun deleteNative(id: String): Boolean
    private external fun putEdgeNative(src: String, kind: Int, target: String, weight: Float)
    private external fun edgesNative(id: String, inbound: Boolean): Array<VaultEdge>
    private external fun putVectorNative(id: String, vector: FloatArray)
    private external fun searchVectorNative(query: FloatArray, limit: Int): Array<ScoredEntity>
    private external fun contextPackNative(text: String?, vector: FloatArray?, limit: Int, format: String?): String
    private external fun searchTextNative(query: String, limit: Int): Array<ScoredEntity>
    private external fun targetsNative(src: String, kind: Int, hasType: Boolean, targetType: Int): Array<String>
    private external fun sourcesNative(target: String, kind: Int, hasType: Boolean, sourceType: Int): Array<String>
    private external fun subtreeNative(root: String, maxDepth: Int): Array<SubtreeEntry>
    private external fun ancestorsNative(node: String): Array<String>
    private external fun closeNative()

    companion object {
        init { System.loadLibrary("oneiron_android") }
    }
}
