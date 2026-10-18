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

/** One vector search hit ([EmbeddedVault.searchVector]): the hex entity [id] and its [score]. */
class ScoredEntity(val id: String, val score: Float)

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
    private external fun closeNative()

    companion object {
        init { System.loadLibrary("oneiron_android") }
    }
}
