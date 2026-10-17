package org.oneiron

/** One embedded core vault. Each instance owns its native environment, or a share of an engine's. */
class EmbeddedVault private constructor() : AutoCloseable {
    private var nativeHandle: Long = 0
    private var closed = false

    /** Opens the vault at [path] on its own, with no server. */
    constructor(path: String) : this() { synchronized(this) { openNative(path) } }

    /** The vault [engine] serves: the same open vault, never opened again. */
    internal constructor(engine: EmbeddedEngine) : this() { synchronized(this) { shareNative(engine) } }

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

    @Synchronized
    override fun close() {
        if (!closed) { closeNative(); closed = true }
    }

    private external fun openNative(path: String)
    private external fun shareNative(engine: EmbeddedEngine)
    private external fun putNative(id: String, kind: Int, occurredSeconds: Long, body: ByteArray)
    private external fun getNative(id: String): ByteArray?
    private external fun closeNative()

    companion object {
        init { System.loadLibrary("oneiron_android") }
    }
}
