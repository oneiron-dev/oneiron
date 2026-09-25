package org.oneiron

/** One embedded core vault. Each instance owns its native environment. */
class EmbeddedVault(path: String) : AutoCloseable {
    private var nativeHandle: Long = 0
    private var closed = false

    init { synchronized(this) { openNative(path) } }

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
    private external fun putNative(id: String, kind: Int, occurredSeconds: Long, body: ByteArray)
    private external fun getNative(id: String): ByteArray?
    private external fun closeNative()

    companion object {
        init { System.loadLibrary("oneiron_android") }
    }
}
