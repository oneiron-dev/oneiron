package org.oneiron

import java.util.concurrent.atomic.AtomicBoolean

/**
 * One connection this app holds to its [EmbeddedEngine]'s server (OF-237): one in-process stream
 * the server serves as a socket's connection, HTTP/1.1 with upgrades. Write the request with
 * [send] (a `GET /ws` with its upgrade headers holds `/ws`; after the `101`, send the upgraded
 * protocol's frames, and bring your own auth) and read what the server writes with [receive].
 *
 * A [send] and a [receive] may block two app threads at once, and [close] from a third returns
 * the blocked [receive]. Every method blocks: call it from an app thread, never from an [AppHost]
 * callback. It keeps the engine's native half alive until closed; once the engine stops,
 * [receive] returns an empty array and [send] throws.
 */
class EngineConnection internal constructor(engine: EmbeddedEngine) : AutoCloseable {
    private var nativeHandle: Long = 0
    private val closed = AtomicBoolean(false)

    init { openNative(engine) }

    /** Writes all of [bytes] to the server; throws once closed or once the server ended it. */
    fun send(bytes: ByteArray) {
        check(!closed.get()) { "connection is closed" }
        sendNative(bytes)
    }

    /** The next bytes the server wrote, at most 64 KiB; empty once the connection has ended. */
    fun receive(): ByteArray {
        if (closed.get()) return ByteArray(0)
        return receiveNative()
    }

    /** Ends this side: a blocked [receive] returns empty and the server reads the end of the stream. */
    override fun close() {
        if (closed.compareAndSet(false, true)) closeNative()
    }

    private external fun openNative(engine: EmbeddedEngine)
    private external fun sendNative(bytes: ByteArray)
    private external fun receiveNative(): ByteArray
    private external fun closeNative()

    companion object {
        init { System.loadLibrary("oneiron_android") }
    }
}
