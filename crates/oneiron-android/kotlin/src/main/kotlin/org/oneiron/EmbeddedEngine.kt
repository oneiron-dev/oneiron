package org.oneiron

import java.util.concurrent.atomic.AtomicBoolean

/** One reply of [EmbeddedEngine.request]; a 4xx or 5xx status is a reply, not an error. */
class EngineReply(
    val status: Int,
    val headerNames: Array<String>,
    val headerValues: Array<ByteArray>,
    val body: ByteArray,
)

/**
 * The full Oneiron server inside this app's process, over the vault at [path] (OF-237). The
 * plain [EmbeddedVault] constructor stays beside it, a vault with no server.
 *
 * The config is the one `oneiron serve --config <configFile>` resolves for this path, with
 * [dimensions] when it is not 0. A [memoryBytes] or [cpuMillisPerSecond] of 0 is unbounded.
 * The constructor returns once [AppHost.ready] has run.
 *
 * Every method blocks: call it from an app thread, never from an [AppHost] callback, and call
 * [close] before letting the engine go. No method holds this object's monitor, so a callback
 * that runs while a call blocks never waits on it.
 */
class EmbeddedEngine(
    path: String,
    host: AppHost,
    configFile: String? = null,
    dimensions: Int = 0,
    memoryBytes: Long = 0,
    cpuMillisPerSecond: Int = 0,
) : AutoCloseable {
    private var nativeHandle: Long = 0
    private val closed = AtomicBoolean(false)

    init { startNative(path, host, configFile, dimensions, memoryBytes, cpuMillisPerSecond) }

    /**
     * One buffered HTTP/1.1 request over a fresh in-process stream. Headers pass through as
     * given (bring your own auth); `/ws` and other upgrades, and a reply body over 64 MiB, throw.
     */
    fun request(
        method: String,
        path: String,
        headers: List<Pair<String, ByteArray>> = emptyList(),
        body: ByteArray = ByteArray(0),
    ): EngineReply {
        check(!closed.get()) { "engine is closed" }
        val names = Array(headers.size) { headers[it].first }
        val values = Array(headers.size) { headers[it].second }
        return requestNative(method, path, names, values, body)
    }

    /** The app's timer fired, or a push arrived: run what is due; a stopped engine serves again first. */
    fun wake() {
        check(!closed.get()) { "engine is closed" }
        wakeNative()
    }

    /** The app is backgrounding: drain, stop every worker, keep the vault open for the next [wake]. */
    fun stop() {
        check(!closed.get()) { "engine is closed" }
        stopNative()
    }

    /** The engine's own vault, shared rather than opened again; close it on its own. */
    fun vault(): EmbeddedVault {
        check(!closed.get()) { "engine is closed" }
        return EmbeddedVault(this)
    }

    /** Stops the engine in order and releases it; a vault from [vault] stays open until closed. */
    override fun close() {
        if (closed.compareAndSet(false, true)) closeNative()
    }

    private external fun startNative(
        path: String,
        host: AppHost,
        configFile: String?,
        dimensions: Int,
        memoryBytes: Long,
        cpuMillisPerSecond: Int,
    )
    private external fun requestNative(
        method: String,
        path: String,
        headerNames: Array<String>,
        headerValues: Array<ByteArray>,
        body: ByteArray,
    ): EngineReply
    private external fun wakeNative()
    private external fun stopNative()
    private external fun closeNative()

    companion object {
        init { System.loadLibrary("oneiron_android") }
    }
}
