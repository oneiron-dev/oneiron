package org.oneiron

/**
 * What the app brings an [EmbeddedEngine]: its keychain, its wake timer and its readiness
 * signal. The engine calls these on threads of its own, so an implementation must be safe to
 * call from any thread. It must not call back into the engine: such a call throws.
 */
interface AppHost {
    /** One secret from the app keychain by exact name, or null when it holds none. */
    fun keychain(name: String): ByteArray?

    /** Arms the app's timer for [atUnixMs], or clears it on null; when it fires, call [EmbeddedEngine.wake]. */
    fun scheduleWake(atUnixMs: Long?)

    /** The engine opened its vault and takes requests. */
    fun ready()
}
