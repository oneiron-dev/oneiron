package org.oneiron

/**
 * An [EmbeddedEngine] or [EngineConnection] failure, by its stable cause (OF-237): [code] is
 * `ENGINE_STOPPED`, `ENGINE_CLOSED`, `ENGINE_RELAY_REFUSED`, `ENGINE_WRONG_THREAD`,
 * `ENGINE_CONFIG`, `ENGINE_VAULT_OPEN`, `ENGINE_START_FAILED`, `ENGINE_CONNECTION_ENDED`,
 * `ENGINE_REPLY_TOO_LARGE`, `ENGINE_BAD_REQUEST`, or `INTERNAL_SERVER_ERROR` when no cause is
 * named, the same code every binding raises. It is an [IllegalStateException], as every other
 * native failure is.
 */
class EngineException(val code: String, message: String) : IllegalStateException(message)
