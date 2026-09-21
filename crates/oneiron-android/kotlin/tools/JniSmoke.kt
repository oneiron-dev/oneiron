package org.oneiron

import java.io.File

/** Native-host JNI proof; Android instrumentation remains a separate required leg. */
fun main(args: Array<String>) {
    require(args.size == 1) { "supply a scratch vault path" }
    val root = File(args[0]).absoluteFile
    val id = "0102030405060708090a0b0c0d0e0f10"
    val absent = "1112131415161718191a1b1c1d1e1f20"
    val payload = "Kotlin owns the same embedded core".toByteArray()
    EmbeddedVault(root.path).use { vault ->
        vault.put(id, 4, 1, payload)
        check(payload.contentEquals(vault.get(id)))
        check(vault.get(absent) == null)
        check(runCatching { vault.put("not-an-id", 4, 1, payload) }.isFailure)
    }
    val reopened = EmbeddedVault(root.path)
    check(payload.contentEquals(reopened.get(id)))
    reopened.close()
    reopened.close()
    check(runCatching { reopened.get(id) }.isFailure)
    println("JNI-KOTLIN-OK open/put/get/reopen/refusal/close")
}
