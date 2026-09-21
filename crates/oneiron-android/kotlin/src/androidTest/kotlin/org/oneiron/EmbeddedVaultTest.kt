package org.oneiron

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class EmbeddedVaultTest {
    @Test fun openPutGetReopen() {
        val root = File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir, "vault-${System.nanoTime()}")
        val id = "0102030405060708090a0b0c0d0e0f10"
        val payload = "same core, Android JNI".toByteArray()
        try {
            EmbeddedVault(root.absolutePath).use { vault ->
                vault.put(id, 4, 1, payload)
                assertArrayEquals(payload, vault.get(id))
                assertNull(vault.get("1112131415161718191a1b1c1d1e1f20"))
            }
            EmbeddedVault(root.absolutePath).use { assertArrayEquals(payload, it.get(id)) }
        } finally { root.deleteRecursively() }
    }
}
