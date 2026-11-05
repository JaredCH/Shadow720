package com.shadow720.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Opens the vault from a process that has no Tauri application.
 *
 * The foreground service outlives the activity, and Android restarts it in a fresh
 * process after a low-memory kill. In that process the Tauri plugin that owns the
 * Keystore is not registered, so the Rust core cannot unwrap the vault password
 * through it. This object does the unwrap with the platform Keystore directly and
 * hands the bytes to [NativePublisher.bootHeadless].
 *
 * The blob layout and key parameters must match `KeystoreVaultPlugin.kt` exactly:
 * version(1) ‖ ivLen(1) ‖ iv ‖ ciphertext+tag, AES-256-GCM under the alias
 * `shadow720.vault.wrap`. If either side changes, both must change together.
 */
object HeadlessVault {
    /** Must match `KEY_ALIAS` in `keystore_android.rs`. */
    private const val KEY_ALIAS = "shadow720.vault.wrap"

    /** Must match `WRAP_FILENAME` in `vault.rs`. */
    private const val WRAP_FILENAME = "shadow720.vaultpw"

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val FORMAT_VERSION: Byte = 1

    /**
     * Open the vault so the service can publish without the app running.
     *
     * Returns `true` when the core now holds an open vault and a joined group.
     * `false` is not fatal: the service keeps running and retries on the next
     * start, which covers the case where the user has not joined a group yet.
     */
    fun boot(vaultDir: File): Boolean {
        val wrapped = File(vaultDir, WRAP_FILENAME)
        if (!wrapped.exists()) {
            // No vault yet: the user has never completed setup on this device.
            return false
        }

        return try {
            val password = unwrap(wrapped.readBytes())
            NativePublisher.bootHeadless(vaultDir.absolutePath, password, KEY_ALIAS)
        } catch (error: Exception) {
            // A key invalidated by a factory reset lands here. The UI explains that
            // as "you need a fresh invite"; the service just stops publishing.
            false
        }
    }

    /** Reverse the wrap performed by `KeystoreVaultPlugin.wrapSecret`. */
    private fun unwrap(blob: ByteArray): ByteArray {
        require(blob.size >= 2) { "wrapped secret is truncated" }
        require(blob[0] == FORMAT_VERSION) { "wrapped secret has unknown version ${blob[0]}" }

        val ivLength = blob[1].toInt()
        require(ivLength > 0 && blob.size >= 2 + ivLength) { "wrapped secret has a malformed IV" }

        val iv = blob.copyOfRange(2, 2 + ivLength)
        val ciphertext = blob.copyOfRange(2 + ivLength, blob.size)

        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val key = (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: error("the device key is missing")

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }
}
