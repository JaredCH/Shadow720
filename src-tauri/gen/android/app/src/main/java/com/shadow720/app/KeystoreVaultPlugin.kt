package com.shadow720.app

/**
 * Android Keystore plugin.
 *
 * Exposes exactly two operations to the Rust core: wrap a secret with a
 * hardware-backed key, and unwrap it again. There is deliberately **no**
 * general-purpose encryption surface, so nothing reachable from the webview can
 * ask the device to encrypt or decrypt arbitrary data.
 *
 * The only secret this is ever used on is the 32-byte vault password, which in turn
 * protects the GitHub token and the group key. Keeping the wrapping key inside the
 * secure element is what makes a copy of the app's files useless on another device.
 *
 * See `PLAN_ADDENDUM_v1.md` §A4.
 */

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
class WrapArgs {
    /** Default `""` so Glass-Easel-hosted Kotlin can be invoked without a field. */
    var plaintextB64: String = ""
    var alias: String = ""
}

@InvokeArg
class UnwrapArgs {
    var wrappedB64: String = ""
    var alias: String = ""
}

@TauriPlugin
class KeystoreVaultPlugin(private val activity: android.app.Activity) : Plugin(activity) {

    @Command
    fun wrapSecret(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(WrapArgs::class.java)
            val plaintext = Base64.decode(args.plaintextB64, Base64.NO_WRAP)
            val key = getOrCreateKey(args.alias)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)

            val ciphertext = cipher.doFinal(plaintext)
            val iv = cipher.iv

            // Layout: version(1) ‖ ivLen(1) ‖ iv ‖ ciphertext+tag.
            // The version byte lets a future key scheme be recognised rather than
            // silently mis-parsed.
            val out = ByteArray(2 + iv.size + ciphertext.size)
            out[0] = FORMAT_VERSION
            out[1] = iv.size.toByte()
            System.arraycopy(iv, 0, out, 2, iv.size)
            System.arraycopy(ciphertext, 0, out, 2 + iv.size, ciphertext.size)

            invoke.resolve(
                app.tauri.plugin.JSObject().put(
                    "wrappedB64",
                    Base64.encodeToString(out, Base64.NO_WRAP),
                ),
            )
        } catch (error: Exception) {
            // A missing or invalidated key lands here. The Rust side turns this into
            // a "vault unavailable" error, which the UI explains as "you need a
            // fresh invite".
            invoke.reject(describe(error))
        }
    }

    @Command
    fun unwrapSecret(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(UnwrapArgs::class.java)
            val blob = Base64.decode(args.wrappedB64, Base64.NO_WRAP)

            if (blob.size < 2) {
                invoke.reject("wrapped secret is truncated")
                return
            }
            if (blob[0] != FORMAT_VERSION) {
                invoke.reject("wrapped secret has unknown version ${blob[0]}")
                return
            }

            val ivLength = blob[1].toInt()
            if (ivLength <= 0 || blob.size < 2 + ivLength) {
                invoke.reject("wrapped secret has a malformed IV")
                return
            }

            val iv = blob.copyOfRange(2, 2 + ivLength)
            val ciphertext = blob.copyOfRange(2 + ivLength, blob.size)

            val key = getOrCreateKey(args.alias)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))

            val plaintext = cipher.doFinal(ciphertext)
            invoke.resolve(
                app.tauri.plugin.JSObject().put(
                    "plaintextB64",
                    Base64.encodeToString(plaintext, Base64.NO_WRAP),
                ),
            )
        } catch (error: Exception) {
            invoke.reject(describe(error))
        }
    }

    /**
     * Delete the wrapping key.
     *
     * Used only by the vault reset. A key that is present but unusable (for
     * example after a lock-screen change on a device that later dropped the
     * credential) cannot be repaired, so the reset has to remove it; otherwise
     * every subsequent wrap would fail and the reset would never recover.
     */
    @Command
    fun deleteKey(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(WrapArgs::class.java)
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(args.alias)) {
                keyStore.deleteEntry(args.alias)
            }
            invoke.resolve(app.tauri.plugin.JSObject().put("deleted", true))
        } catch (error: Exception) {
            invoke.reject(describe(error))
        }
    }

    @Command
    fun isKeyAvailable(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(WrapArgs::class.java)
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            invoke.resolve(
                app.tauri.plugin.JSObject().put("available", keyStore.containsAlias(args.alias)),
            )
        } catch (error: Exception) {
            invoke.resolve(app.tauri.plugin.JSObject().put("available", false))
        }
    }

    /**
     * Fetch the wrapping key, generating it on first use.
     *
     * `setUserAuthenticationRequired(false)`: the vault must be openable while the
     * app is running in the background publishing location updates, so a per-use
     * biometric prompt would break the app's core function. The key is still
     * hardware-bound and non-exportable.
     */
    private fun getOrCreateKey(alias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let {
            return it.secretKey
        }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)

        // A randomised IV per encryption is mandatory for GCM, and the Keystore
        // enforces it, so this is declared rather than left to chance.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setRandomizedEncryptionRequired(true)
        }

        generator.init(builder.build())
        return generator.generateKey()
    }

    /** Turn a Keystore exception into something a user could act on. */
    private fun describe(error: Exception): String = when {
        error is java.security.UnrecoverableKeyException ->
            "the device key was invalidated; a fresh invite is required"
        error is java.security.KeyStoreException ->
            "the Android Keystore rejected the operation: ${error.message}"
        error is javax.crypto.AEADBadTagException ->
            "the wrapped secret failed its integrity check"
        else -> "keystore operation failed: ${error.javaClass.simpleName}: ${error.message}"
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val FORMAT_VERSION: Byte = 1
    }
}