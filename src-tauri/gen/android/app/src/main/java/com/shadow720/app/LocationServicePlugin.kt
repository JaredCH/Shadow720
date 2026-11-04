package com.shadow720.app

/**
 * Control surface for the location foreground service.
 *
 * Exists so the Rust core never has to know about Android services: it asks this
 * plugin to start or stop background sharing, and the plugin owns the Android
 * specifics.
 *
 * Keeping the surface this small is deliberate. The webview cannot start arbitrary
 * services or reach `LocationForegroundService` directly, only enable or disable the
 * one thing the app is declared to do.
 */

import android.content.Context
import android.content.Intent
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONObject

@InvokeArg
class SetLocationSharingArgs {
    var enabled: Boolean = false
}

@TauriPlugin
class LocationServicePlugin(private val activity: android.app.Activity) : Plugin(activity) {

    @Command
    fun setLocationSharingEnabled(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SetLocationSharingArgs::class.java)

            if (args.enabled) {
                LocationForegroundService.start(activity)
            } else {
                LocationForegroundService.stop(activity)
            }

            invoke.resolve(JSObject().put("running", args.enabled))
        } catch (error: Exception) {
            invoke.reject("could not toggle location sharing: ${error.message}")
        }
    }

    @Command
    fun canPostNotifications(invoke: Invoke) {
        val granted = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            // Before Android 13 the permission does not exist, so notifications can
            // always be shown.
            true
        } else {
            NotificationManagerCompat.from(activity).areNotificationsEnabled()
        }
        invoke.resolve(JSObject().put("granted", granted))
    }

    /**
     * Whether the device-wide location switch is on.
     *
     * A granted runtime permission is not enough: with the system toggle off every
     * fix fails, and the only fix is a trip to Settings. Reporting it separately
     * lets the UI say which of the two problems the user actually has.
     */
    @Command
    fun isSystemLocationEnabled(invoke: Invoke) {
        val manager = activity.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
        val enabled = manager?.let {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                it.isLocationEnabled
            } else {
                @Suppress("DEPRECATION")
                it.isProviderEnabled(LocationManager.GPS_PROVIDER) ||
                    it.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
            }
        } ?: false
        invoke.resolve(JSObject().put("enabled", enabled))
    }

    /**
     * Open the system screen where the user can grant location access.
     *
     * Android has no API to grant a permission on the user's behalf, so the app can
     * only take them to the right screen. `app` opens this app's own permission
     * page, which is where a permanently denied permission is re-enabled.
     */
    @Command
    fun openLocationSettings(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(OpenLocationSettingsArgs::class.java)
            val intent = if (args.app) {
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.fromParts("package", activity.packageName, null),
                )
            } else {
                Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)
            }
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            activity.startActivity(intent)
            invoke.resolve(JSObject().put("opened", true))
        } catch (error: Exception) {
            invoke.reject("could not open location settings: ${error.message}")
        }
    }
}

@InvokeArg
class OpenLocationSettingsArgs {
    /** True for this app's permission page, false for the device location switch. */
    var app: Boolean = true
}