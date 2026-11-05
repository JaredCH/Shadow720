package com.shadow720.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.location.Location
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat

/**
 * Keeps the device's position flowing while the app is not in the foreground.
 *
 * Why this exists: a member's pin freezes the moment their screen locks if the app
 * only receives location while visible, which makes the shared map misleading. This
 * service is what makes that survive a locked screen, and its notification is what
 * makes the behaviour visible and stoppable to the user.
 *
 * Play requirements this implements (see `docs/play/PLAY_CONSOLE_ANSWERS.md`):
 *  - `foregroundServiceType="location"` in the manifest.
 *  - A persistent, non-dismissable notification for the entire time it runs.
 *  - `POST_NOTIFICATIONS` is declared so the notification can be shown on API 33+.
 *
 * The service deliberately does **not** touch encryption or the network. It only
 * produces location fixes and hands them to the Rust core, which keeps all
 * cryptography in one place.
 */
class LocationForegroundService : Service() {

    private lateinit var locationManager: android.location.LocationManager
    private var listener: android.location.LocationListener? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
        locationManager =
            getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTracking()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startTracking()
        }
        return START_STICKY
    }

    private fun startTracking() {
        // `startForeground` must be called promptly after the service starts or the
        // system kills it, so the notification is raised before any location work.
        val notification = buildNotification()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION,
            )
        } else {
            @Suppress("DEPRECATION")
            startForeground(NOTIFICATION_ID, notification)
        }

        if (listener != null) return

        val locationListener =
            object : android.location.LocationListener {
                override fun onLocationChanged(location: Location) {
                    publishFix(location)
                }

                // Required on older API levels; no-ops on new ones.
                @Deprecated("Deprecated in Java")
                override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) = Unit

                override fun onProviderEnabled(provider: String) = Unit

                override fun onProviderDisabled(provider: String) = Unit
            }

        listener = locationListener

        try {
            locationManager.requestLocationUpdates(
                android.location.LocationManager.GPS_PROVIDER,
                MIN_TIME_MS,
                MIN_DISTANCE_M,
                locationListener,
            )
            locationManager.requestLocationUpdates(
                android.location.LocationManager.NETWORK_PROVIDER,
                MIN_TIME_MS,
                MIN_DISTANCE_M,
                locationListener,
            )
        } catch (error: SecurityException) {
            // The permission was revoked while the service was running. That is a
            // normal user action, not a crash: stop cleanly.
            stopTracking()
            stopSelf()
        } catch (error: IllegalArgumentException) {
            // No provider on this device (for example a tablet with no GPS).
            stopTracking()
            stopSelf()
        }
    }

    private fun stopTracking() {
        listener?.let { active ->
            try {
                locationManager.removeUpdates(active)
            } catch (error: SecurityException) {
                // Nothing to clean up if permission is already gone.
            }
        }
        listener = null
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    /**
     * Hand a fix to the Rust core.
     *
     * The core owns the movement gate and the publish cadence, so every fix is
     * forwarded and the core decides whether it is worth a request. That keeps the
     * "15 m and 30 s" policy in exactly one place.
     *
     * The fix is delivered as an ordered broadcast so the webview side can pick it
     * up without this service needing a reference to the Tauri runtime.
     */
    private fun publishFix(location: Location) {
        val intent = Intent(ACTION_FIX).apply {
            setPackage(packageName)
            putExtra(EXTRA_LAT, location.latitude)
            putExtra(EXTRA_LON, location.longitude)
            putExtra(EXTRA_ACCURACY, location.accuracy)
            putExtra(EXTRA_TIME_MS, location.time)
            // Speed and heading come from the platform's own sensor fusion, which
            // is far less noisy than differencing two positions 30 seconds apart.
            putExtra(EXTRA_SPEED, if (location.hasSpeed()) location.speed else -1f)
            putExtra(EXTRA_HEADING, if (location.hasBearing()) location.bearing else -1f)
            putExtra(EXTRA_BATTERY, batteryPercent())
            putExtra(EXTRA_CHARGING, isCharging())
        }
        sendBroadcast(intent)
    }

    /** Battery percentage, or `-1` when the system will not report it. */
    private fun batteryPercent(): Int {
        val manager = getSystemService(Context.BATTERY_SERVICE) as? android.os.BatteryManager
            ?: return -1
        val level = manager.getIntProperty(android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY)
        return if (level in 0..100) level else -1
    }

    /** True when the device is on external power. */
    private fun isCharging(): Boolean {
        val intent = registerReceiver(null, android.content.IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            ?: return false
        val status = intent.getIntExtra(android.os.BatteryManager.EXTRA_STATUS, -1)
        return status == android.os.BatteryManager.BATTERY_STATUS_CHARGING ||
            status == android.os.BatteryManager.BATTERY_STATUS_FULL
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.location_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.location_channel_description)
            // The notification is informational: it must not buzz or appear on the
            // lock screen, which would make background sharing feel intrusive.
            setShowBadge(false)
            enableVibration(false)
            setSound(null, null)
        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val stopSharing = PendingIntent.getService(
            this,
            1,
            Intent(this, LocationForegroundService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.location_notification_title))
            .setContentText(getString(R.string.location_notification_text))
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setOngoing(true)
            // Not dismissable and not groupable: the user must always be able to see
            // that background location is running.
            .setAutoCancel(false)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setContentIntent(openApp)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.location_notification_stop),
                stopSharing,
            )
            .build()
    }

    override fun onDestroy() {
        stopTracking()
        super.onDestroy()
    }

    companion object {
        /** Start background location sharing. */
        const val ACTION_START = "com.shadow720.app.action.START_LOCATION"

        /** Stop background location sharing. */
        const val ACTION_STOP = "com.shadow720.app.action.STOP_LOCATION"

        /** Broadcast delivered for each accepted fix. */
        const val ACTION_FIX = "com.shadow720.app.action.LOCATION_FIX"

        const val EXTRA_LAT = "lat"
        const val EXTRA_LON = "lon"
        const val EXTRA_ACCURACY = "accuracy"
        const val EXTRA_TIME_MS = "time_ms"
        const val EXTRA_SPEED = "speed_mps"
        const val EXTRA_HEADING = "heading_deg"
        const val EXTRA_BATTERY = "battery_pct"
        const val EXTRA_CHARGING = "charging"

        private const val CHANNEL_ID = "shadow720.location"
        private const val NOTIFICATION_ID = 7201

        /**
         * Request interval floor. The Rust core applies the real 30 s / 15 m policy;
         * asking Android for fixes a little more often than that keeps the gate fed
         * without wasting battery on every GPS sample.
         */
        private const val MIN_TIME_MS = 20_000L
        private const val MIN_DISTANCE_M = 10f

        /** True when the user has granted the notification permission, if needed. */
        fun canPostNotifications(context: Context): Boolean {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
            return NotificationManagerCompat.from(context).areNotificationsEnabled()
        }

        /** Start the service from an activity or the webview bridge. */
        fun start(context: Context) {
            val intent = Intent(context, LocationForegroundService::class.java)
                .setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /** Stop the service. */
        fun stop(context: Context) {
            val intent = Intent(context, LocationForegroundService::class.java)
                .setAction(ACTION_STOP)
            context.startService(intent)
        }
    }
}