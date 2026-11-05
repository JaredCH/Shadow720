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
import java.io.File

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
 * # Battery
 *
 * The service does not ask the platform for a fix on a fixed timer. It asks for a
 * *distance* filter and lets the platform's own sensor fusion decide when a fix is
 * worth delivering, then widens the interval when the device is still or the
 * battery is low. A phone in a pocket therefore costs almost nothing, and a phone
 * in a moving car updates every few seconds.
 *
 * The service deliberately does **not** touch encryption or the network. It only
 * produces location fixes and hands them to the Rust core through
 * [NativePublisher], which keeps all cryptography in one place and lets a fix
 * publish with the app closed.
 */
class LocationForegroundService : Service() {

    private lateinit var locationManager: android.location.LocationManager
    private var listener: android.location.LocationListener? = null

    /** True once `startForeground` has succeeded, so teardown knows what to undo. */
    private var foregroundStarted = false

    /** Last fix handed to the core, used to widen the interval when still. */
    private var lastFix: Location? = null

    /** Current request interval, so a cadence change can be applied incrementally. */
    private var currentIntervalMs = MOVING_INTERVAL_MS

    /** True once the core has an open vault in this process. */
    private var headlessReady = false

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
        // START_STICKY so the system restarts the service after a low-memory kill.
        // The user's preference is the source of truth, and the notification is
        // re-raised on restart, so a restart never hides that sharing is running.
        return START_STICKY
    }

    private fun startTracking() {
        // `startForeground` must be called promptly after the service starts or the
        // system kills it, so the notification is raised before any location work.
        if (!raiseForeground()) {
            // Android 14+ throws when the location permission is missing, and a
            // service that cannot show its notification must not run at all: the
            // location policy requires the user to always see it.
            stopSelf()
            return
        }

        // Android restarts this service in a fresh process after a low-memory kill,
        // and in that process the Tauri bootstrap never ran, so the core has no open
        // vault and would reject every fix. Opening it here is what makes background
        // sharing survive the app being killed rather than merely backgrounded.
        if (!headlessReady) {
            headlessReady = HeadlessVault.boot(File(applicationInfo.dataDir, VAULT_SUBDIR))
        }

        if (listener != null) return

        val locationListener =
            object : android.location.LocationListener {
                override fun onLocationChanged(location: Location) {
                    onFix(location)
                }

                // Required on older API levels; no-ops on new ones.
                @Deprecated("Deprecated in Java")
                override fun onStatusChanged(provider: String?, status: Int, extras: android.os.Bundle?) = Unit

                override fun onProviderEnabled(provider: String) = Unit

                override fun onProviderDisabled(provider: String) = Unit
            }

        listener = locationListener
        requestUpdates(locationListener, MOVING_INTERVAL_MS)
    }

    /**
     * Raise the ongoing notification.
     *
     * Returns `false` when the platform refused, which happens on Android 14+ if
     * the location permission is not granted. Callers must stop the service rather
     * than continue without a visible notification.
     */
    private fun raiseForeground(): Boolean {
        val notification = buildNotification()
        return try {
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
            foregroundStarted = true
            true
        } catch (error: SecurityException) {
            // Location permission was revoked, or the FGS type is not allowed.
            false
        } catch (error: IllegalArgumentException) {
            // The manifest is missing the FGS type declaration.
            false
        }
    }

    /**
     * Ask the platform for fixes.
     *
     * `minDistanceM` is the real battery lever: with a distance filter the platform
     * can keep the GPS chip idle until the device has actually moved, instead of
     * waking it on a timer. `minTimeMs` is only a floor.
     *
     * The distance filter is deliberately **smaller** than the Rust gate's
     * `MIN_MOVE_METERS` (15 m). If the two were equal, a device that drifted 14 m
     * would never be reported, so the core would never see a fix, so the heartbeat
     * could never fire — and a member walking slowly around a house would vanish
     * from the map entirely. A smaller filter keeps the core fed while still
     * letting the platform skip the GPS wake-up for genuinely stationary devices.
     */
    private fun requestUpdates(target: android.location.LocationListener, intervalMs: Long) {
        currentIntervalMs = intervalMs
        try {
            locationManager.requestLocationUpdates(
                android.location.LocationManager.GPS_PROVIDER,
                intervalMs,
                MIN_DISTANCE_M,
                target,
            )
            locationManager.requestLocationUpdates(
                android.location.LocationManager.NETWORK_PROVIDER,
                intervalMs,
                MIN_DISTANCE_M,
                target,
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

    /**
     * Handle one fix: publish it, then adapt the cadence.
     *
     * The Rust core applies the authoritative 30 s / 15 m publish policy, so every
     * fix is forwarded. What this method decides is how often the *platform* is
     * asked, which is the part that costs battery.
     */
    private fun onFix(location: Location) {
        val previous = lastFix
        lastFix = location

        NativePublisher.publishFix(
            location.latitude,
            location.longitude,
            location.accuracy,
            location.time,
            if (location.hasSpeed()) location.speed else -1f,
            if (location.hasBearing()) location.bearing else -1f,
            batteryPercent(),
            isCharging(),
        )

        // Also broadcast so an open webview can update its own pin immediately
        // rather than waiting for the next roster poll.
        broadcastFix(location)

        val nextInterval = chooseInterval(location, previous)
        if (nextInterval != currentIntervalMs) {
            listener?.let { active ->
                try {
                    locationManager.removeUpdates(active)
                } catch (error: SecurityException) {
                    // Nothing to clean up if permission is already gone.
                }
                requestUpdates(active, nextInterval)
            }
        }
    }

    /**
     * Pick the next request interval.
     *
     * Three inputs, in order of importance:
     *
     * 1. **Battery.** Below [LOW_BATTERY_PCT] and not charging, everything slows
     *    down. A member whose phone is about to die is better served by a stale pin
     *    than by a dead phone.
     * 2. **Movement.** A device that has not moved is not worth a GPS wake-up, so
     *    the interval widens to the heartbeat. This is what makes a phone on a desk
     *    cost almost nothing.
     * 3. **Speed.** A fast-moving device gets the tightest interval, because that is
     *    when a stale pin is most misleading.
     */
    private fun chooseInterval(location: Location, previous: Location?): Long {
        val battery = batteryPercent()
        val charging = isCharging()
        if (!charging && battery in 0..LOW_BATTERY_PCT) {
            return LOW_BATTERY_INTERVAL_MS
        }

        val moved = previous == null || previous.distanceTo(location) >= STILL_RADIUS_M
        if (!moved) return STILL_INTERVAL_MS

        val speed = if (location.hasSpeed()) location.speed else 0f
        return if (speed >= FAST_SPEED_MPS) FAST_INTERVAL_MS else MOVING_INTERVAL_MS
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
        lastFix = null
        if (foregroundStarted) {
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            foregroundStarted = false
        }
    }

    /**
     * Mirror the fix to an open webview.
     *
     * Best-effort: with the app closed nothing receives it, which is exactly why
     * [NativePublisher] exists. This is only for the case where the UI is on screen
     * and wants to move the pin without waiting for a poll.
     */
    private fun broadcastFix(location: Location) {
        val intent = Intent(ACTION_FIX).apply {
            setPackage(packageName)
            putExtra(EXTRA_LAT, location.latitude)
            putExtra(EXTRA_LON, location.longitude)
            putExtra(EXTRA_ACCURACY, location.accuracy)
            putExtra(EXTRA_TIME_MS, location.time)
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

    /**
     * The user swiped the app out of recents.
     *
     * Background sharing is an explicit, notified choice, so it keeps running: the
     * whole point is that the pin keeps moving while the app is closed. The
     * notification is the control surface, and it stays visible.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        // Nothing to do: START_STICKY plus the ongoing notification is the correct
        // behaviour. Overriding this only to call `super` documents the intent.
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        stopTracking()
        super.onDestroy()
    }

    companion object {
        /**
         * Directory under `applicationInfo.dataDir` that holds the vault.
         *
         * Tauri's `appDataDir()` resolves to `Context.getDataDir()` on Android, and
         * the UI passes that straight to `unlock_vault`, so the vault files sit at
         * the root of the app's data directory. This must stay in step with
         * `resolveVaultDir` in `src/App.tsx`.
         */
        private const val VAULT_SUBDIR = ""

        /** Start background location sharing. */
        const val ACTION_START = "com.shadow720.app.action.START_LOCATION"

        /** Stop background location sharing. */
        const val ACTION_STOP = "com.shadow720.app.action.STOP_LOCATION"

        /** Broadcast delivered for each accepted fix, for an open webview. */
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
         * Distance filter.
         *
         * This is the real battery lever: the platform keeps the GPS chip idle until
         * the device has actually moved this far, instead of waking it on a timer.
         *
         * Deliberately smaller than the Rust gate's `MIN_MOVE_METERS` (15 m). If the
         * two were equal, a device that drifted 14 m would never be reported, so the
         * core would never see a fix, so the heartbeat could never fire — and a
         * member walking slowly around a house would vanish from the map entirely.
         */
        private const val MIN_DISTANCE_M = 5f

        /** Interval while moving at a normal pace. */
        private const val MOVING_INTERVAL_MS = 30_000L

        /** Interval while moving fast, where a stale pin is most misleading. */
        private const val FAST_INTERVAL_MS = 10_000L

        /** Interval while stationary: a heartbeat, so peers see the device is alive. */
        private const val STILL_INTERVAL_MS = 120_000L

        /** Interval when the battery is low and the device is not charging. */
        private const val LOW_BATTERY_INTERVAL_MS = 300_000L

        /** Below this percentage, cadence drops to the low-battery interval. */
        private const val LOW_BATTERY_PCT = 15

        /** Movement below this radius counts as stationary. */
        private const val STILL_RADIUS_M = 15f

        /** Above this speed the device is treated as driving. */
        private const val FAST_SPEED_MPS = 8f

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
