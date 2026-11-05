package com.shadow720.app

/**
 * Bridge from the location foreground service into the Rust core.
 *
 * The service outlives the activity, so a fix routed through the webview would be
 * dropped exactly when background sharing matters most. This object is the only
 * thing the service calls: the Rust side owns the movement gate, the envelope, and
 * the relay write, so a fix published with the app closed obeys the same battery
 * policy as one published with it open.
 *
 * `System.loadLibrary` is idempotent, so loading it here as well as in the Tauri
 * bootstrap is safe and makes the dependency explicit.
 */
object NativePublisher {
    init {
        System.loadLibrary("shadow720_lib")
    }

    /**
     * Hand a fix to the core.
     *
     * Returns `true` when the core accepted it. `false` means the app is not in a
     * publishable state (no vault open, no group joined), which the service treats
     * as "keep running and try the next fix" rather than as a fatal error.
     *
     * `speedMps` and `headingDeg` are `-1` when the platform did not report them;
     * `batteryPct` is `-1` when the system declines to report a level.
     */
    external fun publishFix(
        lat: Double,
        lon: Double,
        accuracyM: Float,
        unixMs: Long,
        speedMps: Float,
        headingDeg: Float,
        batteryPct: Int,
        isCharging: Boolean,
    ): Boolean
}
