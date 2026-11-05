//! JNI bridge for the Android location foreground service.
//!
//! # Why this exists
//!
//! The foreground service keeps producing fixes after the activity - and with it
//! the webview - is gone. Routing those fixes through JavaScript would mean they
//! are dropped exactly when background sharing matters most, so the service calls
//! straight into the Rust core instead.
//!
//! The bridge is deliberately narrow: one function, one direction. Kotlin hands
//! over a raw fix and gets back a boolean saying whether the core accepted it.
//! Everything else - the movement gate, the envelope, the relay write - stays in
//! [`crate::commands::publish_fix`], so a fix published while the app is closed
//! obeys exactly the same battery policy as one published while it is open.
//!
//! # Threading
//!
//! JNI calls arrive on a binder thread and must return promptly, so the publish is
//! spawned onto the Tauri async runtime and the call returns as soon as the fix is
//! queued. A failure to publish is not reported back: the next fix retries, and
//! the service has no way to act on the error anyway.

use std::sync::OnceLock;

use tauri::Manager as _;

use crate::commands::{publish_fix, AppState, LocationUpdate};

/// The running application, captured at startup.
///
/// A `OnceLock` rather than a managed-state lookup because the JNI entry point has
/// no `AppHandle` of its own: it is called from Kotlin, not from Tauri.
static APP_HANDLE: OnceLock<tauri::AppHandle> = OnceLock::new();

/// Record the application handle so the JNI entry point can reach managed state.
///
/// Called once from [`crate::run`]. A second call is ignored rather than treated
/// as an error: the app is only built once per process, and failing here would
/// turn a harmless duplicate into a startup crash.
pub fn install(handle: tauri::AppHandle) {
    let _ = APP_HANDLE.set(handle);
}

/// Publish a fix captured by the foreground service.
///
/// Returns `true` when the fix was handed to the core. `false` means the app is
/// not in a state where it can publish - no vault open, no group joined, or the
/// runtime is shutting down - which the service treats as "keep running, try the
/// next fix" rather than as a fatal error.
///
/// # Safety
///
/// Called only from Kotlin through `NativePublisher.publishFix`. Every argument is
/// a plain scalar, so there is no object lifetime to uphold beyond the call.
#[no_mangle]
pub extern "system" fn Java_com_shadow720_app_NativePublisher_publishFix(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    lat: jni::sys::jdouble,
    lon: jni::sys::jdouble,
    accuracy: jni::sys::jfloat,
    _time_ms: jni::sys::jlong,
    speed: jni::sys::jfloat,
    heading: jni::sys::jfloat,
    battery_pct: jni::sys::jint,
    charging: jni::sys::jboolean,
) -> jni::sys::jboolean {
    let Some(handle) = APP_HANDLE.get() else {
        return jni::sys::JNI_FALSE;
    };

    // A fix with no coordinates is a platform bug, not a position; publishing it
    // would put the member's pin in the Gulf of Guinea.
    if !lat.is_finite() || !lon.is_finite() {
        return jni::sys::JNI_FALSE;
    }

    let update = LocationUpdate {
        lat,
        lon,
        // The platform reports `-1` for "unknown", which the core treats as absent.
        speed_mps: if speed >= 0.0 { speed } else { 0.0 },
        heading_deg: if heading >= 0.0 { heading } else { 0.0 },
        accuracy_m: if accuracy > 0.0 { accuracy } else { 0.0 },
        battery_pct: u8::try_from(battery_pct).unwrap_or(0),
        is_charging: charging != jni::sys::JNI_FALSE,
    };

    let handle = handle.clone();

    // Binder threads must not block, so the publish is queued and the call returns
    // immediately. The service does not need the result.
    tauri::async_runtime::spawn(async move {
        let state = handle.state::<AppState>();
        if let Err(error) = publish_fix(state.inner(), update).await {
            // Nothing to surface: the service has no UI, and the next fix retries.
            eprintln!("background location publish failed: {error}");
        }
    });

    jni::sys::JNI_TRUE
}
