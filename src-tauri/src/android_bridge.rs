//! JNI bridge for the Android location foreground service.
//!
//! # Why this exists
//!
//! The foreground service keeps producing fixes after the activity - and with it
//! the webview - is gone. Routing those fixes through JavaScript would mean they
//! are dropped exactly when background sharing matters most, so the service calls
//! straight into the Rust core instead.
//!
//! The bridge is deliberately narrow: two entry points, one direction. Kotlin hands
//! over a raw fix and gets back a boolean saying whether the core accepted it.
//! Everything else - the movement gate, the envelope, the relay write - stays in
//! [`crate::commands::publish_fix`], so a fix published while the app is closed
//! obeys exactly the same battery policy as one published while it is open.
//!
//! # Two ways to reach the core
//!
//! * [`Java_com_shadow720_app_NativePublisher_publishFix`] publishes into the
//!   running application, reached through the [`APP_HANDLE`] captured at startup.
//! * [`Java_com_shadow720_app_NativePublisher_bootHeadless`] builds the state the
//!   service needs when there is no application at all.
//!
//! The second exists because Android restarts a `START_STICKY` service in a **fresh
//! process** after a low-memory kill. In that process [`crate::run`] never executes,
//! so there is no `AppHandle`, no managed [`AppState`], and no open vault. Without a
//! headless boot every fix would be rejected and background sharing would stop
//! silently - precisely when the user is not looking at the app.
//!
//! # Threading
//!
//! JNI calls arrive on a binder thread and must return promptly, so the publish is
//! spawned onto the Tauri async runtime and the call returns as soon as the fix is
//! queued. That runtime is created lazily on first use, so it is available in a
//! headless process too. A failure to publish is not reported back: the next fix
//! retries, and the service has no way to act on the error anyway.

use std::sync::{Arc, OnceLock};

use tauri::Manager as _;

use crate::commands::{publish_fix, AppState, LocationUpdate};

/// The running application, captured at startup.
///
/// A `OnceLock` rather than a managed-state lookup because the JNI entry point has
/// no `AppHandle` of its own: it is called from Kotlin, not from Tauri.
static APP_HANDLE: OnceLock<tauri::AppHandle> = OnceLock::new();

/// State built by [`Java_com_shadow720_app_NativePublisher_bootHeadless`].
///
/// Only populated in a process that has no application, which is the
/// after-a-kill restart case described in the module docs.
static HEADLESS: OnceLock<AppState> = OnceLock::new();

/// Record the application handle so the JNI entry point can reach managed state.
///
/// Called once from [`crate::run`]. A second call is ignored rather than treated
/// as an error: the app is only built once per process, and failing here would
/// turn a harmless duplicate into a startup crash.
pub fn install(handle: tauri::AppHandle) {
    let _ = APP_HANDLE.set(handle);
}

/// Open the vault and hydrate the group without a Tauri application.
///
/// Called by the foreground service when it finds itself in a process that has no
/// `AppHandle`. `vault_dir` is the same directory the UI uses, `password` is the
/// already-unwrapped vault password, and `keystore_alias` identifies the device
/// key so the vault refuses to open under a different one.
///
/// Returns `true` when the group is ready to publish. `false` means the vault
/// could not be opened or holds no group, which the service treats as "keep
/// running, try again later" rather than as fatal.
///
/// # Safety
///
/// Called only from Kotlin through `NativePublisher.bootHeadless`. The byte array
/// is copied before the call returns, so no reference outlives it.
#[no_mangle]
pub extern "system" fn Java_com_shadow720_app_NativePublisher_bootHeadless(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    vault_dir: jni::objects::JString,
    password: jni::objects::JByteArray,
    keystore_alias: jni::objects::JString,
) -> jni::sys::jboolean {
    // A second boot is a no-op: the state is already built, and rebuilding it
    // would drop the group the service is publishing into.
    if HEADLESS.get().is_some() {
        return jni::sys::JNI_TRUE;
    }

    // When the application is running, `publishFix` already reaches its managed
    // state, so building a second copy would only pay for an Argon2id decrypt on
    // every service start for nothing.
    if APP_HANDLE.get().is_some() {
        return jni::sys::JNI_TRUE;
    }

    let Ok(dir) = env.get_string(&vault_dir) else {
        return jni::sys::JNI_FALSE;
    };
    let Ok(alias) = env.get_string(&keystore_alias) else {
        return jni::sys::JNI_FALSE;
    };
    let Ok(password) = env.convert_byte_array(&password) else {
        return jni::sys::JNI_FALSE;
    };

    let dir = std::path::PathBuf::from(String::from(dir));
    let alias = String::from(alias);

    match open_headless(&dir, password, &alias) {
        Ok(state) => {
            let _ = HEADLESS.set(state);
            jni::sys::JNI_TRUE
        }
        Err(error) => {
            eprintln!("background location could not open the vault: {error}");
            jni::sys::JNI_FALSE
        }
    }
}

/// Build the state a headless process publishes from.
///
/// Mirrors the hydration half of [`crate::commands::unlock_vault`]. The history log
/// is deliberately not loaded: the service only publishes, and reading the sealed
/// track log would cost a decrypt on every restart for no benefit.
fn open_headless(
    dir: &std::path::Path,
    password: Vec<u8>,
    keystore_alias: &str,
) -> crate::Result<AppState> {
    use crate::group::{GroupState, Identity};
    use crate::vault::{AliasOnlyKeystore, Keystore, SecureVault};

    let keystore: Arc<dyn Keystore> = Arc::new(AliasOnlyKeystore::new(keystore_alias));
    let vault = SecureVault::open_with_password(dir, keystore, password)?;

    let descriptor = vault
        .descriptor()
        .ok_or_else(|| crate::AppError::not_configured("no group has been joined on this device"))?;
    let mut stored = vault
        .load_group()?
        .ok_or_else(|| crate::AppError::not_configured("the vault holds no group"))?;
    let contents = vault
        .load_contents()?
        .ok_or_else(|| crate::AppError::vault("group credentials are missing"))?;

    stored.invite.group_master_key = *contents.group_key;
    stored.invite.key_epoch = descriptor.current_epoch;
    let identity = Identity::from_secret(stored.identity_secret);
    let group_state = GroupState::from_invite(
        &stored.invite,
        identity,
        stored.preferences.clone(),
        stored.is_host,
    )?;
    group_state.install_roles(
        &stored
            .roles
            .iter()
            .map(|role| (role.pubkey_b64.clone(), role.role.clone()))
            .collect::<Vec<_>>(),
    );

    let state = AppState::new();
    *state.group.write() = Some(Arc::new(group_state));
    *state.vault.write() = Some(Arc::new(vault));
    Ok(state)
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

    // The application path is preferred: it is the one with a live webview, so the
    // map updates as the fix lands. The headless path only exists for the process
    // Android restarted after a kill.
    if let Some(handle) = APP_HANDLE.get() {
        let handle = handle.clone();
        // Binder threads must not block, so the publish is queued and the call
        // returns immediately. The service does not need the result.
        tauri::async_runtime::spawn(async move {
            let state = handle.state::<AppState>();
            if let Err(error) = publish_fix(state.inner(), update).await {
                // Nothing to surface: the service has no UI, and the next fix retries.
                eprintln!("background location publish failed: {error}");
            }
        });
        return jni::sys::JNI_TRUE;
    }

    // `HEADLESS` is a static `OnceLock` that is never cleared, so this borrow is
    // `'static` and can be moved into the spawned task.
    let Some(state) = HEADLESS.get() else {
        // Neither an application nor a headless boot: the service has not called
        // `bootHeadless` yet, or the vault could not be opened.
        return jni::sys::JNI_FALSE;
    };

    tauri::async_runtime::spawn(async move {
        if let Err(error) = publish_fix(state, update).await {
            eprintln!("background location publish failed: {error}");
        }
    });

    jni::sys::JNI_TRUE
}
