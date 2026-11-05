//! Shadow720 — serverless E2EE group app.
//!
//! Rust core for a Tauri v2 Android client that uses public Nostr relays as an
//! untrusted ciphertext store. There is no application server and no account: the
//! device talks to relays directly, and every payload is sealed locally with
//! `XChaCha20-Poly1305` and signed with `Ed25519` before it leaves the app.
//!
//! # Module layout
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`error`] | Single `AppError` type, panic-free fallible operations |
//! | [`crypto`] | Key material, invite tokens, envelope seal/open, key epochs |
//! | [`geo_filter`] | Movement gating, polling cadence, jitter, rate-limit halting |
//! | [`nostr`] | Event signing, verification, and filter construction |
//! | [`nostr_relay`] | Relay websocket transport |
//! | [`nostr_store`] | Relay and Blossom storage engine |
//! | [`wire`] | Backend-neutral wire types shared with the command layer |
//! | [`vault`] | Keystore-backed secret storage at rest |
//! | [`group`] | In-memory aggregate: group keys, roster, cadence budget |
//! | [`history`] | Month-long local track log |
//! | [`outbox`] | Fixes deferred while offline, replayed on reconnect |
//! | [`commands`] | `#[tauri::command]` surface for the TypeScript UI |
//! # Panic freedom
//!
//! Production code denies `unwrap`, `expect`, `panic`, slice indexing, `todo!`
//! and `unimplemented!`. Tests are exempt because a failing assertion *should*
//! panic. See `PLAN.md` §2.

// Panic-freedom is enforced in production code only; tests may unwrap freely.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod commands;
pub mod crypto;
pub mod error;
pub mod geo_filter;
pub mod group;
pub mod history;
pub mod nostr;
pub mod nostr_relay;
pub mod nostr_store;
pub mod outbox;
pub mod storage;
pub mod vault;
pub mod wire;

#[cfg(target_os = "android")]
pub mod android_bridge;
#[cfg(target_os = "android")]
pub mod keystore_android;

pub use error::{AppError, AppErrorKind, Result};

/// Only the desktop fallback keystore needs `Arc`; on Android the trait object is
/// installed by the mobile plugin, so importing it there would be unused.
#[cfg(not(target_os = "android"))]
use std::sync::Arc;

/// Build and run the Tauri application.
///
/// Both `main.rs` entry points call this, so the plugin set, the managed state,
/// and the command list are defined exactly once.
///
/// # Keystore selection
///
/// Both targets install a [`vault::Keystore`] into managed state, which is what
/// the vault commands expect:
///
/// * On **Android**, the hardware-backed implementation, so the vault password is
///   wrapped by a key that lives in the device's secure element and can never be
///   extracted. This is the configuration the threat model in
///   `PLAN_ADDENDUM_v1.md` §A4 describes, and the only one that is secure.
/// * On **Windows**, DPAPI protects the vault password for the current Windows user.
/// * On other desktop targets, an in-memory double. It is deliberately *not* secure and
///   deliberately not persistent: it exists so the desktop build and the test suite
///   can exercise the vault logic, and it is never selected on a device.
///
/// The Android implementation lives in `keystore_android` and is compiled only for
/// that target, so this crate builds cleanly on a host without any mobile tooling.
///
/// The attribute is what emits the `start_app` JNI entry point Android calls. Without
/// it the shared library exports no entry point at all, so the app launches and closes
/// immediately with nothing in the log to explain why.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_geolocation::init())
        // The desktop geolocation plugin is a stub, so the webview's own
        // Geolocation API is what supplies a fix there. WebView2 asks before
        // granting it, and without a handler the request is denied outright.
        .on_permission_request(|_, kind| match kind {
            tauri::webview::PermissionKind::Geolocation => {
                tauri::webview::PermissionResponse::Allow
            }
            _ => tauri::webview::PermissionResponse::Default,
        });

    #[cfg(target_os = "android")]
    {
        // Each Android class needs its own Rust plugin name. Registering both
        // from one plugin makes the second replace the first, so vault commands
        // were delivered to the location plugin and the app could not start.
        builder = builder
            .plugin(keystore_android::init_keystore())
            .plugin(keystore_android::init_location());
    }

    #[cfg(windows)]
    {
        let keystore: Arc<dyn vault::Keystore> = Arc::new(vault::WindowsKeystore);
        builder = builder.manage(keystore);
    }

    #[cfg(target_os = "linux")]
    {
        // The device key lives in the Secret Service, or in a 0600 file when no
        // keyring daemon is running. Either way it persists across launches, so a
        // Linux install keeps its vault like the Windows and Android builds do.
        match vault::LinuxKeystore::new() {
            Ok(keystore) => {
                let keystore: Arc<dyn vault::Keystore> = Arc::new(keystore);
                builder = builder.manage(keystore);
            }
            Err(error) => {
                // Without a keystore the app cannot store anything, so this is
                // fatal rather than something to limp past.
                eprintln!("fatal: could not create the Linux keystore: {error}");
                return;
            }
        }
    }

    #[cfg(all(not(target_os = "android"), not(windows), not(target_os = "linux")))]
    {
        // Remaining desktop targets have no keystore integration yet, so they get
        // the in-memory double: deliberately not persistent across launches.
        match vault::InMemoryKeystore::new() {
            Ok(keystore) => {
                let keystore: Arc<dyn vault::Keystore> = Arc::new(keystore);
                builder = builder.manage(keystore);
            }
            Err(error) => {
                eprintln!("fatal: could not create the development keystore: {error}");
                return;
            }
        }
    }

    let result = builder
        .manage(commands::AppState::new())
        .setup(|app| {
            // The location foreground service outlives the webview, so it calls
            // into the core through JNI rather than through JavaScript. That entry
            // point has no `AppHandle` of its own, so one is captured here.
            #[cfg(target_os = "android")]
            android_bridge::install(app.handle().clone());
            let _ = app;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::unlock_vault,
            commands::reset_vault,
            commands::list_groups,
            commands::switch_group,
            commands::forget_group,
            commands::discard_legacy_group,
            commands::lock_vault,
            commands::consent_status,
            commands::set_preferences,
            commands::set_background_location,
            commands::location_access,
            commands::battery_status,
            commands::open_location_settings,
            commands::create_nostr_group,
            commands::join_group,
            commands::update_location,
            commands::flush_pending_locations,
            commands::poll_roster,
            commands::poll_chat,
            commands::refresh_rate_limit,
            commands::roster_snapshot,
            commands::chat_snapshot,
            commands::location_history,
            commands::save_location_history,
            commands::clear_location_history,
            commands::diagnostics,
            commands::send_text,
            commands::send_file,
            commands::download_file,
            commands::block_member,
            commands::blocked_members,
            commands::report_content,
            commands::delete_own_message,
            commands::check_rotation,
            commands::current_invite,
            commands::share_invite,
            commands::set_member_role,
            commands::rotate_group_key,
            commands::leave_and_wipe,
            commands::destroy_group,
            commands::check_group_closed,
            commands::vault_report,
            commands::delete_asset,
            commands::delete_nostr_blob,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = result {
        // A failure to start is unrecoverable from inside the app; report it
        // rather than panicking, which would hide the cause on Android.
        eprintln!("fatal: the Shadow720 runtime could not start: {error}");
    }
}