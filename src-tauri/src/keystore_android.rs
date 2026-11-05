//! Shadow720 — Android-specific plugins.
//!
//! The whole module is `cfg(target_os = "android")`, so it compiles only for an
//! Android target. That keeps the host build (and its test suite) free of
//! mobile-only Tauri APIs while still shipping the real implementation to the
//! device.
//!
//! Two plugins live behind this module, each as its own Tauri plugin. Tauri keys
//! an Android class by the Rust plugin name, so registering both classes from one
//! plugin makes the second replace the first.
//!
//! * **`KeystoreVaultPlugin`** — wraps the 32-byte vault password with a key held
//!   in the device's secure element. Exposes exactly `wrapSecret` and
//!   `unwrapSecret`; there is deliberately no general-purpose Keystore surface
//!   reachable from the webview.
//! * **`LocationServicePlugin`** — starts and stops the location foreground
//!   service, so the Rust core never has to know about Android services.
//!
//! See `PLAN_ADDENDUM_v1.md` §A4 and `docs/play/PLAY_CONSOLE_ANSWERS.md` §3.
#![cfg(target_os = "android")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tauri::plugin::{Builder as PluginBuilder, PluginHandle, TauriPlugin};
use tauri::{Manager as _, Runtime};

use crate::error::{AppError, Result};
use crate::vault::Keystore;

/// Application package the Kotlin plugins are registered under.
const ANDROID_PACKAGE: &str = "com.shadow720.app";
/// Kotlin plugin class that wraps the vault password with the device key.
const KEYSTORE_PLUGIN_CLASS: &str = "KeystoreVaultPlugin";
/// Kotlin plugin class that controls the location foreground service.
const LOCATION_PLUGIN_CLASS: &str = "LocationServicePlugin";

/// Rust plugin id the keystore class is registered under.
///
/// `register_android_plugin` keys the Android class by this name, not by the
/// Kotlin class. Two classes registered from one Rust plugin share that key, and
/// the second `load` replaces the first. `wrapSecret` was then dispatched to
/// `LocationServicePlugin` ("no command wrapSecret found"), so the vault could
/// neither open nor be reset.
const KEYSTORE_PLUGIN_NAME: &str = "shadow720-keystore";
/// Rust plugin id the location-service class is registered under.
///
/// Must stay distinct from [`KEYSTORE_PLUGIN_NAME`]. See that constant.
const LOCATION_PLUGIN_NAME: &str = "shadow720-location";

/// Alias of the wrapping key inside the Android Keystore.
const KEY_ALIAS: &str = "shadow720.vault.wrap";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WrapRequest {
    /// Base64 of the plaintext vault password.
    plaintext_b64: String,
    alias: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrapResponse {
    /// Base64 of the wrapped blob.
    wrapped_b64: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnwrapRequest {
    wrapped_b64: String,
    alias: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnwrapResponse {
    plaintext_b64: String,
}

/// A [`Keystore`] backed by the Android Keystore through the Kotlin plugin.
pub struct AndroidKeystore<R: Runtime> {
    handle: PluginHandle<R>,
}

impl<R: Runtime> AndroidKeystore<R> {
    /// Build from a registered mobile plugin handle.
    pub fn new(handle: PluginHandle<R>) -> Self {
        Self { handle }
    }
}

impl<R: Runtime> Keystore for AndroidKeystore<R> {
    fn wrap_secret(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let request = WrapRequest {
            plaintext_b64: B64.encode(plaintext),
            alias: KEY_ALIAS.to_string(),
        };

        let response: WrapResponse = self
            .handle
            .run_mobile_plugin("wrapSecret", request)
            .map_err(|e| {
                // A missing or invalidated key is the actionable case: the user
                // needs a fresh invite, not a retry.
                AppError::vault(format!(
                    "the device key could not wrap the vault password (key missing or invalidated): {e}"
                ))
            })?;

        B64.decode(response.wrapped_b64.as_bytes())
            .map_err(|e| AppError::vault(format!("device returned a malformed wrapped blob: {e}")))
    }

    fn unwrap_secret(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        let request = UnwrapRequest {
            wrapped_b64: B64.encode(wrapped),
            alias: KEY_ALIAS.to_string(),
        };

        let response: UnwrapResponse = self
            .handle
            .run_mobile_plugin("unwrapSecret", request)
            .map_err(|e| {
                AppError::vault(format!(
                    "the device key could not unwrap the vault password; the key was likely invalidated by a device reset: {e}"
                ))
            })?;

        B64.decode(response.plaintext_b64.as_bytes())
            .map_err(|e| AppError::vault(format!("device returned malformed plaintext: {e}")))
    }

    fn key_alias(&self) -> String {
        KEY_ALIAS.to_string()
    }

    fn delete_key(&self) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            deleted: bool,
        }

        let response: Response = self
            .handle
            .run_mobile_plugin("deleteKey", serde_json::json!({ "alias": KEY_ALIAS }))
            .map_err(|e| AppError::vault(format!("could not delete the device key: {e}")))?;
        if !response.deleted {
            return Err(AppError::vault("the device key could not be deleted"));
        }
        Ok(())
    }
}

/// Wrapper so the location-service plugin handle can be managed state.
///
/// Kept separate from the keystore so a failure to register one does not take the
/// other down with it: the vault must work even if the location service cannot.
pub struct LocationServiceHandle<R: Runtime> {
    handle: PluginHandle<R>,
}

impl<R: Runtime> LocationServiceHandle<R> {
    /// Build from a registered mobile plugin handle.
    pub fn new(handle: PluginHandle<R>) -> Self {
        Self { handle }
    }

    /// Ask Android to start or stop the location foreground service.
    ///
    /// The service itself is Kotlin; this is only the control channel, so no
    /// Android-specific behaviour leaks into this crate.
    pub fn set_enabled(&self, enabled: bool) -> Result<bool> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            running: bool,
        }

        let response: Response = self
            .handle
            .run_mobile_plugin(
                "setLocationSharingEnabled",
                serde_json::json!({ "enabled": enabled }),
            )
            .map_err(|e| {
                AppError::vault(format!("could not toggle the location service: {e}"))
            })?;
        Ok(response.running)
    }

    /// True when the device-wide location switch is on.
    ///
    /// Distinct from the runtime permission: with the switch off, every fix fails
    /// even though the app has been granted access.
    pub fn is_system_location_enabled(&self) -> bool {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            enabled: bool,
        }

        self.handle
            .run_mobile_plugin::<Response>("isSystemLocationEnabled", serde_json::json!({}))
            .map(|response| response.enabled)
            .unwrap_or(false)
    }

    /// Open the system screen where location access can be granted.
    ///
    /// `app` selects this app's permission page rather than the device switch.
    /// Android offers no way to grant the permission programmatically, so this is
    /// the only path for a permanently denied permission.
    pub fn open_location_settings(&self, app: bool) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            opened: bool,
        }

        let response: Response = self
            .handle
            .run_mobile_plugin("openLocationSettings", serde_json::json!({ "app": app }))
            .map_err(|e| AppError::vault(format!("could not open location settings: {e}")))?;
        if !response.opened {
            return Err(AppError::vault("the system did not open the location settings screen"));
        }
        Ok(())
    }

    /// True when the notification permission is granted, so the persistent
    /// notification can actually be shown.
    pub fn can_post_notifications(&self) -> bool {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            granted: bool,
        }

        self.handle
            .run_mobile_plugin::<Response>("canPostNotifications", serde_json::json!({}))
            .map(|response| response.granted)
            .unwrap_or(false)
    }

    /// Battery percentage and charging state, or `None` when unavailable.
    ///
    /// `pct` of `-1` from the platform means "not reported", which is mapped to
    /// `None` so the UI can say "unknown" instead of showing a dead battery.
    pub fn battery_status(&self) -> Option<(u8, bool)> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Response {
            pct: i32,
            charging: bool,
        }

        let response: Response = self
            .handle
            .run_mobile_plugin("batteryStatus", serde_json::json!({}))
            .ok()?;
        if !(0..=100).contains(&response.pct) {
            return None;
        }
        Some((response.pct as u8, response.charging))
    }
}

/// Register the keystore plugin and install it as the vault [`Keystore`].
///
/// Must run before the commands are invoked, which the builder ordering guarantees.
/// A registration failure is propagated: without this plugin the vault cannot open.
pub fn init_keystore<R: Runtime>() -> TauriPlugin<R> {
    PluginBuilder::new(KEYSTORE_PLUGIN_NAME)
        .setup(|app, api| {
            let keystore_handle =
                api.register_android_plugin(ANDROID_PACKAGE, KEYSTORE_PLUGIN_CLASS)?;
            let keystore: Arc<dyn Keystore> = Arc::new(AndroidKeystore::new(keystore_handle));
            app.manage(keystore);
            Ok(())
        })
        .build()
}

/// Register the location-service plugin.
///
/// Not essential to launch: an app that cannot start the foreground service can
/// still chat and read the map, so a registration failure is logged and ignored.
/// Kept as its own plugin so it cannot replace the keystore registration.
pub fn init_location<R: Runtime>() -> TauriPlugin<R> {
    PluginBuilder::new(LOCATION_PLUGIN_NAME)
        .setup(|app, api| {
            match api.register_android_plugin(ANDROID_PACKAGE, LOCATION_PLUGIN_CLASS) {
                Ok(location_handle) => {
                    app.manage(LocationServiceHandle::new(location_handle));
                }
                Err(error) => {
                    eprintln!(
                        "warning: the Android location-service plugin did not register ({error}); background sharing will be unavailable"
                    );
                }
            }
            Ok(())
        })
        .build()
}