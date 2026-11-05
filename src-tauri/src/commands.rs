//! The `#[tauri::command]` surface consumed by the TypeScript UI.
//!
//! # Conventions
//!
//! * Every command returns [`crate::error::Result`], so the TS side receives
//!   `{ kind, message }` on failure and can branch on `kind` instead of parsing
//!   prose.
//! * No command takes a signing secret as an argument: it lives in the vault and is
//!   only ever read from there, so it cannot be echoed through the webview by
//!   accident.
//! * Commands that mutate group state persist to the vault before reporting
//!   success, so a crash immediately after cannot leave memory and disk disagree.
//! * Commands are deliberately coarse. The UI gets a snapshot (`roster`, `chat`)
//!   rather than a per-member API, which keeps the polling loop in Rust where the
//!   cadence and rate-limit policy already live.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::crypto::{self, InviteCredentialsPayload, PROTOCOL_VERSION};
use crate::error::{AppError, Result};
use crate::geo_filter::{Fix, Publish};
use crate::group::{
    self, ChatItem, GroupState, Identity, MemberView, Preferences, RotationNotice, SharedGroup,
};
use crate::vault::{SecureVault, StoredGroup, StoredUpload, VaultContents, VaultDescriptor, DESCRIPTOR_VERSION};
use crate::wire::{now_unix_ms, IssueComment};

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Everything the command layer needs, managed by Tauri.
pub struct AppState {
    /// The open vault, or `None` before it is unlocked.
    pub vault: parking_lot::RwLock<Option<Arc<SecureVault>>>,
    /// The active group, or `None` before join/create.
    pub group: SharedGroup,
    file_deletion_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("vault_open", &self.vault.read().is_some())
            .field("group_active", &self.group.read().is_some())
            .finish()
    }
}

impl AppState {
    /// Fresh, locked state.
    pub fn new() -> Self {
        Self {
            vault: parking_lot::RwLock::new(None),
            group: Arc::new(parking_lot::RwLock::new(None)),
            file_deletion_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Borrow the vault or explain that it must be unlocked first.
    fn vault(&self) -> Result<Arc<SecureVault>> {
        self.vault.read().clone().ok_or_else(|| {
            AppError::vault("the secure vault is locked; unlock it before this operation")
        })
    }

    /// Borrow the active group.
    fn group(&self) -> Result<Arc<GroupState>> {
        group::require_group(&self.group)
    }

    /// Read the group signing secret out of the vault.
    fn secret(&self) -> Result<String> {
        let vault = self.vault()?;
        let contents = vault
            .load_contents()?
            .ok_or_else(|| AppError::NotConfigured("no group credentials are stored yet".into()))?;
        Ok(contents.secret)
    }

    /// Build a Nostr store for the active group.
    fn nostr_store(&self) -> Result<crate::nostr_store::NostrStore> {
        let group_state = self.group()?;
        let secret = self.secret()?;
        let identity = crate::nostr::NostrIdentity::from_hex(&secret)?;
        crate::nostr_store::store_for(
            &group_state.group_id,
            &group_state.relays,
            &group_state.blossom_servers,
            Arc::new(identity),
        )
    }

        /// Borrow the signing secret so invite re-issue can embed it. Reads from
        /// the vault only; never from a command argument.
        #[allow(dead_code)]
        fn secret_for_invites(&self) -> Result<String> {
            self.secret()
        }
    }

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Where the vault should live, resolved by the caller from Tauri's paths.
///
/// Passed explicitly rather than derived inside Rust so tests can point at a
/// scratch directory.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockRequest {
    /// Directory that will contain the vault files.
    pub vault_dir: PathBuf,
}

/// Result of unlocking or creating the vault.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResponse {
    /// True when a vault already existed and was opened.
    pub existed: bool,
    /// True when a group is already configured in this vault.
    pub group_configured: bool,
    /// Group reference the stored credentials belong to, when configured.
    pub group_ref: Option<String>,
    /// Current key epoch, when configured.
    pub current_epoch: Option<u8>,
    pub requires_recovery: bool,
}

/// Request to join as a guest.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinGroupRequest {
    pub invite: String,
    pub join_password: String,
    pub display_name: String,
}

/// Result of joining.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinGroupResponse {
    pub group_ref: String,
    pub group_label: String,
    pub key_epoch: u8,
    pub fingerprint: String,
    /// True when this device already had a roster entry, i.e. a re-join.
    pub already_member: bool,
}

/// A GPS sample from the platform.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationUpdate {
    pub lat: f64,
    pub lon: f64,
    /// Ground speed in metres per second, when the platform reports it.
    #[serde(default)]
    pub speed_mps: f32,
    /// Direction of travel in degrees clockwise from north.
    #[serde(default)]
    pub heading_deg: f32,
    /// Horizontal accuracy radius in metres.
    #[serde(default)]
    pub accuracy_m: f32,
    /// Battery percentage, or `0` when the platform cannot report it.
    #[serde(default)]
    pub battery_pct: u8,
    /// True when the device is on external power.
    #[serde(default)]
    pub is_charging: bool,
}

/// Whether a submitted fix was published.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationUpdateResponse {
    /// True when a `PATCH` is required.
    pub should_publish: bool,
    /// Human-readable reason when it is not.
    pub skip_reason: Option<String>,
}

/// Result of a poll.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PollResponse {
    /// Milliseconds the caller should wait before polling this channel again.
    pub next_delay_ms: u64,
    /// True when the server reported no change, so nothing was re-decoded.
    pub not_modified: bool,
    /// True when the poll was skipped because a rate limit is in force.
    pub rate_limited: bool,
    /// Seconds until polling resumes, when rate limited.
    pub halt_remaining_secs: Option<i64>,
}

/// A roster snapshot for the map.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RosterSnapshot {
    pub members: Vec<MemberView>,
    pub self_pubkey: String,
    pub current_epoch: u8,
    /// Recent positions per member public key, oldest first.
    pub trails: std::collections::HashMap<String, Vec<crate::group::TrailPoint>>,
}

/// A chat snapshot for the drawer.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatSnapshot {
    pub items: Vec<ChatItem>,
    pub self_pubkey: String,
}

/// Request to send a text message.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTextRequest {
    pub text: String,
}

/// Request to upload and share a file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendFileRequest {
    /// Plaintext file bytes. Sealed before it leaves this command.
    pub data: Vec<u8>,
    pub file_name: String,
    pub mime: String,
    #[serde(default)]
    pub caption: Option<String>,
}

/// Result of a file share.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendFileResponse {
    pub asset_name: String,
    /// Number of older assets deleted to make room.
    pub pruned_count: usize,
    /// Vault size after pruning and upload.
    pub vault_bytes: u64,
}

/// A downloaded and verified file.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadedFile {
    pub file_name: String,
    pub mime: String,
    /// Plaintext bytes.
    pub data: Vec<u8>,
    /// True when the decrypted content matched the advertised digest.
    pub sha256_verified: bool,
}

/// Request to block or unblock a member.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockRequest {
    pub pubkey_b64: String,
    pub blocked: bool,
}

/// Request to report a message.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportRequest {
    pub target_comment_id: u64,
    pub target_pubkey_b64: String,
    pub reason: String,
}

/// Request to persist display preferences.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferencesRequest {
    pub display_name: String,
    pub avatar_color: String,
    pub accepted_eula: bool,
    pub accepted_location_disclosure: bool,
    #[serde(default)]
    pub enabled_background_location: bool,
}

/// Consent status, so the UI can render the correct gate on launch.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentStatus {
    pub accepted_eula: bool,
    pub accepted_location_disclosure: bool,
    pub enabled_background_location: bool,
    pub onboarding_complete: bool,
}

/// Result of toggling background location sharing.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundLocationResponse {
    /// True when background sharing should now be running.
    pub enabled: bool,
    /// True when the platform accepted the change.
    pub applied: bool,
    /// Present when the change could not be fully applied.
    pub warning: Option<String>,
}

// ---------------------------------------------------------------------------
// Background location
// ---------------------------------------------------------------------------

/// Start or stop background location sharing.
///
/// On Android this drives the location foreground service; on desktop it only
/// records the preference, because there is no equivalent to a foreground service.
/// Recording the preference either way keeps the UI state consistent across
/// platforms, so the toggle does not appear to do nothing in a development build.
#[tauri::command]
pub fn set_background_location(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<BackgroundLocationResponse> {
    if let Some(group_state) = state.group.read().as_ref() {
        let mut preferences = group_state.preferences();
        preferences.enabled_background_location = enabled;
        state.vault()?.update_preferences(&preferences)?;
        group_state.set_preferences(preferences);
    }

    #[cfg(target_os = "android")]
    {
            // The location service is the thing actually being toggled, so its reported
            // state is what determines `applied`. A missing window would only matter if
            // the service needed an activity, which it does not.
            use tauri::Manager as _;

            let running = match app
                .try_state::<crate::keystore_android::LocationServiceHandle<tauri::Wry>>()
            {
                Some(handle) => handle.inner().set_enabled(enabled).unwrap_or(false),
                None => false,
            };
            return Ok(BackgroundLocationResponse {
                enabled,
                applied: running == enabled,
                warning: if running == enabled {
                    None
                } else {
                    Some(
                        "Android did not accept the change, so background sharing may not be running. Check the notification shade."
                            .to_string(),
                    )
                },
            });
        }

    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        // The preference is recorded so the UI stays truthful, but there is no
        // foreground service on this platform to start.
        Ok(BackgroundLocationResponse {
            enabled,
            applied: true,
            warning: if enabled {
                Some(
                    "Background location needs a foreground service, which only exists on Android. The preference is saved for when this group is used on a phone."
                        .to_string(),
                )
            } else {
                None
            },
        })
    }
}

/// What the platform reports about location access.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationAccessResponse {
    /// True when the device-wide location switch is on.
    pub system_location_enabled: bool,
    /// True when this platform can open a settings screen for the user.
    pub can_open_settings: bool,
    /// True when the app holds fine or coarse location.
    pub foreground_granted: bool,
    /// True when the app holds the background location grant.
    ///
    /// On Android 11+ this is a separate settings action, not a dialog, so the UI
    /// has to offer that trip rather than a prompt.
    pub background_granted: bool,
    /// True when the foreground-service notification can be shown.
    ///
    /// The location policy requires the user to always see that background sharing
    /// is running, so a denied notification permission blocks background sharing.
    pub notifications_granted: bool,
}

/// Report whether the device location switch is on and which grants are held.
///
/// The runtime permission is checked in the webview, which owns the plugin call;
/// this covers the other half of the problem, where the permission is granted but
/// the system switch is off and every fix fails.
#[tauri::command]
pub fn location_access(app: tauri::AppHandle) -> Result<LocationAccessResponse> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager as _;

        let handle = app
            .try_state::<crate::keystore_android::LocationServiceHandle<tauri::Wry>>();
        return Ok(match handle {
            Some(handle) => {
                let inner = handle.inner();
                LocationAccessResponse {
                    system_location_enabled: inner.is_system_location_enabled(),
                    can_open_settings: true,
                    foreground_granted: inner.has_foreground_location(),
                    background_granted: inner.has_background_location(),
                    notifications_granted: inner.can_post_notifications(),
                }
            }
            None => LocationAccessResponse {
                system_location_enabled: false,
                can_open_settings: false,
                foreground_granted: false,
                background_granted: false,
                notifications_granted: false,
            },
        });
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        // Desktop has no equivalent switch to read, and the browser owns its own
        // prompt, so the state is reported as unknown-but-not-blocking.
        Ok(LocationAccessResponse {
            system_location_enabled: true,
            can_open_settings: cfg!(windows),
            foreground_granted: true,
            background_granted: false,
            notifications_granted: true,
        })
    }
}

/// Battery level and charging state, when the platform can report them.
///
/// `pct` is `null` rather than `0` when unavailable, so the UI can distinguish
/// "the phone is dead" from "this platform does not say".
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatteryResponse {
    pub pct: Option<u8>,
    pub charging: bool,
}

/// Read the device's battery state.
///
/// Android is asked through the location plugin, because the webview's Battery
/// Status API is not present on every WebView build. Desktop falls back to the
/// webview API, which the UI reads directly, so this reports "unknown" there.
#[tauri::command]
pub fn battery_status(app: tauri::AppHandle) -> Result<BatteryResponse> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager as _;

        let handle = app
            .try_state::<crate::keystore_android::LocationServiceHandle<tauri::Wry>>();
        if let Some(handle) = handle {
            if let Some((pct, charging)) = handle.inner().battery_status() {
                return Ok(BatteryResponse {
                    pct: Some(pct),
                    charging,
                });
            }
        }
        return Ok(BatteryResponse {
            pct: None,
            charging: false,
        });
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Ok(BatteryResponse {
            pct: None,
            charging: false,
        })
    }
}

/// Open the system screen where location access can be granted.
///
/// Android cannot grant a permission on the app's behalf, so a permanently denied
/// permission can only be fixed by the user in Settings. `app` selects this app's
/// permission page instead of the device location switch.
#[tauri::command]
pub fn open_location_settings(app: tauri::AppHandle, app_page: bool) -> Result<()> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager as _;

        let handle = app
            .try_state::<crate::keystore_android::LocationServiceHandle<tauri::Wry>>()
            .ok_or_else(|| AppError::not_configured("the location service is unavailable on this device"))?;
        return handle.inner().open_location_settings(app_page);
    }

    #[cfg(windows)]
    {
        let _ = (app, app_page);
        // Windows has one location privacy page; there is no per-app variant, so
        // both remedies land on the same screen.
        open_windows_settings("ms-settings:privacy-location")
    }

    #[cfg(all(not(target_os = "android"), not(windows)))]
    {
        let _ = (app, app_page);
        Err(AppError::not_configured(
            "this platform has no location settings screen to open",
        ))
    }
}

/// Open a `ms-settings:` URI in the Windows Settings app.
#[cfg(windows)]
fn open_windows_settings(uri: &str) -> Result<()> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let to_wide = |value: &str| -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    };
    let operation = to_wide("open");
    let target = to_wide(uri);

    // ShellExecuteW returns a value greater than 32 on success; anything at or
    // below that is an error code rather than a handle.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        return Err(AppError::not_configured(
            "Windows did not open the location settings screen",
        ));
    }
    Ok(())
}

/// Result of a rotation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateResponse {
    pub new_epoch: u8,
    pub retired_epoch: u8,
    /// Fresh invite strings, keyed by member public key.
    pub invites: Vec<MemberInvite>,
    /// Members who were removed as part of this rotation.
    pub removed_pubkeys: Vec<String>,
    /// One current group code the owner can hand to anyone who should stay.
    pub group_invite: String,
}

/// An invite string bound to one member.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberInvite {
    pub pubkey_b64: String,
    pub display_name: String,
    pub invite: String,
}

/// Request to rotate the group key, optionally removing members.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateRequest {
    pub join_password: String,
    #[serde(default)]
    pub reason: Option<String>,
    /// Members to remove as part of the rotation.
    #[serde(default)]
    pub remove_pubkeys: Vec<String>,
}

/// Request to pack the current group code.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareInviteRequest {
    pub join_password: String,
}

/// A freshly packed group code.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareInviteResponse {
    pub invite: String,
    pub fingerprint: String,
}

/// Request to promote or demote a member.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRoleRequest {
    pub pubkey_b64: String,
    pub role: String,
}

/// Result of leaving and wiping.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WipeResponse {
    /// True when this device's roster comment was deleted.
    pub roster_comment_deleted: bool,
    /// True when the vault files were removed.
    pub vault_wiped: bool,
}

/// Result of destroying the group.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestroyResponse {
    pub group_ref: String,
    pub vault_wiped: bool,
    pub accepted_relays: Vec<String>,
    pub unconfirmed_relays: Vec<String>,
}

/// Diagnostics for a developer panel.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsResponse {
    pub group_ref: String,
    pub group_label: String,
    /// Which storage backend holds this group.
    pub backend: String,
    /// True when the backend needs no account.
    pub accountless: bool,
    pub is_host: bool,
    pub current_epoch: u8,
    pub known_epochs: Vec<u8>,
    pub roster_len: usize,
    pub chat_len: usize,
    pub blocked_count: usize,
    pub chat_interval_s: u64,
    pub roster_interval_s: u64,
    pub halted_until_unix_s: Option<i64>,
    pub remaining_requests: Option<u32>,
    pub total_requests: Option<u32>,
    pub fingerprint: String,
}

/// Outcome of a rotation notice check.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationStatus {
    pub new_epoch: u8,
    pub retired_epoch: u8,
    pub already_held: bool,
    /// True when the UI should prompt the host for a re-issued invite.
    pub needs_reissue: bool,
}

/// A single asset listing entry.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultAssetView {
    pub id: u64,
    pub name: String,
    pub size: u64,
    pub created_at_ms: i64,
    pub deletion_status: Option<String>,
}

/// Vault storage report.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultReport {
    pub assets: Vec<VaultAssetView>,
    pub total_bytes: u64,
    pub max_bytes: u64,
    /// Requests remaining this hour, when the backend reports a budget.
    pub rate_limit_remaining: Option<u32>,
}

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

/// Open or create the vault, then hydrate group state from it.
///
/// `keystore` is injected by the caller: on Android it is the hardware-backed
/// implementation, on desktop and in tests it is the in-memory double.
#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, AppState>,
    keystore: State<'_, Arc<dyn crate::vault::Keystore>>,
    request: UnlockRequest,
) -> Result<UnlockResponse> {
    let existed = SecureVault::exists(&request.vault_dir);
    let keystore_handle = Arc::clone(&keystore);

    let vault = SecureVault::open_or_create(request.vault_dir.clone(), keystore_handle)?;
    let descriptor = vault.descriptor();
    let stored_group = vault.load_group()?;
    let requires_recovery = descriptor.is_some() && stored_group.is_none();
    if let (Some(descriptor), Some(mut stored)) = (descriptor.as_ref(), stored_group) {
        let contents = vault.load_contents()?.ok_or_else(|| AppError::vault("group credentials are missing"))?;
        stored.invite.group_master_key = *contents.group_key;
        stored.invite.key_epoch = descriptor.current_epoch;
        let identity = Identity::from_secret(stored.identity_secret);
        let group_state = GroupState::from_invite(&stored.invite, identity, stored.preferences.clone(), stored.is_host)?;
        group_state.install_roles(&stored.roles.iter().map(|role| (role.pubkey_b64.clone(), role.role.clone())).collect::<Vec<_>>());
        // The track log is sealed with the group key, so it can only be opened
        // once the group is known. A log that cannot be read is not fatal: the
        // app starts with an empty history rather than refusing to launch.
        match crate::history::TrackHistory::load(&request.vault_dir, &contents.group_key) {
            Ok(history) => group_state.install_history(history),
            Err(error) => {
                eprintln!("warning: location history could not be loaded ({error}); starting empty");
            }
        }
        *state.group.write() = Some(Arc::new(group_state));
    }
    *state.vault.write() = Some(Arc::new(vault));

    let configured = descriptor.is_some();
    Ok(UnlockResponse {
        existed,
        group_configured: configured,
        group_ref: descriptor.as_ref().map(|d| d.group_ref.clone()),
        current_epoch: descriptor.as_ref().map(|d| d.current_epoch),
        requires_recovery,
    })
}

/// Request to delete the local vault.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetVaultRequest {
    /// Directory holding the vault files.
    ///
    /// Required in practice: the reset button only appears after `unlock_vault`
    /// failed, so there is no open vault to ask for its directory. Optional so an
    /// already-open vault can still be reset without repeating the path.
    #[serde(default)]
    pub vault_dir: Option<PathBuf>,
}

/// Delete the local vault so an unreadable one can be replaced.
///
/// This is the only escape from a vault whose device key was invalidated: the
/// password can never be unwrapped again, so the file is dead weight that blocks
/// the app from starting. Nothing remote is touched.
///
/// Deliberately does *not* go through [`AppState::vault`]: that requires an open
/// vault, and the whole point of this command is the case where opening failed.
#[tauri::command]
pub fn reset_vault(
    state: State<'_, AppState>,
    keystore: State<'_, Arc<dyn crate::vault::Keystore>>,
    request: Option<ResetVaultRequest>,
) -> Result<()> {
    reset_vault_inner(&state, &keystore, request)
}

fn reset_vault_inner(
    state: &AppState,
    keystore: &Arc<dyn crate::vault::Keystore>,
    request: Option<ResetVaultRequest>,
) -> Result<()> {
    let open = state.vault.read().clone();
    let dir = request
        .and_then(|request| request.vault_dir)
        .or_else(|| open.as_ref().map(|vault| vault.dir().to_path_buf()))
        .ok_or_else(|| {
            AppError::invalid_argument("the vault directory is required to reset the vault")
        })?;

    // Drop the in-memory handle first so nothing can re-persist the files we are
    // about to delete.
    *state.vault.write() = None;
    *state.group.write() = None;

    SecureVault::wipe_dir(&dir)?;

    // A key that is present but unusable would fail every future wrap, so the
    // reset must remove it too. Best-effort: the files are already gone, and
    // reporting a key-deletion failure would leave the user stuck on the error
    // screen with nothing left to reset.
    if let Err(error) = keystore.delete_key() {
        eprintln!("warning: the device key could not be deleted during reset: {error}");
    }
    Ok(())
}

/// Every group this device belongs to, for the switcher.
#[tauri::command]
pub fn list_groups(state: State<'_, AppState>) -> Result<Vec<crate::vault::GroupSummary>> {
    Ok(state.vault()?.list_groups())
}

/// Switch to another stored group.
///
/// Everything needed is already in the vault, so this is a local operation: no
/// network call, and it works with the device offline.
#[tauri::command]
pub fn switch_group(state: State<'_, AppState>, group_id: String) -> Result<()> {
    let vault = state.vault()?;
    let (contents, descriptor, stored) = vault.activate_group(&group_id)?;

    let mut stored = stored.ok_or_else(|| {
        AppError::vault("that group has no saved identity; rejoin it with a fresh invite")
    })?;
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
        &stored.roles.iter().map(|role| (role.pubkey_b64.clone(), role.role.clone())).collect::<Vec<_>>(),
    );
    *state.group.write() = Some(Arc::new(group_state));
    Ok(())
}

/// Forget one stored group without touching the others.
#[tauri::command]
pub fn forget_group(state: State<'_, AppState>, group_id: String) -> Result<bool> {
    let vault = state.vault()?;
    let was_active = vault.remove_group(&group_id)?;
    if was_active {
        *state.group.write() = None;
    }
    Ok(was_active)
}

/// Explicitly discard an old vault that did not persist its group identity.
#[tauri::command]
pub fn discard_legacy_group(state: State<'_, AppState>) -> Result<()> {
    let vault = state.vault()?;
    if vault.descriptor().is_none() || vault.load_group()?.is_some() {
        return Err(AppError::invalid_argument("this vault is not an unrestorable legacy group"));
    }
    vault.wipe()?;
    *state.group.write() = None;
    *state.vault.write() = None;
    Ok(())
}

/// Lock the vault, dropping the in-memory handle.
#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>) -> Result<()> {
    *state.vault.write() = None;
    *state.group.write() = None;
    Ok(())
}

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

/// Read the stored consent state.
#[tauri::command]
pub fn consent_status(state: State<'_, AppState>) -> Result<ConsentStatus> {
    let preferences = match group::require_group(&state.group) {
        Ok(group_state) => group_state.preferences(),
        Err(_) => Preferences::seeded(),
    };

    Ok(ConsentStatus {
        accepted_eula: preferences.accepted_eula,
        accepted_location_disclosure: preferences.accepted_location_disclosure,
        enabled_background_location: preferences.enabled_background_location,
        onboarding_complete: preferences.is_onboarding_complete(),
    })
}

/// Record consent choices and the display name.
///
/// Separate from group creation because the Play Store requires the disclosure
/// to precede any permission request, which happens before a group exists.
#[tauri::command]
pub fn set_preferences(
    state: State<'_, AppState>,
    request: PreferencesRequest,
) -> Result<ConsentStatus> {
    let name = request.display_name.trim();
    if name.is_empty() {
        return Err(AppError::invalid_argument("a display name is required"));
    }
    if name.chars().count() > 32 {
        return Err(AppError::invalid_argument(
            "display name must be 32 characters or fewer",
        ));
    }
    validate_hex_color(&request.avatar_color)?;

    let preferences = Preferences {
        display_name: name.to_string(),
        avatar_color: request.avatar_color,
        // The block list is preserved across preference writes.
        blocked_pubkeys: state
            .group
            .read()
            .as_ref()
            .map(|g| g.blocked_pubkeys())
            .unwrap_or_default(),
        accepted_eula: request.accepted_eula,
        accepted_location_disclosure: request.accepted_location_disclosure,
        enabled_background_location: request.enabled_background_location,
    };

    if let Some(group_state) = state.group.read().as_ref() {
        state.vault()?.update_preferences(&preferences)?;
        group_state.set_preferences(preferences);
    }

    Ok(ConsentStatus {
        accepted_eula: request.accepted_eula,
        accepted_location_disclosure: request.accepted_location_disclosure,
        enabled_background_location: request.enabled_background_location,
        onboarding_complete: false,
    })
}

// ---------------------------------------------------------------------------
// Create and join
// ---------------------------------------------------------------------------

/// Request to create a group on the accountless Nostr backend.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateNostrGroupRequest {
    pub group_label: String,
    pub join_password: String,
    pub display_name: String,
    /// Relay URLs. Defaults to the built-in list when empty.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Blossom servers for blobs. Defaults to the built-in list when empty.
    #[serde(default)]
    pub blossom_servers: Vec<String>,
}

/// Result of creating a Nostr group.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateNostrGroupResponse {
    pub invite: String,
    pub fingerprint: String,
    pub group_id: String,
    pub relays: Vec<String>,
    /// This device's Nostr public key, which is its identity in the group.
    pub nostr_pubkey: String,
}

/// Create a group on Nostr: no account, no token, no repository.
///
/// The identity is a keypair generated here, so there is nothing to sign in to.
/// The invite carries the group key and the relay list, and deliberately carries
/// no credential: each member signs their own events, so a guest can only write
/// their own slot.
#[tauri::command]
pub async fn create_nostr_group(
    state: State<'_, AppState>,
    request: CreateNostrGroupRequest,
) -> Result<CreateNostrGroupResponse> {
    let vault = state.vault()?;
    if request.join_password.is_empty() {
        return Err(AppError::invalid_argument(
            "a join password is required; it is what protects the invite string",
        ));
    }

    let relays = if request.relays.is_empty() {
        crate::nostr::DEFAULT_RELAYS
            .iter()
            .map(|relay| (*relay).to_string())
            .collect()
    } else {
        request.relays.clone()
    };
    let blossom_servers = if request.blossom_servers.is_empty() {
        crate::nostr::DEFAULT_BLOSSOM_SERVERS
            .iter()
            .map(|server| (*server).to_string())
            .collect()
    } else {
        request.blossom_servers.clone()
    };

    let group_id = uuid::Uuid::new_v4().to_string();
    let backend = crate::storage::Backend::Nostr(crate::storage::NostrBackend {
        group_id: group_id.clone(),
        relays: relays.clone(),
        blossom_servers: blossom_servers.clone(),
    });
    backend.validate()?;

    let nostr_identity = crate::nostr::NostrIdentity::generate()?;
    let identity = Identity::generate()?;
    let group_key = crypto::new_group_key()?;

    let invite_payload = InviteCredentialsPayload {
        version: PROTOCOL_VERSION,
        backend: crate::storage::BackendKind::Nostr,
        group_id: group_id.clone(),
        group_master_key: *group_key,
        relays: relays.clone(),
        blossom_servers: blossom_servers.clone(),
        host_pubkey: identity.pubkey_b64.clone(),
        group_label: request.group_label.clone(),
        key_epoch: 0,
    };

    let invite = crypto::pack_invite(&invite_payload, &request.join_password)?;

    let preferences = Preferences {
        display_name: request.display_name.trim().to_string(),
        avatar_color: "#5b8cff".to_string(),
        blocked_pubkeys: Default::default(),
        accepted_eula: true,
        accepted_location_disclosure: true,
        enabled_background_location: true,
    };

    let descriptor = VaultDescriptor {
        version: DESCRIPTOR_VERSION,
        keystore_alias: vault.keystore_alias(),
        group_ref: format!("nostr:{group_id}"),
        current_epoch: 0,
    };
    vault.store_group_contents(
        &VaultContents {
            // The Nostr signing secret is the group credential.
            secret: nostr_identity.secret_hex().to_string(),
            group_key: zeroize::Zeroizing::new(*group_key),
        },
        &descriptor,
        Some(StoredGroup {
            invite: invite_payload.clone(),
            identity_secret: *identity.secret_bytes(),
            preferences: preferences.clone(),
            is_host: true,
            uploads: Vec::new(),
            invite_code: Some(invite.clone()),
            roles: Vec::new(),
        }),
    )?;

    let group_state = GroupState::from_invite(&invite_payload, identity, preferences, true)?;
    let fingerprint = group_state.identity.fingerprint();
    *state.group.write() = Some(Arc::new(group_state));

    Ok(CreateNostrGroupResponse {
        invite,
        fingerprint,
        group_id,
        relays,
        nostr_pubkey: nostr_identity.pubkey_hex().to_string(),
    })
}

/// Join a group with an invite string.
#[tauri::command]
pub async fn join_group(
    state: State<'_, AppState>,
    request: JoinGroupRequest,
) -> Result<JoinGroupResponse> {
    let vault = state.vault()?;

    let invite = crypto::unpack_invite(&request.invite, &request.join_password)?;
    invite.validate()?;

    let identity = Identity::generate()?;

    // Nostr is the only backend: joining generates a fresh keypair and checks
    // whether this device already has a slot, and whether the host closed the
    // group.
    let nostr_identity = crate::nostr::NostrIdentity::generate()?;
    let store = crate::nostr_store::store_for(
        &invite.group_id,
        &invite.relays,
        &invite.blossom_servers,
        Arc::new(crate::nostr::NostrIdentity::from_hex(
            &nostr_identity.secret_hex(),
        )?),
    )?;

    // A fresh keypair can never already be a member, but the check keeps the
    // path honest and catches a replayed secret.
    let already_member = store.has_own_slot().await?;
    let closures = store.read_closures().await?;
    if closures.iter().any(|event| {
        group::verify_closure_proof(&invite.host_pubkey, &invite.group_id, &event.content)
    }) {
        return Err(AppError::group_state(
            "the host has closed this group; this invite can no longer be used",
        ));
    }
    let group_ref = format!("nostr:{}", invite.group_id);
    let stored_secret = nostr_identity.secret_hex().to_string();

    let preferences = Preferences {
        display_name: request.display_name.trim().to_string(),
        avatar_color: "#5b8cff".to_string(),
        blocked_pubkeys: Default::default(),
        accepted_eula: true,
        accepted_location_disclosure: true,
        enabled_background_location: true,
    };

    let descriptor = VaultDescriptor {
        version: DESCRIPTOR_VERSION,
        keystore_alias: vault.keystore_alias(),
        group_ref: group_ref.clone(),
        current_epoch: invite.key_epoch,
    };
    vault.store_group_contents(
        &VaultContents {
            secret: stored_secret,
            group_key: zeroize::Zeroizing::new(*invite.group_key()),
        },
        &descriptor,
        Some(StoredGroup {
            invite: invite.clone(),
            identity_secret: *identity.secret_bytes(),
            preferences: preferences.clone(),
            invite_code: Some(request.invite.trim().to_string()),
            roles: Vec::new(),
            is_host: false,
            uploads: Vec::new(),
        }),
    )?;

    let group_state = GroupState::from_invite(&invite, identity, preferences, false)?;
    let fingerprint = group_state.identity.fingerprint();
    *state.group.write() = Some(Arc::new(group_state));

    Ok(JoinGroupResponse {
        group_ref,
        group_label: invite.group_label.clone(),
        key_epoch: invite.key_epoch,
        fingerprint,
        already_member,
    })
}

// ---------------------------------------------------------------------------
// Location
// ---------------------------------------------------------------------------

/// Submit a GPS fix, publishing it when policy allows.
#[tauri::command]
pub async fn update_location(
    state: State<'_, AppState>,
    update: LocationUpdate,
) -> Result<LocationUpdateResponse> {
    publish_fix(&state, update).await
}

/// Apply the movement gate and publish a fix.
///
/// Split out of the command so the background publisher can drive the same path
/// without a webview: the gate, the envelope, and the relay write must not exist
/// in two places, or a fix published while the app is closed would bypass the
/// battery policy.
pub(crate) async fn publish_fix(
    state: &AppState,
    update: LocationUpdate,
) -> Result<LocationUpdateResponse> {
    let group_state = state.group()?;
    let fix = Fix {
        lat: update.lat,
        lon: update.lon,
        unix_ms: now_unix_ms(),
        speed_mps: update.speed_mps,
        heading_deg: update.heading_deg,
        accuracy_m: update.accuracy_m,
    };

    // Battery is device state rather than position, so it is recorded even when
    // the fix itself is not worth publishing: a member sitting still still wants
    // their peers to see the phone is about to die.
    group_state.set_battery(update.battery_pct, update.is_charging);

    let decision = group_state.consider_location(fix)?;
    if let Publish::No(reason) = decision {
        return Ok(LocationUpdateResponse {
            should_publish: false,
            skip_reason: Some(group::describe_skip(reason)),
        });
    }

    let envelope = group_state.build_location_envelope(fix)?;
    let body = serde_json::to_string(&envelope)
        .map_err(|e| AppError::crypto(format!("could not serialize the envelope: {e}")))?;

    let outcome = {
        // Addressable event: republishing replaces this member's slot, so there
        // is no comment id to track and no way to collide with another member.
        let store = state.nostr_store()?;
        store
            .publish_roster(&body)
            .await
            .map(|_| crate::wire::nostr_numeric_id(group_state.identity.pubkey_b64.as_str()))
    };

    match outcome {
        Ok(id) => {
            *group_state.my_comment_id.write() = Some(id);
            Ok(LocationUpdateResponse {
                should_publish: true,
                skip_reason: None,
            })
        }
        Err(error) => {
            // Do not let a failed request suppress the next attempt.
            group_state.record_location_publish_failed();
            Err(error)
        }
    }
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

/// Poll the roster channel and refresh the snapshot.
#[tauri::command]
pub async fn poll_roster(state: State<'_, AppState>) -> Result<PollResponse> {
    let group_state = state.group()?;
    let now_s = crate::wire::now_unix_s();

    if let Some(remaining) = group_state.halt_remaining_secs(now_s) {
        return Ok(PollResponse {
            next_delay_ms: (remaining.max(1) as u64) * 1_000,
            not_modified: false,
            rate_limited: true,
            halt_remaining_secs: Some(remaining),
        });
    }

    // Relays push, so there is no conditional-GET path and no quota to observe.
    let store = state.nostr_store()?;
    let comments = store.read_roster().await?;
    group_state.apply_roster(&comments);
    if let Ok(controls) = store.read_control().await {
        group_state.apply_role_controls(&controls);
    }
    announce_roles_if_needed(state.clone(), &group_state).await;
    Ok(PollResponse {
        next_delay_ms: group_state.roster_delay(false).await.as_millis() as u64,
        not_modified: false,
        rate_limited: false,
        halt_remaining_secs: None,
    })
}

/// Poll the chat channel and refresh the snapshot.
#[tauri::command]
pub async fn poll_chat(state: State<'_, AppState>) -> Result<PollResponse> {
    let group_state = state.group()?;
    let now_s = crate::wire::now_unix_s();

    if let Some(remaining) = group_state.halt_remaining_secs(now_s) {
        return Ok(PollResponse {
            next_delay_ms: (remaining.max(1) as u64) * 1_000,
            not_modified: false,
            rate_limited: true,
            halt_remaining_secs: Some(remaining),
        });
    }

    let store = state.nostr_store()?;
    let comments = store.read_chat().await?;
    let removals = store.read_file_removals().await?;
    group_state.apply_chat(&comments);
    group_state.apply_file_removals(&removals);
    Ok(PollResponse {
        next_delay_ms: group_state.chat_delay(false).await.as_millis() as u64,
        not_modified: false,
        rate_limited: false,
        halt_remaining_secs: None,
    })
}

/// Report the current rate-limit state.
///
/// Nostr has no shared request budget: relays push, and each member signs with
/// its own key, so there is nothing to throttle. The command stays so the UI
/// keeps a stable surface.
#[tauri::command]
pub async fn refresh_rate_limit(state: State<'_, AppState>) -> Result<PollResponse> {
    let _ = state.group()?;
    Ok(PollResponse {
        next_delay_ms: 0,
        not_modified: false,
        rate_limited: false,
        halt_remaining_secs: None,
    })
}

// ---------------------------------------------------------------------------
// Location history
// ---------------------------------------------------------------------------

/// Request for a member's track history.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRequest {
    /// Member public key, Base64. Omit for every member.
    #[serde(default)]
    pub pubkey_b64: Option<String>,
    /// How far back to look, in hours. Clamped to the retention window.
    #[serde(default)]
    pub hours: Option<u32>,
}

/// One member's track history.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryResponse {
    /// Points per member public key, oldest first.
    pub tracks: std::collections::HashMap<String, Vec<crate::history::TrackPoint>>,
    /// Oldest point the log still holds, so the UI can say how far back it goes.
    pub oldest_unix_ms: Option<i64>,
    /// Retention window, in days.
    pub retention_days: i64,
}

/// Track history for one member, or for everyone.
///
/// Local only: this reads the on-device log and never touches the network, so it
/// works offline and costs no requests.
#[tauri::command]
pub fn location_history(
    state: State<'_, AppState>,
    request: HistoryRequest,
) -> Result<HistoryResponse> {
    let group_state = state.group()?;
    let hours = request.hours.unwrap_or(24).clamp(1, crate::history::HISTORY_RETENTION_DAYS as u32 * 24);
    let since_ms = now_unix_ms().saturating_sub(i64::from(hours) * 60 * 60 * 1_000);

    let tracks = match request.pubkey_b64.as_deref() {
        Some(pubkey) => {
            let points = group_state.history_since(pubkey, since_ms);
            if points.is_empty() {
                std::collections::HashMap::new()
            } else {
                std::collections::HashMap::from([(pubkey.to_string(), points)])
            }
        }
        None => group_state.history_snapshot(since_ms),
    };

    let oldest_unix_ms = tracks
        .values()
        .filter_map(|points| points.first().map(|point| point.unix_ms))
        .min();

    Ok(HistoryResponse {
        tracks,
        oldest_unix_ms,
        retention_days: crate::history::HISTORY_RETENTION_DAYS,
    })
}

/// Persist the track log now.
///
/// Called on a timer and when the app is backgrounded. Returns `true` when a
/// write happened, so the caller can avoid pointless work.
#[tauri::command]
pub fn save_location_history(state: State<'_, AppState>) -> Result<bool> {
    let group_state = state.group()?;
    let vault = state.vault()?;
    group_state.save_history(vault.dir())
}

/// Delete one member's history, or all of it.
///
/// Blocking a member calls this for that member: keeping a month of someone's
/// movements after blocking them would defeat the point of blocking them.
#[tauri::command]
pub fn clear_location_history(
    state: State<'_, AppState>,
    pubkey_b64: Option<String>,
) -> Result<()> {
    let group_state = state.group()?;
    match pubkey_b64 {
        Some(pubkey) => group_state.forget_history(&pubkey),
        None => group_state.history.write().clear(),
    }
    let vault = state.vault()?;
    group_state.save_history(vault.dir())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

/// Current roster, for the map.
#[tauri::command]
pub fn roster_snapshot(state: State<'_, AppState>) -> Result<RosterSnapshot> {
    let group_state = state.group()?;
    Ok(RosterSnapshot {
        members: group_state.visible_roster(),
        self_pubkey: group_state.identity.pubkey_b64.clone(),
        current_epoch: group_state.current_epoch(),
        trails: group_state.trails_snapshot(),
    })
}

/// Current chat, for the drawer.
#[tauri::command]
pub fn chat_snapshot(state: State<'_, AppState>) -> Result<ChatSnapshot> {
    let group_state = state.group()?;
    Ok(ChatSnapshot {
        items: group_state.visible_chat(),
        self_pubkey: group_state.identity.pubkey_b64.clone(),
    })
}

/// Diagnostics for a developer panel.
#[tauri::command]
pub fn diagnostics(state: State<'_, AppState>) -> Result<DiagnosticsResponse> {
    let group_state = state.group()?;
    let report = group_state.cadence_report();
        let current_epoch = group_state.current_epoch();
        let known_epochs = {
            let keys = group_state.keys.read();
            keys.known_epochs()
        };
        let roster_len = group_state.roster.read().len();
        let chat_len = group_state.chat.read().len();
        let blocked_count = group_state.blocked_sorted().len();

        Ok(DiagnosticsResponse {
            group_ref: group_state.backend.location(),
            group_label: group_state.group_label.clone(),
            backend: group_state.backend.kind().as_str().to_string(),
            accountless: !group_state.backend.kind().requires_account(),
            is_host: group_state.is_host,
            current_epoch,
            known_epochs,
            roster_len,
            chat_len,
            blocked_count,
            chat_interval_s: report.chat_interval_s,
        roster_interval_s: report.roster_interval_s,
        halted_until_unix_s: report.halted_until_unix_s,
        remaining_requests: report.remaining_requests,
        total_requests: report.total_requests,
        fingerprint: group_state.identity.fingerprint(),
    })
}

// ---------------------------------------------------------------------------
// Chat
// ---------------------------------------------------------------------------

/// Send a text message.
#[tauri::command]
pub async fn send_text(
    state: State<'_, AppState>,
    request: SendTextRequest,
) -> Result<PollResponse> {
    let group_state = state.group()?;

    let envelope = group_state.build_text_envelope(&request.text, now_unix_ms())?;
    let body = serde_json::to_string(&envelope)
        .map_err(|e| AppError::crypto(format!("could not serialize the envelope: {e}")))?;

    let created = {
        let store = state.nostr_store()?;
        let event_id = store.publish_chat(&body).await?;
        // Reflect the send locally without a round trip, using the same shape a
        // relay read would produce.
        crate::wire::IssueComment {
            id: crate::wire::nostr_numeric_id(&event_id),
            body,
            created_at_ms: now_unix_ms(),
            updated_at_ms: now_unix_ms(),
            author_login: store.pubkey_hex().to_string(),
            nostr_event_id: Some(event_id),
        }
    };

    group_state.append_chat(&created);
    // A send is a strong signal that the channel is live, so drop back to cadence.
    group_state.reset_cadence();

    Ok(PollResponse {
        next_delay_ms: (crate::group::CHAT_INTERVAL_SECS * 1_000),
        not_modified: false,
        rate_limited: false,
        halt_remaining_secs: None,
    })
}

/// Seal, upload, and announce a file.
#[tauri::command]
pub async fn send_file(
    state: State<'_, AppState>,
    request: SendFileRequest,
) -> Result<SendFileResponse> {
    let group_state = state.group()?;

    if request.data.is_empty() {
        return Err(AppError::invalid_argument("cannot share an empty file"));
    }
    crate::wire::enforce_file_size(request.data.len() as u64)?;

    let plaintext_digest = crypto::sha256_b64(&request.data);
    let key = group_state.current_group_key()?;
    let sealed = crypto::seal_blob(&key, &request.data)?;

    // Blossom is content-addressed and has no per-group quota to prune.
    let pruned_count = 0;

    // The asset name is the content address, which is what makes the pointer
    // verifiable and deduplicates identical files.
    let store = state.nostr_store()?;
    let upload = store.upload_blob(&sealed).await?;
    let asset_name = upload.blob.sha256.clone();

    // Announce the pointer only after the blob exists, so no member ever sees a
    // dangling reference.
    let envelope = group_state.build_file_envelope(
        &asset_name,
        request.data.len() as u64,
        &request.mime,
        &plaintext_digest,
        request.caption.clone(),
        now_unix_ms(),
    )?;
    let body = serde_json::to_string(&envelope)
        .map_err(|e| AppError::crypto(format!("could not serialize the envelope: {e}")))?;

    let (created, vault_bytes) = {
        let event = store.file_event(&body)?;
        state.vault()?.save_upload(StoredUpload {
            sha256: upload.blob.sha256.clone(),
            server: upload.server.clone(),
            size: upload.blob.size,
            event: event.clone(),
            deleted: false,
            notice_published: false,
        }).map_err(|error| AppError::vault(format!(
            "file uploaded to {} as {}, but its ownership could not be saved: {error}",
            upload.server, upload.blob.sha256
        )))?;
        store.publish_file(&event).await?;
        let event_id = event.id;
        let comment = crate::wire::IssueComment {
            id: crate::wire::nostr_numeric_id(&event_id),
            body,
            created_at_ms: now_unix_ms(),
            updated_at_ms: now_unix_ms(),
            author_login: store.pubkey_hex().to_string(),
            nostr_event_id: Some(event_id),
        };
        // Blossom has no per-group quota, so report the blob size instead.
        (comment, sealed.len() as u64)
    };
    group_state.append_chat(&created);

    Ok(SendFileResponse {
        asset_name,
        pruned_count,
        vault_bytes,
    })
}

/// Fetch a shared file and verify its digest.
#[tauri::command]
pub async fn download_file(
    state: State<'_, AppState>,
    asset_name: String,
    expected_sha256_b64: Option<String>,
    mime: Option<String>,
) -> Result<DownloadedFile> {
    let group_state = state.group()?;

    if asset_name.trim().is_empty() {
        return Err(AppError::invalid_argument("an asset name is required"));
    }

    // The asset name is the content address, so the fetch is self-verifying:
    // `download_blob` rejects bytes that do not hash to it.
    let sealed = state.nostr_store()?.download_blob(&asset_name).await?;
    let key = group_state.current_group_key()?;
    let plaintext = crypto::open_blob(&key, &sealed)?;

    // Verification is advisory: the digest is content the sender chose to
    // advertise, so a mismatch is reported rather than silently trusted.
    let sha256_verified = match expected_sha256_b64 {
        Some(expected) => crypto::sha256_b64(&plaintext) == expected,
        None => true,
    };

    Ok(DownloadedFile {
        file_name: asset_name,
        mime: mime.unwrap_or_else(|| "application/octet-stream".to_string()),
        data: plaintext,
        sha256_verified,
    })
}

// ---------------------------------------------------------------------------
// Moderation
// ---------------------------------------------------------------------------

/// Block or unblock a member. Purely local; nothing is sent.
#[tauri::command]
pub fn block_member(state: State<'_, AppState>, request: BlockRequest) -> Result<()> {
    let group_state = state.group()?;
    if request.pubkey_b64.trim().is_empty() {
        return Err(AppError::invalid_argument("a member public key is required"));
    }
    let mut preferences = group_state.preferences();
    if request.blocked {
        preferences.blocked_pubkeys.insert(request.pubkey_b64.clone());
    } else {
        preferences.blocked_pubkeys.remove(&request.pubkey_b64);
    }
    state.vault()?.update_preferences(&preferences)?;
    group_state.set_preferences(preferences);

    // Blocking someone should also stop this device from keeping a record of
    // where they have been. Unblocking does not restore it: the log is gone.
    if request.blocked {
        group_state.forget_history(&request.pubkey_b64);
        if let Ok(vault) = state.vault() {
            let _ = group_state.save_history(vault.dir());
        }
    }
    Ok(())
}

/// Report a message, optionally deleting it when this device is the host.
#[tauri::command]
pub async fn report_content(
    state: State<'_, AppState>,
    request: ReportRequest,
) -> Result<PollResponse> {
    let group_state = state.group()?;

    let envelope = group_state.build_flag_envelope(
        request.target_comment_id,
        &request.target_pubkey_b64,
        &request.reason,
        now_unix_ms(),
    )?;
    let body = serde_json::to_string(&envelope)
        .map_err(|e| AppError::crypto(format!("could not serialize the envelope: {e}")))?;

    let created = {
        // Nostr has no server-side deletion: an event is signed by its author, so
        // only the author can retract it, and even then relays may ignore the
        // request. The flag is published and the block list does the enforcement.
        let store = state.nostr_store()?;
        let event_id = store.publish_chat(&body).await?;
        crate::wire::IssueComment {
            id: crate::wire::nostr_numeric_id(&event_id),
            body,
            created_at_ms: now_unix_ms(),
            updated_at_ms: now_unix_ms(),
            author_login: store.pubkey_hex().to_string(),
            nostr_event_id: Some(event_id),
        }
    };
    group_state.append_chat(&created);

    Ok(PollResponse {
        next_delay_ms: crate::group::CHAT_INTERVAL_SECS * 1_000,
        not_modified: false,
        rate_limited: false,
        halt_remaining_secs: None,
    })
}

/// Result of publishing a deletion request.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionResponse {
    pub accepted_relays: Vec<String>,
    pub unconfirmed_relays: Vec<String>,
}

/// Request deletion of a Nostr event authored by this device.
#[tauri::command]
pub async fn delete_own_message(state: State<'_, AppState>, event_id: String) -> Result<DeletionResponse> {
    let store = state.nostr_store()?;
    let accepted = store.delete_own_event(&event_id).await?;
    let unconfirmed_relays = store.relays.iter()
        .filter(|url| !accepted.contains(url))
        .cloned()
        .collect();
    Ok(DeletionResponse {
        accepted_relays: accepted,
        unconfirmed_relays,
    })
}

/// List currently blocked member keys.
#[tauri::command]
pub fn blocked_members(state: State<'_, AppState>) -> Result<Vec<String>> {
    let group_state = state.group()?;
    Ok(group_state.blocked_sorted())
}

// ---------------------------------------------------------------------------
// Rotation and re-key
// ---------------------------------------------------------------------------

/// Check whether the host has announced a rotation this device cannot read.
#[tauri::command]
pub async fn check_rotation(state: State<'_, AppState>) -> Result<Option<RotationStatus>> {
    let group_state = state.group()?;

    let comments = {
        let store = state.nostr_store()?;
        let mut comments = store.read_roster().await?;
        comments.extend(store.read_rotations().await?);
        comments
    };
    for comment in comments {
        let envelope: crate::crypto::EncryptedEnvelope = match serde_json::from_str(&comment.body) {
            Ok(envelope) => envelope,
            Err(_) => continue,
        };
        // Rotation announcements are control messages; if we cannot open them we
        // have to compare epochs structurally instead.
        if envelope.key_epoch <= group_state.current_epoch() {
            continue;
        }
        if envelope.sender_pubkey != group_state.host_pubkey_b64 {
            continue;
        }
        let notice: RotationNotice = group_state
            .observe_rotation(&envelope.sender_pubkey, envelope.key_epoch, group_state.current_epoch())?;
        return Ok(Some(RotationStatus {
            new_epoch: notice.new_epoch,
            retired_epoch: notice.retired_epoch,
            already_held: notice.already_held,
            needs_reissue: !notice.already_held,
        }));
    }
    Ok(None)
}

/// The invite string already saved on this device, if there is one.
#[tauri::command]
pub fn current_invite(state: State<'_, AppState>) -> Result<Option<String>> {
    let _group = state.group()?;
    Ok(state.vault()?.invite_code())
}

/// Pack a fresh invite from the live group key.
///
/// Any member can do this. It does not rotate the key. The join password is
/// required because it is what seals the string.
#[tauri::command]
pub fn share_invite(state: State<'_, AppState>, request: ShareInviteRequest) -> Result<ShareInviteResponse> {
    let group_state = state.group()?;
    let vault = state.vault()?;
    if request.join_password.is_empty() {
        return Err(AppError::invalid_argument("the join password is required to pack the group code"));
    }
    let invite = pack_current_invite(&group_state, &request.join_password)?;
    vault.save_invite_code(&invite)?;
    Ok(ShareInviteResponse {
        invite,
        fingerprint: group_state.identity.fingerprint(),
    })
}

/// Assign `admin` or `member`. Only the pinned owner may do this.
#[tauri::command]
pub async fn set_member_role(state: State<'_, AppState>, request: SetRoleRequest) -> Result<()> {
    let group_state = state.group()?;
    group_state.assign_role(&request.pubkey_b64, &request.role)?;
    state.vault()?.save_roles(&stored_roles(&group_state))?;
    publish_role_set(&state, &group_state).await?;
    *group_state.roles_announced.write() = true;
    Ok(())
}

/// Rotate the group key, optionally removing members.
#[tauri::command]
pub async fn rotate_group_key(
    state: State<'_, AppState>,
    request: RotateRequest,
) -> Result<RotateResponse> {
    let vault = state.vault()?;
    let group_state = state.group()?;

    if !group_state.is_host {
        return Err(AppError::group_state(
            "only the host may rotate the group key",
        ));
    }
    if request.join_password.is_empty() {
        return Err(AppError::invalid_argument(
            "a join password is required to re-issue invites",
        ));
    }

    let removed_pubkeys = {
        confirm_removals(&group_state, &request.remove_pubkeys)?;
        request.remove_pubkeys.clone()
    };

    let new_epoch = group_state
        .current_epoch()
        .checked_add(1)
        .ok_or_else(|| AppError::group_state("the group has exhausted its key epochs"))?;
    let new_key = *crypto::new_group_key()?;
    let reason = request
        .reason
        .clone()
        .unwrap_or_else(|| "scheduled rotation".to_string());
    let envelope = group_state.build_rotation_envelope_with_key(
        new_epoch,
        group_state.current_epoch(),
        &reason,
        now_unix_ms(),
        &new_key,
    )?;
    let body = serde_json::to_string(&envelope)
        .map_err(|e| AppError::crypto(format!("could not serialize the envelope: {e}")))?;

    // Announce under the new key before installing it locally, so a failed publish
    // does not leave this device ahead of everyone else.
    state.nostr_store()?.publish_rotation(&body).await?;

    group_state.apply_rotation(new_epoch, new_key)?;
    let descriptor = VaultDescriptor {
        version: DESCRIPTOR_VERSION,
        keystore_alias: vault.keystore_alias(),
        group_ref: format!("nostr:{}", group_state.group_id),
        current_epoch: new_epoch,
    };
    vault.update_group_key(&new_key, &descriptor)?;

    let invites = build_member_invites(
        &group_state,
        &request.join_password,
        new_epoch,
        &new_key,
        &removed_pubkeys,
    )?;
    let group_invite = pack_current_invite(&group_state, &request.join_password)?;
    let _ = vault.save_invite_code(&group_invite);

    Ok(RotateResponse {
        new_epoch,
        retired_epoch: new_epoch.saturating_sub(1),
        invites,
        removed_pubkeys,
        group_invite,
    })
}

// ---------------------------------------------------------------------------
// Leaving and destroying
// ---------------------------------------------------------------------------

/// Leave the group: delete this device's roster comment, then wipe locally.
#[tauri::command]
pub async fn leave_and_wipe(state: State<'_, AppState>) -> Result<WipeResponse> {
    let _group_state = state.group()?;

    // Deleting the roster entry is best-effort: if it fails, the user's intent to
    // wipe locally still has to be honoured, otherwise their data stays on a
    // device they are trying to clean.
    let roster_comment_deleted = {
        // A Nostr slot can only be retracted by its author, and relays may ignore
        // the request. Publishing an empty slot is the closest equivalent, and a
        // failure here must not block the local wipe.
        match state.nostr_store() {
            Ok(store) => store.publish_roster("").await.is_ok(),
            Err(_) => false,
        }
    };

    let vault_wiped = match state.vault.read().clone() {
        Some(vault) => vault.wipe().is_ok(),
        None => true,
    };

    *state.group.write() = None;
    *state.vault.write() = None;

    Ok(WipeResponse {
        roster_comment_deleted,
        vault_wiped,
    })
}

/// Destroy the group by publishing a closure signed by the host.
#[tauri::command]
pub async fn destroy_group(state: State<'_, AppState>) -> Result<DestroyResponse> {
    let group_state = state.group()?;

    if !group_state.is_host {
        return Err(AppError::group_state(
            "only the host may destroy the group; guests must leave instead",
        ));
    }

    let store = state.nostr_store()?;
    let proof = group_state.closure_proof()?;
    let accepted_relays = store.publish_closure(&proof).await?;
    let unconfirmed_relays = store.relays.iter()
        .filter(|url| !accepted_relays.contains(url))
        .cloned()
        .collect();
    state.vault()?.wipe()?;
    *state.group.write() = None;
    *state.vault.write() = None;
    Ok(DestroyResponse {
        group_ref: format!("nostr:{}", group_state.group_id),
        vault_wiped: true,
        accepted_relays,
        unconfirmed_relays,
    })
}

/// Wipe this device after observing a closure signed by its pinned host.
#[tauri::command]
pub async fn check_group_closed(state: State<'_, AppState>) -> Result<bool> {
    check_group_closed_inner(&state).await
}

async fn check_group_closed_inner(state: &AppState) -> Result<bool> {
    let group_state = state.group()?;
    let store = state.nostr_store()?;
    let events = store.read_closures().await?;
    if !events.iter().any(|event| group_state.verifies_closure(&store.group_id, &event.content)) {
        return Ok(false);
    }
    state.vault()?.wipe()?;
    *state.group.write() = None;
    *state.vault.write() = None;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Vault inspection
// ---------------------------------------------------------------------------

/// List the encrypted blobs and current storage usage.
#[tauri::command]
pub async fn vault_report(state: State<'_, AppState>) -> Result<VaultReport> {
    let _group_state = state.group()?;

    // The local encrypted index contains only uploads made by this device.
    let stored = state.vault()?.load_group()?.ok_or_else(|| AppError::vault("the stored group cannot be restored"))?;
    let assets: Vec<VaultAssetView> = stored.uploads.iter().map(|upload| VaultAssetView {
        id: crate::wire::nostr_numeric_id(&upload.event.id),
        name: upload.sha256.clone(),
        size: upload.size,
        created_at_ms: upload.event.created_at.saturating_mul(1_000),
        deletion_status: Some(if !upload.deleted { "available" } else if upload.notice_published { "announced" } else { "notice_pending" }.into()),
    }).collect();
    let total_bytes = stored.uploads.iter().filter(|upload| !upload.deleted).map(|upload| upload.size).sum();
    Ok(VaultReport {
        assets,
        total_bytes,
        max_bytes: crate::wire::MAX_VAULT_BYTES,
        rate_limit_remaining: None,
    })
}

/// Result of a Blossom deletion and its relay announcement.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobDeletionResponse {
    pub server: String,
    pub accepted_relays: Vec<String>,
    pub unconfirmed_relays: Vec<String>,
    pub notice_error: Option<String>,
}

/// Delete a locally owned Blossom upload and publish a verifiable notice.
#[tauri::command]
pub async fn delete_nostr_blob(state: State<'_, AppState>, sha256: String) -> Result<BlobDeletionResponse> {
    delete_nostr_blob_inner(&state, sha256).await
}

async fn delete_nostr_blob_inner(state: &AppState, sha256: String) -> Result<BlobDeletionResponse> {
    let _guard = state.file_deletion_lock.lock().await;
    let group = state.group()?;
    let vault = state.vault()?;
    let store = state.nostr_store()?;
    let stored = vault.load_group()?.ok_or_else(|| AppError::vault("the stored group cannot be restored"))?;
    let mut upload = stored.uploads.iter().find(|upload| upload.sha256 == sha256).cloned()
        .ok_or_else(|| AppError::invalid_argument("this device has no ownership record for that file"))?;
    if upload.event.pubkey != store.pubkey_hex()
        || !matches!(upload.event.kind, crate::nostr::KIND_FILE | crate::nostr::KIND_FILE_LEGACY)
        || upload.event.d_tag() != Some(store.group_id.as_str())
        || upload.event.verify_id().is_err()
        || upload.event.verify_signature().is_err()
    {
        return Err(AppError::crypto("the stored upload ownership proof is invalid"));
    }
    let original = IssueComment::from_nostr_event(&upload.event);
    if !matches!(group.decode_chat(&original), Ok(ChatItem::File { asset_name, .. }) if asset_name == sha256) {
        return Err(AppError::crypto("the stored file pointer does not match the blob"));
    }
    if !upload.deleted {
        store.delete_blob(&upload.server, &upload.sha256).await?;
        upload.deleted = true;
        vault.save_upload(upload.clone()).map_err(|error| AppError::vault(format!(
            "{} confirmed deletion, but saving the result failed: {error}", upload.server
        )))?;
    }
    let (accepted_relays, notice_error) = match store.publish_file_removal(&upload.event).await {
        Ok(accepted) => {
            upload.notice_published = true;
            vault.save_upload(upload.clone()).map_err(|error| AppError::vault(format!(
                "{} confirmed deletion and relays accepted the removal notice, but saving the announcement status failed: {error}",
                upload.server
            )))?;
            (accepted, None)
        }
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let unconfirmed_relays = store.relays.iter().filter(|url| !accepted_relays.contains(url)).cloned().collect();
    Ok(BlobDeletionResponse {
        server: upload.server,
        accepted_relays,
        unconfirmed_relays,
        notice_error,
    })
}

/// Delete one blob from the vault.
///
/// Blossom blobs are content-addressed and shared: deleting one would break
/// every pointer to it, including other members' messages. Refuse rather than
/// silently corrupting the group's history.
#[tauri::command]
pub async fn delete_asset(state: State<'_, AppState>, asset_id: u64) -> Result<()> {
    let _ = (state, asset_id);
    Err(AppError::invalid_argument(
        "files on Nostr are content-addressed and cannot be deleted individually",
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validate a `#rrggbb` colour so the UI cannot inject arbitrary CSS.
fn validate_hex_color(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 7 {
        return Err(AppError::invalid_argument(
            "avatar colour must look like #rrggbb",
        ));
    }
    if bytes.first() != Some(&b'#') {
        return Err(AppError::invalid_argument(
            "avatar colour must start with '#'",
        ));
    }
    if !bytes
        .get(1..)
        .unwrap_or_default()
        .iter()
        .all(|b| b.is_ascii_hexdigit())
    {
        return Err(AppError::invalid_argument(
            "avatar colour must be hexadecimal digits",
        ));
    }
    Ok(())
}

/// Republish saved roles once per session so a restarted owner does not lose them on relays.
async fn announce_roles_if_needed(state: State<'_, AppState>, group_state: &GroupState) {
    if !group_state.is_host || *group_state.roles_announced.read() || group_state.role_grants().is_empty() {
        return;
    }
    if publish_role_set(&state, group_state).await.is_ok() {
        *group_state.roles_announced.write() = true;
    }
}

async fn publish_role_set(state: &State<'_, AppState>, group_state: &GroupState) -> Result<()> {
    let envelope = group_state.build_role_envelope(now_unix_ms())?;
    let body = serde_json::to_string(&envelope)
        .map_err(|e| AppError::crypto(format!("could not serialize the role set: {e}")))?;
    state.nostr_store()?.publish_control(&body).await?;
    Ok(())
}

fn stored_roles(group_state: &GroupState) -> Vec<crate::vault::StoredRole> {
    group_state
        .role_grants()
        .into_iter()
        .map(|grant| crate::vault::StoredRole {
            pubkey_b64: grant.member_pubkey,
            role: grant.role,
        })
        .collect()
}

fn pack_current_invite(group_state: &GroupState, join_password: &str) -> Result<String> {
    let payload = InviteCredentialsPayload {
        version: PROTOCOL_VERSION,
        backend: group_state.backend.kind(),
        group_id: group_state.group_id.clone(),
        group_master_key: group_state.current_group_key()?,
        relays: group_state.relays.clone(),
        blossom_servers: group_state.blossom_servers.clone(),
        host_pubkey: group_state.host_pubkey_b64.clone(),
        group_label: group_state.group_label.clone(),
        key_epoch: group_state.current_epoch(),
    };
    crypto::pack_invite(&payload, join_password)
}

fn confirm_removals(group_state: &GroupState, remove_pubkeys: &[String]) -> Result<()> {
    let roster = group_state.roster.read();
    for pubkey in remove_pubkeys {
        if pubkey == &group_state.host_pubkey_b64 {
            return Err(AppError::invalid_argument("the owner cannot be removed"));
        }
        if !roster.iter().any(|member| member.pubkey_b64 == *pubkey) {
            return Err(AppError::group_state(format!(
                "member {pubkey} is not in the current roster, so it cannot be removed"
            )));
        }
    }
    Ok(())
}

/// Build one invite per member, excluding removed members.
///
/// The group key is passed in explicitly because it lives in the vault, not in
/// group state; taking it as an argument makes it obvious at each call site that
/// a secret is being embedded.
fn build_member_invites(
    group_state: &GroupState,
    join_password: &str,
    epoch: u8,
    group_key: &[u8; 32],
    excluded: &[String],
) -> Result<Vec<MemberInvite>> {
    let mut invites = Vec::new();

    for member in group_state.roster.read().iter() {
        if excluded.iter().any(|excluded| excluded == &member.pubkey_b64) {
            continue;
        }

        let payload = InviteCredentialsPayload {
            version: PROTOCOL_VERSION,
            backend: group_state.backend.kind(),
            group_id: group_state.group_id.clone(),
            group_master_key: *group_key,
            relays: group_state.relays.clone(),
            blossom_servers: group_state.blossom_servers.clone(),
            host_pubkey: group_state.host_pubkey_b64.clone(),
            group_label: group_state.group_label.clone(),
            key_epoch: epoch,
        };

        invites.push(MemberInvite {
            pubkey_b64: member.pubkey_b64.clone(),
            display_name: member.display_name.clone(),
            invite: crypto::pack_invite(&payload, join_password)?,
        });
    }

    Ok(invites)
}

/// Return one item per chat entry, turning decode failures into
/// [`ChatItem::Undecryptable`] rather than dropping them.
///
/// Useful where a caller has already fetched a comment page and wants view
/// models without going through the snapshot commands.
pub fn decode_chat_items(
    group_state: &GroupState,
    comments: &[IssueComment],
) -> Vec<ChatItem> {
    let mut items: Vec<ChatItem> = Vec::with_capacity(comments.len());
    for comment in comments {
        match group_state.decode_chat(comment) {
            Ok(item) => items.push(item),
            Err(failure) => items.push(ChatItem::Undecryptable {
                comment_id: comment.id,
                reason: failure.reason(),
            }),
        }
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closure_wipes_only_after_a_verified_host_notice() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let relay = format!("ws://{}", listener.local_addr().expect("address"));
        let host = Identity::from_secret([31; 32]);
        let invite = InviteCredentialsPayload {
            version: PROTOCOL_VERSION,
            backend: crate::storage::BackendKind::Nostr,
            group_master_key: [9; 32], relays: vec![relay], blossom_servers: Vec::new(),
            group_id: "closure-test".into(), host_pubkey: host.pubkey_b64.clone(),
            group_label: "test".into(), key_epoch: 0,
        };
        let host_group = GroupState::from_invite(&invite, host, test_preferences(), true).expect("host");
        let guest_identity = Identity::from_secret([32; 32]);
        let guest_group = GroupState::from_invite(&invite, Identity::from_secret([32; 32]), test_preferences(), false).expect("guest");
        let real_proof = host_group.closure_proof().expect("proof");
        let attacker = Identity::from_secret([33; 32]);
        let mut attacker_invite = invite.clone();
        attacker_invite.host_pubkey = attacker.pubkey_b64.clone();
        let forged_proof = GroupState::from_invite(&attacker_invite, attacker, test_preferences(), true)
            .expect("attacker").closure_proof().expect("forged proof");
        let nostr = crate::nostr::NostrIdentity::from_secret_bytes([34; 32]).expect("nostr");
        let relay_author = crate::nostr::NostrIdentity::from_secret_bytes([35; 32]).expect("relay author");
        let forged = crate::nostr::sign_event(&relay_author, crate::nostr::KIND_GROUP_CLOSED,
            vec![vec!["d".into(), "closure-test".into()]], forged_proof, 100).expect("event");
        let valid = crate::nostr::sign_event(&relay_author, crate::nostr::KIND_GROUP_CLOSED,
            vec![vec!["d".into(), "closure-test".into()]], real_proof, 101).expect("event");
        let server = tokio::spawn(async move {
            for event in [forged, valid] {
                let (stream, _) = listener.accept().await.expect("accept");
                let mut ws = tokio_tungstenite::accept_async(stream).await.expect("websocket");
                let request = ws.next().await.expect("request").expect("frame").into_text().expect("text");
                let request: serde_json::Value = serde_json::from_str(&request).expect("json");
                let subscription = request[1].as_str().expect("subscription");
                ws.send(Message::Text(serde_json::json!(["EVENT", subscription, event]).to_string().into())).await.expect("event");
                ws.send(Message::Text(serde_json::json!(["EOSE", subscription]).to_string().into())).await.expect("eose");
                let _ = ws.next().await;
            }
        });
        let dir = std::env::temp_dir().join(format!("shadow720-closure-{}", uuid::Uuid::new_v4()));
        let keystore: Arc<dyn crate::vault::Keystore> = Arc::new(crate::vault::InMemoryKeystore::new().expect("keystore"));
        let vault = Arc::new(SecureVault::create(&dir, keystore).expect("vault"));
        let descriptor = VaultDescriptor { version: DESCRIPTOR_VERSION, keystore_alias: vault.keystore_alias(),
            group_ref: "nostr:closure-test".into(), current_epoch: 0 };
        vault.store_group_contents(&VaultContents { secret: nostr.secret_hex().to_string(), group_key: zeroize::Zeroizing::new([9; 32]) },
            &descriptor, Some(StoredGroup { invite: invite.clone(), identity_secret: *guest_identity.secret_bytes(),
                preferences: test_preferences(), is_host: false, uploads: Vec::new(),
                invite_code: None, roles: Vec::new() })).expect("store");
        let state = AppState::new();
        *state.vault.write() = Some(vault);
        *state.group.write() = Some(Arc::new(guest_group));
        assert!(!check_group_closed_inner(&state).await.expect("forged ignored"));
        assert!(SecureVault::exists(&dir));
        assert!(check_group_closed_inner(&state).await.expect("valid closure"));
        assert!(!SecureVault::exists(&dir));
        assert!(state.group.read().is_none());
        server.await.expect("relay");
        std::fs::remove_dir(&dir).expect("remove empty test directory");
    }

    #[tokio::test]
    async fn deleted_blob_persists_and_notice_can_be_retried() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_tungstenite::tungstenite::Message;

        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("http");
        let server_url = format!("http://{}", http.local_addr().expect("address"));
        let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("relay");
        let relay_url = format!("ws://{}", relay.local_addr().expect("address"));
        let host = Identity::from_secret([41; 32]);
        let nostr = crate::nostr::NostrIdentity::from_secret_bytes([42; 32]).expect("nostr");
        let invite = InviteCredentialsPayload {
            version: PROTOCOL_VERSION, backend: crate::storage::BackendKind::Nostr,
            group_master_key: [8; 32], relays: vec![relay_url], blossom_servers: vec![server_url.clone()],
            group_id: "file-test".into(), host_pubkey: host.pubkey_b64.clone(),
            group_label: "test".into(), key_epoch: 0,
        };
        let group = GroupState::from_invite(&invite, Identity::from_secret([41; 32]), test_preferences(), true).expect("group");
        let sha256 = crate::nostr::BlobRef::of(b"sealed").sha256;
        let envelope = group.build_file_envelope(&sha256, 6, "text/plain", "digest", None, 100).expect("envelope");
        let original = crate::nostr::sign_event(&nostr, crate::nostr::KIND_FILE,
            vec![vec!["d".into(), "file-test".into()]], serde_json::to_string(&envelope).expect("json"), 100).expect("file event");
        let dir = std::env::temp_dir().join(format!("shadow720-delete-{}", uuid::Uuid::new_v4()));
        let keystore: Arc<dyn crate::vault::Keystore> = Arc::new(crate::vault::InMemoryKeystore::new().expect("keystore"));
        let vault = Arc::new(SecureVault::create(&dir, keystore).expect("vault"));
        let descriptor = VaultDescriptor { version: DESCRIPTOR_VERSION, keystore_alias: vault.keystore_alias(),
            group_ref: "nostr:file-test".into(), current_epoch: 0 };
        vault.store_group_contents(&VaultContents { secret: nostr.secret_hex().to_string(), group_key: zeroize::Zeroizing::new([8; 32]) },
            &descriptor, Some(StoredGroup { invite, identity_secret: *host.secret_bytes(), preferences: test_preferences(),
                is_host: true, uploads: vec![StoredUpload { sha256: sha256.clone(), server: server_url,
                    size: 6, event: original, deleted: false, notice_published: false }],
                invite_code: None, roles: Vec::new() })).expect("store");
        let state = AppState::new();
        *state.vault.write() = Some(vault.clone());
        *state.group.write() = Some(Arc::new(group));
        let http_task = tokio::spawn(async move {
            let (mut socket, _) = http.accept().await.expect("delete request");
            let mut buffer = [0; 4096];
            let n = socket.read(&mut buffer).await.expect("read request");
            assert!(String::from_utf8_lossy(&buffer[..n]).starts_with("DELETE /"));
            socket.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await.expect("response");
        });
        let relay_task = tokio::spawn(async move {
            for accepted in [false, true] {
                let (stream, _) = relay.accept().await.expect("accept relay");
                let mut ws = tokio_tungstenite::accept_async(stream).await.expect("websocket");
                let request = ws.next().await.expect("request").expect("frame").into_text().expect("text");
                let request: serde_json::Value = serde_json::from_str(&request).expect("json");
                let event: crate::nostr::Event = serde_json::from_value(request[1].clone()).expect("event");
                assert_eq!(event.kind, crate::nostr::KIND_FILE_REMOVED);
                event.verify_signature().expect("signature");
                ws.send(Message::Text(serde_json::json!(["OK", event.id, accepted, "test"]).to_string().into())).await.expect("ack");
                let _ = ws.next().await;
            }
        });
        let first = delete_nostr_blob_inner(&state, sha256.clone()).await.expect("first request");
        assert!(first.notice_error.is_some());
        let recorded = vault.load_group().expect("load").expect("group");
        assert!(recorded.uploads[0].deleted);
        assert!(!recorded.uploads[0].notice_published);
        let second = delete_nostr_blob_inner(&state, sha256).await.expect("retry");
        assert!(second.notice_error.is_none());
        assert_eq!(second.accepted_relays.len(), 1);
        assert!(vault.load_group().expect("load").expect("group").uploads[0].notice_published);
        http_task.await.expect("http task");
        relay_task.await.expect("relay task");
        vault.wipe().expect("wipe");
        std::fs::remove_dir(&dir).expect("remove empty test directory");
    }

    #[test]
    fn hex_colour_validation_accepts_valid_values() {
        assert!(validate_hex_color("#5b8cff").is_ok());
        assert!(validate_hex_color("#000000").is_ok());
        assert!(validate_hex_color("#FFFFFF").is_ok());
    }

    #[test]
    fn hex_colour_validation_rejects_injection_attempts() {
        for bad in [
            "red",
            "#fff",
            "#5b8cff; background: url(evil)",
            "5b8cff",
            "",
            "#gggggg",
            "#5b8cff\n",
        ] {
            assert!(
                validate_hex_color(bad).is_err(),
                "{bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn app_state_starts_locked_and_empty() {
        let state = AppState::new();
        assert!(state.vault.read().is_none());
        assert!(state.group.read().is_none());
        assert_eq!(
            state.vault().expect_err("must fail").kind(),
            crate::error::AppErrorKind::VaultUnavailable
        );
        assert_eq!(
            state.group().expect_err("must fail").kind(),
            crate::error::AppErrorKind::GroupState
        );
    }

    #[test]
    fn app_state_debug_is_safe() {
        let state = AppState::new();
        let rendered = format!("{state:?}");
        assert!(rendered.contains("vault_open"));
        assert!(rendered.contains("group_active"));
    }

    #[test]
    fn unlock_response_serializes_with_camel_case_keys() {
        let response = UnlockResponse {
            existed: false,
            group_configured: true,
            group_ref: Some("nostr:group-1".into()),
            current_epoch: Some(0),
            requires_recovery: false,
        };
        let json = serde_json::to_value(&response).expect("serialize");
        assert!(json.get("groupConfigured").is_some());
        assert!(json.get("groupRef").is_some());
        assert!(json.get("currentEpoch").is_some());
    }

    #[test]
    fn diagnostics_response_serializes_with_camel_case_keys() {
        let response = DiagnosticsResponse {
            group_label: "test".into(),
            group_ref: "nostr:group-1".into(),
            backend: "nostr".into(),
            accountless: true,
            is_host: true,
            current_epoch: 0,
            known_epochs: vec![0],
            roster_len: 1,
            chat_len: 2,
            blocked_count: 0,
            chat_interval_s: 10,
            roster_interval_s: 30,
            halted_until_unix_s: None,
            remaining_requests: Some(4_999),
            total_requests: Some(5_000),
            fingerprint: "ABCD1234".into(),
        };
        let json = serde_json::to_value(&response).expect("serialize");
        assert!(json.get("groupRef").is_some());
        assert!(json.get("knownEpochs").is_some());
        assert!(json.get("chatIntervalS").is_some());
        assert_eq!(json.get("backend").and_then(|v| v.as_str()), Some("nostr"));
        assert_eq!(json.get("accountless").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn rotate_request_defaults_are_supported() {
        let request: RotateRequest =
            serde_json::from_str(r#"{"joinPassword":"pw"}"#).expect("deserialize");
        assert_eq!(request.join_password, "pw");
        assert!(request.reason.is_none());
        assert!(request.remove_pubkeys.is_empty());
    }


    #[test]
    fn nostr_store_requires_a_nostr_group() {
        let state = AppState::new();
        // No group at all: the error must say so rather than panicking.
        assert!(state.nostr_store().is_err());
    }

    #[test]
    fn nostr_store_builds_for_a_nostr_group() {
        let state = AppState::new();
        let invite = crate::crypto::InviteCredentialsPayload {
            version: crate::crypto::PROTOCOL_VERSION,
            backend: crate::storage::BackendKind::Nostr,
            group_id: "group-1".into(),
            group_master_key: [1u8; 32],
            relays: vec!["wss://relay.example".into()],
            blossom_servers: vec!["https://blossom.example".into()],
            host_pubkey: String::new(),
            group_label: "g".into(),
            key_epoch: 0,
        };
        let identity = Identity::generate().expect("identity");
        let group = GroupState::from_invite(&invite, identity, test_preferences(), true)
            .expect("group");
        *state.group.write() = Some(Arc::new(group));

        // The vault is locked, so the secret cannot be read yet; the error must
        // be about the vault rather than about the backend.
        let error = state.nostr_store().expect_err("vault is locked");
        assert_eq!(error.kind(), crate::error::AppErrorKind::VaultUnavailable);
    }

    fn test_preferences() -> Preferences {
        Preferences {
            display_name: "Jared".into(),
            avatar_color: "#5b8cff".into(),
            blocked_pubkeys: Default::default(),
            accepted_eula: true,
            accepted_location_disclosure: true,
            enabled_background_location: false,
        }
    }

    #[test]
    fn reset_vault_works_while_the_vault_is_locked() {
        // Regression: `reset_vault` used to call `state.vault()`, which fails when
        // no vault is open. The reset button only appears after unlocking failed,
        // so the command always returned "the secure vault is locked" and the user
        // was bounced straight back to the same error screen.
        let dir = std::env::temp_dir().join(format!("shadow720-reset-{}", uuid::Uuid::new_v4()));
        let keystore: Arc<dyn crate::vault::Keystore> =
            Arc::new(crate::vault::InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault
            .store_contents(
                &VaultContents { secret: "nostr_secret_TEST".into(), group_key: zeroize::Zeroizing::new([7; 32]) },
                &VaultDescriptor {
                    version: DESCRIPTOR_VERSION,
                    keystore_alias: vault.keystore_alias(),
                    group_ref: "nostr:group-1".into(),
                    current_epoch: 0,
                },
            )
            .expect("store");
        drop(vault);

        let state = AppState::new();
        assert!(state.vault.read().is_none(), "precondition: nothing is open");

        let keystore: Arc<dyn crate::vault::Keystore> =
            Arc::new(crate::vault::InMemoryKeystore::new().expect("keystore"));
        reset_vault_inner(
            &state,
            &keystore,
            Some(ResetVaultRequest { vault_dir: Some(dir.clone()) }),
        )
        .expect("reset must not require an open vault");

        assert!(!SecureVault::exists(&dir), "the vault files must be gone");
        assert!(state.group.read().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reset_vault_requires_a_directory_when_nothing_is_open() {
        let state = AppState::new();
        let keystore: Arc<dyn crate::vault::Keystore> =
            Arc::new(crate::vault::InMemoryKeystore::new().expect("keystore"));
        let error = reset_vault_inner(&state, &keystore, None).expect_err("no directory");
        assert_eq!(error.kind(), crate::error::AppErrorKind::InvalidArgument);
    }

    #[test]
    fn reset_vault_falls_back_to_the_open_vault_directory() {
        let dir = std::env::temp_dir().join(format!("shadow720-resetopen-{}", uuid::Uuid::new_v4()));
        let keystore: Arc<dyn crate::vault::Keystore> =
            Arc::new(crate::vault::InMemoryKeystore::new().expect("keystore"));
        let vault = Arc::new(SecureVault::create(&dir, keystore).expect("create"));

        let state = AppState::new();
        *state.vault.write() = Some(vault);

        let keystore: Arc<dyn crate::vault::Keystore> =
            Arc::new(crate::vault::InMemoryKeystore::new().expect("keystore"));
        reset_vault_inner(&state, &keystore, None).expect("reset via the open handle");

        assert!(!SecureVault::exists(&dir));
        assert!(state.vault.read().is_none(), "the handle must be dropped");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn block_request_round_trips() {
        let request: BlockRequest =
            serde_json::from_str(r#"{"pubkeyB64":"AAAA","blocked":true}"#).expect("deserialize");
        assert_eq!(request.pubkey_b64, "AAAA");
        assert!(request.blocked);
    }

    #[test]
    fn location_update_round_trips() {
        let update: LocationUpdate =
            serde_json::from_str(r#"{"lat":41.5,"lon":-87.5}"#).expect("deserialize");
        assert!((update.lat - 41.5).abs() < f64::EPSILON);
        assert!((update.lon + 87.5).abs() < f64::EPSILON);
    }

    #[test]
    fn send_file_request_defaults_caption() {
        let request: SendFileRequest =
            serde_json::from_str(r#"{"data":[1,2,3],"fileName":"a.png","mime":"image/png"}"#)
                .expect("deserialize");
        assert_eq!(request.data, vec![1, 2, 3]);
        assert!(request.caption.is_none());
    }

    #[test]
    fn poll_response_ms_is_a_plain_integer() {
        let response = PollResponse {
            next_delay_ms: 10_000,
            not_modified: true,
            rate_limited: false,
            halt_remaining_secs: None,
        };
        let json = serde_json::to_value(&response).expect("serialize");
        assert_eq!(json.get("nextDelayMs").and_then(|v| v.as_u64()), Some(10_000));
    }
}
