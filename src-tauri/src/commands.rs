//! The `#[tauri::command]` surface consumed by the TypeScript UI.
//!
//! # Conventions
//!
//! * Every command returns [`crate::error::Result`], so the TS side receives
//!   `{ kind, message }` on failure and can branch on `kind` instead of parsing
//!   prose.
//! * No command takes a PAT as an argument: the token lives in the vault and is
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
use zeroize::Zeroizing;

use crate::crypto::{self, InviteCredentialsPayload, PROTOCOL_VERSION};
use crate::error::{AppError, Result};
use crate::geo_filter::{Fix, Publish};
use crate::github_db::{now_unix_ms, GitHubClient, IssueComment, ProvisioningClient, RepoRef};
use crate::oauth;
use crate::group::{
    self, ChatItem, GroupState, Identity, MemberView, Preferences, RotationNotice, SharedGroup,
};
use crate::vault::{SecureVault, StoredGroup, StoredUpload, VaultContents, VaultDescriptor, DESCRIPTOR_VERSION};

/// Release tag used for the vault when the caller does not name one.
const DEFAULT_RELEASE_TAG: &str = "vault-v1";

/// Public OAuth client id for the device flow.
///
/// Device-flow client ids are not secrets: the grant is designed for public
/// clients, so this is safe to compile in. Replace it with the id of the app
/// registered under the project's GitHub account before shipping.
const DEFAULT_OAUTH_CLIENT_ID: &str = "Ov23liShadow720DeviceFlow";

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Everything the command layer needs, managed by Tauri.
pub struct AppState {
    /// The open vault, or `None` before it is unlocked.
    pub vault: parking_lot::RwLock<Option<Arc<SecureVault>>>,
    /// The active group, or `None` before join/create.
    pub group: SharedGroup,
    /// Token from a completed sign-in, held only until the group is created.
    ///
    /// Kept in Rust rather than handed to the webview so an account-scoped token
    /// never crosses the JS boundary. Cleared as soon as it is consumed.
    pub pending_account_token: parking_lot::RwLock<Option<Zeroizing<String>>>,
    /// Opaque device code for the sign-in in progress.
    ///
    /// Also kept in Rust: the UI only ever sees the short `user_code` the human
    /// types, never the polling secret.
    pub pending_device_code: parking_lot::RwLock<Option<Zeroizing<String>>>,
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
            pending_account_token: parking_lot::RwLock::new(None),
            pending_device_code: parking_lot::RwLock::new(None),
            file_deletion_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Take the signed-in account token, clearing it so it is used at most once.
    fn take_account_token(&self) -> Option<Zeroizing<String>> {
        self.pending_account_token.write().take()
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

    /// Read the PAT out of the vault.
    fn pat(&self) -> Result<String> {
        let vault = self.vault()?;
        let contents = vault
            .load_contents()?
            .ok_or_else(|| AppError::NotConfigured("no group credentials are stored yet".into()))?;
        Ok(contents.pat)
    }

    /// Build a GitHub client for the active group.
    fn client(&self) -> Result<GitHubClient> {
        let group_state = self.group()?;
        let pat = self.pat()?;
        GitHubClient::new(group_state.repo.clone(), pat)
    }

    /// Build a Nostr store for the active group.
    ///
    /// The vault holds the Nostr secret in the same slot the PAT occupies, so
    /// switching backends does not need a second storage path.
    fn nostr_store(&self) -> Result<crate::nostr_store::NostrStore> {
        let group_state = self.group()?;
        if group_state.backend.kind() != crate::storage::BackendKind::Nostr {
            return Err(AppError::group_state(
                "this group is stored on GitHub, not Nostr",
            ));
        }
        let secret = self.pat()?;
        let identity = crate::nostr::NostrIdentity::from_hex(&secret)?;
        crate::nostr_store::store_for(
            &group_state.group_id,
            &group_state.relays,
            &group_state.blossom_servers,
            Arc::new(identity),
        )
    }

    /// True when the active group is stored on Nostr.
    fn is_nostr(&self) -> Result<bool> {
        Ok(self.group()?.backend.kind() == crate::storage::BackendKind::Nostr)
    }

        /// Borrow the PAT, inserting it into the group state so invite re-issue can
        /// embed it. Reads from the vault only; never from a command argument.
        fn pat_for_invites(&self) -> Result<String> {
            self.pat()
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
    /// Repo the stored credentials belong to, when configured.
    pub repo_full_name: Option<String>,
    /// Current key epoch, when configured.
    pub current_epoch: Option<u8>,
    pub requires_recovery: bool,
}

/// Request to create a group as the host.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupRequest {
    /// Owner of the repository. Provisioned repos report this back to the UI.
    #[serde(default)]
    pub repo_owner: Option<String>,
    /// Repository name.
    #[serde(default)]
    pub repo_name: Option<String>,
    /// Repository token. When empty, the signed-in account token is used instead,
    /// which removes the last manual setup step at the cost of embedding an
    /// account-scoped token in the invite.
    #[serde(default)]
    pub repo_scoped_pat: String,
    pub group_label: String,
    /// Password guests will need to unwrap the invite.
    pub join_password: String,
    pub display_name: String,
    /// Issue number holding the roster. `0` creates one and uses its number.
    #[serde(default)]
    pub roster_issue_num: u64,
    /// Issue number holding the chat. `0` creates one and uses its number.
    #[serde(default)]
    pub chat_issue_num: u64,
    /// Release id whose assets form the vault. Use 0 to look it up by tag.
    #[serde(default)]
    pub release_id: u64,
    /// Tag to resolve when `release_id` is 0.
    #[serde(default)]
    pub release_tag: Option<String>,
    /// True when [`provision_repository`] created this repository.
    #[serde(default)]
    pub repo_created: bool,
}

/// Result of creating a group.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupResponse {
    /// The invite string to hand to guests.
    pub invite: String,
    /// This device's key fingerprint, for verbal identification.
    pub fingerprint: String,
    /// Resolved repo, after validation.
    pub repo_full_name: String,
    /// Authenticated login the token belongs to.
    pub token_login: String,
    /// True when the token carries `Administration: Read/Write`.
    pub has_admin_scope: bool,
    /// Resolved vault release id.
    pub release_id: u64,
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
    pub repo_full_name: String,
    pub group_label: String,
    pub roster_issue_num: u64,
    pub chat_issue_num: u64,
    pub release_id: u64,
    pub key_epoch: u8,
    pub fingerprint: String,
    /// True when this device already had a roster comment, i.e. a re-join.
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
}

/// Report whether the device location switch is on.
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
            Some(handle) => LocationAccessResponse {
                system_location_enabled: handle.inner().is_system_location_enabled(),
                can_open_settings: true,
            },
            None => LocationAccessResponse {
                system_location_enabled: false,
                can_open_settings: false,
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

/// Request to re-key the group with a replacement token.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RekeyRequest {
    pub new_pat: String,
    pub join_password: String,
    /// Release tag to resolve, creating the release when it is missing.
    #[serde(default)]
    pub release_tag: Option<String>,
}

/// Result of a re-key.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RekeyResponse {
    /// True when the new token authenticated successfully.
    pub token_valid: bool,
    /// Authenticated login the new token belongs to.
    pub token_login: String,
    pub invites: Vec<MemberInvite>,
    /// Key epoch, unchanged by a re-key.
    pub key_epoch: u8,
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
    pub repo_full_name: String,
    pub vault_wiped: bool,
    pub accepted_relays: Vec<String>,
    pub unconfirmed_relays: Vec<String>,
}

/// Diagnostics for a developer panel.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsResponse {
    pub repo_full_name: String,
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
    /// Requests remaining this hour, if GitHub reported it.
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
        if stored.invite.backend == crate::storage::BackendKind::GitHub {
            stored.invite.repo_scoped_pat = contents.pat;
        }
        let identity = Identity::from_secret(stored.identity_secret);
        let group_state = GroupState::from_invite(&stored.invite, identity, stored.preferences.clone(), stored.is_host)?;
        group_state.install_roles(&stored.roles.iter().map(|role| (role.pubkey_b64.clone(), role.role.clone())).collect::<Vec<_>>());
        *state.group.write() = Some(Arc::new(group_state));
    }
    *state.vault.write() = Some(Arc::new(vault));

    let configured = descriptor.is_some();
    Ok(UnlockResponse {
        existed,
        group_configured: configured,
        repo_full_name: descriptor.as_ref().map(|d| d.repo_full_name.clone()),
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
    if stored.invite.backend == crate::storage::BackendKind::GitHub {
        stored.invite.repo_scoped_pat = contents.pat;
    }
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

/// Request to start an account sign-in.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeginSignInRequest {
    /// Include the destructive `delete_repo` scope so "Destroy Group" works.
    #[serde(default)]
    pub allow_destroy: bool,
}

/// A pending sign-in, ready to show the user.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BeginSignInResponse {
    /// Short code the user types at `verificationUri`.
    pub user_code: String,
    /// Page the user should open.
    pub verification_uri: String,
    /// Seconds until the code expires.
    pub expires_in: u64,
    /// Minimum seconds between polls.
    pub interval: u64,
}

/// Result of a completed sign-in.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInResponse {
    /// Authenticated login.
    pub login: String,
    /// Scopes GitHub actually granted.
    pub scope: String,
    /// True when `delete_repo` was granted, so Destroy Group will work.
    pub can_destroy: bool,
}

/// Request to create a repository and its schema, before any token exists.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionRequest {
    /// Account-scoped token, for callers that paste one instead of signing in.
    ///
    /// Optional: when a sign-in has already completed, the token is taken from
    /// app state and this is ignored.
    #[serde(default)]
    pub account_token: Option<String>,
    /// Repository name. Generated when empty.
    #[serde(default)]
    pub repo_name: Option<String>,
    /// Release tag for the vault. Defaults to `vault-v1`.
    #[serde(default)]
    pub release_tag: Option<String>,
}

/// Result of provisioning, before the group itself exists.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionResponse {
    pub repo_owner: String,
    pub repo_name: String,
    pub repo_full_name: String,
    pub roster_issue_num: u64,
    pub chat_issue_num: u64,
    pub release_id: u64,
    /// Authenticated login the account token belongs to.
    pub account_login: String,
}

// ---------------------------------------------------------------------------
// Account sign-in (OAuth device flow)
// ---------------------------------------------------------------------------

/// Start an account sign-in and return the code to show the user.
///
/// This is the whole point of the device flow: the user presses one button, sees
/// a short code, approves on whatever device they already have, and never has to
/// create a token by hand. Fine-grained PATs cannot be minted through the API, so
/// this is the only way to keep setup inside the app.
#[tauri::command]
pub async fn begin_sign_in(
    state: State<'_, AppState>,
    request: BeginSignInRequest,
) -> Result<BeginSignInResponse> {
    let client = oauth::DeviceFlowClient::new(oauth_client_id()?)?;
    let scopes = oauth::scopes_for_group(request.allow_destroy);
    let code = client.request_device_code(&scopes).await?;

    // Keep the polling secret in Rust; the UI only needs the human-typed code.
    *state.pending_device_code.write() = Some(Zeroizing::new(code.device_code.clone()));

    Ok(BeginSignInResponse {
        user_code: code.user_code.clone(),
        verification_uri: code.verification_uri.clone(),
        expires_in: code.expires_in,
        interval: code.interval,
    })
}

/// Poll once for a completed sign-in.
///
/// Returns `None` while the user has not approved yet, so the UI can keep a
/// spinner running without treating "not yet" as an error.
#[tauri::command]
pub async fn poll_sign_in(state: State<'_, AppState>) -> Result<Option<SignInResponse>> {
    let device_code = state
        .pending_device_code
        .read()
        .clone()
        .ok_or_else(|| AppError::not_configured("no sign-in is in progress"))?;

    let client = oauth::DeviceFlowClient::new(oauth_client_id()?)?;
    match client.poll_once(device_code.as_str()).await? {
        Ok(token) => {
            let login = ProvisioningClient::new(token.access_token.to_string())?
                .validate_token()
                .await?;
            let can_destroy = token
                .scope
                .split([',', ' '])
                .any(|s| s == oauth::SCOPE_DESTROY);
            let scope = token.scope.clone();
            // Hold the token in Rust; the webview only ever sees the login.
            *state.pending_account_token.write() = Some(token.access_token);
            // The device code is single-use; drop it so a stale poll cannot retry.
            *state.pending_device_code.write() = None;
            Ok(Some(SignInResponse {
                login,
                scope,
                can_destroy,
            }))
        }
        Err(_pending) => Ok(None),
    }
}

/// Read the embedded OAuth client id.
///
/// A device-flow client id is public by design, so it is compiled in rather than
/// configured. It can still be overridden for a fork or a test build.
fn oauth_client_id() -> Result<String> {
    let id = std::env::var("SHADOW720_OAUTH_CLIENT_ID")
        .ok()
        .filter(|id| !id.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_OAUTH_CLIENT_ID.to_string());
    if id.trim().is_empty() {
        return Err(AppError::not_configured(
            "no OAuth client id is compiled in, so account sign-in is unavailable",
        ));
    }
    Ok(id)
}

/// Create the repository, both schema issues, and the vault release.
///
/// Split out from [`create_group`] because a fine-grained token cannot be scoped
/// to a repository that does not exist yet: the UI provisions first, then asks
/// for a token scoped to the repository it just created.
#[tauri::command]
pub async fn provision_repository(
    state: State<'_, AppState>,
    request: ProvisionRequest,
) -> Result<ProvisionResponse> {
    // Prefer the signed-in token; fall back to a pasted one for headless use.
    let signed_in = state.take_account_token();
    let account_token: Zeroizing<String> = match signed_in {
        Some(token) => token,
        None => Zeroizing::new(
            request
                .account_token
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_string(),
        ),
    };
    if account_token.trim().is_empty() {
        return Err(AppError::not_configured(
            "sign in to an account first; creating a repository needs an account token",
        ));
    }

    let release_tag = request
        .release_tag
        .as_deref()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .unwrap_or(DEFAULT_RELEASE_TAG);

    let name = request
        .repo_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(generate_repo_name);

    let provisioner = ProvisioningClient::new(account_token.as_str())?;
    let account_login = provisioner.validate_token().await?;
    let provisioned = provisioner.provision(&name, release_tag).await?;

    Ok(ProvisionResponse {
        repo_owner: provisioned.repo.owner.clone(),
        repo_name: provisioned.repo.name.clone(),
        repo_full_name: provisioned.repo.full_name(),
        roster_issue_num: provisioned.roster_issue_num,
        chat_issue_num: provisioned.chat_issue_num,
        release_id: provisioned.release_id,
        account_login,
    })
}

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
        repo_owner: String::new(),
        repo_name: String::new(),
        // No shared credential: this is the whole point of the Nostr backend.
        repo_scoped_pat: String::new(),
        group_master_key: *group_key,
        roster_issue_num: 0,
        chat_issue_num: 0,
        release_id: 0,
        repo_created: true,
        relays: relays.clone(),
        blossom_servers: blossom_servers.clone(),
        group_id: group_id.clone(),
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
        repo_full_name: format!("nostr:{group_id}"),
        current_epoch: 0,
    };
    vault.store_group_contents(
        &VaultContents {
            // The Nostr secret is the group credential; it replaces the PAT.
            pat: nostr_identity.secret_hex().to_string(),
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

/// Create a group as the host.
#[tauri::command]
pub async fn create_group(
    state: State<'_, AppState>,
    request: CreateGroupRequest,
) -> Result<CreateGroupResponse> {
    let vault = state.vault()?;
    if request.join_password.is_empty() {
        return Err(AppError::invalid_argument(
            "a join password is required; it is what protects the invite string",
        ));
    }

    let release_tag = request
        .release_tag
        .clone()
        .filter(|tag| !tag.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_RELEASE_TAG.to_string());

    let owner = request.repo_owner.as_deref().unwrap_or("").trim();
    let name = request.repo_name.as_deref().unwrap_or("").trim();
    if owner.is_empty() || name.is_empty() {
        return Err(AppError::invalid_argument(
            "a repository owner and name are required; provision one first if it does not exist",
        ));
    }

    let repo = RepoRef::new(owner, name)?;

    // Prefer an explicit repository token; fall back to the signed-in account
    // token so the user never has to create one by hand.
    let group_token: Zeroizing<String> = if request.repo_scoped_pat.trim().is_empty() {
        state.take_account_token().ok_or_else(|| {
            AppError::not_configured(
                "sign in to an account, or paste a repository token, before creating a group",
            )
        })?
    } else {
        Zeroizing::new(request.repo_scoped_pat.trim().to_string())
    };

    let client = GitHubClient::new(repo.clone(), group_token.as_str())?;

    // Fail before writing anything if the token cannot reach the repository.
    let token_login = client.validate_token().await?;
    let _is_private = client.repo_is_accessible().await?;

    // Repair pass: create any missing schema piece rather than telling the host
    // to go and do it by hand. A provisioned repo already has all of it, so this
    // is a no-op there and a fix-up on the adopt path.
    let (roster_issue_num, chat_issue_num) = client
        .ensure_schema_issues(request.roster_issue_num, request.chat_issue_num)
        .await?;
    let release_id = if request.release_id != 0 {
        request.release_id
    } else {
        client.ensure_release(&release_tag).await?
    };

    let has_admin_scope = client.has_admin_scope().await.unwrap_or(false);

    let identity = Identity::generate()?;
    let group_key = crypto::new_group_key()?;

    let invite_payload = InviteCredentialsPayload {
        version: PROTOCOL_VERSION,
        backend: crate::storage::BackendKind::GitHub,
        repo_owner: repo.owner.clone(),
        repo_name: repo.name.clone(),
        repo_scoped_pat: group_token.to_string(),
        group_master_key: *group_key,
        roster_issue_num,
        chat_issue_num,
        release_id,
        repo_created: request.repo_created,
        relays: Vec::new(),
        blossom_servers: Vec::new(),
        group_id: String::new(),
        host_pubkey: identity.pubkey_b64.clone(),
        group_label: request.group_label.clone(),
        key_epoch: 0,
    };

    let invite = crypto::pack_invite(&invite_payload, &request.join_password)?;

    // Persist credentials before building in-memory state, so a failure here
    // cannot leave a group the user cannot re-open.
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
        repo_full_name: repo.full_name(),
        current_epoch: 0,
    };
    vault.store_group_contents(
        &VaultContents {
            pat: group_token.to_string(),
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

    Ok(CreateGroupResponse {
        invite,
        fingerprint,
        repo_full_name: repo.full_name(),
        token_login,
        has_admin_scope,
        release_id,
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

    // The two backends differ in what "verify access" even means: GitHub checks a
    // token against a repository, Nostr generates a keypair and checks whether
    // this device already has a slot.
    let (repo, already_member, stored_secret) = match invite.backend {
        crate::storage::BackendKind::Nostr => {
            let nostr_identity = crate::nostr::NostrIdentity::generate()?;
            let store = crate::nostr_store::store_for(
                &invite.group_id,
                &invite.relays,
                &invite.blossom_servers,
                Arc::new(crate::nostr::NostrIdentity::from_hex(
                    &nostr_identity.secret_hex(),
                )?),
            )?;

            // A fresh keypair can never already be a member, but the check keeps
            // the two paths shaped the same and catches a replayed secret.
            let already_member = store.has_own_slot().await?;
            let closures = store.read_closures().await?;
            if closures.iter().any(|event| group::verify_closure_proof(
                &invite.host_pubkey, &invite.group_id, &event.content,
            )) {
                return Err(AppError::group_state("the host has closed this group; this invite can no longer be used"));
            }
            let repo = RepoRef::new("nostr", invite.group_id.clone())?;
            (repo, already_member, nostr_identity.secret_hex().to_string())
        }
        crate::storage::BackendKind::GitHub => {
            let repo = RepoRef::new(invite.repo_owner.clone(), invite.repo_name.clone())?;
            let client = GitHubClient::new(repo.clone(), invite.repo_scoped_pat.clone())?;

            // Verify access before storing anything. The invite's issue numbers
            // are authoritative, so the repair pass only confirms they exist.
            client.validate_token().await?;
            client
                .ensure_schema_issues(invite.roster_issue_num, invite.chat_issue_num)
                .await?;

            // Decide whether this is a re-join by looking for an existing comment.
            let existing = client.list_comments(invite.roster_issue_num).await?;
            let already_member = existing
                .iter()
                .any(|comment| comment.author_login == repo.owner);
            (repo, already_member, invite.repo_scoped_pat.clone())
        }
    };

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
        repo_full_name: repo.full_name(),
        current_epoch: invite.key_epoch,
    };
    vault.store_group_contents(
        &VaultContents {
            pat: stored_secret,
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
        repo_full_name: repo.full_name(),
        group_label: invite.group_label.clone(),
        roster_issue_num: invite.roster_issue_num,
        chat_issue_num: invite.chat_issue_num,
        release_id: invite.release_id,
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
    let group_state = state.group()?;
    let fix = Fix {
        lat: update.lat,
        lon: update.lon,
        unix_ms: now_unix_ms(),
        speed_mps: update.speed_mps,
        heading_deg: update.heading_deg,
        accuracy_m: update.accuracy_m,
    };

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

    let outcome = if state.is_nostr()? {
        // Addressable event: republishing replaces this member's slot, so there
        // is no comment id to track and no way to collide with another member.
        let store = state.nostr_store()?;
        store
            .publish_roster(&body)
            .await
            .map(|_| crate::github_db::nostr_numeric_id(group_state.identity.pubkey_b64.as_str()))
    } else {
        let client = state.client()?;
        let comment_id = *group_state.my_comment_id.read();
        match comment_id {
            // A member only ever PATCHes their own comment, which is why
            // concurrent location updates from many phones never conflict.
            Some(id) => client.update_comment(id, &body).await.map(|c| c.id),
            None => client
                .create_comment(group_state.roster_issue_num, &body)
                .await
                .map(|c| c.id),
        }
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
    let now_s = crate::github_db::now_unix_s();

    if let Some(remaining) = group_state.halt_remaining_secs(now_s) {
        return Ok(PollResponse {
            next_delay_ms: (remaining.max(1) as u64) * 1_000,
            not_modified: false,
            rate_limited: true,
            halt_remaining_secs: Some(remaining),
        });
    }

    if state.is_nostr()? {
        // Relays push, so there is no conditional-GET path and no quota to
        // observe. The cadence is still returned so the UI keeps a timer.
        let store = state.nostr_store()?;
        let comments = store.read_roster().await?;
        group_state.apply_roster(&comments);
        if let Ok(controls) = store.read_control().await {
            group_state.apply_role_controls(&controls);
        }
        announce_roles_if_needed(state.clone(), &group_state).await;
        return Ok(PollResponse {
            next_delay_ms: group_state.roster_delay(false).await.as_millis() as u64,
            not_modified: false,
            rate_limited: false,
            halt_remaining_secs: None,
        });
    }

    let client = state.client()?;
    let (comments, not_modified) = client
        .list_comments_conditional(group_state.roster_issue_num)
        .await?;

    if !not_modified {
        group_state.apply_roster(&comments);
        group_state.apply_role_controls(&comments);
        announce_roles_if_needed(state.clone(), &group_state).await;
    }
    group_state.observe_rate_limit(200, None, None, None);

    Ok(PollResponse {
        next_delay_ms: group_state.roster_delay(not_modified).await.as_millis() as u64,
        not_modified,
        rate_limited: false,
        halt_remaining_secs: None,
    })
}

/// Poll the chat channel and refresh the snapshot.
#[tauri::command]
pub async fn poll_chat(state: State<'_, AppState>) -> Result<PollResponse> {
    let group_state = state.group()?;
    let now_s = crate::github_db::now_unix_s();

    if let Some(remaining) = group_state.halt_remaining_secs(now_s) {
        return Ok(PollResponse {
            next_delay_ms: (remaining.max(1) as u64) * 1_000,
            not_modified: false,
            rate_limited: true,
            halt_remaining_secs: Some(remaining),
        });
    }

    if state.is_nostr()? {
        let store = state.nostr_store()?;
        let comments = store.read_chat().await?;
        let removals = store.read_file_removals().await?;
        group_state.apply_chat(&comments);
        group_state.apply_file_removals(&removals);
        return Ok(PollResponse {
            next_delay_ms: group_state.chat_delay(false).await.as_millis() as u64,
            not_modified: false,
            rate_limited: false,
            halt_remaining_secs: None,
        });
    }

    let client = state.client()?;
    let (comments, not_modified) = client
        .list_comments_conditional(group_state.chat_issue_num)
        .await?;

    if !not_modified {
        group_state.apply_chat(&comments);
    }
    group_state.observe_rate_limit(200, None, None, None);

    Ok(PollResponse {
        next_delay_ms: group_state.chat_delay(not_modified).await.as_millis() as u64,
        not_modified,
        rate_limited: false,
        halt_remaining_secs: None,
    })
}

/// Report the current rate-limit state by querying GitHub directly.
#[tauri::command]
pub async fn refresh_rate_limit(state: State<'_, AppState>) -> Result<PollResponse> {
    let group_state = state.group()?;

    // Nostr has no shared request budget: relays push, and each member signs with
    // its own key, so there is nothing to throttle.
    if state.is_nostr()? {
        return Ok(PollResponse {
            next_delay_ms: 0,
            not_modified: false,
            rate_limited: false,
            halt_remaining_secs: None,
        });
    }

    let client = state.client()?;
    let snapshot = client.rate_limit().await?;

    group_state.observe_rate_limit(
        if snapshot.is_exhausted() { 429 } else { 200 },
        snapshot.reset_unix_s,
        snapshot.remaining,
        snapshot.limit,
    );

    let now_s = crate::github_db::now_unix_s();
    let remaining = group_state.halt_remaining_secs(now_s);
    Ok(PollResponse {
        next_delay_ms: remaining.map(|r| (r.max(1) as u64) * 1_000).unwrap_or(0),
        not_modified: false,
        rate_limited: remaining.is_some(),
        halt_remaining_secs: remaining,
    })
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
            repo_full_name: group_state.backend.location(),
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

    let created = if state.is_nostr()? {
        let store = state.nostr_store()?;
        let event_id = store.publish_chat(&body).await?;
        // Reflect the send locally without a round trip, using the same shape a
        // relay read would produce.
        crate::github_db::IssueComment {
            id: crate::github_db::nostr_numeric_id(&event_id),
            body,
            created_at_ms: now_unix_ms(),
            updated_at_ms: now_unix_ms(),
            author_login: store.pubkey_hex().to_string(),
            nostr_event_id: Some(event_id),
        }
    } else {
        let client = state.client()?;
        client
            .create_comment(group_state.chat_issue_num, &body)
            .await?
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
    crate::github_db::enforce_file_size(request.data.len() as u64)?;

    let plaintext_digest = crypto::sha256_b64(&request.data);
    let key = group_state.current_group_key()?;
    let sealed = crypto::seal_blob(&key, &request.data)?;

    let nostr = state.is_nostr()?;

    // Reclaim space first, so the upload does not push the vault past its ceiling.
    // Blossom is content-addressed and has no per-group quota to prune.
    let pruned_count = if nostr {
        0
    } else {
        let client = state.client()?;
        client
            .prune_vault(group_state.release_id, sealed.len() as u64)
            .await?
            .to_delete
            .len()
    };

    // On Nostr the asset name is the content address, which is what makes the
    // pointer verifiable and deduplicates identical files.
    let uploaded = if nostr {
        let store = state.nostr_store()?;
        Some(store.upload_blob(&sealed).await?)
    } else {
        None
    };
    let asset_name = if let Some(upload) = &uploaded {
        upload.blob.sha256.clone()
    } else {
        let client = state.client()?;
        let name = format!("{}.bin", uuid::Uuid::new_v4());
        client
            .upload_asset(
                group_state.release_id,
                &name,
                &sealed,
                "application/octet-stream",
            )
            .await?;
        name
    };

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

    let (created, vault_bytes) = if nostr {
        let store = state.nostr_store()?;
        let event = store.file_event(&body)?;
        let upload = uploaded.as_ref().ok_or_else(|| AppError::group_state("uploaded Blossom file metadata is missing"))?;
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
        let comment = crate::github_db::IssueComment {
            id: crate::github_db::nostr_numeric_id(&event_id),
            body,
            created_at_ms: now_unix_ms(),
            updated_at_ms: now_unix_ms(),
            author_login: store.pubkey_hex().to_string(),
            nostr_event_id: Some(event_id),
        };
        // Blossom has no per-group quota, so report the blob size instead.
        (comment, sealed.len() as u64)
    } else {
        let client = state.client()?;
        let comment = client
            .create_comment(group_state.chat_issue_num, &body)
            .await?;
        let bytes = client.vault_size(group_state.release_id).await?;
        (comment, bytes)
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

    let sealed = if state.is_nostr()? {
        // On Nostr the asset name is the content address, so the fetch is
        // self-verifying: `download_blob` rejects bytes that do not hash to it.
        state.nostr_store()?.download_blob(&asset_name).await?
    } else {
        state
            .client()?
            .download_asset(group_state.release_id, &asset_name)
            .await?
    };
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
        preferences.blocked_pubkeys.insert(request.pubkey_b64);
    } else {
        preferences.blocked_pubkeys.remove(&request.pubkey_b64);
    }
    state.vault()?.update_preferences(&preferences)?;
    group_state.set_preferences(preferences);
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

    let created = if state.is_nostr()? {
        // Nostr has no server-side deletion: an event is signed by its author, so
        // only the author can retract it, and even then relays may ignore the
        // request. The flag is published and the block list does the enforcement.
        let store = state.nostr_store()?;
        let event_id = store.publish_chat(&body).await?;
        crate::github_db::IssueComment {
            id: crate::github_db::nostr_numeric_id(&event_id),
            body,
            created_at_ms: now_unix_ms(),
            updated_at_ms: now_unix_ms(),
            author_login: store.pubkey_hex().to_string(),
            nostr_event_id: Some(event_id),
        }

    } else {
        let client = state.client()?;
        // The host additionally removes the offending comment, which is the only
        // server-side enforcement available with a shared token.
        if group_state.is_host {
            client.delete_comment(request.target_comment_id).await?;
        }
        client
            .create_comment(group_state.chat_issue_num, &body)
            .await?
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

    let comments = if state.is_nostr()? {
        let store = state.nostr_store()?;
        let mut comments = store.read_roster().await?;
        comments.extend(store.read_rotations().await?);
        comments
    } else {
        state
            .client()?
            .list_comments(group_state.roster_issue_num)
            .await?
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
    let invite = pack_current_invite(&group_state, &request.join_password, &state.pat_for_invites()?)?;
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

    let removed_pubkeys = if state.is_nostr()? {
        confirm_removals(&group_state, &request.remove_pubkeys)?;
        request.remove_pubkeys.clone()
    } else {
        let client = state.client()?;
        let comments = client.list_comments(group_state.roster_issue_num).await?;
        group_state.apply_roster(&comments);
        delete_removed_members(&client, &group_state, &request.remove_pubkeys).await?
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
    if state.is_nostr()? {
        state.nostr_store()?.publish_rotation(&body).await?;
    } else {
        state.client()?.create_comment(group_state.roster_issue_num, &body).await?;
    }

    group_state.apply_rotation(new_epoch, new_key)?;
    let descriptor = VaultDescriptor {
        version: DESCRIPTOR_VERSION,
        keystore_alias: vault.keystore_alias(),
        repo_full_name: group_state.repo.full_name(),
        current_epoch: new_epoch,
    };
    vault.update_group_key(&new_key, &descriptor)?;

    let pat = state.pat_for_invites()?;
    let invites = build_member_invites(
        &group_state,
        &request.join_password,
        new_epoch,
        &new_key,
        &removed_pubkeys,
        &pat,
    )?;
    let group_invite = pack_current_invite(&group_state, &request.join_password, &pat)?;
    let _ = vault.save_invite_code(&group_invite);

    Ok(RotateResponse {
        new_epoch,
        retired_epoch: new_epoch.saturating_sub(1),
        invites,
        removed_pubkeys,
        group_invite,
    })
}

/// Replace the group token without touching the group key.
#[tauri::command]
pub async fn rekey_group(
    state: State<'_, AppState>,
    request: RekeyRequest,
) -> Result<RekeyResponse> {
    let vault = state.vault()?;
    let group_state = state.group()?;

    if !group_state.is_host {
        return Err(AppError::group_state(
            "only the host may re-issue invites with a new token",
        ));
    }
    if request.new_pat.trim().is_empty() {
        return Err(AppError::invalid_argument("a replacement token is required"));
    }
    if request.join_password.is_empty() {
        return Err(AppError::invalid_argument(
            "a join password is required to re-issue invites",
        ));
    }

    // The new token must work before it replaces a working one.
    let client = GitHubClient::new(group_state.repo.clone(), request.new_pat.clone())?;
    let token_login = client.validate_token().await?;
    client
        .ensure_schema_issues(group_state.roster_issue_num, group_state.chat_issue_num)
        .await?;
    client.ensure_release(&request.release_tag.clone().unwrap_or_else(|| "vault-v1".into())).await?;

    let epoch = group_state.current_epoch();
    let key = group_state.current_group_key()?;

    let descriptor = VaultDescriptor {
        version: DESCRIPTOR_VERSION,
        keystore_alias: vault.keystore_alias(),
        repo_full_name: group_state.repo.full_name(),
        current_epoch: epoch,
    };
    vault.update_pat(&request.new_pat, &descriptor)?;

    let invites = build_member_invites(
        &group_state,
        &request.join_password,
        epoch,
        &key,
        &[],
            &request.new_pat,
        )?;

    Ok(RekeyResponse {
        token_valid: true,
        token_login,
        invites,
        key_epoch: epoch,
    })
}

// ---------------------------------------------------------------------------
// Leaving and destroying
// ---------------------------------------------------------------------------

/// Leave the group: delete this device's roster comment, then wipe locally.
#[tauri::command]
pub async fn leave_and_wipe(state: State<'_, AppState>) -> Result<WipeResponse> {
    let group_state = state.group()?;

    // Deleting the roster entry is best-effort: if it fails, the user's intent to
    // wipe locally still has to be honoured, otherwise their data stays on a
    // device they are trying to clean.
    let roster_comment_deleted = if state.is_nostr()? {
        // A Nostr slot can only be retracted by its author, and relays may ignore
        // the request. Publishing an empty slot is the closest equivalent, and a
        // failure here must not block the local wipe.
        match state.nostr_store() {
            Ok(store) => store.publish_roster("").await.is_ok(),
            Err(_) => false,
        }
    } else {
        // Copy the id out before awaiting: holding a `parking_lot` guard across
        // an await makes the future non-Send.
        let comment_id = *group_state.my_comment_id.read();
        match comment_id {
            Some(id) => state.client()?.delete_comment(id).await.is_ok(),
            None => true,
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

/// Destroy the group repository. Host-only in the UI, but enforced by the token.
#[tauri::command]
pub async fn destroy_group(state: State<'_, AppState>) -> Result<DestroyResponse> {
    let group_state = state.group()?;

    if !group_state.is_host {
        return Err(AppError::group_state(
            "only the host may destroy the group; guests must leave instead",
        ));
    }

    if state.is_nostr()? {
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
        return Ok(DestroyResponse {
            repo_full_name: format!("nostr:{}", group_state.group_id),
            vault_wiped: true,
            accepted_relays,
            unconfirmed_relays,
        });
    }

    let client = state.client()?;
    let repo_full_name = group_state.repo.full_name();

    // Require admin scope up front, so the failure message says what to fix
    // instead of surfacing a bare 403.
    if !client.has_admin_scope().await.unwrap_or(false) {
        return Err(AppError::GitHubAuth { status: 403 });
    }

    client.delete_repository().await?;

    let vault_wiped = match state.vault.read().clone() {
        Some(vault) => vault.wipe().is_ok(),
        None => true,
    };

    *state.group.write() = None;
    *state.vault.write() = None;

    Ok(DestroyResponse {
        repo_full_name,
        vault_wiped,
        accepted_relays: Vec::new(),
        unconfirmed_relays: Vec::new(),
    })
}

/// Wipe this device after observing a closure signed by its pinned host.
#[tauri::command]
pub async fn check_group_closed(state: State<'_, AppState>) -> Result<bool> {
    check_group_closed_inner(&state).await
}

async fn check_group_closed_inner(state: &AppState) -> Result<bool> {
    let group_state = state.group()?;
    if !state.is_nostr()? {
        return Ok(false);
    }
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
    let group_state = state.group()?;

    // The local encrypted index contains only uploads made by this device.
    if state.is_nostr()? {
        let stored = state.vault()?.load_group()?.ok_or_else(|| AppError::vault("the stored group cannot be restored"))?;
        let assets: Vec<VaultAssetView> = stored.uploads.iter().map(|upload| VaultAssetView {
            id: crate::github_db::nostr_numeric_id(&upload.event.id),
            name: upload.sha256.clone(),
            size: upload.size,
            created_at_ms: upload.event.created_at.saturating_mul(1_000),
            deletion_status: Some(if !upload.deleted { "available" } else if upload.notice_published { "announced" } else { "notice_pending" }.into()),
        }).collect();
        let total_bytes = stored.uploads.iter().filter(|upload| !upload.deleted).map(|upload| upload.size).sum();
        return Ok(VaultReport {
            assets,
            total_bytes,
            max_bytes: crate::github_db::MAX_VAULT_BYTES,
            rate_limit_remaining: None,
        });
    }

    let client = state.client()?;
    let assets = client.list_assets(group_state.release_id).await?;
    let total_bytes: u64 = assets.iter().map(|a| a.size).sum();
    let snapshot = client.rate_limit().await.ok();

    Ok(VaultReport {
        assets: assets
            .into_iter()
            .map(|asset| VaultAssetView {
                id: asset.id,
                name: asset.name,
                size: asset.size,
                created_at_ms: asset.created_at_ms,
                deletion_status: None,
            })
            .collect(),
        total_bytes,
        max_bytes: crate::github_db::MAX_VAULT_BYTES,
        rate_limit_remaining: snapshot.and_then(|s| s.remaining),
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

/// Delete one GitHub blob from the vault.
#[tauri::command]
pub async fn delete_asset(state: State<'_, AppState>, asset_id: u64) -> Result<()> {
    let group_state = state.group()?;

    if state.is_nostr()? {
        // Blossom blobs are content-addressed and shared: deleting one would
        // break every pointer to it, including other members' messages. Refuse
        // rather than silently corrupting the group's history.
        return Err(AppError::invalid_argument(
            "files on Nostr are content-addressed and cannot be deleted individually",
        ));
    }

    let client = state.client()?;
    client.delete_asset(asset_id).await?;
    group_state.reset_cadence();
    Ok(())
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

/// Generate a repository name that is unlikely to collide.
///
/// Matches the `grp-<hex>` shape the UI has always suggested, so a provisioned
/// repository is recognisable in the account's repository list.
fn generate_repo_name() -> String {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    let suffix: String = bytes[..4].iter().map(|b| format!("{b:02x}")).collect();
    format!("grp-{suffix}")
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
    if state.is_nostr()? {
        state.nostr_store()?.publish_control(&body).await?;
    } else {
        state.client()?.create_comment(group_state.roster_issue_num, &body).await?;
    }
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

fn pack_current_invite(group_state: &GroupState, join_password: &str, repo_scoped_pat: &str) -> Result<String> {
    let payload = InviteCredentialsPayload {
        version: PROTOCOL_VERSION,
        backend: group_state.backend.kind(),
        repo_owner: group_state.repo.owner.clone(),
        repo_name: group_state.repo.name.clone(),
        repo_scoped_pat: repo_scoped_pat.to_string(),
        group_master_key: group_state.current_group_key()?,
        roster_issue_num: group_state.roster_issue_num,
        chat_issue_num: group_state.chat_issue_num,
        release_id: group_state.release_id,
        repo_created: true,
        relays: group_state.relays.clone(),
        blossom_servers: group_state.blossom_servers.clone(),
        group_id: group_state.group_id.clone(),
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

async fn delete_removed_members(
    client: &crate::github_db::GitHubClient,
    group_state: &GroupState,
    remove_pubkeys: &[String],
) -> Result<Vec<String>> {
    confirm_removals(group_state, remove_pubkeys)?;
    let member_ids = group::comment_ids_by_pubkey(&group_state.roster.read());
    let mut removed = Vec::new();
    for pubkey in remove_pubkeys {
        let comment_id = member_ids.get(pubkey).copied().ok_or_else(|| {
            AppError::group_state(format!(
                "member {pubkey} is not in the current roster, so it cannot be removed"
            ))
        })?;
        client.delete_comment(comment_id).await?;
        removed.push(pubkey.clone());
    }
    Ok(removed)
}

/// Build one invite per member, excluding removed members.
///
/// The PAT is passed in explicitly because it lives in the vault, not in group
/// state; taking it as an argument makes it obvious at each call site that a
/// secret is being embedded.
fn build_member_invites(
    group_state: &GroupState,
    join_password: &str,
    epoch: u8,
    group_key: &[u8; 32],
    excluded: &[String],
    repo_scoped_pat: &str,
) -> Result<Vec<MemberInvite>> {
    if group_state.backend.kind().requires_account() && repo_scoped_pat.trim().is_empty() {
        return Err(AppError::NotConfigured(
            "no group token is stored, so invites cannot be re-issued".into(),
        ));
    }

    let mut invites = Vec::new();

    for member in group_state.roster.read().iter() {
        if excluded.iter().any(|excluded| excluded == &member.pubkey_b64) {
            continue;
        }

        let payload = InviteCredentialsPayload {
            version: PROTOCOL_VERSION,
            backend: group_state.backend.kind(),
            repo_owner: group_state.repo.owner.clone(),
            repo_name: group_state.repo.name.clone(),
            repo_scoped_pat: repo_scoped_pat.to_string(),
            group_master_key: *group_key,
            roster_issue_num: group_state.roster_issue_num,
            chat_issue_num: group_state.chat_issue_num,
            release_id: group_state.release_id,
            repo_created: true,
            relays: group_state.relays.clone(),
            blossom_servers: group_state.blossom_servers.clone(),
            group_id: group_state.group_id.clone(),
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
            repo_owner: String::new(), repo_name: String::new(), repo_scoped_pat: String::new(),
            group_master_key: [9; 32], roster_issue_num: 0, chat_issue_num: 0, release_id: 0,
            repo_created: true, relays: vec![relay], blossom_servers: Vec::new(),
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
            repo_full_name: "nostr:closure-test".into(), current_epoch: 0 };
        vault.store_group_contents(&VaultContents { pat: nostr.secret_hex().to_string(), group_key: Zeroizing::new([9; 32]) },
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
            repo_owner: String::new(), repo_name: String::new(), repo_scoped_pat: String::new(),
            group_master_key: [8; 32], roster_issue_num: 0, chat_issue_num: 0, release_id: 0,
            repo_created: true, relays: vec![relay_url], blossom_servers: vec![server_url.clone()],
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
            repo_full_name: "nostr:file-test".into(), current_epoch: 0 };
        vault.store_group_contents(&VaultContents { pat: nostr.secret_hex().to_string(), group_key: Zeroizing::new([8; 32]) },
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
            repo_full_name: Some("JaredCH/sandbox".into()),
            current_epoch: Some(0),
            requires_recovery: false,
        };
        let json = serde_json::to_value(&response).expect("serialize");
        assert!(json.get("groupConfigured").is_some());
        assert!(json.get("repoFullName").is_some());
        assert!(json.get("currentEpoch").is_some());
    }

    #[test]
    fn diagnostics_response_serializes_with_camel_case_keys() {
        let response = DiagnosticsResponse {
            group_label: "test".into(),
            repo_full_name: "JaredCH/sandbox".into(),
            backend: "github".into(),
            accountless: false,
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
        assert!(json.get("repoFullName").is_some());
        assert!(json.get("knownEpochs").is_some());
        assert!(json.get("chatIntervalS").is_some());
        assert_eq!(json.get("backend").and_then(|v| v.as_str()), Some("github"));
        assert_eq!(json.get("accountless").and_then(|v| v.as_bool()), Some(false));
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
    fn create_group_request_requires_core_fields() {
        let json = r#"{
            "repoOwner":"JaredCH",
            "repoName":"shadow720-sandbox",
            "repoScopedPat":"github_pat_X",
            "groupLabel":"Trip",
            "joinPassword":"pw",
            "displayName":"Jared",
            "rosterIssueNum":1,
            "chatIssueNum":2
        }"#;
        let request: CreateGroupRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(request.repo_owner.as_deref(), Some("JaredCH"));
        assert_eq!(request.release_id, 0, "defaulted");
        assert!(request.release_tag.is_none());
        assert!(!request.repo_created, "adopt is the default");

        let missing = r#"{"repoOwner":"x"}"#;
        assert!(serde_json::from_str::<CreateGroupRequest>(missing).is_err());
    }

    #[test]
    fn create_group_request_accepts_a_provisioned_repo() {
        let json = r#"{
            "repoOwner":"JaredCH",
            "repoName":"grp-9f8a7b6c",
            "repoScopedPat":"github_pat_X",
            "groupLabel":"Trip",
            "joinPassword":"pw",
            "displayName":"Jared",
            "repoCreated":true
        }"#;
        let request: CreateGroupRequest = serde_json::from_str(json).expect("deserialize");
        assert!(request.repo_created);
        assert_eq!(request.repo_name.as_deref(), Some("grp-9f8a7b6c"));
        assert_eq!(request.roster_issue_num, 0, "0 means create one");
        assert_eq!(request.chat_issue_num, 0, "0 means create one");
    }

    #[test]
    fn provision_request_requires_an_account_token() {
        let request: ProvisionRequest =
            serde_json::from_str(r#"{"accountToken":"ghp_x"}"#).expect("deserialize");
        assert_eq!(request.account_token.as_deref(), Some("ghp_x"));
        assert!(request.repo_name.is_none());
        assert!(request.release_tag.is_none());

        // The token is optional: a completed sign-in supplies it from app state.
        let signed_in: ProvisionRequest =
            serde_json::from_str(r#"{"repoName":"grp-1"}"#).expect("deserialize");
        assert!(signed_in.account_token.is_none());
    }

    #[test]
    fn nostr_store_requires_a_nostr_group() {
        let state = AppState::new();
        // No group at all: the error must say so rather than panicking.
        assert!(state.nostr_store().is_err());
        assert!(state.is_nostr().is_err());
    }

    #[test]
    fn nostr_store_rejects_a_github_group() {
        let state = AppState::new();
        let invite = crate::crypto::InviteCredentialsPayload {
            version: crate::crypto::PROTOCOL_VERSION,
            backend: crate::storage::BackendKind::GitHub,
            repo_owner: "o".into(),
            repo_name: "r".into(),
            repo_scoped_pat: "github_pat_X".into(),
            group_master_key: [1u8; 32],
            roster_issue_num: 1,
            chat_issue_num: 2,
            release_id: 3,
            repo_created: true,
            relays: Vec::new(),
            blossom_servers: Vec::new(),
            group_id: String::new(),
            host_pubkey: String::new(),
            group_label: "g".into(),
            key_epoch: 0,
        };
        let identity = Identity::generate().expect("identity");
        let group = GroupState::from_invite(&invite, identity, test_preferences(), true)
            .expect("group");
        *state.group.write() = Some(Arc::new(group));

        assert!(!state.is_nostr().expect("kind"));
        let error = state.nostr_store().expect_err("must refuse");
        assert_eq!(error.kind(), crate::error::AppErrorKind::GroupState);
    }

    #[test]
    fn nostr_store_builds_for_a_nostr_group() {
        let state = AppState::new();
        let invite = crate::crypto::InviteCredentialsPayload {
            version: crate::crypto::PROTOCOL_VERSION,
            backend: crate::storage::BackendKind::Nostr,
            repo_owner: String::new(),
            repo_name: String::new(),
            repo_scoped_pat: String::new(),
            group_master_key: [1u8; 32],
            roster_issue_num: 0,
            chat_issue_num: 0,
            release_id: 0,
            repo_created: true,
            relays: vec!["wss://relay.example".into()],
            blossom_servers: vec!["https://blossom.example".into()],
            group_id: "group-1".into(),
            host_pubkey: String::new(),
            group_label: "g".into(),
            key_epoch: 0,
        };
        let identity = Identity::generate().expect("identity");
        let group = GroupState::from_invite(&invite, identity, test_preferences(), true)
            .expect("group");
        *state.group.write() = Some(Arc::new(group));

        assert!(state.is_nostr().expect("kind"));
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
    fn account_token_is_consumed_at_most_once() {
        let state = AppState::new();
        assert!(state.take_account_token().is_none(), "starts empty");

        *state.pending_account_token.write() = Some(Zeroizing::new("gho_x".to_string()));
        let first = state.take_account_token().expect("first take");
        assert_eq!(first.as_str(), "gho_x");
        assert!(
            state.take_account_token().is_none(),
            "a second take must not hand out the same token"
        );
    }

    #[test]
    fn oauth_client_id_is_never_empty() {
        let id = oauth_client_id().expect("client id");
        assert!(!id.trim().is_empty());
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
                &VaultContents { pat: "github_pat_TEST".into(), group_key: Zeroizing::new([7; 32]) },
                &VaultDescriptor {
                    version: DESCRIPTOR_VERSION,
                    keystore_alias: vault.keystore_alias(),
                    repo_full_name: "o/r".into(),
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
    fn begin_sign_in_request_defaults_to_no_destroy_scope() {
        let request: BeginSignInRequest = serde_json::from_str(r#"{}"#).expect("deserialize");
        assert!(!request.allow_destroy);

        let opted_in: BeginSignInRequest =
            serde_json::from_str(r#"{"allowDestroy":true}"#).expect("deserialize");
        assert!(opted_in.allow_destroy);
    }

    #[test]
    fn generated_repo_names_are_unique_and_prefixed() {
        let first = generate_repo_name();
        let second = generate_repo_name();
        assert!(first.starts_with("grp-"));
        assert_eq!(first.len(), "grp-".len() + 8);
        assert_ne!(first, second);
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
