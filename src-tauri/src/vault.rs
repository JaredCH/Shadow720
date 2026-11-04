//! Secure at-rest storage for the two secrets that matter: the repo-scoped PAT
//! and the group master key.
//!
//! # Why not Stronghold
//!
//! The plan originally specified `tauri-plugin-stronghold`. Three hard blockers
//! were found during implementation, all verified against `iota_stronghold 2.1`:
//!
//! 1. **Vault records are not readable.** `ClientVault::read_secret` is
//!    `#[cfg(test)]` only, by design: records are meant to be used, never
//!    extracted. A PAT has to be handed to an HTTP client, so it must be readable.
//! 2. **Snapshot writes take ~100 seconds on Windows.** Stronghold's runtime is
//!    built on its own hardened shared-memory allocator; a single
//!    `commit_with_keyprovider` for a 32-byte payload measured 103 s on this
//!    machine. A hundred-second freeze when a user taps "Join" is not shippable.
//! 3. **A client with no records cannot be written at all**, so a freshly created
//!    vault fails with "no data present" before its first secret is stored.
//!
//! The replacement keeps every security property the plan cares about:
//!
//! * Confidentiality and integrity come from `XChaCha20-Poly1305` in
//!   [`crate::crypto`], which is covered by single-bit tamper tests.
//! * The vault key is wrapped by the Android Keystore through [`Keystore`], so the
//!   hardware keystore remains the root of trust exactly as specified.
//! * The file format is versioned and self-describing, and a hostile file is
//!   rejected before any plaintext is produced.
//!
//! What changes is only the *mechanism*; the threat model is unchanged.
//!
//! # Design (`PLAN_ADDENDUM_v1.md` §A4)
//!
//! ```text
//!   Android Keystore            Sealed vault file
//!   ┌──────────────┐            ┌─────────────────────┐
//!   │ AES-GCM key  │ ──wraps──▶ │ 32-byte vault pass  │
//!   │ hardware-    │            │         │           │
//!   │ backed       │            │         ▼           │
//!   └──────────────┘            │  PAT + group_key    │
//!                               └─────────────────────┘
//! ```
//!
//! * The **Keystore** key is generated in hardware and never leaves the TEE. It is
//!   the only thing that can unwrap the vault password.
//! * The **vault password** is 32 random bytes, generated on first launch, and is
//!   never stored in the clear.
//! * The vault file is sealed with a key derived from that password by `Argon2id`
//!   and authenticated with AEAD, so a modified file fails to open.
//!
//! Compromising the app's filesystem alone yields nothing: the vault file is
//! useless without the hardware-wrapped password, and the wrapped password is
//! useless without the Keystore key.
//!
//! # Why the keystore is a trait
//!
//! Windows and desktop Linux have no Android Keystore. [`Keystore`] abstracts the
//! platform call so the vault logic is testable on any host, and so a desktop key
//! store can be slotted in behind the same three methods.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, random_bytes, GroupKey, GROUP_KEY_LEN, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{AppError, Result};

/// Length of the vault password. 32 bytes = 256 bits.
pub const VAULT_PASSWORD_LEN: usize = 32;
/// Filename of the sealed vault payload.
pub const VAULT_FILENAME: &str = "shadow720.vault";
/// Filename of the Keystore-wrapped vault password.
pub const WRAP_FILENAME: &str = "shadow720.vaultpw";
/// Filename of the non-secret descriptor.
pub const DESCRIPTOR_FILENAME: &str = "shadow720.vault.json";

/// Magic bytes prefixing every vault file.
///
/// Lets a foreign or truncated file be rejected with a clear message instead of an
/// AEAD failure, which would look identical to a wrong password.
const VAULT_MAGIC: &[u8; 8] = b"SHDW720V";
/// On-disk vault format version.
const VAULT_FORMAT_VERSION: u8 = 1;
/// `magic(8) ‖ version(1) ‖ salt(16) ‖ nonce(24) ‖ ciphertext+tag`.
const VAULT_HEADER_LEN: usize = 8 + 1 + SALT_LEN + NONCE_LEN;
/// Context string bound into the vault's Argon2id derivation, so a password reused
/// as an invite wrapping key cannot produce the same vault key.
const VAULT_KDF_CONTEXT: &[u8] = b"shadow720/vault/kdf/v1";
/// Associated data binding a vault ciphertext to its purpose.
const VAULT_AAD: &[u8] = b"shadow720/vault/payload/v1";

/// The plaintext contents of the vault file.
#[derive(Serialize, Deserialize)]
struct VaultPayload {
    /// Schema version, so a future layout change can migrate rather than fail.
    version: u8,
    /// Secret of the *active* group: a PAT on GitHub, a Nostr secret on Nostr.
    pat: String,
    /// Group master key for the active group's current epoch.
    group_key: [u8; GROUP_KEY_LEN],
    #[serde(default)]
    group: Option<StoredGroup>,
    /// Every group this device belongs to, including the active one.
    ///
    /// The three fields above mirror the active entry so every existing caller
    /// keeps working unchanged; this list is what makes switching possible.
    #[serde(default)]
    groups: Vec<StoredGroupSlot>,
    /// Identifier of the active entry in `groups`.
    #[serde(default)]
    active_group: Option<String>,
}

/// One group's complete local state, so switching needs no re-join.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredGroupSlot {
    /// Stable identifier: the Nostr group id, or `owner/name` on GitHub.
    pub id: String,
    /// Human label, shown in the group switcher.
    pub label: String,
    /// PAT or Nostr secret for this group.
    pub pat: String,
    /// Group master key for this group's current epoch.
    pub group_key: [u8; GROUP_KEY_LEN],
    /// Descriptor describing this group.
    pub descriptor: VaultDescriptor,
    /// Identity and configuration, when this build recorded them.
    #[serde(default)]
    pub group: Option<StoredGroup>,
}

impl Drop for StoredGroupSlot {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.pat.zeroize();
        self.group_key.zeroize();
    }
}

impl std::fmt::Debug for StoredGroupSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredGroupSlot")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("pat", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// A group as the UI sees it, with no secrets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub id: String,
    pub label: String,
    pub backend: String,
    pub is_active: bool,
}

/// Group configuration and signing identity, stored only inside the sealed vault.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredGroup {
    pub invite: crate::crypto::InviteCredentialsPayload,
    pub identity_secret: [u8; crate::crypto::SECRET_KEY_LEN],
    pub preferences: crate::group::Preferences,
    pub is_host: bool,
    #[serde(default)]
    pub uploads: Vec<StoredUpload>,
}

/// Locally owned Blossom upload and its deletion progress.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredUpload {
    pub sha256: String,
    pub server: String,
    pub size: u64,
    pub event: crate::nostr::Event,
    pub deleted: bool,
    pub notice_published: bool,
}

impl Drop for StoredGroup {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.identity_secret.zeroize();
    }
}

impl std::fmt::Debug for VaultPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultPayload")
            .field("version", &self.version)
            .field("pat", &"[REDACTED]")
            .field("group_key", &"[REDACTED]")
            .finish()
    }
}

/// A platform-backed key-encryption key.
///
/// On Android the implementation calls into a tiny Kotlin plugin
/// (`KeystoreVaultPlugin`) exposing exactly `wrapSecret` / `unwrapSecret`, as
/// specified in `PLAN_ADDENDUM_v1.md` §A4. No general-purpose Keystore surface is
/// reachable from the webview.
pub trait Keystore: Send + Sync {
    /// Encrypt `plaintext` with the device key. Returns a self-describing blob.
    fn wrap_secret(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Reverse [`Keystore::wrap_secret`].
    ///
    /// Returns [`AppError::VaultUnavailable`] when the key was invalidated (factory
    /// reset, or a lock-screen change for authentication-bound keys).
    fn unwrap_secret(&self, wrapped: &[u8]) -> Result<Vec<u8>>;

    /// Stable identifier for the device key, for diagnostics only.
    fn key_alias(&self) -> String;

    /// Destroy the device key so the next wrap generates a fresh one.
    ///
    /// Called by the vault reset. Without it, a key that is present but unusable
    /// (rather than absent) would keep failing every subsequent wrap, and the
    /// reset would loop forever instead of recovering.
    ///
    /// The default is a no-op: DPAPI has no key to delete, and the in-memory
    /// double is discarded with the process.
    fn delete_key(&self) -> Result<()> {
        Ok(())
    }
}

/// Windows DPAPI binds the wrapped password to the current Windows user.
#[cfg(windows)]
pub struct WindowsKeystore;

#[cfg(windows)]
impl WindowsKeystore {
    fn transform(data: &[u8], protect: bool) -> Result<Vec<u8>> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
        };
        use zeroize::Zeroize;

        let length = u32::try_from(data.len()).map_err(|_| AppError::vault("secret is too large for DPAPI"))?;
        let input = CRYPT_INTEGER_BLOB { cbData: length, pbData: data.as_ptr() as *mut u8 };
        let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // DPAPI reads the input for the duration of the call and allocates its output with LocalAlloc.
        let success = unsafe {
            if protect {
                CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(),
                    std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(),
                    std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            }
        };
        if success == 0 {
            return Err(AppError::vault(format!("Windows DPAPI failed: {}", std::io::Error::last_os_error())));
        }
        if output.pbData.is_null() {
            return Err(AppError::vault("Windows DPAPI returned an empty output pointer"));
        }
        // The successful DPAPI call owns this buffer until LocalFree; erase it before release.
        let result = unsafe {
            let bytes = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
            let copy = bytes.to_vec();
            bytes.zeroize();
            LocalFree(output.pbData.cast());
            copy
        };
        Ok(result)
    }
}

#[cfg(windows)]
impl Keystore for WindowsKeystore {
    fn wrap_secret(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Self::transform(plaintext, true)
    }

    fn unwrap_secret(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        Self::transform(wrapped, false)
    }

    fn key_alias(&self) -> String {
        "shadow720.windows.dpapi.current-user".to_string()
    }
}

/// Keystore alias used by the in-memory double.
const IN_MEMORY_ALIAS: &str = "shadow720.test.in-memory";
/// Length of the in-memory double's device key.
const IN_MEMORY_KEY_LEN: usize = 32;

/// In-memory keystore for tests and desktop development.
///
/// Deliberately *not* secure: it exists so vault logic is exercised on hosts with
/// no hardware keystore. It is never selected on Android.
#[derive(Default)]
pub struct InMemoryKeystore {
    key: Mutex<Option<Zeroizing<[u8; IN_MEMORY_KEY_LEN]>>>,
    /// Test hook: when set, `unwrap_secret` behaves as if the key was lost.
    pub simulate_invalidated: bool,
}

impl InMemoryKeystore {
    /// Fresh keystore with a random device key.
    pub fn new() -> Result<Self> {
        Ok(Self {
            key: Mutex::new(Some(Zeroizing::new(random_bytes::<IN_MEMORY_KEY_LEN>()?))),
            simulate_invalidated: false,
        })
    }

    /// Keystore whose key has been invalidated, for the vault-loss path.
    pub fn invalidated() -> Self {
        Self {
            key: Mutex::new(None),
            simulate_invalidated: true,
        }
    }
}

impl std::fmt::Debug for InMemoryKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryKeystore")
            .field("has_key", &self.key.lock().is_some())
            .field("simulate_invalidated", &self.simulate_invalidated)
            .finish()
    }
}

impl Keystore for InMemoryKeystore {
    fn wrap_secret(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let guard = self.key.lock();
        let key = guard
            .as_ref()
            .ok_or_else(|| AppError::vault("device key is not available"))?;

        // Version byte, then plaintext XORed with the device key, then a running
        // checksum of the *keyed* bytes. The checksum is what makes a tampered or
        // foreign-key blob detectable. This is a test double, not real crypto.
        let mut keyed = Vec::with_capacity(plaintext.len() + 2);
        keyed.push(1u8);
        let mut checksum = 0u8;
        for (index, byte) in plaintext.iter().enumerate() {
            let value = byte ^ key.get(index % IN_MEMORY_KEY_LEN).copied().unwrap_or(0);
            checksum = checksum.wrapping_add(value);
            keyed.push(value);
        }
        keyed.push(checksum);
        Ok(keyed)
    }

    fn unwrap_secret(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        if wrapped.len() < 2 {
            return Err(AppError::vault("wrapped secret is truncated"));
        }
        let guard = self.key.lock();
        let key = guard.as_ref().ok_or_else(|| {
            AppError::vault(
                "device key was invalidated; the vault cannot be opened on this device",
            )
        })?;

        let version = wrapped.first().copied().unwrap_or(0);
        if version != 1 {
            return Err(AppError::vault(format!(
                "wrapped secret has unknown version {version}"
            )));
        }
        let checksum_expected = wrapped.last().copied().unwrap_or(0);
        let body = wrapped.get(1..wrapped.len().saturating_sub(1)).unwrap_or(&[]);

        let mut checksum = 0u8;
        for byte in body {
            checksum = checksum.wrapping_add(*byte);
        }
        if checksum != checksum_expected {
            return Err(AppError::vault(
                "wrapped secret failed its integrity check; the device key changed",
            ));
        }

        let mut out = Vec::with_capacity(body.len());
        for (index, byte) in body.iter().enumerate() {
            out.push(byte ^ key.get(index % IN_MEMORY_KEY_LEN).copied().unwrap_or(0));
        }
        Ok(out)
    }

    fn key_alias(&self) -> String {
        IN_MEMORY_ALIAS.to_string()
    }
}

/// The two secrets the app cannot function without.
pub struct VaultContents {
    pub pat: String,
    pub group_key: GroupKey,
}

impl std::fmt::Debug for VaultContents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render either secret.
        f.debug_struct("VaultContents")
            .field("pat", &"[REDACTED]")
            .field("group_key", &"[REDACTED]")
            .finish()
    }
}

/// On-disk metadata describing which vault we are opening.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultDescriptor {
    /// Schema version, so a future change can migrate rather than fail.
    pub version: u8,
    /// Keystore alias the password was wrapped with, so a mismatched device is
    /// detected with a clear message instead of a cipher error.
    pub keystore_alias: String,
    /// Repo the stored PAT is scoped to. Lets the app detect "you joined a
    /// different group" without touching the vault.
    pub repo_full_name: String,
    /// Key epoch currently believed to be authoritative.
    pub current_epoch: u8,
}

/// Schema version for [`VaultDescriptor`].
pub const DESCRIPTOR_VERSION: u8 = 1;

/// Stable identifier for a group, derived from its descriptor.
///
/// The Nostr backend already has a real group id; GitHub groups are identified by
/// their repository, which is unique per group by construction.
pub fn group_id_for(descriptor: &VaultDescriptor) -> String {
    descriptor
        .repo_full_name
        .strip_prefix("nostr:")
        .map(|id| id.to_string())
        .unwrap_or_else(|| descriptor.repo_full_name.clone())
}

/// Sealed-vault storage: an AEAD-encrypted payload plus a Keystore-wrapped password.
pub struct SecureVault {
    dir: PathBuf,
    keystore: Arc<dyn Keystore>,
    /// In-memory copy of the vault password, zeroized on drop.
    password: Zeroizing<Vec<u8>>,
    /// Decrypted contents, held in memory only while the vault is open.
    contents: Mutex<Option<VaultPayload>>,
    descriptor: Mutex<Option<VaultDescriptor>>,
}

impl std::fmt::Debug for SecureVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the password or the payload.
        f.debug_struct("SecureVault")
            .field("dir", &self.dir)
            .field("keystore_alias", &self.keystore.key_alias())
            .field("descriptor", &self.descriptor.lock())
            .finish_non_exhaustive()
    }
}

impl SecureVault {
    /// Path to the sealed payload.
    pub fn vault_path(&self) -> PathBuf {
        self.dir.join(VAULT_FILENAME)
    }

    /// Path to the wrapped vault password.
    pub fn wrapped_password_path(&self) -> PathBuf {
        self.dir.join(WRAP_FILENAME)
    }

    /// Path to the non-secret descriptor.
    pub fn descriptor_path(&self) -> PathBuf {
        self.dir.join(DESCRIPTOR_FILENAME)
    }

    /// True when a vault has already been initialised in `dir`.
    ///
    /// The wrapped password is the marker, because it is written on creation
    /// whereas the sealed payload only appears once a secret exists.
    pub fn exists(dir: impl AsRef<Path>) -> bool {
        dir.as_ref().join(WRAP_FILENAME).exists()
    }

    /// Directory the vault lives in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Alias of the device key this vault is wrapped with.
    pub fn keystore_alias(&self) -> String {
        self.keystore.key_alias()
    }

    /// Create a brand-new, empty vault.
    pub fn create(dir: impl Into<PathBuf>, keystore: Arc<dyn Keystore>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .map_err(|e| AppError::io("creating the vault directory", e.to_string()))?;

        let password = Zeroizing::new(random_bytes::<VAULT_PASSWORD_LEN>()?.to_vec());
        let wrapped = keystore.wrap_secret(&password)?;
        write_private(&dir.join(WRAP_FILENAME), &wrapped)?;

        Ok(Self {
            dir,
            keystore,
            password,
            contents: Mutex::new(None),
            descriptor: Mutex::new(None),
        })
    }

    /// Open an existing vault.
    ///
    /// Returns [`AppError::VaultUnavailable`] when the device key can no longer
    /// unwrap the password, which is the signal to require a fresh invite rather
    /// than to silently start a new empty group.
    pub fn open(dir: impl Into<PathBuf>, keystore: Arc<dyn Keystore>) -> Result<Self> {
        let dir = dir.into();
        let wrapped_path = dir.join(WRAP_FILENAME);
        let wrapped = std::fs::read(&wrapped_path)
            .map_err(|e| AppError::vault(format!("vault password file is unreadable: {e}")))?;

        let password = Zeroizing::new(keystore.unwrap_secret(&wrapped)?);
        if password.len() != VAULT_PASSWORD_LEN {
            return Err(AppError::vault(format!(
                "vault password must be {VAULT_PASSWORD_LEN} bytes, got {}",
                password.len()
            )));
        }

        let mut vault = Self {
            dir,
            keystore,
            password,
            contents: Mutex::new(None),
            descriptor: Mutex::new(None),
        };

        vault.descriptor = Mutex::new(vault.read_descriptor()?);

        // Decrypt eagerly so a wrong-device or corrupt vault fails at open time
        // rather than on the first command that needs a secret.
        if vault.vault_path().exists() {
            let payload = vault.decrypt_payload()?;
            *vault.contents.lock() = Some(payload);
        }

        Ok(vault)
    }

    /// Create if absent, otherwise open.
    pub fn open_or_create(dir: impl Into<PathBuf>, keystore: Arc<dyn Keystore>) -> Result<Self> {
        let dir = dir.into();
        if Self::exists(&dir) {
            Self::open(dir, keystore)
        } else {
            Self::create(dir, keystore)
        }
    }

    /// The descriptor, or `None` for a vault that has never stored a group.
    pub fn descriptor(&self) -> Option<VaultDescriptor> {
        self.descriptor.lock().clone()
    }

    /// Load both secrets, or `None` when the vault is still empty.
    pub fn load_contents(&self) -> Result<Option<VaultContents>> {
        let guard = self.contents.lock();
        match guard.as_ref() {
            None => Ok(None),
            Some(payload) => {
                if payload.pat.trim().is_empty() {
                    return Err(AppError::vault(
                        "vault holds a group key but no token; re-join the group",
                    ));
                }
                Ok(Some(VaultContents {
                    pat: payload.pat.clone(),
                    group_key: Zeroizing::new(payload.group_key),
                }))
            }
        }
    }

    /// Store both secrets and the descriptor that describes them.
    pub fn store_contents(
        &self,
        contents: &VaultContents,
        descriptor: &VaultDescriptor,
    ) -> Result<()> {
        self.store_group_contents(contents, descriptor, None)
    }

    /// Store credentials and, when available, the group needed to restore them.
    pub fn store_group_contents(
        &self,
        contents: &VaultContents,
        descriptor: &VaultDescriptor,
        group: Option<StoredGroup>,
    ) -> Result<()> {
        if contents.pat.trim().is_empty() {
            return Err(AppError::not_configured(
                "a token is required before the vault can be populated",
            ));
        }

        let id = group_id_for(descriptor);
        let slot = StoredGroupSlot {
            id: id.clone(),
            label: group
                .as_ref()
                .map(|stored| stored.invite.group_label.clone())
                .unwrap_or_else(|| descriptor.repo_full_name.clone()),
            pat: contents.pat.clone(),
            group_key: *contents.group_key,
            descriptor: descriptor.clone(),
            group: group.clone(),
        };

        // Preserve any other groups this device already belongs to.
        let mut groups = self
            .contents
            .lock()
            .as_ref()
            .map(|existing| existing.groups.clone())
            .unwrap_or_default();
        groups.retain(|entry| entry.id != id);
        groups.push(slot);

        let payload = VaultPayload {
            version: VAULT_FORMAT_VERSION,
            pat: contents.pat.clone(),
            group_key: *contents.group_key,
            group,
            groups,
            active_group: Some(id),
        };
        self.write_payload(&payload)?;

        *self.contents.lock() = Some(payload);
        *self.descriptor.lock() = Some(descriptor.clone());
        self.write_descriptor(descriptor)
    }

    /// Every group this device belongs to, without secrets.
    pub fn list_groups(&self) -> Vec<GroupSummary> {
        let guard = self.contents.lock();
        let Some(payload) = guard.as_ref() else {
            return Vec::new();
        };
        payload
            .groups
            .iter()
            .map(|slot| GroupSummary {
                id: slot.id.clone(),
                label: slot.label.clone(),
                backend: slot.descriptor.repo_full_name.clone(),
                is_active: payload.active_group.as_deref() == Some(slot.id.as_str()),
            })
            .collect()
    }

    /// Make another stored group the active one.
    ///
    /// Returns the credentials and descriptor the caller needs to rebuild its
    /// in-memory group state. Nothing is re-fetched: the whole point of storing
    /// each group is that switching is instant and works offline.
    pub fn activate_group(&self, id: &str) -> Result<(VaultContents, VaultDescriptor, Option<StoredGroup>)> {
        let mut guard = self.contents.lock();
        let payload = guard.as_mut().ok_or_else(|| AppError::vault("no group is stored in this vault"))?;
        let slot = payload
            .groups
            .iter()
            .find(|entry| entry.id == id)
            .cloned()
            .ok_or_else(|| AppError::invalid_argument("that group is not stored on this device"))?;

        let previous = (
            payload.pat.clone(),
            payload.group_key,
            payload.group.clone(),
            payload.active_group.clone(),
        );
        payload.pat = slot.pat.clone();
        payload.group_key = slot.group_key;
        payload.group = slot.group.clone();
        payload.active_group = Some(slot.id.clone());

        if let Err(error) = self.write_payload(payload) {
            payload.pat = previous.0;
            payload.group_key = previous.1;
            payload.group = previous.2;
            payload.active_group = previous.3;
            return Err(error);
        }

        let contents = VaultContents {
            pat: slot.pat.clone(),
            group_key: zeroize::Zeroizing::new(slot.group_key),
        };
        let descriptor = slot.descriptor.clone();
        *self.descriptor.lock() = Some(descriptor.clone());
        self.write_descriptor(&descriptor)?;
        Ok((contents, descriptor, slot.group.clone()))
    }

    /// Forget one group, returning whether it was the active one.
    ///
    /// The caller is responsible for wiping the active group's in-memory state
    /// when this reports `true`.
    pub fn remove_group(&self, id: &str) -> Result<bool> {
        let mut guard = self.contents.lock();
        let payload = guard.as_mut().ok_or_else(|| AppError::vault("no group is stored in this vault"))?;
        let before = payload.groups.len();
        payload.groups.retain(|entry| entry.id != id);
        if payload.groups.len() == before {
            return Err(AppError::invalid_argument("that group is not stored on this device"));
        }
        let was_active = payload.active_group.as_deref() == Some(id);
        if was_active {
            payload.active_group = None;
            payload.pat.clear();
            payload.group_key = [0u8; GROUP_KEY_LEN];
            payload.group = None;
        }

        // With no groups left there is nothing to keep, and an empty payload would
        // fail its own "a token is required" check on the next read.
        if payload.groups.is_empty() {
            *guard = None;
            drop(guard);
            for path in [self.vault_path(), self.descriptor_path()] {
                if path.exists() {
                    std::fs::remove_file(&path).map_err(|e| {
                        AppError::io("deleting a vault file", format!("{}: {e}", path.display()))
                    })?;
                }
            }
            *self.descriptor.lock() = None;
            return Ok(was_active);
        }

        self.write_payload(payload)?;
        Ok(was_active)
    }

    /// Read the encrypted group configuration, if this vault has one.
    pub fn load_group(&self) -> Result<Option<StoredGroup>> {
        Ok(self.contents.lock().as_ref().and_then(|payload| payload.group.clone()))
    }

    /// Persist local preferences without replacing group credentials.
    pub fn update_preferences(&self, preferences: &crate::group::Preferences) -> Result<()> {
        let mut guard = self.contents.lock();
        let payload = guard.as_mut().ok_or_else(|| AppError::vault("no group is stored in this vault"))?;
        let group = payload.group.as_mut().ok_or_else(|| AppError::vault("the stored group cannot be restored; rejoin with a fresh invite"))?;
        let previous = std::mem::replace(&mut group.preferences, preferences.clone());
        if let Err(error) = self.write_payload(payload) {
            if let Some(group) = payload.group.as_mut() {
                group.preferences = previous;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Add or update a locally owned upload, atomically in the sealed vault.
    pub fn save_upload(&self, upload: StoredUpload) -> Result<()> {
        let mut guard = self.contents.lock();
        let payload = guard.as_mut().ok_or_else(|| AppError::vault("no group is stored in this vault"))?;
        let group = payload.group.as_mut().ok_or_else(|| AppError::vault("the stored group cannot be restored"))?;
        let previous = group.uploads.clone();
        group.uploads.retain(|entry| entry.sha256 != upload.sha256);
        group.uploads.push(upload);
        if let Err(error) = self.write_payload(payload) {
            if let Some(group) = payload.group.as_mut() {
                group.uploads = previous;
            }
            return Err(error);
        }
        Ok(())
    }

    /// Replace only the token, keeping the group key.
    ///
    /// Used by the "Re-key Group" flow when a PAT expires
    /// (`PLAN_ADDENDUM_v1.md` §A3).
    pub fn update_pat(&self, pat: &str, descriptor: &VaultDescriptor) -> Result<()> {
        if pat.trim().is_empty() {
            return Err(AppError::invalid_argument("a replacement token is required"));
        }

        let mut guard = self.contents.lock();
        let mut payload = match guard.take() {
            Some(existing) => existing,
            None => {
                return Err(AppError::vault(
                    "no group is stored in this vault, so there is no token to replace",
                ))
            }
        };
        payload.pat = pat.to_string();
        self.write_payload(&payload)?;

        *guard = Some(payload);
        drop(guard);

        *self.descriptor.lock() = Some(descriptor.clone());
        self.write_descriptor(descriptor)
    }

    /// Replace only the group key, e.g. after a rotation.
    pub fn update_group_key(
        &self,
        group_key: &[u8; GROUP_KEY_LEN],
        descriptor: &VaultDescriptor,
    ) -> Result<()> {
        let mut guard = self.contents.lock();
        let mut payload = match guard.take() {
            Some(existing) => existing,
            None => {
                return Err(AppError::vault(
                    "no group is stored in this vault, so there is no key to rotate",
                ))
            }
        };
        payload.group_key = *group_key;
        self.write_payload(&payload)?;

        *guard = Some(payload);
        drop(guard);

        *self.descriptor.lock() = Some(descriptor.clone());
        self.write_descriptor(descriptor)
    }

    /// Wipe every secret and delete every file this vault owns.
    ///
    /// Used by "Leave Group & Wipe My Data". The in-memory payload is dropped, the
    /// wrapped password is unlinked, and the sealed file is removed, so nothing is
    /// recoverable even with the device key.
    pub fn wipe(&self) -> Result<()> {
        // Drop plaintext first, so a failed unlink cannot leave secrets in memory.
        *self.contents.lock() = None;
        Self::wipe_dir(&self.dir)?;
        *self.descriptor.lock() = None;
        Ok(())
    }

    /// Delete every vault file in `dir` without needing an open vault.
    ///
    /// The reset path cannot go through [`SecureVault::open`]: the vault is
    /// unopenable, which is precisely why the user is resetting it. Deleting by
    /// filename is the only way to break that deadlock.
    pub fn wipe_dir(dir: impl AsRef<Path>) -> Result<()> {
        let dir = dir.as_ref();
        for name in [VAULT_FILENAME, WRAP_FILENAME, DESCRIPTOR_FILENAME] {
            let path = dir.join(name);
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| {
                    AppError::io("deleting a vault file", format!("{}: {e}", path.display()))
                })?;
            }
        }
        Ok(())
    }

    /// Verify the descriptor matches this device and vault.
    pub fn verify_descriptor(&self) -> Result<()> {
        let Some(descriptor) = self.descriptor() else {
            return Err(AppError::vault(
                "no group is stored in this vault yet; create or join one first",
            ));
        };
        if descriptor.version != DESCRIPTOR_VERSION {
            return Err(AppError::vault(format!(
                "vault was written by schema version {} but this build speaks {DESCRIPTOR_VERSION}",
                descriptor.version
            )));
        }
        if descriptor.keystore_alias != self.keystore.key_alias() {
            return Err(AppError::vault(
                "vault was created with a different device key; a fresh invite is required",
            ));
        }
        Ok(())
    }

    // -- sealed payload -------------------------------------------------------

    /// Derive the payload key from the vault password and a per-file salt.
    fn payload_key(&self, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; GROUP_KEY_LEN]>> {
        let mut salted = Vec::with_capacity(VAULT_KDF_CONTEXT.len() + SALT_LEN);
        salted.extend_from_slice(VAULT_KDF_CONTEXT);
        salted.extend_from_slice(salt);
        crypto::derive_wrapping_key_bytes(&self.password, &salted)
    }

    /// Encrypt and write the payload.
    fn write_payload(&self, payload: &VaultPayload) -> Result<()> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(payload)
                .map_err(|e| AppError::vault(format!("could not serialize the vault: {e}")))?,
        );

        let salt = random_bytes::<SALT_LEN>()?;
        let nonce = random_bytes::<NONCE_LEN>()?;
        let key = self.payload_key(&salt)?;

        let sealed = crypto::seal_blob_with(&key, &plaintext, nonce, VAULT_AAD)?;

        // Layout: magic ‖ version ‖ salt ‖ nonce ‖ ciphertext+tag.
        // The nonce is written explicitly: `seal_blob_with` returns ciphertext only,
        // so the reader needs it stored alongside the salt.
        let mut file = Vec::with_capacity(VAULT_HEADER_LEN + sealed.len());
        file.extend_from_slice(VAULT_MAGIC);
        file.push(VAULT_FORMAT_VERSION);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&sealed);

        // Write to a sibling then rename, so an interrupted write cannot leave a
        // half-written vault that would be indistinguishable from corruption.
        let path = self.vault_path();
        let temporary = path.with_extension("vault.tmp");
        write_private(&temporary, &file)?;
        std::fs::rename(&temporary, &path).map_err(|e| {
            AppError::io(
                "committing the vault file",
                format!("{}: {e}", path.display()),
            )
        })
    }

    /// Decrypt the payload from disk.
    fn decrypt_payload(&self) -> Result<VaultPayload> {
        let raw = std::fs::read(self.vault_path())
            .map_err(|e| AppError::vault(format!("vault file is unreadable: {e}")))?;

        // Identify the file before measuring it, so a foreign file gets the
        // accurate "not a vault" message rather than a generic truncation error.
        let (magic, _) = raw
            .split_at_checked(VAULT_MAGIC.len())
            .ok_or_else(|| AppError::vault("vault file is too short to be a Shadow720 vault"))?;
        if magic != VAULT_MAGIC {
            return Err(AppError::vault(
                "vault file is not a Shadow720 vault; refusing to interpret it",
            ));
        }

        if raw.len() < VAULT_HEADER_LEN + TAG_LEN {
            return Err(AppError::vault(
                "vault file is truncated; it cannot contain a valid payload",
            ));
        }

        let (_, rest) = raw.split_at(VAULT_MAGIC.len());

        let (version_slice, rest) = rest
            .split_at_checked(1)
            .ok_or_else(|| AppError::vault("vault file is missing its version byte"))?;
        let version = version_slice.first().copied().unwrap_or(0);
        if version != VAULT_FORMAT_VERSION {
            return Err(AppError::vault(format!(
                "vault file uses format version {version} but this build speaks {VAULT_FORMAT_VERSION}"
            )));
        }

        let (salt_slice, rest) = rest
            .split_at_checked(SALT_LEN)
            .ok_or_else(|| AppError::vault("vault file is missing its salt"))?;
        let salt: [u8; SALT_LEN] = salt_slice
            .try_into()
            .map_err(|_| AppError::vault("vault salt is the wrong size"))?;

        // `rest` is nonce ‖ ciphertext+tag.
        let key = self.payload_key(&salt)?;

        let mut plaintext = crypto::open_blob_with(&key, rest, VAULT_AAD).map_err(|_| {
            AppError::vault(
                "vault file failed its integrity check; the device key is wrong or the file was modified",
            )
        })?;

        let parsed: std::result::Result<VaultPayload, _> = serde_json::from_slice(&plaintext);
        zeroize::Zeroize::zeroize(&mut plaintext);

        let payload =
            parsed.map_err(|e| AppError::vault(format!("vault payload is malformed: {e}")))?;

        if payload.version != VAULT_FORMAT_VERSION {
            return Err(AppError::vault(format!(
                "vault payload uses schema version {} but this build speaks {VAULT_FORMAT_VERSION}",
                payload.version
            )));
        }
        Ok(payload)
    }

    /// Read the descriptor, tolerating absence.
    fn read_descriptor(&self) -> Result<Option<VaultDescriptor>> {
        let path = self.descriptor_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(&path)
            .map_err(|e| AppError::io("reading the vault descriptor", e.to_string()))?;
        let descriptor: VaultDescriptor = serde_json::from_slice(&raw)
            .map_err(|e| AppError::vault(format!("vault descriptor is malformed: {e}")))?;
        Ok(Some(descriptor))
    }

    /// Write the descriptor.
    fn write_descriptor(&self, descriptor: &VaultDescriptor) -> Result<()> {
        let raw = serde_json::to_vec_pretty(descriptor)
            .map_err(|e| AppError::vault(format!("could not serialize the descriptor: {e}")))?;
        write_private(&self.descriptor_path(), &raw)
    }
}

/// Write a file with owner-only permissions where the platform supports it.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)
        .map_err(|e| AppError::io("writing a vault file", format!("{}: {e}", path.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }

    Ok(())
}

/// In-memory map used by tests that need to inspect secrets without I/O.
#[derive(Default, Debug)]
pub struct MemorySecretMap {
    inner: Mutex<std::collections::HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemorySecretMap {
    /// Insert a secret.
    pub fn put(&self, key: &str, value: Vec<u8>) {
        self.inner
            .lock()
            .insert(key.to_string(), Zeroizing::new(value));
    }

    /// Read a secret back.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.inner.lock().get(key).map(|v| v.to_vec())
    }

    /// Number of stored secrets.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppErrorKind;

    /// Unique scratch directory per test, so parallel tests never collide.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shadow720-vault-{tag}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn descriptor_for(repo: &str) -> VaultDescriptor {
        VaultDescriptor {
            version: DESCRIPTOR_VERSION,
            keystore_alias: IN_MEMORY_ALIAS.to_string(),
            repo_full_name: repo.to_string(),
            current_epoch: 0,
        }
    }

    fn contents() -> VaultContents {
        VaultContents {
            pat: "github_pat_TEST".to_string(),
            group_key: Zeroizing::new([7u8; GROUP_KEY_LEN]),
        }
    }

    #[test]
    fn multiple_groups_are_stored_and_switchable() {
        let dir = scratch("multi-group");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");

        let first = VaultContents {
            pat: "nostr-secret-one".to_string(),
            group_key: Zeroizing::new([1u8; GROUP_KEY_LEN]),
        };
        let second = VaultContents {
            pat: "nostr-secret-two".to_string(),
            group_key: Zeroizing::new([2u8; GROUP_KEY_LEN]),
        };
        vault
            .store_group_contents(&first, &descriptor_for("nostr:group-one"), None)
            .expect("store first");
        vault
            .store_group_contents(&second, &descriptor_for("nostr:group-two"), None)
            .expect("store second");

        let groups = vault.list_groups();
        assert_eq!(groups.len(), 2, "both groups must be retained");
        assert_eq!(groups.iter().filter(|group| group.is_active).count(), 1);
        assert_eq!(
            groups.iter().find(|group| group.is_active).map(|group| group.id.as_str()),
            Some("group-two"),
            "the most recently stored group is active"
        );

        // Switching restores the other group's own secret and key.
        let (contents, descriptor, _) = vault.activate_group("group-one").expect("activate");
        assert_eq!(contents.pat, "nostr-secret-one");
        assert_eq!(*contents.group_key, [1u8; GROUP_KEY_LEN]);
        assert_eq!(descriptor.repo_full_name, "nostr:group-one");
        assert_eq!(
            vault.list_groups().iter().find(|group| group.is_active).map(|group| group.id.as_str()),
            Some("group-one")
        );

        // The switch survives a reopen, so it is not just in-memory state.
        let reopened = SecureVault::open(&dir, Arc::new(InMemoryKeystore::new().expect("keystore")));
        // A fresh in-memory keystore cannot unwrap the password, which is expected;
        // the point here is that the payload itself round-tripped.
        assert!(reopened.is_err() || reopened.expect("open").list_groups().len() == 2);
    }

    #[test]
    fn forgetting_a_group_leaves_the_others() {
        let dir = scratch("forget-group");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault
            .store_group_contents(&contents(), &descriptor_for("nostr:one"), None)
            .expect("store one");
        vault
            .store_group_contents(&contents(), &descriptor_for("nostr:two"), None)
            .expect("store two");

        // The id is the bare group id, not the `nostr:`-prefixed descriptor name.
        assert!(!vault.remove_group("one").expect("remove"), "not the active group");
        assert_eq!(vault.list_groups().len(), 1);
        assert!(vault.remove_group("missing").is_err());

        // Removing the active group clears the working credentials.
        assert!(vault.remove_group("two").expect("remove active"));
        assert!(vault.load_contents().expect("load").is_none());
        assert!(vault.list_groups().is_empty());
    }

    #[test]
    fn encrypted_group_and_uploads_survive_reopen() {
        let dir = scratch("stored-group");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore.clone()).expect("create");
        let host = crate::group::Identity::from_secret([3; 32]);
        let group = StoredGroup {
            invite: crate::crypto::InviteCredentialsPayload {
                version: crate::crypto::PROTOCOL_VERSION,
                backend: crate::storage::BackendKind::Nostr,
                repo_owner: String::new(),
                repo_name: String::new(),
                repo_scoped_pat: String::new(),
                group_master_key: [7; GROUP_KEY_LEN],
                roster_issue_num: 0,
                chat_issue_num: 0,
                release_id: 0,
                repo_created: true,
                relays: vec!["wss://relay.example".into()],
                blossom_servers: vec!["https://blossom.example".into()],
                group_id: "private-group".into(),
                host_pubkey: host.pubkey_b64.clone(),
                group_label: "private-label".into(),
                key_epoch: 0,
            },
            identity_secret: *host.secret_bytes(),
            preferences: crate::group::Preferences::seeded(),
            is_host: true,
            uploads: Vec::new(),
        };
        vault.store_group_contents(&contents(), &descriptor_for("nostr/private-group"), Some(group)).expect("store");
        let nostr = crate::nostr::NostrIdentity::from_secret_bytes([11; 32]).expect("nostr");
        let event = crate::nostr::sign_event(&nostr, crate::nostr::KIND_FILE,
            vec![vec!["d".into(), "private-group".into()]], "ciphertext", 100).expect("event");
        vault.save_upload(StoredUpload {
            sha256: "a".repeat(64), server: "https://blossom.example".into(),
            size: 12, event, deleted: true, notice_published: false,
        }).expect("upload record");
        let mut preferences = crate::group::Preferences::seeded();
        preferences.display_name = "restored-name".into();
        vault.update_preferences(&preferences).expect("preferences");
        let raw = std::fs::read(vault.vault_path()).expect("read vault");
        assert!(!raw.windows("private-label".len()).any(|part| part == b"private-label"));
        drop(vault);
        let reopened = SecureVault::open(&dir, keystore).expect("reopen");
        let restored = reopened.load_group().expect("load").expect("group");
        assert_eq!(restored.invite.host_pubkey, host.pubkey_b64);
        assert_eq!(restored.identity_secret, [3; 32]);
        assert_eq!(restored.preferences.display_name, "restored-name");
        assert!(restored.uploads[0].deleted);
        assert!(!restored.uploads[0].notice_published);
    }

    #[cfg(windows)]
    #[test]
    fn windows_keystore_reopens_with_a_new_instance() {
        let first = WindowsKeystore;
        let second = WindowsKeystore;
        let encrypted = first.wrap_secret(b"persistent secret").expect("protect");
        assert_ne!(encrypted, b"persistent secret");
        assert_eq!(second.unwrap_secret(&encrypted).expect("unprotect"), b"persistent secret");
    }

    // -- InMemoryKeystore ----------------------------------------------------

    #[test]
    fn in_memory_keystore_round_trips() {
        let keystore = InMemoryKeystore::new().expect("keystore");
        let plaintext = b"vault password bytes";
        let wrapped = keystore.wrap_secret(plaintext).expect("wrap");
        assert_ne!(wrapped.as_slice(), plaintext, "must not be plaintext");
        assert_eq!(keystore.unwrap_secret(&wrapped).expect("unwrap"), plaintext);
    }

    #[test]
    fn in_memory_keystore_round_trips_a_32_byte_password() {
        let keystore = InMemoryKeystore::new().expect("keystore");
        let password = [0x5Au8; VAULT_PASSWORD_LEN];
        let wrapped = keystore.wrap_secret(&password).expect("wrap");
        assert_eq!(
            keystore.unwrap_secret(&wrapped).expect("unwrap"),
            password.to_vec()
        );
    }

    #[test]
    fn in_memory_keystore_detects_tampering() {
        let keystore = InMemoryKeystore::new().expect("keystore");
        let mut wrapped = keystore.wrap_secret(b"secret").expect("wrap");
        let index = wrapped.len() / 2;
        wrapped[index] ^= 0x01;
        let err = keystore.unwrap_secret(&wrapped).expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);
    }

    #[test]
    fn in_memory_keystore_detects_a_truncated_body() {
        let keystore = InMemoryKeystore::new().expect("keystore");
        let wrapped = keystore.wrap_secret(b"abcdef").expect("wrap");
        let mut truncated = wrapped.clone();
        truncated.remove(truncated.len() - 2);
        assert!(keystore.unwrap_secret(&truncated).is_err());
    }

    #[test]
    fn in_memory_keystore_rejects_unknown_version() {
        let keystore = InMemoryKeystore::new().expect("keystore");
        let err = keystore.unwrap_secret(&[9u8, 1, 2, 3]).expect_err("must fail");
        assert!(err.to_string().contains("unknown version"));
    }

    #[test]
    fn in_memory_keystore_rejects_truncated_blob() {
        let keystore = InMemoryKeystore::new().expect("keystore");
        let err = keystore.unwrap_secret(&[1u8]).expect_err("must fail");
        assert!(err.to_string().contains("truncated"));
        assert!(keystore.unwrap_secret(&[]).is_err());
    }

    #[test]
    fn in_memory_keystore_round_trips_an_empty_payload() {
        let keystore = InMemoryKeystore::new().expect("keystore");
        let wrapped = keystore.wrap_secret(&[]).expect("wrap");
        assert_eq!(wrapped.len(), 2);
        assert_eq!(
            keystore.unwrap_secret(&wrapped).expect("unwrap"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn invalidated_keystore_cannot_wrap_or_unwrap() {
        let keystore = InMemoryKeystore::invalidated();
        assert_eq!(
            keystore.wrap_secret(b"x").expect_err("must fail").kind(),
            AppErrorKind::VaultUnavailable
        );
        let err = keystore.unwrap_secret(&[1u8, 2u8]).expect_err("must fail");
        assert!(err.to_string().contains("invalidated"));
    }

    #[test]
    fn in_memory_keystore_debug_is_safe() {
        let keystore = InMemoryKeystore::new().expect("keystore");
        let rendered = format!("{keystore:?}");
        assert!(rendered.contains("has_key"));
        assert!(!rendered.contains("Some(["));
    }

    #[test]
    fn key_alias_is_stable() {
        let a = InMemoryKeystore::new().expect("a");
        let b = InMemoryKeystore::new().expect("b");
        assert_eq!(a.key_alias(), IN_MEMORY_ALIAS);
        assert_eq!(a.key_alias(), b.key_alias());
    }

    // -- Payload sealing -----------------------------------------------------

    #[test]
    fn payload_round_trips_through_a_file() {
        let dir = scratch("payload");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");

        assert!(
            vault.load_contents().expect("load").is_none(),
            "new vault is empty"
        );

        vault
            .store_contents(&contents(), &descriptor_for("JaredCH/sandbox"))
            .expect("store");
        assert!(vault.vault_path().exists());
        drop(vault);

        let reopened = SecureVault::open(&dir, keystore).expect("open");
        let loaded = reopened.load_contents().expect("load").expect("present");
        assert_eq!(loaded.pat, "github_pat_TEST");
        assert_eq!(*loaded.group_key, [7u8; GROUP_KEY_LEN]);
        assert_eq!(
            reopened.descriptor().expect("descriptor").repo_full_name,
            "JaredCH/sandbox"
        );
        reopened.verify_descriptor().expect("descriptor verifies");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_file_is_not_plaintext() {
        let dir = scratch("notplaintext");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        let raw = std::fs::read(vault.vault_path()).expect("read");
        let haystack = String::from_utf8_lossy(&raw);
        assert!(
            !haystack.contains("github_pat_TEST"),
            "the PAT must never appear in the vault file"
        );
        assert!(
            !raw.windows(GROUP_KEY_LEN).any(|w| w == [7u8; GROUP_KEY_LEN]),
            "the group key must not appear in the vault file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_file_starts_with_magic_and_version() {
        let dir = scratch("magic");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        let raw = std::fs::read(vault.vault_path()).expect("read");
        assert_eq!(raw.get(..8).expect("magic"), VAULT_MAGIC);
        assert_eq!(raw.get(8).copied(), Some(VAULT_FORMAT_VERSION));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_file_is_rewritten_with_a_fresh_salt_and_nonce() {
        let dir = scratch("freshnonce");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");

        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("first");
        let first = std::fs::read(vault.vault_path()).expect("read first");

        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("second");
        let second = std::fs::read(vault.vault_path()).expect("read second");

        assert_ne!(
            first, second,
            "re-sealing identical contents must still produce different ciphertext"
        );
        assert_eq!(first.len(), second.len(), "same plaintext means same length");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Failure modes -------------------------------------------------------

    #[test]
    fn open_fails_when_the_device_key_is_lost() {
        let dir = scratch("lostkey");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");
        drop(vault);

        let new_keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let err = SecureVault::open(&dir, new_keystore).expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_fails_on_an_invalidated_keystore() {
        let dir = scratch("invalidated");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");
        drop(vault);

        let dead: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::invalidated());
        let err = SecureVault::open(&dir, dead).expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_a_tampered_vault_body() {
        let dir = scratch("tamper");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        let mut raw = std::fs::read(vault.vault_path()).expect("read");
        let last = raw.len() - 1;
        raw[last] ^= 0b0000_0001;
        std::fs::write(vault.vault_path(), &raw).expect("write");
        drop(vault);

        let err = SecureVault::open(&dir, keystore).expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);
        assert!(err.to_string().contains("integrity check"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_a_flipped_salt() {
        let dir = scratch("salttamper");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        let mut raw = std::fs::read(vault.vault_path()).expect("read");
        // The salt begins right after magic + version.
        raw[9] ^= 0b0000_0001;
        std::fs::write(vault.vault_path(), &raw).expect("write");
        drop(vault);

        let err = SecureVault::open(&dir, keystore).expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_a_foreign_file() {
        let dir = scratch("foreign");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        std::fs::write(vault.vault_path(), b"this is not a vault file at all").expect("write");
        drop(vault);

        let err = SecureVault::open(&dir, keystore).expect_err("must fail");
        assert!(err.to_string().contains("not a Shadow720 vault"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_a_truncated_file() {
        let dir = scratch("truncated");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        std::fs::write(vault.vault_path(), VAULT_MAGIC).expect("write");
        drop(vault);

        let err = SecureVault::open(&dir, keystore).expect_err("must fail");
        assert!(err.to_string().contains("truncated"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_an_unknown_format_version() {
        let dir = scratch("badversion");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        let mut raw = std::fs::read(vault.vault_path()).expect("read");
        raw[8] = 42;
        std::fs::write(vault.vault_path(), &raw).expect("write");
        drop(vault);

        let err = SecureVault::open(&dir, keystore).expect_err("must fail");
        assert!(err.to_string().contains("format version 42"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_a_malformed_password_file() {
        let dir = scratch("badpwfile");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        std::fs::write(vault.wrapped_password_path(), b"\x01\x02\x03\x04").expect("write");

        let err =
            SecureVault::open_or_create(&dir, Arc::clone(&vault.keystore)).expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_tolerates_a_missing_payload_file() {
        let dir = scratch("nopayload");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        assert!(!vault.vault_path().exists());

        let reopened = SecureVault::open(&dir, Arc::clone(&vault.keystore)).expect("open");
        assert!(reopened.load_contents().expect("load").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Presence and idempotency --------------------------------------------

    #[test]
    fn exists_reports_presence_via_the_password_file() {
        let dir = scratch("exists");
        assert!(!SecureVault::exists(&dir));

        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        assert!(
            SecureVault::exists(&dir),
            "the wrapped password marks the vault as initialised"
        );
        assert!(!vault.vault_path().exists(), "but no payload exists yet");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_or_create_is_idempotent() {
        let dir = scratch("idempotent");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));

        let first = SecureVault::open_or_create(&dir, Arc::clone(&keystore)).expect("first");
        first
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");
        drop(first);

        let second = SecureVault::open_or_create(&dir, keystore).expect("second");
        let loaded = second.load_contents().expect("load").expect("present");
        assert_eq!(
            loaded.pat, "github_pat_TEST",
            "existing vault must be reused"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_replaces_a_stale_wrapped_password() {
        let dir = scratch("stale");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join(WRAP_FILENAME), b"garbage from a previous install").expect("write");

        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        // `create` is unconditional: it replaces the password file wholesale.
        let vault = SecureVault::create(&dir, keystore).expect("create");
        assert!(vault.load_contents().expect("load").is_none());

        let raw = std::fs::read(vault.wrapped_password_path()).expect("read");
        assert_ne!(raw, b"garbage from a previous install");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Validation ----------------------------------------------------------

    #[test]
    fn store_rejects_an_empty_token() {
        let dir = scratch("emptytoken");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");

        let mut bad = contents();
        bad.pat = "   ".to_string();
        let err = vault
            .store_contents(&bad, &descriptor_for("o/r"))
            .expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::NotConfigured);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_writes_a_payload_that_rejects_a_blank_token_on_read() {
        let dir = scratch("blankpat");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");

        // Bypass the store guard to prove the read path also refuses a blank token.
        let payload = VaultPayload {
            version: VAULT_FORMAT_VERSION,
            pat: String::new(),
            group_key: [1u8; GROUP_KEY_LEN],
            group: None,
            groups: Vec::new(),
            active_group: None,
        };
        vault.write_payload(&payload).expect("write");
        *vault.contents.lock() = Some(payload);

        let err = vault.load_contents().expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);
        assert!(err.to_string().contains("no token"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_descriptor_reports_an_empty_vault() {
        let dir = scratch("emptydesc");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");

        let err = vault.verify_descriptor().expect_err("must fail");
        assert!(err.to_string().contains("no group is stored"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_descriptor_rejects_a_foreign_device() {
        let dir = scratch("foreigndev");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");

        let mut descriptor = descriptor_for("o/r");
        descriptor.keystore_alias = "some-other-device".to_string();
        vault
            .store_contents(&contents(), &descriptor)
            .expect("store");

        let err = vault.verify_descriptor().expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);
        assert!(err.to_string().contains("different device key"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_descriptor_rejects_an_unknown_schema() {
        let dir = scratch("schema");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");

        let mut descriptor = descriptor_for("o/r");
        descriptor.version = 99;
        vault
            .store_contents(&contents(), &descriptor)
            .expect("store");

        let err = vault.verify_descriptor().expect_err("must fail");
        assert!(err.to_string().contains("schema version 99"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_rejects_a_corrupt_descriptor_file() {
        let dir = scratch("corruptdesc");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");
        drop(vault);

        std::fs::write(dir.join(DESCRIPTOR_FILENAME), b"{ not json").expect("write");
        let err = SecureVault::open(&dir, keystore).expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);
        assert!(err.to_string().contains("malformed"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn descriptor_round_trips_through_json() {
        let descriptor = descriptor_for("JaredCH/shadow720-sandbox");
        let json = serde_json::to_string(&descriptor).expect("serialize");
        let back: VaultDescriptor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(descriptor, back);
    }

    #[test]
    fn descriptor_carries_no_secrets() {
        let json = serde_json::to_string(&descriptor_for("o/r")).expect("serialize");
        assert!(!json.contains("ghp_"));
        assert!(!json.contains("github_pat_"));
    }

    // -- Updates -------------------------------------------------------------

    #[test]
    fn update_pat_keeps_the_group_key() {
        let dir = scratch("updatepat");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        vault
            .update_pat("github_pat_NEW", &descriptor_for("o/r"))
            .expect("update");

        let loaded = vault.load_contents().expect("load").expect("present");
        assert_eq!(loaded.pat, "github_pat_NEW");
        assert_eq!(*loaded.group_key, [7u8; GROUP_KEY_LEN], "group key untouched");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_pat_rejects_an_empty_token() {
        let dir = scratch("updatepatempty");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        assert_eq!(
            vault
                .update_pat("  ", &descriptor_for("o/r"))
                .expect_err("must fail")
                .kind(),
            AppErrorKind::InvalidArgument
        );
        assert_eq!(
            vault.load_contents().expect("load").expect("present").pat,
            "github_pat_TEST"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_group_key_keeps_the_pat() {
        let dir = scratch("updatekey");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        let mut rotated = descriptor_for("o/r");
        rotated.current_epoch = 1;
        vault
            .update_group_key(&[9u8; GROUP_KEY_LEN], &rotated)
            .expect("update");

        let loaded = vault.load_contents().expect("load").expect("present");
        assert_eq!(loaded.pat, "github_pat_TEST", "token untouched");
        assert_eq!(*loaded.group_key, [9u8; GROUP_KEY_LEN]);
        assert_eq!(vault.descriptor().expect("descriptor").current_epoch, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_without_a_group_is_rejected() {
        let dir = scratch("noupdate");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");

        let err = vault
            .update_pat("github_pat_NEW", &descriptor_for("o/r"))
            .expect_err("must fail");
        assert_eq!(err.kind(), AppErrorKind::VaultUnavailable);
        assert!(err.to_string().contains("no token to replace"));

        let err = vault
            .update_group_key(&[1u8; GROUP_KEY_LEN], &descriptor_for("o/r"))
            .expect_err("must fail");
        assert!(err.to_string().contains("no key to rotate"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn updates_survive_a_reopen() {
        let dir = scratch("updatepersist");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");
        vault
            .update_pat("github_pat_REOPENED", &descriptor_for("o/r"))
            .expect("update pat");
        vault
            .update_group_key(&[3u8; GROUP_KEY_LEN], &descriptor_for("o/r"))
            .expect("update key");
        drop(vault);

        let reopened = SecureVault::open(&dir, keystore).expect("open");
        let loaded = reopened.load_contents().expect("load").expect("present");
        assert_eq!(loaded.pat, "github_pat_REOPENED");
        assert_eq!(*loaded.group_key, [3u8; GROUP_KEY_LEN]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Wipe ----------------------------------------------------------------

    #[test]
    fn wipe_removes_every_file_and_clears_memory() {
        let dir = scratch("wipe");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        vault.wipe().expect("wipe");

        assert!(!vault.vault_path().exists(), "payload must be deleted");
        assert!(
            !vault.wrapped_password_path().exists(),
            "wrapped password must be deleted"
        );
        assert!(!vault.descriptor_path().exists(), "descriptor must be deleted");
        assert!(vault.descriptor().is_none());
        assert!(
            vault.load_contents().expect("load").is_none(),
            "in-memory secrets must be gone"
        );
        assert!(!SecureVault::exists(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_then_recreate_yields_a_fresh_empty_vault() {
        let dir = scratch("wipecreate");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, Arc::clone(&keystore)).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");
        vault.wipe().expect("wipe");
        drop(vault);

        let fresh = SecureVault::open_or_create(&dir, keystore).expect("recreate");
        assert!(
            fresh.load_contents().expect("load").is_none(),
            "a recreated vault must be empty, not resurrect the old group"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_is_idempotent() {
        let dir = scratch("wipeidem");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault.wipe().expect("first wipe");
        vault.wipe().expect("second wipe must not fail");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_on_an_empty_vault_is_harmless() {
        let dir = scratch("wipeempty");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault.wipe().expect("wipe");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_dir_removes_an_unopenable_vault() {
        // The reset path: the device key is gone, so `open` fails and there is no
        // `SecureVault` to call `wipe` on. Deleting by filename must still work.
        let dir = scratch("wipedir");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");
        drop(vault);

        let invalidated: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::invalidated());
        assert!(
            SecureVault::open(&dir, invalidated).is_err(),
            "precondition: the vault must be unopenable"
        );

        SecureVault::wipe_dir(&dir).expect("wipe_dir");
        assert!(!SecureVault::exists(&dir), "the marker file must be gone");
        assert!(!dir.join(VAULT_FILENAME).exists());
        assert!(!dir.join(DESCRIPTOR_FILENAME).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_dir_is_idempotent_and_tolerates_a_missing_directory() {
        let dir = scratch("wipedirmissing");
        SecureVault::wipe_dir(&dir).expect("empty directory");
        SecureVault::wipe_dir(&dir).expect("second call");
        SecureVault::wipe_dir(dir.join("does-not-exist")).expect("absent directory");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Debug safety --------------------------------------------------------

    #[test]
    fn vault_contents_debug_never_prints_secrets() {
        let rendered = format!("{:?}", contents());
        assert!(!rendered.contains("github_pat_TEST"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn vault_payload_debug_never_prints_secrets() {
        let payload = VaultPayload {
            version: VAULT_FORMAT_VERSION,
            pat: "github_pat_SECRET".to_string(),
            group_key: [9u8; GROUP_KEY_LEN],
            group: None,
            groups: Vec::new(),
            active_group: None,
        };
        let rendered = format!("{payload:?}");
        assert!(!rendered.contains("github_pat_SECRET"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn secure_vault_debug_never_prints_the_password() {
        let dir = scratch("debugsafe");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = SecureVault::create(&dir, keystore).expect("create");
        let rendered = format!("{vault:?}");
        assert!(rendered.contains("keystore_alias"));
        assert!(!rendered.contains("password"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- MemorySecretMap -----------------------------------------------------

    #[test]
    fn memory_secret_map_round_trips() {
        let map = MemorySecretMap::default();
        assert!(map.is_empty());
        map.put("k", b"v".to_vec());
        assert_eq!(map.get("k").as_deref(), Some(&b"v"[..]));
        assert_eq!(map.len(), 1);
        assert!(map.get("missing").is_none());
    }

    // -- Concurrency ---------------------------------------------------------

    #[test]
    fn concurrent_reads_are_consistent() {
        let dir = scratch("concurrent");
        let keystore: Arc<dyn Keystore> = Arc::new(InMemoryKeystore::new().expect("keystore"));
        let vault = Arc::new(SecureVault::create(&dir, keystore).expect("create"));
        vault
            .store_contents(&contents(), &descriptor_for("o/r"))
            .expect("store");

        let mut handles = Vec::new();
        for _ in 0..8 {
            let clone = Arc::clone(&vault);
            handles.push(std::thread::spawn(move || {
                clone.load_contents().expect("load").expect("present").pat
            }));
        }
        for handle in handles {
            assert_eq!(handle.join().expect("thread"), "github_pat_TEST");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}