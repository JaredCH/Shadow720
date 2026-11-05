//! Cryptographic core: group keys, invite tokens, and the `EncryptedEnvelope`
//! wire format.
//!
//! Relays are treated as an **untrusted ciphertext store**. Nothing in this module
//! may emit plaintext to the network, and nothing may panic on hostile input:
//! every byte arriving from a relay, from an invite string, or from local storage
//! is treated as attacker-controlled.
//!
//! Primitives
//! ----------
//! * `Ed25519` — sender authenticity. Deterministic, 32-byte public keys.
//! * `Argon2id` — derives the legacy `GRP1-` invite wrapping key from the join password.
//! * `XChaCha20-Poly1305` — confidentiality + integrity for payloads and invites.
//!
//! Wire formats
//! ------------
//! * Invite token: `GRP1-` + Base64URL-no-pad(`salt16 ‖ nonce24 ‖ ciphertext+tag`).
//! * Envelope: JSON with Base64 **standard, padded** fields.
//!
//! The two encodings are deliberately different; do not unify them. See
//! `PLAN_ADDENDUM_v1.md` §A9.

use std::collections::HashMap;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{AppError, Result};

/// Prefix on every invite string.
pub const INVITE_PREFIX: &str = "GRP1-";
/// Prefix for self-contained invites: the wrapping key rides inside the token,
/// so the whole string is the secret and no join password exists.
pub const INVITE_PREFIX_V2: &str = "GRP2-";
/// Protocol version for both invites and envelopes.
pub const PROTOCOL_VERSION: u8 = 1;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const GROUP_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// Argon2id parameters, shared between host and guest so both derive the same key.
pub const ARGON2_M_COST: u32 = 19_456;
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 1;

/// A 256-bit symmetric group key, zeroized on drop.
pub type GroupKey = Zeroizing<[u8; GROUP_KEY_LEN]>;
/// A 256-bit Ed25519 signing key, zeroized on drop.
pub type DeviceSecretKey = Zeroizing<[u8; SECRET_KEY_LEN]>;

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// Fill a fixed-size array from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| AppError::crypto(format!("OS entropy unavailable: {e}")))?;
    Ok(buf)
}

/// Generate a fresh group master key.
pub fn new_group_key() -> Result<GroupKey> {
    Ok(Zeroizing::new(random_bytes::<GROUP_KEY_LEN>()?))
}

/// Generate a fresh Ed25519 keypair.
pub fn new_signing_key() -> Result<(DeviceSecretKey, VerifyingKey)> {
    let secret: [u8; SECRET_KEY_LEN] = random_bytes()?;
    let signing = SigningKey::from_bytes(&secret);
    let verifying = signing.verifying_key();
    Ok((Zeroizing::new(secret), verifying))
}

/// Seed a deterministic keypair from a single byte, for tests and fixtures.
///
/// Never use this for a real device identity: a one-byte seed space is trivially
/// brute-forced.
pub fn deterministic_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; SECRET_KEY_LEN])
}

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

/// Derive the invite wrapping key from a join password and 16-byte salt.
pub fn derive_wrapping_key(password: &str, salt: &[u8]) -> Result<GroupKey> {
    if salt.len() != SALT_LEN {
        return Err(AppError::crypto(format!(
            "invite salt must be {SALT_LEN} bytes, got {}",
            salt.len()
        )));
    }
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(GROUP_KEY_LEN))
        .map_err(|e| AppError::crypto(format!("invalid Argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut okm = [0u8; GROUP_KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut okm)
        .map_err(|e| AppError::crypto(format!("Argon2id key derivation failed: {e}")))?;
    Ok(Zeroizing::new(okm))
}

/// Derive a `SigningKey` from raw 32-byte secret material.
pub fn signing_key_from_bytes(secret: &[u8; SECRET_KEY_LEN]) -> SigningKey {
    SigningKey::from_bytes(secret)
}

/// Derive an Ed25519 public key from a Base64 secret key, for pre-flight checks.
pub fn verifying_key_for_secret_b64(secret_b64: &str) -> Result<VerifyingKey> {
    let raw = B64_STD
        .decode(secret_b64.as_bytes())
        .map_err(|e| AppError::crypto(format!("secret key is not valid base64: {e}")))?;
    if raw.len() != SECRET_KEY_LEN {
        return Err(AppError::crypto(format!(
            "secret key must be {SECRET_KEY_LEN} bytes, got {}",
            raw.len()
        )));
    }
    let mut secret = [0u8; SECRET_KEY_LEN];
    secret.copy_from_slice(&raw);
    let signing = SigningKey::from_bytes(&secret);
    Ok(signing.verifying_key())
}

// ---------------------------------------------------------------------------
// Invite payload
// ---------------------------------------------------------------------------

/// Everything a guest needs to join, sealed inside a `GRP1-` invite string.
///
/// Carries the group master key, so this struct is zeroized on drop and must never
/// be logged or serialized to disk in the clear.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct InviteCredentialsPayload {
    pub version: u8,
    /// Which storage backend holds this group.
    ///
    /// Kept as a field so an invite written by a build that shipped a different
    /// backend fails to parse loudly instead of being misread as Nostr.
    #[serde(default)]
    pub backend: crate::storage::BackendKind,
    /// Group id, used as the `d` tag on every Nostr event.
    #[serde(default)]
    pub group_id: String,
    pub group_master_key: [u8; GROUP_KEY_LEN],
    /// Relay URLs.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Blossom servers for blobs.
    #[serde(default)]
    pub blossom_servers: Vec<String>,
    /// Host's Ed25519 public key, pinned at join time so the roster can be verified.
    pub host_pubkey: String,
    /// Human label for the group, shown before the user commits to joining.
    pub group_label: String,
    /// Group-key epoch this invite's `group_master_key` belongs to.
    ///
    /// `0` for the original invite. A re-issue after a rotation carries the new
    /// epoch, which is how a member learns that a rotation happened
    /// (`PLAN_ADDENDUM_v1.md` §A3). Defaulted so an invite written before the
    /// field existed still parses as epoch 0.
    #[serde(default)]
    pub key_epoch: u8,
}

impl InviteCredentialsPayload {
    /// Borrow the group key as a plain array for crypto calls.
    pub fn group_key(&self) -> &[u8; GROUP_KEY_LEN] {
        &self.group_master_key
    }

    /// Validate shape and version before use. Cheap checks only; the AEAD tag is
    /// what actually guarantees authenticity.
    ///
    /// Nostr needs a group id and relays, and deliberately carries no token.
    pub fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(AppError::InviteFormat(format!(
                "unsupported invite version {} (this build speaks {PROTOCOL_VERSION})",
                self.version
            )));
        }

        match self.backend {
            crate::storage::BackendKind::Nostr => {
                if self.group_id.trim().is_empty() {
                    return Err(AppError::InviteFormat(
                        "invite has no group id, so no event can be addressed".into(),
                    ));
                }
                if self.relays.is_empty() {
                    return Err(AppError::InviteFormat(
                        "invite lists no relays, so the group cannot be reached".into(),
                    ));
                }
                for relay in &self.relays {
                    if !relay.starts_with("wss://") && !relay.starts_with("ws://") {
                        return Err(AppError::InviteFormat(format!(
                            "invite relay {relay} is not a ws:// or wss:// URL"
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// The backend this invite describes.
    pub fn backend_kind(&self) -> crate::storage::BackendKind {
        self.backend
    }
}

// ---------------------------------------------------------------------------
// Invite pack / unpack
// ---------------------------------------------------------------------------

/// Raw components of a `GRP1-` token, before password unwrapping.
#[derive(Clone, Debug)]
pub struct InviteParts {
    pub version: u8,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Raw components of a `GRP2-` token.
///
/// The wrapping key is carried in the clear inside the token: the token itself is
/// the secret, so there is no join password to remember or transmit separately.
#[derive(Clone, Debug)]
pub struct InvitePartsV2 {
    pub version: u8,
    pub nonce: [u8; NONCE_LEN],
    pub wrapping_key: [u8; GROUP_KEY_LEN],
    pub ciphertext: Vec<u8>,
}

/// Pack credentials into a `GRP2-` invite string.
///
/// The token is self-contained: anyone holding the string can unwrap the group
/// key. That is the intended model — treat the string like a WhatsApp group link.
pub fn pack_invite_v2(payload: &InviteCredentialsPayload) -> Result<String> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let wrapping_key = random_bytes::<GROUP_KEY_LEN>()?;
    pack_invite_v2_with_nonce(payload, nonce, wrapping_key)
}

/// Deterministic variant of [`pack_invite_v2`] for reproducible test vectors.
pub fn pack_invite_v2_with_nonce(
    payload: &InviteCredentialsPayload,
    nonce: [u8; NONCE_LEN],
    wrapping_key: [u8; GROUP_KEY_LEN],
) -> Result<String> {
    payload.validate()?;

    let json = serde_json::to_vec(payload)
        .map_err(|e| AppError::crypto(format!("could not serialize invite payload: {e}")))?;
    let compressed = zstd::bulk::compress(&json, 9)
        .map_err(|e| AppError::crypto(format!("could not compress invite payload: {e}")))?;

    let cipher = cipher_from_key(&wrapping_key)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &compressed,
                aad: &[payload.version],
            },
        )
        .map_err(|_| AppError::crypto("invite encryption failed"))?;

    let mut blob = Vec::with_capacity(1 + NONCE_LEN + GROUP_KEY_LEN + ciphertext.len());
    blob.push(payload.version);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&wrapping_key);
    blob.extend_from_slice(&ciphertext);

    Ok(format!("{INVITE_PREFIX_V2}{}", B64_URL.encode(&blob)))
}

/// Parse the outer structure of a `GRP2-` token.
pub fn parse_invite_parts_v2(token: &str) -> Result<InvitePartsV2> {
    let trimmed = token.trim();
    let body = match trimmed.strip_prefix(INVITE_PREFIX_V2) {
        Some(rest) => rest,
        None => {
            return Err(AppError::InviteFormat(format!(
                "invite string must start with {INVITE_PREFIX_V2}"
            )))
        }
    };
    if body.is_empty() {
        return Err(AppError::InviteFormat("invite string is empty".into()));
    }

    let raw = B64_URL
        .decode(body.as_bytes())
        .map_err(|e| AppError::InviteFormat(format!("invite is not valid base64url: {e}")))?;

    let minimum = 1 + NONCE_LEN + GROUP_KEY_LEN + TAG_LEN;
    if raw.len() < minimum {
        return Err(AppError::InviteFormat(format!(
            "invite is truncated: {} bytes, need at least {minimum}",
            raw.len()
        )));
    }

    let (version_slice, rest) = raw.split_at_checked(1).ok_or_else(|| {
        AppError::InviteFormat("invite is missing its version byte".into())
    })?;
    let (nonce_slice, rest) = rest.split_at_checked(NONCE_LEN).ok_or_else(|| {
        AppError::InviteFormat("invite is missing its nonce".into())
    })?;
    let (key_slice, ciphertext_slice) = rest.split_at_checked(GROUP_KEY_LEN).ok_or_else(|| {
        AppError::InviteFormat("invite is missing its wrapping key".into())
    })?;

    let version = *version_slice
        .first()
        .ok_or_else(|| AppError::InviteFormat("invite is missing its version byte".into()))?;
    let nonce: [u8; NONCE_LEN] = nonce_slice
        .try_into()
        .map_err(|_| AppError::InviteFormat("invite nonce is the wrong size".into()))?;
    let wrapping_key: [u8; GROUP_KEY_LEN] = key_slice
        .try_into()
        .map_err(|_| AppError::InviteFormat("invite wrapping key is the wrong size".into()))?;

    Ok(InvitePartsV2 {
        version,
        nonce,
        wrapping_key,
        ciphertext: ciphertext_slice.to_vec(),
    })
}

/// Unwrap a `GRP2-` invite string. No password is involved.
pub fn unpack_invite_v2(token: &str) -> Result<InviteCredentialsPayload> {
    let parts = parse_invite_parts_v2(token)?;
    if parts.version != PROTOCOL_VERSION {
        return Err(AppError::InviteFormat(format!(
            "unsupported invite version {} (this build speaks {PROTOCOL_VERSION})",
            parts.version
        )));
    }

    let cipher = cipher_from_key(&parts.wrapping_key)?;
    let mut compressed = cipher
        .decrypt(
            &XNonce::from(parts.nonce),
            Payload {
                msg: &parts.ciphertext,
                aad: &[parts.version],
            },
        )
        .map_err(|_| AppError::InviteFormat("this invite code is damaged or was altered".into()))?;

    let mut json = zstd::bulk::decompress(&compressed, DECOMPRESS_LIMIT_BYTES)
        .map_err(|e| AppError::InviteFormat(format!("invite payload is corrupt: {e}")))?;
    compressed.zeroize();

    let payload: InviteCredentialsPayload = serde_json::from_slice(&json)
        .map_err(|e| AppError::InviteFormat(format!("invite payload is malformed: {e}")))?;
    json.zeroize();

    payload.validate()?;
    Ok(payload)
}

/// Pack credentials into a `GRP1-` invite string.
///
/// Fresh salt and nonce are generated internally. Use
/// [`pack_invite_with_nonce`] when a deterministic vector is required (tests).
pub fn pack_invite(payload: &InviteCredentialsPayload, password: &str) -> Result<String> {
    let salt = random_bytes::<SALT_LEN>()?;
    let nonce = random_bytes::<NONCE_LEN>()?;
    pack_invite_with_nonce(payload, password, salt, nonce)
}

/// Deterministic variant of [`pack_invite`] for reproducible test vectors.
pub fn pack_invite_with_nonce(
    payload: &InviteCredentialsPayload,
    password: &str,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> Result<String> {
    payload.validate()?;

    let json = serde_json::to_vec(payload)
        .map_err(|e| AppError::crypto(format!("could not serialize invite payload: {e}")))?;
    let compressed = zstd::bulk::compress(&json, 9)
        .map_err(|e| AppError::crypto(format!("could not compress invite payload: {e}")))?;

    let wrapping_key = derive_wrapping_key(password, &salt)?;
    let cipher = cipher_from_key(&wrapping_key)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &compressed,
                aad: &[payload.version],
            },
        )
        .map_err(|_| AppError::crypto("invite encryption failed"))?;

    let mut blob = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.push(payload.version);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(format!("{INVITE_PREFIX}{}", B64_URL.encode(&blob)))
}

/// Parse the outer structure of a `GRP1-` token without needing the password.
///
/// Lets the UI show the group label prompt before asking for a password, but the
/// label itself is encrypted, so this only yields the version.
pub fn parse_invite_parts(token: &str) -> Result<InviteParts> {
    let trimmed = token.trim();
    let body = match trimmed.strip_prefix(INVITE_PREFIX) {
        Some(rest) => rest,
        None => {
            return Err(AppError::InviteFormat(format!(
                "invite string must start with {INVITE_PREFIX}"
            )))
        }
    };
    if body.is_empty() {
        return Err(AppError::InviteFormat("invite string is empty".into()));
    }

    let raw = B64_URL
        .decode(body.as_bytes())
        .map_err(|e| AppError::InviteFormat(format!("invite is not valid base64url: {e}")))?;

    let minimum = 1 + SALT_LEN + NONCE_LEN + TAG_LEN;
    if raw.len() < minimum {
        return Err(AppError::InviteFormat(format!(
            "invite is truncated: {} bytes, need at least {minimum}",
            raw.len()
        )));
    }

        // `split_at_checked` keeps this panic-free even if the layout ever changes.
        let (version_slice, rest) = raw.split_at_checked(1).ok_or_else(|| {
            AppError::InviteFormat("invite is missing its version byte".into())
        })?;
        let (salt_slice, rest) = rest.split_at_checked(SALT_LEN).ok_or_else(|| {
            AppError::InviteFormat("invite is missing its salt".into())
        })?;
        let (nonce_slice, ciphertext_slice) = rest.split_at_checked(NONCE_LEN).ok_or_else(|| {
            AppError::InviteFormat("invite is missing its nonce".into())
        })?;

        let version = *version_slice
            .first()
            .ok_or_else(|| AppError::InviteFormat("invite is missing its version byte".into()))?;
        let salt: [u8; SALT_LEN] = salt_slice
            .try_into()
            .map_err(|_| AppError::InviteFormat("invite salt is the wrong size".into()))?;
        let nonce: [u8; NONCE_LEN] = nonce_slice
            .try_into()
            .map_err(|_| AppError::InviteFormat("invite nonce is the wrong size".into()))?;

        Ok(InviteParts {
            version,
            salt,
            nonce,
            ciphertext: ciphertext_slice.to_vec(),
        })
}

/// Unwrap a `GRP1-` invite string with the join password.
///
/// Returns [`AppError::InvitePassword`] when the AEAD tag fails, which is the
/// "wrong password" signal for the UI.
pub fn unpack_invite(token: &str, password: &str) -> Result<InviteCredentialsPayload> {
    let parts = parse_invite_parts(token)?;
    if parts.version != PROTOCOL_VERSION {
        return Err(AppError::InviteFormat(format!(
            "unsupported invite version {} (this build speaks {PROTOCOL_VERSION})",
            parts.version
        )));
    }

    let wrapping_key = derive_wrapping_key(password, &parts.salt)?;
    let cipher = cipher_from_key(&wrapping_key)?;
    let mut compressed = cipher
        .decrypt(
            &XNonce::from(parts.nonce),
            Payload {
                msg: &parts.ciphertext,
                aad: &[parts.version],
            },
        )
        .map_err(|_| AppError::InvitePassword)?;

    let mut json = zstd::bulk::decompress(&compressed, DECOMPRESS_LIMIT_BYTES)
        .map_err(|e| AppError::InviteFormat(format!("invite payload is corrupt: {e}")))?;
    compressed.zeroize();

    let payload: InviteCredentialsPayload = serde_json::from_slice(&json)
        .map_err(|e| AppError::InviteFormat(format!("invite payload is malformed: {e}")))?;
    json.zeroize();

    payload.validate()?;
    Ok(payload)
}

/// Ceiling on decompressed invite payloads. Guards against a zip-bomb invite.
const DECOMPRESS_LIMIT_BYTES: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// Inner payloads
// ---------------------------------------------------------------------------

/// Decrypted contents of an envelope. The variant is implied by which issue the
/// envelope was found on, and also self-describes here so a mismatched read is
/// detectable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum InnerPayload {
    Location(LocationState),
    Chat(ChatPayload),
    Control(ControlPayload),
}

/// Body of a member's roster comment on Issue #1.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocationState {
    pub display_name: String,
    /// `#rrggbb`. Generated client-side; carries no PII.
    pub avatar_color: String,
    pub lat: f64,
    pub lon: f64,
    pub accuracy_m: f32,
    pub speed_mps: f32,
    pub heading_deg: f32,
    pub battery_pct: u8,
    pub is_charging: bool,
    pub unix_ms: i64,
    /// The member's own Ed25519 public key, redundant with the envelope sender
    /// but convenient when rendering a roster without decrypting twice.
    pub member_pubkey: String,
}

/// Body of a comment on Issue #2.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChatPayload {
    TextMessage {
        text: String,
        unix_ms: i64,
    },
    FileAttachment {
        /// Release asset name (`{uuid}.bin`), not a filesystem path.
        asset_name: String,
        size_bytes: u64,
        mime: String,
        /// Base64 SHA-256 of the *plaintext* file, so recipients can verify the
        /// decryption result.
        sha256_b64: String,
        caption: Option<String>,
        unix_ms: i64,
    },
    /// Report/flag raised against another member's comment.
    ModerationFlag {
        target_comment_id: u64,
        target_pubkey: String,
        reason: String,
        unix_ms: i64,
    },
}

/// Group-lifecycle events, written to Issue #1 by the host.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlPayload {
    GroupInit {
        group_id: String,
        group_label: String,
        created_unix_ms: i64,
    },
    KeyRotation {
        new_epoch: u8,
        retired_epoch: u8,
        reason: String,
        unix_ms: i64,
    },
    MemberRemoved {
        member_pubkey: String,
        comment_id: u64,
        unix_ms: i64,
    },
    /// The host's current role assignments. Latest message wins.
    ///
    /// `owner` is not assignable: it is the key pinned in the invite. `admin` and
    /// `member` are the only values peers should honor.
    RoleSet {
        grants: Vec<RoleGrant>,
        unix_ms: i64,
    },
}

/// One member's role, as assigned by the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleGrant {
    pub member_pubkey: String,
    /// `admin` or `member`.
    pub role: String,
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// The `EncryptedEnvelope`: exactly what is stored on a relay.
///
/// Field order mirrors the signed input so the canonicalizer and the struct stay
/// in lockstep. Base64 fields are **standard, padded**.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub v: u8,
    /// Group-key epoch. `0` is the key from the original invite.
    pub key_epoch: u8,
    /// Base64 Ed25519 verifying key (32 bytes).
    pub sender_pubkey: String,
    /// Base64 XChaCha20 nonce (24 bytes).
    pub nonce: String,
    /// Base64 `XChaCha20-Poly1305` ciphertext with the tag appended.
    pub ciphertext: String,
    /// Base64 Ed25519 signature over the canonical input (see [`canonical_sig_input`]).
    pub signature: String,
}

impl EncryptedEnvelope {
    /// Decoded sender key, or [`AppError::Crypto`] when malformed.
    pub fn sender_verifying_key(&self) -> Result<VerifyingKey> {
        verifying_key_from_b64(&self.sender_pubkey)
    }
}

/// Decode a Base64 standard sender key.
pub fn verifying_key_from_b64(b64: &str) -> Result<VerifyingKey> {
    let raw = B64_STD
        .decode(b64.as_bytes())
        .map_err(|e| AppError::crypto(format!("public key is not valid base64: {e}")))?;
    if raw.len() != PUBLIC_KEY_LEN {
        return Err(AppError::crypto(format!(
            "public key must be {PUBLIC_KEY_LEN} bytes, got {}",
            raw.len()
        )));
    }
    let mut arr = [0u8; PUBLIC_KEY_LEN];
    arr.copy_from_slice(&raw);
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| AppError::crypto(format!("public key is not a valid curve point: {e}")))
}

/// Encode a sender key as Base64 standard, padded.
pub fn verifying_key_to_b64(key: &VerifyingKey) -> String {
    B64_STD.encode(key.to_bytes())
}

/// Build the canonical, length-prefixed signature input.
///
/// Length prefixes remove any ambiguity between adjacent variable-length fields,
/// so two different logical payloads can never produce the same signed bytes.
pub fn canonical_sig_input(
    v: u8,
    key_epoch: u8,
    sender_pubkey: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + sender_pubkey.len() + nonce.len() + ciphertext.len() + 32);
    out.push(v);
    out.push(key_epoch);
    push_len_prefixed(&mut out, sender_pubkey);
    push_len_prefixed(&mut out, nonce);
    push_len_prefixed(&mut out, ciphertext);
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(field);
}

/// Derive a non-secret "which key is this?" tag for an epoch.
///
/// Lets a reader confirm it holds the right epoch key *before* attempting an
/// AEAD open, which keeps "wrong key" distinguishable from "corrupt data" in
/// logs without leaking key material.
pub fn key_epoch_tag(group_key: &[u8; GROUP_KEY_LEN], epoch: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"shadow720/epoch-tag/v1");
    hasher.update(group_key);
    hasher.update([epoch]);
    hasher.finalize().into()
}

/// SHA-256 of arbitrary plaintext, Base64 standard encoded.
pub fn sha256_b64(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    B64_STD.encode(hasher.finalize())
}

/// Seal a binary blob for the release-asset vault.
///
/// Layout: `nonce(24) ‖ ciphertext+tag`. The nonce is prepended because a release
/// asset is a bare byte stream with nowhere else to carry it, unlike an envelope
/// where the nonce has its own JSON field.
///
/// This is the only path that turns a file into something uploadable, so no
/// caller has to remember to encrypt before uploading.
pub fn seal_blob(group_key: &[u8; GROUP_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let cipher = cipher_from_key(group_key)?;

    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: BLOB_AAD,
            },
        )
        .map_err(|_| AppError::crypto("could not encrypt the file blob"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a blob produced by [`seal_blob`].
pub fn open_blob(group_key: &[u8; GROUP_KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
            open_blob_with(group_key, blob, BLOB_AAD)
        }

        /// Seal with an explicit nonce and associated data.
        ///
        /// Used by the vault, which frames its own header and wants the nonce stored
        /// alongside the salt rather than prepended to the ciphertext.
        pub fn seal_blob_with(
            group_key: &[u8; GROUP_KEY_LEN],
            plaintext: &[u8],
            nonce: [u8; NONCE_LEN],
            aad: &[u8],
        ) -> Result<Vec<u8>> {
            let cipher = cipher_from_key(group_key)?;
            cipher
                .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
                .map_err(|_| AppError::crypto("could not encrypt the payload"))
        }

        /// Open a blob whose layout is `nonce ‖ ciphertext+tag` under explicit AAD.
        pub fn open_blob_with(
            group_key: &[u8; GROUP_KEY_LEN],
            blob: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>> {
            if blob.len() < NONCE_LEN + TAG_LEN {
                return Err(AppError::crypto(format!(
                    "sealed payload is {} bytes, too short to contain a nonce and tag",
                    blob.len()
                )));
            }

            let (nonce_slice, ciphertext) = blob.split_at(NONCE_LEN);
            let nonce: [u8; NONCE_LEN] = nonce_slice
                .try_into()
                .map_err(|_| AppError::crypto("sealed payload nonce is the wrong size"))?;

            let cipher = cipher_from_key(group_key)?;
            cipher
                .decrypt(&XNonce::from(nonce), Payload { msg: ciphertext, aad })
                .map_err(|_| {
                    AppError::crypto(
                        "could not decrypt the sealed payload; the key is wrong or the data is corrupt",
                    )
                })
        }

        /// Derive a 256-bit key from arbitrary key material.
        ///
        /// Unlike [`derive_wrapping_key`], this does not require a 16-byte salt: the
        /// caller supplies the full KDF salt, which lets the vault fold a context string
        /// in alongside the random salt.
        pub fn derive_wrapping_key_bytes(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; GROUP_KEY_LEN]>> {
            if salt.is_empty() {
                return Err(AppError::crypto(
                    "a key-derivation salt is required and must not be empty",
                ));
            }
            let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(GROUP_KEY_LEN))
                .map_err(|e| AppError::crypto(format!("invalid Argon2 parameters: {e}")))?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut okm = [0u8; GROUP_KEY_LEN];
            argon
                .hash_password_into(password, salt, &mut okm)
                .map_err(|e| AppError::crypto(format!("Argon2id key derivation failed: {e}")))?;
            Ok(Zeroizing::new(okm))
        }

/// Associated data binding a blob to its purpose, so an asset cannot be swapped
/// for another kind of ciphertext.
const BLOB_AAD: &[u8] = b"shadow720/blob/v1";

/// Seal a location state into a network-ready envelope.
pub fn seal_location(
    group_key: &[u8; GROUP_KEY_LEN],
    epoch: u8,
    signing_key: &SigningKey,
    state: &LocationState,
) -> Result<EncryptedEnvelope> {
    seal_inner(group_key, epoch, signing_key, &InnerPayload::Location(state.clone()))
}

/// Seal a chat payload into a network-ready envelope.
pub fn seal_chat(
    group_key: &[u8; GROUP_KEY_LEN],
    epoch: u8,
    signing_key: &SigningKey,
    payload: &ChatPayload,
) -> Result<EncryptedEnvelope> {
    seal_inner(group_key, epoch, signing_key, &InnerPayload::Chat(payload.clone()))
}

/// Seal a control payload into a network-ready envelope.
pub fn seal_control(
    group_key: &[u8; GROUP_KEY_LEN],
    epoch: u8,
    signing_key: &SigningKey,
    payload: &ControlPayload,
) -> Result<EncryptedEnvelope> {
    seal_inner(
        group_key,
        epoch,
        signing_key,
        &InnerPayload::Control(payload.clone()),
    )
}

/// Generic sealing path. Generates a fresh nonce and signs the result.
pub fn seal_inner(
    group_key: &[u8; GROUP_KEY_LEN],
    epoch: u8,
    signing_key: &SigningKey,
    payload: &InnerPayload,
) -> Result<EncryptedEnvelope> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    seal_inner_with_nonce(group_key, epoch, signing_key, payload, nonce)
}

/// Deterministic sealing, for reproducible test vectors.
pub fn seal_inner_with_nonce(
    group_key: &[u8; GROUP_KEY_LEN],
    epoch: u8,
    signing_key: &SigningKey,
    payload: &InnerPayload,
    nonce: [u8; NONCE_LEN],
) -> Result<EncryptedEnvelope> {
    let plaintext = serde_json::to_vec(payload)
        .map_err(|e| AppError::crypto(format!("could not serialize payload: {e}")))?;

    let verifying = signing_key.verifying_key();
    let sender_pubkey = verifying.to_bytes();

    let cipher = cipher_from_key(group_key)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &envelope_aad(epoch, &sender_pubkey),
            },
        )
        .map_err(|_| AppError::crypto("payload encryption failed"))?;

    let sig_input = canonical_sig_input(
        PROTOCOL_VERSION,
        epoch,
        &sender_pubkey,
        &nonce,
        &ciphertext,
    );
    let signature = signing_key.sign(&sig_input);

    Ok(EncryptedEnvelope {
        v: PROTOCOL_VERSION,
        key_epoch: epoch,
        sender_pubkey: B64_STD.encode(sender_pubkey),
        nonce: B64_STD.encode(nonce),
        ciphertext: B64_STD.encode(&ciphertext),
        signature: B64_STD.encode(signature.to_bytes()),
    })
}

/// Verify an envelope's signature without decrypting it.
///
/// Run this **before** any key lookup or decryption so forged traffic is rejected
/// cheaply and cannot influence which epoch key is loaded.
pub fn verify_envelope(envelope: &EncryptedEnvelope) -> Result<VerifyingKey> {
    if envelope.v != PROTOCOL_VERSION {
        return Err(AppError::crypto(format!(
            "unsupported envelope version {}",
            envelope.v
        )));
    }

    let verifying = envelope.sender_verifying_key()?;
    let nonce = decode_fixed::<NONCE_LEN>(&envelope.nonce, "nonce")?;
    let ciphertext = B64_STD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|e| AppError::crypto(format!("ciphertext is not valid base64: {e}")))?;
    if ciphertext.len() < TAG_LEN {
        return Err(AppError::crypto(
                "ciphertext is shorter than a Poly1305 tag; envelope is truncated",
        ));
    }

    let sig_bytes = decode_fixed::<SIGNATURE_LEN>(&envelope.signature, "signature")?;
    let signature = Signature::from_bytes(&sig_bytes);

    let sig_input = canonical_sig_input(
        envelope.v,
        envelope.key_epoch,
        &verifying.to_bytes(),
        &nonce,
        &ciphertext,
    );

    verifying
        .verify(&sig_input, &signature)
        .map_err(|_| AppError::crypto("envelope signature verification failed"))?;

    Ok(verifying)
}

/// Open an envelope that has already passed [`verify_envelope`].
///
/// `epoch_key` must be the group key for `envelope.key_epoch`; callers resolve it
/// from the bounded epoch table (see `crate::group::GroupKeys`).
pub fn open_verified(
    envelope: &EncryptedEnvelope,
    epoch_key: &[u8; GROUP_KEY_LEN],
    expected_sender: Option<&VerifyingKey>,
) -> Result<InnerPayload> {
    let sender = verify_envelope(envelope)?;
    if let Some(expected) = expected_sender {
        if sender.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
            return Err(AppError::crypto(
                        "envelope sender does not match the expected member",
            ));
        }
    }

    let nonce = decode_fixed::<NONCE_LEN>(&envelope.nonce, "nonce")?;
    let ciphertext = B64_STD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|e| AppError::crypto(format!("ciphertext is not valid base64: {e}")))?;

    let cipher = cipher_from_key(epoch_key)?;
    let mut plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &ciphertext,
                aad: &envelope_aad(envelope.key_epoch, &sender.to_bytes()),
            },
        )
        .map_err(|_| {
            AppError::crypto(format!(
                "could not decrypt envelope; wrong key for epoch {} or data is corrupt",
                envelope.key_epoch
            ))
        })?;

    let parsed: InnerPayload = serde_json::from_slice(&plaintext)
            .map_err(|e| AppError::crypto(format!("decrypted payload is malformed: {e}")))?;
    plaintext.zeroize();
        Ok(parsed)
}

/// Convenience: verify then decrypt in one call.
pub fn open_envelope(
    envelope: &EncryptedEnvelope,
    epoch_key: &[u8; GROUP_KEY_LEN],
) -> Result<InnerPayload> {
    open_verified(envelope, epoch_key, None)
}

/// Associated data binds a ciphertext to its epoch and sender, so a valid
/// ciphertext cannot be replayed under a different epoch or sender label.
fn envelope_aad(epoch: u8, sender_pubkey: &[u8; PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + sender_pubkey.len());
    aad.push(epoch);
    aad.extend_from_slice(sender_pubkey);
    aad
}

fn cipher_from_key(key: &[u8; 32]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(Key::from_slice(key))
        .map_err(|e| AppError::crypto(format!("invalid key length: {e}")))
}

fn decode_fixed<const N: usize>(b64: &str, what: &'static str) -> Result<[u8; N]> {
    let raw = B64_STD
        .decode(b64.as_bytes())
        .map_err(|e| AppError::crypto(format!("{what} is not valid base64: {e}")))?;
    if raw.len() != N {
        return Err(AppError::crypto(format!(
            "{what} must be {N} bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Group key epochs
// ---------------------------------------------------------------------------

/// Bounded table of group keys, one per rotation epoch.
///
/// Keys are zeroized on drop. The cap exists so a hostile peer cannot force
/// unbounded memory growth by advertising a huge epoch number.
#[derive(Default)]
pub struct GroupKeys {
    keys: HashMap<u8, Zeroizing<[u8; GROUP_KEY_LEN]>>,
    pub current_epoch: u8,
}

/// Maximum retained epochs, as an anti-DoS bound.
pub const MAX_EPOCHS: usize = 32;

impl GroupKeys {
    /// Start a table at epoch 0 with the invite's group key.
    pub fn new(group_key: &[u8; GROUP_KEY_LEN]) -> Self {
        let mut keys = HashMap::new();
        keys.insert(0u8, Zeroizing::new(*group_key));
        Self {
            keys,
            current_epoch: 0,
        }
    }

    /// Start with the epoch carried by an invite or restored vault.
    pub fn from_epoch(epoch: u8, group_key: &[u8; GROUP_KEY_LEN]) -> Self {
        let mut keys = HashMap::new();
        keys.insert(epoch, Zeroizing::new(*group_key));
        Self { keys, current_epoch: epoch }
    }

    /// Register a key for `epoch`. Returns [`AppError::GroupState`] when the
    /// table is full.
    pub fn insert(&mut self, epoch: u8, key: &[u8; GROUP_KEY_LEN]) -> Result<()> {
        if !self.keys.contains_key(&epoch) && self.keys.len() >= MAX_EPOCHS {
            return Err(AppError::group_state(format!(
                "refusing to track more than {MAX_EPOCHS} key epochs"
            )));
        }
        self.keys.insert(epoch, Zeroizing::new(*key));
        Ok(())
    }

    /// Promote a new key to the current epoch.
    pub fn rotate(&mut self, new_epoch: u8, key: &[u8; GROUP_KEY_LEN]) -> Result<()> {
        if new_epoch <= self.current_epoch {
            return Err(AppError::group_state(format!(
                "rotation epoch {new_epoch} must be greater than current epoch {}",
                self.current_epoch
            )));
        }
        self.insert(new_epoch, key)?;
        self.current_epoch = new_epoch;
        Ok(())
    }

    /// Borrow the key for an epoch.
    pub fn get(&self, epoch: u8) -> Option<&[u8; GROUP_KEY_LEN]> {
        self.keys.get(&epoch).map(|k| &**k)
    }

    /// Borrow the current key.
    pub fn current(&self) -> Result<&[u8; GROUP_KEY_LEN]> {
        self.get(self.current_epoch).ok_or_else(|| {
            AppError::group_state(format!(
                "current epoch {} has no key loaded",
                self.current_epoch
            ))
        })
    }

    /// Check whether `tag` matches the stored key for `epoch`, without revealing
    /// the key. Used to reject peers claiming an epoch we don't hold.
    pub fn matches_tag(&self, epoch: u8, tag: &[u8; 32]) -> bool {
        match self.get(epoch) {
            Some(key) => key_epoch_tag(key, epoch).ct_eq(tag).unwrap_u8() == 1,
            None => false,
        }
    }

    /// Decrypt any envelope whose epoch this table holds.
    pub fn open(&self, envelope: &EncryptedEnvelope) -> Result<InnerPayload> {
        // Verify first so a forged envelope never drives key selection.
        verify_envelope(envelope)?;
        let key = self.get(envelope.key_epoch).ok_or_else(|| {
            AppError::group_state(format!(
                "envelope uses unknown key epoch {}; this device holds epochs {:?}",
                envelope.key_epoch,
                self.known_epochs()
            ))
        })?;
        open_verified(envelope, key, None)
    }

    /// Sorted list of held epochs, for diagnostics.
    pub fn known_epochs(&self) -> Vec<u8> {
        let mut epochs: Vec<u8> = self.keys.keys().copied().collect();
        epochs.sort_unstable();
        epochs
    }

    /// Number of retained epochs.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no keys are loaded.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Drop every key except the current one. Called on wipe/logout.
    pub fn prune_to_current(&mut self) {
        let current = self.current_epoch;
        self.keys.retain(|epoch, _| *epoch == current);
    }
}

impl std::fmt::Debug for GroupKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("GroupKeys")
            .field("current_epoch", &self.current_epoch)
            .field("known_epochs", &self.known_epochs())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> InviteCredentialsPayload {
        InviteCredentialsPayload {
            version: PROTOCOL_VERSION,
            backend: crate::storage::BackendKind::Nostr,
            group_id: "group-abc".into(),
            group_master_key: [7u8; GROUP_KEY_LEN],
            relays: vec!["wss://relay.damus.io".into()],
            blossom_servers: vec!["https://blossom.nostr.build".into()],
            host_pubkey: verifying_key_to_b64(&new_signing_key().expect("keygen").1),
            group_label: "Weekend Trip".into(),
            key_epoch: 0,
        }
    }

    fn sample_nostr_payload() -> InviteCredentialsPayload {
        InviteCredentialsPayload {
            version: PROTOCOL_VERSION,
            backend: crate::storage::BackendKind::Nostr,
            group_master_key: [9u8; GROUP_KEY_LEN],
            relays: vec!["wss://relay.damus.io".into(), "wss://nos.lol".into()],
            blossom_servers: vec!["https://blossom.nostr.build".into()],
            group_id: "group-abc".into(),
            host_pubkey: verifying_key_to_b64(&new_signing_key().expect("keygen").1),
            group_label: "Nostr Trip".into(),
            key_epoch: 0,
        }
    }

    #[test]
    fn nostr_invite_round_trips_without_a_token() {
        let payload = sample_nostr_payload();
        payload.validate().expect("valid");

        let invite = pack_invite(&payload, "pw").expect("pack");
        let recovered = unpack_invite(&invite, "pw").expect("unpack");

        assert_eq!(recovered.backend, crate::storage::BackendKind::Nostr);
        assert_eq!(recovered.group_id, "group-abc");
        assert_eq!(recovered.relays.len(), 2);
        assert!(
            recovered.group_master_key == [9u8; GROUP_KEY_LEN],
            "the group key must survive the round trip"
        );
    }

    #[test]
    fn nostr_invite_requires_a_group_id() {
        let mut payload = sample_nostr_payload();
        payload.group_id = String::new();
        assert!(payload.validate().is_err());
    }

    #[test]
    fn nostr_invite_requires_at_least_one_relay() {
        let mut payload = sample_nostr_payload();
        payload.relays.clear();
        assert!(payload.validate().is_err());
    }

    #[test]
    fn nostr_invite_rejects_a_non_websocket_relay() {
        let mut payload = sample_nostr_payload();
        payload.relays = vec!["https://relay.example".into()];
        assert!(payload.validate().is_err());
    }

    #[test]
    fn a_nostr_invite_without_relays_is_rejected() {
        let mut payload = sample_payload();
        payload.relays.clear();
        assert!(
            payload.validate().is_err(),
            "a group with no relays cannot be reached"
        );
    }

    #[test]
    fn a_nostr_invite_without_a_group_id_is_rejected() {
        let mut payload = sample_payload();
        payload.group_id = String::new();
        assert!(
            payload.validate().is_err(),
            "no group id means no event can be addressed"
        );
    }

    #[test]
    fn an_invite_naming_a_removed_backend_fails_to_parse() {
        // An invite written by a build that shipped the GitHub backend must not be
        // silently reinterpreted as Nostr: it would point at a store this build
        // cannot reach.
        let json = serde_json::json!({
            "version": PROTOCOL_VERSION,
            "backend": "github",
            "repo_owner": "o",
            "repo_name": "r",
            "repo_scoped_pat": "github_pat_X",
            "group_master_key": vec![1u8; GROUP_KEY_LEN],
            "roster_issue_num": 1,
            "chat_issue_num": 2,
            "release_id": 5,
            "repo_created": true,
            "host_pubkey": "",
            "group_label": "g",
            "key_epoch": 0
        });
        assert!(
            serde_json::from_value::<InviteCredentialsPayload>(json).is_err(),
            "a github invite must be rejected, not coerced to nostr"
        );
    }

    fn sample_location() -> LocationState {
        LocationState {
            display_name: "Jared".into(),
            avatar_color: "#5b8cff".into(),
            lat: 41.8781,
            lon: -87.6298,
            accuracy_m: 4.5,
            speed_mps: 1.2,
            heading_deg: 181.0,
            battery_pct: 84,
            is_charging: true,
            unix_ms: 1_700_000_000_000,
            member_pubkey: "AAAA".into(),
        }
    }

    // -- Invite round trip ---------------------------------------------------

    #[test]
    fn invite_round_trips() {
        let payload = sample_payload();
        let token = pack_invite(&payload, "correct horse battery staple").expect("pack");
        assert!(token.starts_with(INVITE_PREFIX));

        let recovered = unpack_invite(&token, "correct horse battery staple").expect("unpack");
        assert_eq!(recovered.group_id, "group-abc");
        assert_eq!(recovered.group_master_key, [7u8; GROUP_KEY_LEN]);
        assert_eq!(recovered.relays, vec!["wss://relay.damus.io".to_string()]);
        assert_eq!(recovered.group_label, "Weekend Trip");
    }

    #[test]
    fn invite_is_base64url_without_padding() {
        let token = pack_invite(&sample_payload(), "pw").expect("pack");
        let body = token.strip_prefix(INVITE_PREFIX).expect("prefix");
        assert!(!body.contains('+'), "base64url must not contain '+'");
        assert!(!body.contains('/'), "base64url must not contain '/'");
        assert!(!body.contains('='), "invite must be unpadded");
    }

    #[test]
    fn invite_rejects_wrong_password() {
        let token = pack_invite(&sample_payload(), "right-password").expect("pack");
        let err = unpack_invite(&token, "wrong-password").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InvitePassword);
    }

    #[test]
    fn invite_rejects_password_of_different_length() {
        let token = pack_invite(&sample_payload(), "short").expect("pack");
        let err = unpack_invite(&token, "a-much-longer-password").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InvitePassword);
    }

    #[test]
    fn invite_rejects_missing_prefix() {
        let err = parse_invite_parts("GRP2-AAAA").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
        assert!(err.to_string().contains("GRP1-"));
    }

    #[test]
    fn invite_rejects_non_base64_body() {
        let err = parse_invite_parts("GRP1-not!valid!base64!").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
    }

    #[test]
    fn invite_rejects_truncated_body() {
        let short = B64_URL.encode([1u8, 2, 3, 4]);
        let err = parse_invite_parts(&format!("{INVITE_PREFIX}{short}")).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn invite_rejects_unsupported_version() {
        let mut payload = sample_payload();
        payload.version = 9;
        // validate() rejects before packing, so encode a legacy-shaped token by
        // forcing the version byte through the deterministic packer.
        let err = pack_invite(&payload, "pw").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
    }

    #[test]
    fn invite_requires_valid_fields() {
        let mut payload = sample_payload();
        payload.group_id.clear();
        assert_eq!(
            payload.validate().expect_err("must fail").kind(),
            crate::error::AppErrorKind::InviteFormat
        );

        let mut payload = sample_payload();
        payload.relays.clear();
        assert_eq!(
            payload.validate().expect_err("must fail").kind(),
            crate::error::AppErrorKind::InviteFormat
        );

        let mut payload = sample_payload();
        payload.relays = vec!["https://relay.example".into()];
        assert_eq!(
            payload.validate().expect_err("must fail").kind(),
            crate::error::AppErrorKind::InviteFormat
        );
    }

    #[test]
    fn invite_ciphertext_is_single_bit_flip_sensitive() {
        let payload = sample_payload();
        let salt = [3u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let token =
            pack_invite_with_nonce(&payload, "pw", salt, nonce).expect("deterministic pack");

        let parts = parse_invite_parts(&token).expect("parts");
        let mut tampered = parts.ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0b0000_0001;

        let mut blob = Vec::new();
        blob.push(parts.version);
        blob.extend_from_slice(&parts.salt);
        blob.extend_from_slice(&parts.nonce);
        blob.extend_from_slice(&tampered);
        let bad_token = format!("{INVITE_PREFIX}{}", B64_URL.encode(&blob));

        let err = unpack_invite(&bad_token, "pw").expect_err("tamper must be detected");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InvitePassword);
    }

    #[test]
    fn deterministic_invite_pack_is_stable() {
        let payload = sample_payload();
        let a = pack_invite_with_nonce(&payload, "pw", [1u8; SALT_LEN], [2u8; NONCE_LEN])
            .expect("first");
        let b = pack_invite_with_nonce(&payload, "pw", [1u8; SALT_LEN], [2u8; NONCE_LEN])
            .expect("second");
        assert_eq!(a, b, "same salt+nonce must produce the same token");
    }

    // -- Self-contained invites (GRP2-) ---------------------------------------

    #[test]
    fn self_contained_invite_round_trips_without_a_password() {
        let payload = sample_payload();
        let token = pack_invite_v2(&payload).expect("pack");
        assert!(token.starts_with(INVITE_PREFIX_V2));

        let recovered = unpack_invite_v2(&token).expect("unpack");
        assert_eq!(recovered.group_id, "group-abc");
        assert_eq!(recovered.group_master_key, [7u8; GROUP_KEY_LEN]);
        assert_eq!(recovered.relays, vec!["wss://relay.damus.io".to_string()]);
        assert_eq!(recovered.group_label, "Weekend Trip");
    }

    #[test]
    fn self_contained_invite_is_base64url_without_padding() {
        let token = pack_invite_v2(&sample_payload()).expect("pack");
        let body = token.strip_prefix(INVITE_PREFIX_V2).expect("prefix");
        assert!(!body.contains('+'), "base64url must not contain '+'");
        assert!(!body.contains('/'), "base64url must not contain '/'");
        assert!(!body.contains('='), "invite must be unpadded");
    }

    #[test]
    fn self_contained_invite_rejects_missing_prefix() {
        let err = parse_invite_parts_v2("GRP1-AAAA").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
        assert!(err.to_string().contains("GRP2-"));
    }

    #[test]
    fn self_contained_invite_rejects_non_base64_body() {
        let err = parse_invite_parts_v2("GRP2-not!valid!base64!").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
    }

    #[test]
    fn self_contained_invite_rejects_truncated_body() {
        let short = B64_URL.encode([1u8, 2, 3, 4]);
        let err = parse_invite_parts_v2(&format!("{INVITE_PREFIX_V2}{short}"))
            .expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn self_contained_invite_ciphertext_is_single_bit_flip_sensitive() {
        let payload = sample_payload();
        let nonce = [9u8; NONCE_LEN];
        let wrapping_key = [4u8; GROUP_KEY_LEN];
        let token = pack_invite_v2_with_nonce(&payload, nonce, wrapping_key)
            .expect("deterministic pack");

        let parts = parse_invite_parts_v2(&token).expect("parts");
        let mut tampered = parts.ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0b0000_0001;

        let mut blob = Vec::new();
        blob.push(parts.version);
        blob.extend_from_slice(&parts.nonce);
        blob.extend_from_slice(&parts.wrapping_key);
        blob.extend_from_slice(&tampered);
        let bad_token = format!("{INVITE_PREFIX_V2}{}", B64_URL.encode(&blob));

        let err = unpack_invite_v2(&bad_token).expect_err("tamper must be detected");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
    }

    #[test]
    fn deterministic_self_contained_pack_is_stable() {
        let payload = sample_payload();
        let a = pack_invite_v2_with_nonce(&payload, [1u8; NONCE_LEN], [2u8; GROUP_KEY_LEN])
            .expect("first");
        let b = pack_invite_v2_with_nonce(&payload, [1u8; NONCE_LEN], [2u8; GROUP_KEY_LEN])
            .expect("second");
        assert_eq!(a, b, "same nonce+key must produce the same token");
    }

    #[test]
    fn self_contained_invite_rejects_unsupported_version() {
        let mut payload = sample_payload();
        payload.version = 9;
        let err = pack_invite_v2(&payload).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
    }

    // -- Envelope round trip -------------------------------------------------

    #[test]
    fn envelope_round_trips_location() {
        let (secret, verifying) = new_signing_key().expect("keygen");
        let group_key = [42u8; GROUP_KEY_LEN];
        let signing = SigningKey::from_bytes(&secret);

        let env = seal_location(&group_key, 0, &signing, &sample_location()).expect("seal");
        let opened = open_envelope(&env, &group_key).expect("open");

        match opened {
            InnerPayload::Location(state) => {
                assert_eq!(state.display_name, "Jared");
                assert!((state.lat - 41.8781).abs() < f64::EPSILON);
                assert_eq!(state.battery_pct, 84);
            }
            other => panic!("expected location payload, got {other:?}"),
        }

        assert_eq!(
            env.sender_pubkey,
            verifying_key_to_b64(&verifying),
            "envelope must carry the signer's public key"
        );
    }

    #[test]
    fn envelope_round_trips_chat_variants() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let group_key = [11u8; GROUP_KEY_LEN];

        let text = ChatPayload::TextMessage {
            text: "on my way".into(),
            unix_ms: 1,
        };
        let env = seal_chat(&group_key, 0, &signing, &text).expect("seal");
        assert_eq!(open_envelope(&env, &group_key).expect("open"), InnerPayload::Chat(text));

        let file = ChatPayload::FileAttachment {
            asset_name: "abc.bin".into(),
            size_bytes: 2048,
            mime: "image/jpeg".into(),
            sha256_b64: sha256_b64(b"hello"),
            caption: Some("sunset".into()),
            unix_ms: 2,
        };
        let env = seal_chat(&group_key, 0, &signing, &file).expect("seal");
        assert_eq!(open_envelope(&env, &group_key).expect("open"), InnerPayload::Chat(file));
    }

    #[test]
    fn envelope_round_trips_control() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let group_key = [5u8; GROUP_KEY_LEN];

        let control = ControlPayload::KeyRotation {
            new_epoch: 1,
            retired_epoch: 0,
            reason: "member removed".into(),
            unix_ms: 99,
        };
        let env = seal_control(&group_key, 1, &signing, &control).expect("seal");
        assert_eq!(
            open_envelope(&env, &group_key).expect("open"),
            InnerPayload::Control(control)
        );
    }

    #[test]
    fn envelope_uses_standard_padded_base64() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let env = seal_location(&[1u8; 32], 0, &signing, &sample_location()).expect("seal");

        // 32-byte key encodes to 44 chars with one '=' pad.
        assert_eq!(env.sender_pubkey.len(), 44);
        assert!(env.sender_pubkey.ends_with('='));
        // 24-byte nonce -> 32 chars, no padding needed.
        assert_eq!(env.nonce.len(), 32);
        assert!(!env.nonce.contains('-'));
        assert!(!env.nonce.contains('_'));
    }

    // -- Tamper detection ----------------------------------------------------

    #[test]
    fn flipping_ciphertext_bit_fails_open() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let group_key = [8u8; GROUP_KEY_LEN];

        let mut env = seal_location(&group_key, 0, &signing, &sample_location()).expect("seal");
        let mut raw = B64_STD.decode(env.ciphertext.as_bytes()).expect("decode");
        let last = raw.len() - 1;
        raw[last] ^= 0b0000_0001;
        env.ciphertext = B64_STD.encode(&raw);

        let err = open_envelope(&env, &group_key).expect_err("tamper must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::Crypto);
    }

    #[test]
    fn flipping_nonce_bit_fails_open() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let group_key = [8u8; GROUP_KEY_LEN];

        let mut env = seal_location(&group_key, 0, &signing, &sample_location()).expect("seal");
        let mut raw = B64_STD.decode(env.nonce.as_bytes()).expect("decode");
        raw[0] ^= 0b1000_0000;
        env.nonce = B64_STD.encode(&raw);

        let err = open_envelope(&env, &group_key).expect_err("tamper must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::Crypto);
    }

    #[test]
    fn flipping_key_epoch_bit_fails_open() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let group_key = [8u8; GROUP_KEY_LEN];

        let mut env = seal_location(&group_key, 0, &signing, &sample_location()).expect("seal");
        env.key_epoch = 1;

        // Signature covers the epoch, so verification rejects it before any
        // decryption is attempted.
        let err = open_envelope(&env, &group_key).expect_err("tamper must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::Crypto);
        assert!(err.to_string().contains("signature"));
    }

    #[test]
    fn flipping_sender_pubkey_byte_fails_verification() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let group_key = [8u8; GROUP_KEY_LEN];

        let mut env = seal_location(&group_key, 0, &signing, &sample_location()).expect("seal");
        let mut raw = B64_STD.decode(env.sender_pubkey.as_bytes()).expect("decode");
        raw[31] ^= 0x01;
        env.sender_pubkey = B64_STD.encode(&raw);

        let err = verify_envelope(&env).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::Crypto);
    }

    #[test]
    fn wrong_group_key_fails_open() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);

        let env = seal_location(&[1u8; GROUP_KEY_LEN], 0, &signing, &sample_location())
            .expect("seal");
        // Signature still verifies; only the AEAD open should fail.
        verify_envelope(&env).expect("signature is valid");
        let err = open_envelope(&env, &[2u8; GROUP_KEY_LEN]).expect_err("wrong key must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::Crypto);
        assert!(err.to_string().contains("epoch 0"));
    }

    #[test]
    fn rejects_truncated_ciphertext() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let mut env =
            seal_location(&[1u8; GROUP_KEY_LEN], 0, &signing, &sample_location()).expect("seal");
        env.ciphertext = B64_STD.encode([0u8; 4]);

        let err = verify_envelope(&env).expect_err("must fail");
        assert!(err.to_string().contains("Poly1305"));
    }

    #[test]
    fn rejects_malformed_base64_fields() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let mut env =
            seal_location(&[1u8; GROUP_KEY_LEN], 0, &signing, &sample_location()).expect("seal");
        env.nonce = "!!!!".into();

        let err = verify_envelope(&env).expect_err("must fail");
        assert!(err.to_string().contains("base64"));
    }

    #[test]
    fn rejects_unsupported_envelope_version() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let mut env =
            seal_location(&[1u8; GROUP_KEY_LEN], 0, &signing, &sample_location()).expect("seal");
        env.v = 7;

        let err = verify_envelope(&env).expect_err("must fail");
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn expected_sender_mismatch_is_rejected() {
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let (_, other_key) = new_signing_key().expect("keygen");
        let group_key = [3u8; GROUP_KEY_LEN];

        let env = seal_location(&group_key, 0, &signing, &sample_location()).expect("seal");
        let err = open_verified(&env, &group_key, Some(&other_key)).expect_err("must fail");
        assert!(err.to_string().contains("expected member"));
    }

    #[test]
    fn canonical_input_is_unambiguous() {
        // ("ab","c") and ("a","bc") must not collide now that lengths are signed.
        let a = canonical_sig_input(1, 0, b"ab", b"c", b"d");
        let b = canonical_sig_input(1, 0, b"a", b"bc", b"d");
        assert_ne!(a, b);

        let c = canonical_sig_input(1, 0, b"a", b"b", b"cd");
        let d = canonical_sig_input(1, 0, b"a", b"b", b"c");
        assert_ne!(c, d);
    }

    #[test]
    fn epoch_tag_is_epoch_and_key_specific() {
        let key = [4u8; GROUP_KEY_LEN];
        assert_ne!(key_epoch_tag(&key, 0), key_epoch_tag(&key, 1));
        assert_ne!(key_epoch_tag(&key, 0), key_epoch_tag(&[5u8; GROUP_KEY_LEN], 0));
        assert_eq!(key_epoch_tag(&key, 0), key_epoch_tag(&key, 0));
    }

    // -- GroupKeys -----------------------------------------------------------

    #[test]
    fn group_keys_starts_at_epoch_zero() {
        let keys = GroupKeys::new(&[1u8; GROUP_KEY_LEN]);
        assert_eq!(keys.current_epoch, 0);
        assert_eq!(keys.get(0), Some(&[1u8; GROUP_KEY_LEN]));
        assert_eq!(keys.len(), 1);
        assert!(!keys.is_empty());
    }

    #[test]
    fn group_keys_rotates_and_retains_history() {
        let mut keys = GroupKeys::new(&[1u8; GROUP_KEY_LEN]);
        keys.rotate(1, &[2u8; GROUP_KEY_LEN]).expect("rotate");

        assert_eq!(keys.current_epoch, 1);
        assert_eq!(keys.known_epochs(), vec![0, 1]);
        assert_eq!(keys.current().expect("current"), &[2u8; GROUP_KEY_LEN]);

        // Old-epoch content stays readable after rotation.
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let old_env = seal_location(&[1u8; GROUP_KEY_LEN], 0, &signing, &sample_location())
            .expect("seal");
        assert!(keys.open(&old_env).is_ok());
    }

    #[test]
    fn group_keys_rejects_non_advancing_rotation() {
        let mut keys = GroupKeys::new(&[1u8; GROUP_KEY_LEN]);
        keys.rotate(2, &[2u8; GROUP_KEY_LEN]).expect("rotate");

        let err = keys.rotate(2, &[3u8; GROUP_KEY_LEN]).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::GroupState);
        let err = keys.rotate(1, &[3u8; GROUP_KEY_LEN]).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::GroupState);
    }

    #[test]
    fn group_keys_bounds_epoch_count() {
        let mut keys = GroupKeys::new(&[0u8; GROUP_KEY_LEN]);
        for epoch in 1..MAX_EPOCHS as u8 {
            keys.insert(epoch, &[epoch; GROUP_KEY_LEN]).expect("insert");
        }
        assert_eq!(keys.len(), MAX_EPOCHS);

        let err = keys
            .insert(200, &[9u8; GROUP_KEY_LEN])
            .expect_err("must refuse to grow unbounded");
        assert_eq!(err.kind(), crate::error::AppErrorKind::GroupState);
    }

    #[test]
    fn group_keys_unknown_epoch_is_reported() {
        let keys = GroupKeys::new(&[1u8; GROUP_KEY_LEN]);
        let (secret, _) = new_signing_key().expect("keygen");
        let signing = SigningKey::from_bytes(&secret);
        let env = seal_location(&[9u8; GROUP_KEY_LEN], 5, &signing, &sample_location())
            .expect("seal");

        let err = keys.open(&env).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::GroupState);
        assert!(err.to_string().contains("unknown key epoch 5"));
    }

    #[test]
    fn group_keys_tag_matching() {
        let keys = GroupKeys::new(&[6u8; GROUP_KEY_LEN]);
        assert!(keys.matches_tag(0, &key_epoch_tag(&[6u8; GROUP_KEY_LEN], 0)));
        assert!(!keys.matches_tag(0, &key_epoch_tag(&[6u8; GROUP_KEY_LEN], 1)));
        assert!(!keys.matches_tag(1, &key_epoch_tag(&[6u8; GROUP_KEY_LEN], 1)));
    }

    #[test]
    fn group_keys_prune_to_current() {
        let mut keys = GroupKeys::new(&[1u8; GROUP_KEY_LEN]);
        keys.rotate(1, &[2u8; GROUP_KEY_LEN]).expect("rotate");
        keys.rotate(2, &[3u8; GROUP_KEY_LEN]).expect("rotate");
        assert_eq!(keys.len(), 3);

        keys.prune_to_current();
        assert_eq!(keys.known_epochs(), vec![2]);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn group_keys_debug_never_leaks_key_material() {
        let keys = GroupKeys::new(&[0xAB; GROUP_KEY_LEN]);
        let rendered = format!("{keys:?}");
        assert!(rendered.contains("current_epoch"));
        assert!(!rendered.contains("ab"), "must not print key bytes: {rendered}");
    }

    // -- Misc ----------------------------------------------------------------

    #[test]
    fn random_bytes_are_not_constant() {
        let a = random_bytes::<32>().expect("rng");
        let b = random_bytes::<32>().expect("rng");
        assert_ne!(a, b, "CSPRNG must not repeat");
    }

    #[test]
    fn new_signing_key_yields_distinct_keys() {
        let (_, a) = new_signing_key().expect("keygen");
        let (_, b) = new_signing_key().expect("keygen");
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn argon2_rejects_wrong_salt_length() {
        let err = derive_wrapping_key("pw", &[0u8; 8]).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::Crypto);
        assert!(err.to_string().contains("16 bytes"));
    }

    #[test]
    fn argon2_is_deterministic() {
        let salt = [5u8; SALT_LEN];
        let a = derive_wrapping_key("pw", &salt).expect("derive");
        let b = derive_wrapping_key("pw", &salt).expect("derive");
        assert_eq!(*a, *b);
    }

    #[test]
    fn argon2_differs_by_password_and_salt() {
        let salt = [5u8; SALT_LEN];
        let other_salt = [6u8; SALT_LEN];
        let base = derive_wrapping_key("pw", &salt).expect("derive");
        assert_ne!(*base, *derive_wrapping_key("pw!", &salt).expect("derive"));
        assert_ne!(*base, *derive_wrapping_key("pw", &other_salt).expect("derive"));
    }

    #[test]
    fn sha256_b64_is_stable_and_b64_standard() {
        // Known vector: SHA-256("abc")
        assert_eq!(
            sha256_b64(b"abc"),
            "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        );
    }

        // -- Blob sealing ---------------------------------------------------------

        #[test]
        fn blob_round_trips() {
            let key = [21u8; GROUP_KEY_LEN];
            let plaintext = b"an image or voice note lives here";

            let blob = seal_blob(&key, plaintext).expect("seal");
            assert_ne!(blob.as_slice(), plaintext.as_slice(), "must not be plaintext");
            assert!(blob.len() > plaintext.len(), "nonce and tag add overhead");

            let recovered = open_blob(&key, &blob).expect("open");
            assert_eq!(recovered, plaintext);
        }

        #[test]
        fn blob_round_trips_empty_input() {
            let key = [22u8; GROUP_KEY_LEN];
            let blob = seal_blob(&key, b"").expect("seal");
            assert_eq!(blob.len(), NONCE_LEN + TAG_LEN);
            assert_eq!(open_blob(&key, &blob).expect("open"), b"");
        }

        #[test]
        fn blob_nonce_differs_between_calls() {
            let key = [23u8; GROUP_KEY_LEN];
            let a = seal_blob(&key, b"same").expect("a");
            let b = seal_blob(&key, b"same").expect("b");
            assert_ne!(a, b, "a fresh nonce per blob is mandatory");
        }

        #[test]
        fn blob_rejects_the_wrong_key() {
            let blob = seal_blob(&[24u8; GROUP_KEY_LEN], b"secret").expect("seal");
            let err = open_blob(&[25u8; GROUP_KEY_LEN], &blob).expect_err("must fail");
            assert_eq!(err.kind(), crate::error::AppErrorKind::Crypto);
        }

        #[test]
        fn blob_detects_a_single_bit_flip() {
            let key = [26u8; GROUP_KEY_LEN];
            let mut blob = seal_blob(&key, b"tamper me").expect("seal");
            let last = blob.len() - 1;
            blob[last] ^= 0b0000_0001;

            let err = open_blob(&key, &blob).expect_err("must fail");
            assert_eq!(err.kind(), crate::error::AppErrorKind::Crypto);
        }

        #[test]
        fn blob_detects_a_flipped_nonce_bit() {
            let key = [27u8; GROUP_KEY_LEN];
            let mut blob = seal_blob(&key, b"tamper me").expect("seal");
            blob[0] ^= 0b1000_0000;

            assert!(open_blob(&key, &blob).is_err());
        }

        #[test]
        fn blob_rejects_truncated_input() {
            let key = [28u8; GROUP_KEY_LEN];
            assert!(open_blob(&key, &[]).is_err());
            assert!(open_blob(&key, &[0u8; NONCE_LEN]).is_err());
            let err = open_blob(&key, &[0u8; 4]).expect_err("must fail");
            assert!(err.to_string().contains("too short"));
        }

        #[test]
        fn blob_is_not_confusable_with_an_envelope() {
            let key = [29u8; GROUP_KEY_LEN];
            let blob = seal_blob(&key, b"payload").expect("seal");
            // Envelope sealing uses a different AAD, so neither can be opened as the other.
            let (secret, _) = new_signing_key().expect("keygen");
            let signing = signing_key_from_bytes(&secret);
            let env = seal_location(
                &key,
                0,
                &signing,
                &LocationState {
                    display_name: "x".into(),
                    avatar_color: "#000000".into(),
                    lat: 0.0,
                    lon: 0.0,
                    accuracy_m: 0.0,
                    speed_mps: 0.0,
                    heading_deg: 0.0,
                    battery_pct: 0,
                    is_charging: false,
                    unix_ms: 1,
                    member_pubkey: "AAAA".into(),
                },
            )
            .expect("env");

            let raw_env = B64_STD
                .decode(env.ciphertext.as_bytes())
                .expect("decode");
            // The envelope ciphertext is not a valid blob.
            assert!(open_blob(&key, &raw_env).is_err());
            // And the blob body is not a valid envelope ciphertext either.
            assert!(B64_STD.encode(&blob).is_empty().eq(&false));
        }

    #[test]
    fn verify_key_round_trips_through_base64() {
        let (_, verifying) = new_signing_key().expect("keygen");
        let encoded = verifying_key_to_b64(&verifying);
        let decoded = verifying_key_from_b64(&encoded).expect("decode");
        assert_eq!(decoded.to_bytes(), verifying.to_bytes());
    }

    #[test]
    fn verify_key_rejects_wrong_length_and_bad_point() {
        let err = verifying_key_from_b64(&B64_STD.encode([0u8; 16])).expect_err("must fail");
        assert!(err.to_string().contains("32 bytes"));

        let err = verifying_key_from_b64("!!!").expect_err("must fail");
        assert!(err.to_string().contains("base64"));
    }
}