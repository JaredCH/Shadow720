//! In-memory group state: the aggregate that ties keys, identity, roster, chat,
//! and the shared request budget together.
//!
//! This module owns *policy* — when to poll, when to publish a location, which
//! key epoch to use, which peers are blocked — and delegates *mechanism* to
//! [`crate::crypto`], [`crate::geo_filter`], and [`crate::wire`].
//!
//! Nothing here writes to the network directly, which makes the whole decision
//! surface unit-testable without a sandbox repository.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use zeroize::Zeroizing;

use crate::crypto::{
    self, ChatPayload, ControlPayload, EncryptedEnvelope, GroupKeys, InnerPayload,
    InviteCredentialsPayload, LocationState, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
};
use crate::error::{AppError, Result};
use crate::geo_filter::{
    haversine_m, AdaptiveBackoff, Fix, GeoGate, Jitter, Publish, RateLimitHalt, SkipReason,
};
use crate::wire::IssueComment;

/// Poll cadence for the chat channel, from `PLAN_ADDENDUM_v1.md` §A5.
///
/// Nostr relays push over WebSocket and there is no shared request budget, so
/// the cadence can be tighter than a REST-backed store allowed.
pub const CHAT_INTERVAL_SECS: u64 = 5;
/// Poll cadence for the roster channel.
pub const ROSTER_INTERVAL_SECS: u64 = 15;
/// A roster comment older than this is treated as a stale/offline member.
pub const MEMBER_STALE_SECS: i64 = 300;
/// A roster comment older than this is pruned from the UI entirely.
pub const MEMBER_EXPIRE_SECS: i64 = 3_600;
/// Longest text message accepted, before envelope overhead.
pub const MAX_TEXT_CHARS: usize = 4_000;

/// Roles the owner may assign. Owner itself is pinned in the invite.
pub fn is_assignable_role(role: &str) -> bool {
    matches!(role, "admin" | "member")
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// A device's long-term identity.
///
/// The secret is zeroized on drop. `pubkey_b64` is the stable identifier used for
/// block lists and for verifying roster comments.
pub struct Identity {
    signing_key: SigningKey,
    secret_bytes: Zeroizing<[u8; SECRET_KEY_LEN]>,
    pub pubkey_b64: String,
    pub verifying_key: VerifyingKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret scalar.
        f.debug_struct("Identity")
            .field("pubkey_b64", &self.pubkey_b64)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Restore an identity from its stored 32-byte secret.
        pub fn from_secret(secret: [u8; SECRET_KEY_LEN]) -> Self {
            let signing_key = crypto::signing_key_from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            secret_bytes: Zeroizing::new(secret),
            pubkey_b64: crypto::verifying_key_to_b64(&verifying_key),
            verifying_key,
        }
    }

    /// Generate a fresh identity.
    pub fn generate() -> Result<Self> {
        let (secret, verifying_key) = crypto::new_signing_key()?;
            let signing_key = crypto::signing_key_from_bytes(&secret);
        Ok(Self {
            signing_key,
            secret_bytes: secret,
            pubkey_b64: crypto::verifying_key_to_b64(&verifying_key),
            verifying_key,
        })
    }

    /// Borrow the signing key, for sealing envelopes.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// The raw secret, for persisting into the vault.
        pub fn secret_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.secret_bytes
    }

    /// Short, human-recognisable prefix of the public key.
    ///
    /// Two phones in the same room need a way to tell their own entry apart
    /// without reading a 44-character Base64 string aloud.
    pub fn fingerprint(&self) -> String {
        let stripped: String = self.pubkey_b64.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        stripped.chars().take(8).collect::<String>().to_uppercase()
    }
}

/// `SigningKeyBytes` re-export helper so callers do not need to know the dalek type.
pub type SecretBytes = [u8; SECRET_KEY_LEN];

/// Borrow the raw bytes of an Ed25519 verifying key.
pub fn verifying_key_bytes(key: &VerifyingKey) -> [u8; PUBLIC_KEY_LEN] {
    key.to_bytes()
}

// ---------------------------------------------------------------------------
// Roster and chat view models
// ---------------------------------------------------------------------------

/// A decrypted member entry, ready for rendering.
///
/// Serialized as camelCase to match the TypeScript `MemberView`; without this the
/// UI received `avatar_color` and crashed reading `avatarColor`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberView {
    /// The member's roster slot handle, i.e. the value replaced on updates.
    pub comment_id: u64,
    /// Member's Ed25519 public key, Base64.
    pub pubkey_b64: String,
    pub display_name: String,
    pub avatar_color: String,
    pub lat: f64,
    pub lon: f64,
    pub accuracy_m: f32,
    pub speed_mps: f32,
    pub heading_deg: f32,
    /// How the member appears to be moving, derived from `speed_mps`.
    pub activity: crate::geo_filter::Activity,
    pub battery_pct: u8,
    pub is_charging: bool,
    pub unix_ms: i64,
    /// True when this entry belongs to the local device.
    pub is_self: bool,
    /// True when the last fix is older than [`MEMBER_STALE_SECS`].
    pub is_stale: bool,
    /// True when the member's key is on the local block list.
    pub is_blocked: bool,
    /// `owner`, `admin`, or `member`. Owner is the key pinned in the invite.
    pub role: String,
}

/// A decrypted chat entry, ready for rendering.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ChatItem {
    Text {
        comment_id: u64,
        nostr_event_id: Option<String>,
        sender_pubkey_b64: String,
        text: String,
        unix_ms: i64,
        is_self: bool,
        /// True when [`GroupState::should_display`] filtered the sender out.
        is_blocked: bool,
    },
    File {
        comment_id: u64,
        nostr_event_id: Option<String>,
        sender_pubkey_b64: String,
        asset_name: String,
        size_bytes: u64,
        mime: String,
        sha256_b64: String,
        caption: Option<String>,
        unix_ms: i64,
        is_self: bool,
        is_blocked: bool,
        unavailable: bool,
    },
    Moderation {
        comment_id: u64,
        sender_pubkey_b64: String,
        target_comment_id: u64,
        reason: String,
        unix_ms: i64,
    },
    /// An envelope that arrived but could not be read; surfaced rather than
    /// silently dropped, because silent loss looks identical to censorship.
    Undecryptable {
        comment_id: u64,
        reason: String,
    },
}

/// Why a comment could not be turned into a view model.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodeFailure {
    /// Signature invalid, or the payload was tampered with.
    Crypto(String),
    /// The envelope parsed, but it was a control message in a chat slot.
    UnexpectedKind,
    /// The envelope used an epoch this device does not hold.
    UnknownEpoch(u8),
}

impl DecodeFailure {
    /// Explain the failure without leaking key material.
    pub fn reason(&self) -> String {
        match self {
            DecodeFailure::Crypto(message) => message.clone(),
            DecodeFailure::UnexpectedKind => "payload was not a chat event".to_string(),
            DecodeFailure::UnknownEpoch(epoch) => format!("unknown key epoch {epoch}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Local preferences
// ---------------------------------------------------------------------------

/// Local-only preferences. Never transmitted.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Preferences {
    pub display_name: String,
    pub avatar_color: String,
    /// Public keys the user has blocked or muted.
    pub blocked_pubkeys: HashSet<String>,
    /// True once the user accepted the EULA.
    pub accepted_eula: bool,
    /// True once the user accepted the location disclosure.
    pub accepted_location_disclosure: bool,
    /// True once the user granted background location.
    pub enabled_background_location: bool,
}

impl Preferences {
    /// Default avatar colour and label for a brand-new install.
    pub fn seeded() -> Self {
        Self {
            display_name: String::new(),
            avatar_color: "#5b8cff".to_string(),
            blocked_pubkeys: HashSet::new(),
            accepted_eula: false,
            accepted_location_disclosure: false,
            enabled_background_location: false,
        }
    }

    /// True when the consent gates have all been cleared.
    pub fn is_onboarding_complete(&self) -> bool {
        self.accepted_eula && self.accepted_location_disclosure && !self.display_name.trim().is_empty()
    }
}

// ---------------------------------------------------------------------------
// Group state
// ---------------------------------------------------------------------------

/// Everything the app needs to operate in a group, plus the policy state that
/// decides how often it talks to the relays.
pub struct GroupState {
    /// Which storage backend holds this group.
    pub backend: crate::storage::Backend,
    /// Relay URLs, on the Nostr backend.
    pub relays: Vec<String>,
    /// Blossom servers for blobs, on the Nostr backend.
    pub blossom_servers: Vec<String>,
    /// Group id, used as the `d` tag on every Nostr event.
    pub group_id: String,
    pub identity: Identity,
    pub keys: RwLock<GroupKeys>,
    pub preferences: RwLock<Preferences>,
    pub is_host: bool,
    pub host_pubkey_b64: String,
    pub group_label: String,

    /// This device's own roster slot handle, once it has joined the roster.
    pub my_comment_id: RwLock<Option<u64>>,
    /// Movement gate for location publishing.
    pub gate: RwLock<GeoGate>,
    /// Backoff for the chat channel.
    pub chat_backoff: RwLock<AdaptiveBackoff>,
    /// Backoff for the roster channel.
    pub roster_backoff: RwLock<AdaptiveBackoff>,
    /// Shared rate-limit halt switch.
    pub rate_halt: RwLock<RateLimitHalt>,
    /// Jitter source, serialized because SplitMix64 is stateful.
    pub jitter: AsyncMutex<Jitter>,
    /// Latest decrypted roster.
    pub roster: RwLock<Vec<MemberView>>,
    /// Latest decrypted chat, oldest first.
    /// Host-assigned roles. Missing keys are members. The pinned host is always owner.
    pub roles: RwLock<HashMap<String, String>>,
    /// True once this session has published the saved role set.
    pub roles_announced: RwLock<bool>,
    pub chat: RwLock<Vec<ChatItem>>,
    /// Own latest known fix, so the UI can render self immediately.
    pub my_fix: RwLock<Option<Fix>>,
    /// Own latest battery reading, so a publish carries it even when the fix that
    /// triggered the publish did not include one.
    pub my_battery: RwLock<(u8, bool)>,
    /// Recent positions per member, oldest first, for the fading trail.
    pub trails: RwLock<std::collections::HashMap<String, Vec<TrailPoint>>>,
    /// Month-long track log, kept on this device only.
    pub history: RwLock<crate::history::TrackHistory>,
    /// Fixes that could not be published yet, replayed when a relay answers.
    pub outbox: RwLock<crate::outbox::Outbox>,
    /// Smoothed activity per member, so a single noisy fix cannot flip the label.
    pub activity: RwLock<HashMap<String, crate::geo_filter::ActivityTracker>>,
}

/// One recorded position on a member's trail.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrailPoint {
    pub lat: f64,
    pub lon: f64,
    pub unix_ms: i64,
}

/// Most points kept per member.
///
/// A trail is a visual aid, not a track log: 60 points at the 30-second publish
/// floor is roughly half an hour of movement, which is what a "where have they
/// been" glance needs. Keeping more would grow without bound in a long session.
pub const TRAIL_MAX_POINTS: usize = 60;
/// Points closer together than this are collapsed, in metres.
pub const TRAIL_MIN_SPACING_M: f64 = 10.0;

impl std::fmt::Debug for GroupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupState")
            .field("backend", &self.backend.location())
            .field("identity", &self.identity)
            .field("is_host", &self.is_host)
            .field("group_label", &self.group_label)
            .field("current_epoch", &self.keys.read().current_epoch)
            .field("roster_len", &self.roster.read().len())
            .field("chat_len", &self.chat.read().len())
            .finish_non_exhaustive()
    }
}

/// Verify a closure proof against the host key pinned by the invitation.
pub fn verify_closure_proof(host_pubkey: &str, group_id: &str, proof: &str) -> bool {
    use base64::Engine;
    let Ok(key) = crypto::verifying_key_from_b64(host_pubkey) else {
        return false;
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(proof) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(&bytes) else {
        return false;
    };
    let message = format!("shadow720/group-close/v1\0{group_id}");
    key.verify_strict(message.as_bytes(), &signature).is_ok()
}

impl GroupState {
    /// Create a host signature bound to this group and the closure protocol.
    pub fn closure_proof(&self) -> Result<String> {
        use base64::Engine;
        use ed25519_dalek::Signer;
        if !self.is_host || self.identity.pubkey_b64 != self.host_pubkey_b64 {
            return Err(AppError::group_state("only the pinned host can close the group"));
        }
        let message = format!("shadow720/group-close/v1\0{}", self.group_id);
        Ok(base64::engine::general_purpose::STANDARD.encode(
            self.identity.signing_key().sign(message.as_bytes()).to_bytes(),
        ))
    }

    /// Verify a closure using the host key pinned in the invitation.
    pub fn verifies_closure(&self, group_id: &str, proof: &str) -> bool {
        if group_id != self.group_id {
            return false;
        }
        verify_closure_proof(&self.host_pubkey_b64, group_id, proof)
    }

    /// Build state from an unpacked invite plus a locally generated identity.
    pub fn from_invite(
        invite: &InviteCredentialsPayload,
        identity: Identity,
        preferences: Preferences,
        is_host: bool,
    ) -> Result<Self> {
        invite.validate()?;

        let backend = match invite.backend {
            crate::storage::BackendKind::Nostr => {
                crate::storage::Backend::Nostr(crate::storage::NostrBackend {
                    group_id: invite.group_id.clone(),
                    relays: invite.relays.clone(),
                    blossom_servers: invite.blossom_servers.clone(),
                })
            }
        };

        let host_pubkey_b64 = if invite.host_pubkey.trim().is_empty() {
            // A host that has not published its key yet is only possible for a
            // brand-new group the host itself is creating.
            if !is_host {
                return Err(AppError::InviteFormat(
                    "invite does not carry the host's public key, so roster entries cannot be verified"
                        .into(),
                ));
            }
            identity.pubkey_b64.clone()
        } else {
            // Validate the pinned host key now rather than at first use.
            crypto::verifying_key_from_b64(&invite.host_pubkey)?;
            invite.host_pubkey.clone()
        };

        let jitter = Jitter::from_entropy()?;

        Ok(Self {
            backend,
            relays: invite.relays.clone(),
            blossom_servers: invite.blossom_servers.clone(),
            group_id: invite.group_id.clone(),
            identity,
            keys: RwLock::new(GroupKeys::from_epoch(invite.key_epoch, invite.group_key())),
            preferences: RwLock::new(preferences),
            is_host,
            host_pubkey_b64,
            group_label: invite.group_label.clone(),
            my_comment_id: RwLock::new(None),
            gate: RwLock::new(GeoGate::new()),
            chat_backoff: RwLock::new(AdaptiveBackoff::new(Duration::from_secs(CHAT_INTERVAL_SECS))),
            roster_backoff: RwLock::new(AdaptiveBackoff::new(Duration::from_secs(ROSTER_INTERVAL_SECS))),
            rate_halt: RwLock::new(RateLimitHalt::new()),
            jitter: AsyncMutex::new(jitter),
            roles: RwLock::new(HashMap::new()),
            roles_announced: RwLock::new(false),
            roster: RwLock::new(Vec::new()),
            chat: RwLock::new(Vec::new()),
            my_fix: RwLock::new(None),
            my_battery: RwLock::new((0, false)),
            trails: RwLock::new(std::collections::HashMap::new()),
            history: RwLock::new(crate::history::TrackHistory::new()),
            outbox: RwLock::new(crate::outbox::Outbox::new()),
            activity: RwLock::new(HashMap::new()),
        })
    }

    /// Install roles saved in the vault. Does not mark them as announced.
    pub fn install_roles(&self, roles: &[(String, String)]) {
        let mut map = self.roles.write();
        map.clear();
        for (pubkey, role) in roles {
            if is_assignable_role(role) {
                map.insert(pubkey.clone(), role.clone());
            }
        }
        *self.roles_announced.write() = false;
    }

    /// Role peers should display for `pubkey`.
    pub fn role_of(&self, pubkey: &str) -> String {
        if pubkey == self.host_pubkey_b64 {
            return "owner".to_string();
        }
        self.roles
            .read()
            .get(pubkey)
            .cloned()
            .filter(|role| is_assignable_role(role))
            .unwrap_or_else(|| "member".to_string())
    }

    /// Assign `admin` or `member`. The pinned host cannot be reassigned.
    pub fn assign_role(&self, pubkey: &str, role: &str) -> Result<()> {
        if !self.is_host || self.identity.pubkey_b64 != self.host_pubkey_b64 {
            return Err(AppError::group_state("only the owner may assign roles"));
        }
        if pubkey == self.host_pubkey_b64 || pubkey == self.identity.pubkey_b64 {
            return Err(AppError::invalid_argument("the owner role is pinned by the invite and cannot be changed"));
        }
        if !is_assignable_role(role) {
            return Err(AppError::invalid_argument("role must be admin or member"));
        }
        self.roles.write().insert(pubkey.to_string(), role.to_string());
        self.stamp_roles();
        *self.roles_announced.write() = false;
        Ok(())
    }

    /// Current assignable grants, for publishing and for the vault.
    pub fn role_grants(&self) -> Vec<crypto::RoleGrant> {
        let mut grants: Vec<crypto::RoleGrant> = self
            .roles
            .read()
            .iter()
            .filter(|(_, role)| is_assignable_role(role))
            .map(|(pubkey, role)| crypto::RoleGrant {
                member_pubkey: pubkey.clone(),
                role: role.clone(),
            })
            .collect();
        grants.sort_by(|a, b| a.member_pubkey.cmp(&b.member_pubkey));
        grants
    }

    /// Apply the newest host-signed role set found in `comments`.
    pub fn apply_role_controls(&self, comments: &[IssueComment]) {
        let mut best: Option<(i64, Vec<crypto::RoleGrant>)> = None;
        for comment in comments {
            let Ok(envelope) = serde_json::from_str::<EncryptedEnvelope>(&comment.body) else {
                continue;
            };
            if envelope.sender_pubkey != self.host_pubkey_b64 {
                continue;
            }
            let Ok(payload) = self.keys.read().open(&envelope) else {
                continue;
            };
            let InnerPayload::Control(ControlPayload::RoleSet { grants, unix_ms }) = payload else {
                continue;
            };
            if best.as_ref().map(|(seen, _)| unix_ms >= *seen).unwrap_or(true) {
                best = Some((unix_ms, grants));
            }
        }
        let Some((_, grants)) = best else {
            return;
        };
        let mut map = self.roles.write();
        map.clear();
        for grant in grants {
            if is_assignable_role(&grant.role) && grant.member_pubkey != self.host_pubkey_b64 {
                map.insert(grant.member_pubkey, grant.role);
            }
        }
        drop(map);
        self.stamp_roles();
    }

    fn stamp_roles(&self) {
        for member in self.roster.write().iter_mut() {
            member.role = self.role_of(&member.pubkey_b64);
        }
    }

    /// Seal the current role set under the live group key.
    pub fn build_role_envelope(&self, unix_ms: i64) -> Result<EncryptedEnvelope> {
        if !self.is_host {
            return Err(AppError::group_state("only the owner may publish roles"));
        }
        let key = self.current_group_key()?;
        let payload = ControlPayload::RoleSet {
            grants: self.role_grants(),
            unix_ms,
        };
        crypto::seal_control(&key, self.current_epoch(), self.identity.signing_key(), &payload)
    }

    /// The group key for the current epoch.
    pub fn current_group_key(&self) -> Result<[u8; 32]> {
        let keys = self.keys.read();
        keys.current().copied()
    }

    /// Current key epoch.
    pub fn current_epoch(&self) -> u8 {
        self.keys.read().current_epoch
    }

    // -- Preferences and moderation -------------------------------------------

    /// Replace local preferences wholesale.
    pub fn set_preferences(&self, preferences: Preferences) {
        *self.preferences.write() = preferences;
    }

    /// Snapshot local preferences.
    pub fn preferences(&self) -> Preferences {
        self.preferences.read().clone()
    }

    /// Local block list.
    pub fn blocked_pubkeys(&self) -> HashSet<String> {
        self.preferences.read().blocked_pubkeys.clone()
    }

    /// Block or mute a member by public key.
    ///
    /// Blocking is purely local: nothing is sent to a relay, so the blocked party
    /// cannot tell they were blocked. Returns `true` when the list changed.
    pub fn block(&self, pubkey_b64: &str) -> bool {
        let mut preferences = self.preferences.write();
        preferences.blocked_pubkeys.insert(pubkey_b64.to_string())
    }

    /// Remove a member from the block list. Returns `true` when the list changed.
    pub fn unblock(&self, pubkey_b64: &str) -> bool {
        let mut preferences = self.preferences.write();
        preferences.blocked_pubkeys.remove(pubkey_b64)
    }

    /// True when a sender should be hidden from chat and the map.
    pub fn is_blocked(&self, pubkey_b64: &str) -> bool {
        // Never hide our own content, even if our own key somehow landed in the
        // list (e.g. a corrupt preferences file).
        if pubkey_b64 == self.identity.pubkey_b64 {
            return false;
        }
        self.preferences.read().blocked_pubkeys.contains(pubkey_b64)
    }

    // -- Location policy ------------------------------------------------------

    /// Decide whether a GPS fix is worth publishing, and record it if so.
    ///
    /// Keeps the local "my fix" cache current either way, so the UI can show the
    /// device's own position without spending a request.
    pub fn consider_location(&self, fix: Fix) -> Result<Publish> {
        fix.validate()?;
        let decision = {
            let gate = self.gate.read();
            gate.evaluate(&fix)?
        };

        *self.my_fix.write() = Some(fix);

        if decision == Publish::Yes {
            // Record optimistically: the caller may still fail to PATCH, in which
            // case `record_publish_failed` re-arms the gate.
            let mut gate = self.gate.write();
            gate.record_published(fix);
        }
        Ok(decision)
    }

    /// Call when a location `PATCH` failed, so the next fix is not suppressed by a
    /// publish that never landed.
    pub fn record_location_publish_failed(&self) {
        let mut gate = self.gate.write();
        // Rewind by clearing history: the next valid fix will be published.
        gate.reset();
    }

    // -- Offline outbox -------------------------------------------------------

    /// Defer a fix that could not be published, and record it locally.
    ///
    /// The fix is added to the sealed outbox so it can be replayed once a relay
    /// answers, and to the local track log so the map's history view shows the
    /// offline stretch rather than a straight line across it. Returns the number
    /// of fixes now waiting.
    pub fn queue_location(&self, fix: Fix) -> usize {
        let (battery_pct, is_charging) = self.battery();
        let now_ms = crate::wire::now_unix_ms();

        self.record_own_history(fix, battery_pct, is_charging, now_ms);

        let mut outbox = self.outbox.write();
        outbox.push(
            crate::outbox::PendingFix {
                lat: fix.lat,
                lon: fix.lon,
                unix_ms: fix.unix_ms,
                speed_mps: fix.speed_mps,
                heading_deg: fix.heading_deg,
                accuracy_m: fix.accuracy_m,
                battery_pct,
                is_charging,
            },
            now_ms,
        )
    }

    /// Append this device's own fix to the local track log.
    ///
    /// The roster pass does this for every member it decodes, but a fix that was
    /// never published is never decoded, so without this the offline stretch would
    /// be missing from the history exactly when it is most interesting.
    fn record_own_history(&self, fix: Fix, battery_pct: u8, is_charging: bool, now_ms: i64) {
        let activity = self.activity_of(&self.identity.pubkey_b64, fix.speed_mps);
        self.history.write().record(
            &self.identity.pubkey_b64,
            crate::history::TrackPoint {
                lat: fix.lat,
                lon: fix.lon,
                unix_ms: fix.unix_ms,
                speed_mps: fix.speed_mps,
                activity,
                battery_pct,
                is_charging,
            },
            now_ms,
        );
    }

    /// How many fixes are waiting for a connection.
    pub fn pending_location_count(&self) -> usize {
        self.outbox.read().len()
    }

    /// The newest queued fix, which is the one worth publishing.
    pub fn newest_pending_location(&self) -> Option<crate::outbox::PendingFix> {
        self.outbox.read().newest()
    }

    /// Remove every queued fix, oldest first, so the caller can publish them.
    pub fn take_pending_locations(&self) -> Vec<crate::outbox::PendingFix> {
        self.outbox.write().take()
    }

    /// Put fixes back after a flush failed.
    pub fn restore_pending_locations(&self, fixes: Vec<crate::outbox::PendingFix>) {
        self.outbox.write().restore(fixes);
    }

    /// Replace the in-memory outbox, e.g. after loading it from disk.
    pub fn install_outbox(&self, outbox: crate::outbox::Outbox) {
        *self.outbox.write() = outbox;
    }

    /// Persist the outbox when it has unsaved changes.
    ///
    /// Returns `true` when a write happened. A failure is returned rather than
    /// swallowed: losing the queue means losing the offline stretch, which the
    /// caller may want to report.
    pub fn save_outbox(&self, dir: &std::path::Path) -> Result<bool> {
        let key = self.current_group_key()?;
        let mut outbox = self.outbox.write();
        if !outbox.is_dirty() {
            return Ok(false);
        }
        outbox.save(dir, &key)?;
        Ok(true)
    }

    /// Record this device's battery state.
    ///
    /// Kept separately from the fix because battery changes on its own schedule:
    /// a phone can drop 20% while its owner sits at a desk, and that is exactly
    /// the moment peers want to know.
    pub fn set_battery(&self, battery_pct: u8, is_charging: bool) {
        *self.my_battery.write() = (battery_pct.min(100), is_charging);
    }

    /// This device's last known battery state.
    pub fn battery(&self) -> (u8, bool) {
        *self.my_battery.read()
    }

    /// Build the roster envelope for a fix.
    pub fn build_location_envelope(&self, fix: Fix) -> Result<EncryptedEnvelope> {
        let preferences = self.preferences();
        let key = self.current_group_key()?;
        let epoch = self.current_epoch();
        let (battery_pct, is_charging) = self.battery();

        let state = LocationState {
            display_name: preferences.display_name.clone(),
            avatar_color: preferences.avatar_color.clone(),
            lat: fix.lat,
            lon: fix.lon,
            accuracy_m: fix.accuracy_m,
            speed_mps: fix.speed_mps,
            heading_deg: fix.heading_deg,
            battery_pct,
            is_charging,
            unix_ms: fix.unix_ms,
            member_pubkey: self.identity.pubkey_b64.clone(),
        };

        crypto::seal_location(&key, epoch, self.identity.signing_key(), &state)
    }

    /// Build a text-message envelope.
    pub fn build_text_envelope(&self, text: &str, unix_ms: i64) -> Result<EncryptedEnvelope> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(AppError::invalid_argument("cannot send an empty message"));
        }
        if trimmed.chars().count() > MAX_TEXT_CHARS {
            return Err(AppError::invalid_argument(format!(
                "message is {} characters, which exceeds the {MAX_TEXT_CHARS} character limit",
                trimmed.chars().count()
            )));
        }

        let key = self.current_group_key()?;
        let epoch = self.current_epoch();
        let payload = ChatPayload::TextMessage {
            text: trimmed.to_string(),
            unix_ms,
        };
        crypto::seal_chat(&key, epoch, self.identity.signing_key(), &payload)
    }

    /// Build a file-pointer envelope, posted after the blob itself is uploaded.
    pub fn build_file_envelope(
        &self,
        asset_name: &str,
        size_bytes: u64,
        mime: &str,
        sha256_b64: &str,
        caption: Option<String>,
        unix_ms: i64,
    ) -> Result<EncryptedEnvelope> {
        let key = self.current_group_key()?;
        let epoch = self.current_epoch();
        let payload = ChatPayload::FileAttachment {
            asset_name: asset_name.to_string(),
            size_bytes,
            mime: mime.to_string(),
            sha256_b64: sha256_b64.to_string(),
            caption,
            unix_ms,
        };
        crypto::seal_chat(&key, epoch, self.identity.signing_key(), &payload)
    }

    /// Build a moderation flag envelope.
    pub fn build_flag_envelope(
        &self,
        target_comment_id: u64,
        target_pubkey_b64: &str,
        reason: &str,
        unix_ms: i64,
    ) -> Result<EncryptedEnvelope> {
        if reason.trim().is_empty() {
            return Err(AppError::invalid_argument("a report needs a reason"));
        }
        let key = self.current_group_key()?;
        let epoch = self.current_epoch();
        let payload = ChatPayload::ModerationFlag {
            target_comment_id,
            target_pubkey: target_pubkey_b64.to_string(),
            reason: reason.trim().to_string(),
            unix_ms,
        };
        crypto::seal_chat(&key, epoch, self.identity.signing_key(), &payload)
    }

    /// Seal a key-rotation announcement under an explicit new key.
        ///
        /// The ordinary [`GroupState::build_rotation_envelope`] requires the epoch to
        /// already be installed, which is impossible during the rotation itself: the
        /// announcement has to be readable *by* the new key, not before it.
        pub fn build_rotation_envelope_with_key(
            &self,
            new_epoch: u8,
            retired_epoch: u8,
            reason: &str,
            unix_ms: i64,
            new_key: &[u8; 32],
        ) -> Result<EncryptedEnvelope> {
            if new_epoch <= retired_epoch {
                return Err(AppError::group_state(format!(
                    "rotation to epoch {new_epoch} from {retired_epoch} is not an advance"
                )));
            }
            let payload = ControlPayload::KeyRotation {
                new_epoch,
                retired_epoch,
                reason: reason.to_string(),
                unix_ms,
            };
            crypto::seal_control(new_key, new_epoch, self.identity.signing_key(), &payload)
        }

        /// Build a key-rotation announcement for the roster channel.
        pub fn build_rotation_envelope(
        &self,
        new_epoch: u8,
        retired_epoch: u8,
        reason: &str,
        unix_ms: i64,
    ) -> Result<EncryptedEnvelope> {
        let key = *self
            .keys
            .read()
            .get(new_epoch)
            .ok_or_else(|| AppError::group_state(format!("rotation epoch {new_epoch} has no key")))?;
        let payload = ControlPayload::KeyRotation {
            new_epoch,
            retired_epoch,
            reason: reason.to_string(),
            unix_ms,
        };
        crypto::seal_control(&key, new_epoch, self.identity.signing_key(), &payload)
    }

    // -- Rotation --------------------------------------------------------------

    /// Install a rotated key as the new current epoch.
    pub fn apply_rotation(&self, new_epoch: u8, new_key: [u8; 32]) -> Result<()> {
        let mut keys = self.keys.write();
        keys.rotate(new_epoch, &new_key)
    }

    /// Learn about a `KeyRotation` control message written by a peer.
    ///
    /// The peer must be the host, and the announced key is *not* delivered here:
    /// this only records that an epoch exists so the UI can ask the host for a
    /// re-issued invite. Accepting a key from an untrusted comment would let any
    /// member hijack the group.
    pub fn observe_rotation(
        &self,
        sender_pubkey_b64: &str,
        new_epoch: u8,
        retired_epoch: u8,
    ) -> Result<RotationNotice> {
        if sender_pubkey_b64 != self.host_pubkey_b64 {
            return Err(AppError::group_state(format!(
                "ignoring key rotation from {sender_pubkey_b64}; only the host may rotate the group key"
            )));
        }
        if new_epoch <= retired_epoch {
            return Err(AppError::group_state(format!(
                "host announced rotation to epoch {new_epoch} from {retired_epoch}, which is not an advance"
            )));
        }
        Ok(RotationNotice {
            new_epoch,
            retired_epoch,
            already_held: self.keys.read().get(new_epoch).is_some(),
        })
    }

    // -- Decoding --------------------------------------------------------------

    /// Decode a roster comment into a member view.
    pub fn decode_member(&self, comment: &IssueComment) -> std::result::Result<MemberView, DecodeFailure> {
        let envelope: EncryptedEnvelope = serde_json::from_str(&comment.body)
            .map_err(|e| DecodeFailure::Crypto(format!("comment is not a valid envelope: {e}")))?;

        let payload = self
            .keys
            .read()
            .open(&envelope)
            .map_err(|e| match e.kind() {
                crate::error::AppErrorKind::GroupState => {
                    DecodeFailure::UnknownEpoch(envelope.key_epoch)
                }
                _ => DecodeFailure::Crypto(e.to_string()),
            })?;

        match payload {
            InnerPayload::Location(state) => Ok(self.member_view(comment.id, &envelope.sender_pubkey, state)),
            _ => Err(DecodeFailure::UnexpectedKind),
        }
    }

    /// Decode a chat comment into a view model.
    pub fn decode_chat(&self, comment: &IssueComment) -> std::result::Result<ChatItem, DecodeFailure> {
        let envelope: EncryptedEnvelope = serde_json::from_str(&comment.body)
            .map_err(|e| DecodeFailure::Crypto(format!("comment is not a valid envelope: {e}")))?;

        let payload = self
            .keys
            .read()
            .open(&envelope)
            .map_err(|e| match e.kind() {
                crate::error::AppErrorKind::GroupState => {
                    DecodeFailure::UnknownEpoch(envelope.key_epoch)
                }
                _ => DecodeFailure::Crypto(e.to_string()),
            })?;

        let sender = envelope.sender_pubkey.clone();
        let is_self = sender == self.identity.pubkey_b64;

        match payload {
            InnerPayload::Chat(payload) => Ok(self.chat_item(
                comment.id, comment.nostr_event_id.clone(), sender, is_self, payload,
            )),
            _ => Err(DecodeFailure::UnexpectedKind),
        }
    }

    /// Turn a decoded [`LocationState`] into a [`MemberView`], applying policy.
    fn member_view(&self, comment_id: u64, sender_pubkey: &str, state: LocationState) -> MemberView {
        let is_self = sender_pubkey == self.identity.pubkey_b64;
        let age_ms = crate::wire::now_unix_ms().saturating_sub(state.unix_ms);
        let age_s = age_ms / 1_000;

        MemberView {
            comment_id,
            pubkey_b64: sender_pubkey.to_string(),
            display_name: state.display_name,
            avatar_color: state.avatar_color,
            lat: state.lat,
            lon: state.lon,
            accuracy_m: state.accuracy_m,
            speed_mps: state.speed_mps,
            heading_deg: state.heading_deg,
            activity: self.activity_of(sender_pubkey, state.speed_mps),
            battery_pct: state.battery_pct,
            is_charging: state.is_charging,
            unix_ms: state.unix_ms,
            is_self,
            is_stale: age_s > MEMBER_STALE_SECS,
            is_blocked: self.is_blocked(sender_pubkey),
            role: self.role_of(sender_pubkey),
        }
    }

    /// Turn a decoded [`ChatPayload`] into a [`ChatItem`], applying policy.
    fn chat_item(&self, comment_id: u64, nostr_event_id: Option<String>, sender: String, is_self: bool, payload: ChatPayload) -> ChatItem {
        let blocked = self.is_blocked(&sender);
        match payload {
            ChatPayload::TextMessage { text, unix_ms } => ChatItem::Text {
                comment_id,
                nostr_event_id,
                sender_pubkey_b64: sender,
                text,
                unix_ms,
                is_self,
                is_blocked: blocked,
            },
            ChatPayload::FileAttachment {
                asset_name,
                size_bytes,
                mime,
                sha256_b64,
                caption,
                unix_ms,
            } => ChatItem::File {
                comment_id,
                nostr_event_id,
                sender_pubkey_b64: sender,
                asset_name,
                size_bytes,
                mime,
                sha256_b64,
                caption,
                unix_ms,
                is_self,
                is_blocked: blocked,
                unavailable: false,
            },
            ChatPayload::ModerationFlag {
                target_comment_id,
                target_pubkey: _,
                reason,
                unix_ms,
            } => ChatItem::Moderation {
                comment_id,
                sender_pubkey_b64: sender,
                target_comment_id,
                reason,
                unix_ms,
            },
        }
    }

    /// Replace the roster with a freshly decoded set.
    ///
    /// Entries that expired are dropped; blocked members are retained but flagged,
    /// so the block list can be managed from a settings screen instead of the
    /// member silently vanishing.
    pub fn apply_roster(&self, comments: &[IssueComment]) -> usize {
        let now_ms = crate::wire::now_unix_ms();
        let mut members = Vec::with_capacity(comments.len());

        for comment in comments {
            match self.decode_member(comment) {
                Ok(member) => {
                    let age_s = (now_ms.saturating_sub(member.unix_ms)) / 1_000;
                    if age_s > MEMBER_EXPIRE_SECS {
                        continue;
                    }
                    members.push(member);
                }
                Err(DecodeFailure::Crypto(_)) => {
                    // A malformed roster comment is not ours to interpret; skip it
                    // rather than rendering a broken pin.
                }
                Err(_) => {}
            }
        }

        // Newest first, self pinned to the top, so the UI list is stable.
        members.sort_by(|a, b| {
            b.is_self
                .cmp(&a.is_self)
                .then_with(|| b.unix_ms.cmp(&a.unix_ms))
                .then_with(|| a.comment_id.cmp(&b.comment_id))
        });

        let count = members.len();
        self.record_trails(&members);
        *self.roster.write() = members;
        count
    }

    /// Append each member's current position to their trail and the track log.
    ///
    /// Points are deduplicated by spacing and capped, so a member who sits still
    /// does not fill the buffer with identical coordinates and a long session does
    /// not grow it without bound.
    ///
    /// The same pass feeds two other things, because they need exactly the same
    /// input and doing it once keeps them consistent:
    ///
    /// * the **activity tracker**, which smooths the reported speed so a single
    ///   noisy fix cannot flip a member between "walking" and "driving", and
    /// * the **track log**, which is the month-long history the map's history view
    ///   reads. It is local-only and never published.
    fn record_trails(&self, members: &[MemberView]) {
        let now_ms = crate::wire::now_unix_ms();
        let mut trails = self.trails.write();
        let mut history = self.history.write();
        let mut activity = self.activity.write();

        for member in members {
            let tracker = activity.entry(member.pubkey_b64.clone()).or_default();
            let smoothed = tracker.observe(member.speed_mps, member.accuracy_m);

            history.record(
                &member.pubkey_b64,
                crate::history::TrackPoint {
                    lat: member.lat,
                    lon: member.lon,
                    unix_ms: member.unix_ms,
                    speed_mps: member.speed_mps,
                    activity: smoothed,
                    battery_pct: member.battery_pct,
                    is_charging: member.is_charging,
                },
                now_ms,
            );

            let points = trails.entry(member.pubkey_b64.clone()).or_default();
            let last = points.last().copied();
            let should_push = match last {
                None => true,
                Some(previous) => {
                    previous.unix_ms != member.unix_ms
                        && haversine_m(previous.lat, previous.lon, member.lat, member.lon)
                            >= TRAIL_MIN_SPACING_M
                }
            };
            if !should_push {
                continue;
            }
            points.push(TrailPoint { lat: member.lat, lon: member.lon, unix_ms: member.unix_ms });
            if points.len() > TRAIL_MAX_POINTS {
                let excess = points.len() - TRAIL_MAX_POINTS;
                points.drain(0..excess);
            }
        }
    }

    /// A copy of every member's trail, for the map.
    pub fn trails_snapshot(&self) -> std::collections::HashMap<String, Vec<TrailPoint>> {
        self.trails.read().clone()
    }

    /// Smoothed activity for `pubkey`, falling back to the raw speed class.
    ///
    /// The tracker is authoritative once it has seen a sample; the fallback only
    /// matters for a member decoded before any roster pass has run.
    pub fn activity_of(&self, pubkey: &str, speed_mps: f32) -> crate::geo_filter::Activity {
        self.activity
            .read()
            .get(pubkey)
            .map(|tracker| tracker.current())
            .unwrap_or_else(|| crate::geo_filter::Activity::from_speed(speed_mps))
    }

    /// Track points for one member at or after `since_ms`, oldest first.
    pub fn history_since(&self, pubkey: &str, since_ms: i64) -> Vec<crate::history::TrackPoint> {
        self.history.read().points_since(pubkey, since_ms)
    }

    /// Every member's track points at or after `since_ms`.
    pub fn history_snapshot(
        &self,
        since_ms: i64,
    ) -> std::collections::HashMap<String, Vec<crate::history::TrackPoint>> {
        self.history.read().snapshot_since(since_ms)
    }

    /// Replace the in-memory track log, e.g. after loading it from disk.
    pub fn install_history(&self, history: crate::history::TrackHistory) {
        *self.history.write() = history;
    }

    /// Persist the track log when it has unsaved changes.
    ///
    /// Returns `true` when a write happened. A failure is returned rather than
    /// swallowed so the caller can decide whether it is worth telling the user;
    /// losing history is not fatal to the app.
    pub fn save_history(&self, dir: &std::path::Path) -> Result<bool> {
        let key = self.current_group_key()?;
        let mut history = self.history.write();
        if !history.is_dirty() {
            return Ok(false);
        }
        history.save(dir, &key)?;
        Ok(true)
    }

    /// Drop one member's history, e.g. when they are blocked.
    pub fn forget_history(&self, pubkey: &str) {
        self.history.write().forget(pubkey);
        self.activity.write().remove(pubkey);
    }
    /// Replace the chat log with a freshly decoded set.
    ///
    /// Undecryptable comments are surfaced as [`ChatItem::Undecryptable`] so the
    /// user can see that content exists which they cannot read, which is the
    /// difference between "nothing was sent" and "something was sent that I lack
    /// the key for".
    pub fn apply_chat(&self, comments: &[IssueComment]) -> usize {
        let mut items: Vec<ChatItem> = Vec::with_capacity(comments.len());

        for comment in comments {
            match self.decode_chat(comment) {
                Ok(item) => items.push(item),
                Err(failure) => items.push(ChatItem::Undecryptable {
                    comment_id: comment.id,
                    reason: failure.reason(),
                }),
            }
        }

        // Ascending by id preserves the store's ordering for equal
        // timestamps, giving a stable transcript.
        items.sort_by_key(chat_sort_key);

        let count = items.len();
        *self.chat.write() = items;
        count
    }

    /// Mark known file pointers after validating an uploader's signed notice.
    pub fn apply_file_removals(&self, notices: &[crate::nostr::Event]) {
        let mut removed = HashSet::new();
        for notice in notices {
            if notice.kind != crate::nostr::KIND_FILE_REMOVED
                || notice.d_tag() != Some(self.group_id.as_str())
                || notice.verify_id().is_err()
                || notice.verify_signature().is_err()
            {
                continue;
            }
            let Ok(original) = serde_json::from_str::<crate::nostr::Event>(&notice.content) else {
                continue;
            };
            if !matches!(original.kind, crate::nostr::KIND_FILE | crate::nostr::KIND_FILE_LEGACY)
                || original.d_tag() != Some(self.group_id.as_str())
                || original.pubkey != notice.pubkey
                || original.verify_id().is_err()
                || original.verify_signature().is_err()
            {
                continue;
            }
            let comment = IssueComment::from_nostr_event(&original);
            if let Ok(ChatItem::File { asset_name, .. }) = self.decode_chat(&comment) {
                removed.insert(asset_name);
            }
        }
        for item in self.chat.write().iter_mut() {
            if let ChatItem::File { asset_name, unavailable, .. } = item {
                *unavailable = removed.contains(asset_name);
            }
        }
    }

    /// Append one decoded chat comment without re-listing the whole channel.
    ///
    /// Used by the incremental poll so a busy group does not re-decode history.
    pub fn append_chat(&self, comment: &IssueComment) {
        let item = match self.decode_chat(comment) {
            Ok(item) => item,
            Err(failure) => ChatItem::Undecryptable {
                comment_id: comment.id,
                reason: failure.reason(),
            },
        };

        let mut chat = self.chat.write();
        let already_present = chat.iter().any(|existing| chat_key(existing) == comment.id);
        if !already_present {
            chat.push(item);
            chat.sort_by_key(chat_sort_key);
        }
    }

    /// Should this chat item be rendered, given the local block list?
    ///
        /// The block list is consulted **live** rather than trusting the `is_blocked`
        /// flag captured at decode time. Otherwise blocking a member would not take
        /// effect until the next poll, which reads as the block silently not working.
        pub fn should_display(&self, item: &ChatItem) -> bool {
            match item {
                ChatItem::Text {
                    sender_pubkey_b64, ..
                }
                | ChatItem::File {
                    sender_pubkey_b64, ..
                } => !self.is_blocked(sender_pubkey_b64),
                // Moderation notes are local governance, not the blocked member's
                // content, so they stay visible.
                ChatItem::Moderation { .. } | ChatItem::Undecryptable { .. } => true,
            }
        }

    /// Visible chat, with blocked senders removed.
    pub fn visible_chat(&self) -> Vec<ChatItem> {
        self.chat
            .read()
            .iter()
            .filter(|item| self.should_display(item))
            .cloned()
            .collect()
    }

    /// Visible members, with blocked members removed.
        ///
        /// Like [`GroupState::should_display`], this consults the live block list so a
        /// newly blocked member disappears from the map immediately, and an unblock
        /// restores them without waiting for a poll.
        pub fn visible_roster(&self) -> Vec<MemberView> {
            self.roster
                .read()
                .iter()
                .filter(|member| !self.is_blocked(&member.pubkey_b64))
                .cloned()
                .collect()
        }

    // -- Cadence ---------------------------------------------------------------

    /// True when the store told us to stop, so no channel should poll.
    pub fn is_halted(&self, now_unix_s: i64) -> bool {
        self.rate_halt.read().is_halted(now_unix_s)
    }

    /// Seconds until polling may resume, if halted.
    pub fn halt_remaining_secs(&self, now_unix_s: i64) -> Option<i64> {
        self.rate_halt.read().remaining_secs(now_unix_s)
    }

    /// Observe rate-limit headers from any response.
    pub fn observe_rate_limit(
        &self,
        status: u16,
        reset_unix_s: Option<i64>,
        remaining: Option<u32>,
        limit: Option<u32>,
    ) {
        let mut halt = self.rate_halt.write();
        halt.observe_limit(limit);
        halt.observe(status, reset_unix_s, remaining);
    }

    /// Feed a chat poll result into the backoff and produce the next delay.
    pub async fn chat_delay(&self, not_modified: bool) -> Duration {
        let current = {
            let mut backoff = self.chat_backoff.write();
            backoff.observe(not_modified);
            backoff.current()
        };
        let mut jitter = self.jitter.lock().await;
        jitter.apply(current)
    }

    /// Feed a roster poll result into the backoff and produce the next delay.
    pub async fn roster_delay(&self, not_modified: bool) -> Duration {
        let current = {
            let mut backoff = self.roster_backoff.write();
            backoff.observe(not_modified);
            backoff.current()
        };
        let mut jitter = self.jitter.lock().await;
        jitter.apply(current)
    }

    /// Force both channels back to their plan cadence, e.g. after a user sends a
    /// message and expects a prompt echo.
    pub fn reset_cadence(&self) {
        self.chat_backoff.write().reset();
        self.roster_backoff.write().reset();
    }

    /// Current budgets, for a developer/diagnostics panel.
    pub fn cadence_report(&self) -> CadenceReport {
        let halt = self.rate_halt.read();
        CadenceReport {
            chat_interval_s: self.chat_backoff.read().current().as_secs(),
            roster_interval_s: self.roster_backoff.read().current().as_secs(),
            halted_until_unix_s: halt.halted_until(),
            remaining_requests: halt.last_remaining(),
            total_requests: halt.last_limit(),
        }
    }

    /// Public keys currently blocked, sorted, for stable UI rendering.
    pub fn blocked_sorted(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.preferences.read().blocked_pubkeys.iter().cloned().collect();
        keys.sort();
        keys
    }
}

/// A de-duplicable key for a chat item.
fn chat_key(item: &ChatItem) -> u64 {
    match item {
        ChatItem::Text { comment_id, .. }
        | ChatItem::File { comment_id, .. }
        | ChatItem::Moderation { comment_id, .. }
        | ChatItem::Undecryptable { comment_id, .. } => *comment_id,
    }
}

/// Sort key for a chat item: `(timestamp, comment_id)`.
fn chat_sort_key(item: &ChatItem) -> (i64, u64) {
    match item {
        ChatItem::Text {
            comment_id, unix_ms, ..
        }
        | ChatItem::File {
            comment_id, unix_ms, ..
        }
        | ChatItem::Moderation {
            comment_id, unix_ms, ..
        } => (*unix_ms, *comment_id),
        ChatItem::Undecryptable { comment_id, .. } => (0, *comment_id),
    }
}

/// Outcome of learning about a rotation from the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationNotice {
    pub new_epoch: u8,
    pub retired_epoch: u8,
    /// True when this device already holds the new epoch's key.
    pub already_held: bool,
}

/// Diagnostics snapshot of the current cadence and budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CadenceReport {
    pub chat_interval_s: u64,
    pub roster_interval_s: u64,
    pub halted_until_unix_s: Option<i64>,
    pub remaining_requests: Option<u32>,
    pub total_requests: Option<u32>,
}


/// Describe a skip reason for the UI/telemetry layer.
pub fn describe_skip(reason: SkipReason) -> String {
    match reason {
        SkipReason::MovedTooLittle {
            moved_m,
            required_m,
            waited_s,
        } => format!(
            "moved {moved_m:.0} m of the {required_m:.0} m needed, {waited_s} s since the last update"
        ),
        SkipReason::CooldownActive {
            waited_s,
            required_s,
        } => format!("{waited_s} s of the {required_s} s cooldown elapsed"),
    }
}

/// Shared handle used by Tauri commands.
pub type SharedGroup = Arc<RwLock<Option<Arc<GroupState>>>>;

/// Wrap a group in the shared handle.
pub fn shared(state: GroupState) -> SharedGroup {
    Arc::new(RwLock::new(Some(Arc::new(state))))
}

/// Borrow the current group or explain why there is none.
pub fn require_group(shared: &SharedGroup) -> Result<Arc<GroupState>> {
    shared
        .read()
        .clone()
        .ok_or_else(|| AppError::group_state("no group is active; create or join one first"))
}

/// Map of member public keys to their roster comment ids.
///
/// Used by removal flows: the host needs a comment id to delete, and the only
/// trustworthy source for it is the roster itself.
pub fn comment_ids_by_pubkey(members: &[MemberView]) -> HashMap<String, u64> {
    members
        .iter()
        .map(|member| (member.pubkey_b64.clone(), member.comment_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PROTOCOL_VERSION;

    const TEST_KEY: [u8; 32] = [7u8; 32];

    fn identity() -> Identity {
        Identity::from_secret([3u8; 32])
    }

    fn other_identity(seed: u8) -> Identity {
        Identity::from_secret([seed; 32])
    }

    fn invite_for(host_pubkey: &str) -> InviteCredentialsPayload {
        InviteCredentialsPayload {
            version: PROTOCOL_VERSION,
            backend: crate::storage::BackendKind::Nostr,
            group_master_key: TEST_KEY,
            relays: vec!["wss://relay.example".into()],
            blossom_servers: vec!["https://blossom.example".into()],
            group_id: "group-test".into(),
            host_pubkey: host_pubkey.to_string(),
            group_label: "Weekend Trip".into(),
            key_epoch: 0,
        }
    }

    fn prefs() -> Preferences {
        Preferences {
            display_name: "Jared".into(),
            avatar_color: "#5b8cff".into(),
            blocked_pubkeys: HashSet::new(),
            accepted_eula: true,
            accepted_location_disclosure: true,
            enabled_background_location: true,
        }
    }

    fn state() -> GroupState {
        let me = identity();
        GroupState::from_invite(&invite_for(&me.pubkey_b64), me, prefs(), true).expect("state")
    }

    #[test]
    fn trails_record_movement_and_skip_repeats() {
        let state = state();
        let me = identity();
        let now = crate::wire::now_unix_ms();

        // Two fixes at the same spot: only the first should be recorded.
        state.apply_roster(&[roster_comment(&state, &me, Fix::at(1.0, 1.0, now - 20_000), "Me")]);
        state.apply_roster(&[roster_comment(&state, &me, Fix::at(1.0, 1.0, now - 10_000), "Me")]);
        let trails = state.trails_snapshot();
        assert_eq!(trails[&me.pubkey_b64].len(), 1, "a stationary member must not fill the trail");

        // A move beyond the spacing threshold is recorded.
        state.apply_roster(&[roster_comment(&state, &me, Fix::at(1.001, 1.0, now), "Me")]);
        let trails = state.trails_snapshot();
        assert_eq!(trails[&me.pubkey_b64].len(), 2);
        // Oldest first, so the renderer can fade by index.
        assert!(trails[&me.pubkey_b64][0].unix_ms < trails[&me.pubkey_b64][1].unix_ms);
    }

    #[test]
    fn trails_are_capped() {
        let state = state();
        let me = identity();
        let now = crate::wire::now_unix_ms();
        for step in 0..(TRAIL_MAX_POINTS + 20) {
            let lat = 1.0 + step as f64 * 0.001;
            state.apply_roster(&[roster_comment(&state, &me, Fix::at(lat, 1.0, now + step as i64), "Me")]);
        }
        let trails = state.trails_snapshot();
        assert_eq!(trails[&me.pubkey_b64].len(), TRAIL_MAX_POINTS);
    }

    #[test]
    fn member_view_serializes_as_camel_case() {
        // The UI reads `avatarColor`; a snake_case payload crashed the map tab.
        let state = state();
        let me = identity();
        let view = state.member_view(1, &me.pubkey_b64, LocationState {
            display_name: "Ada".into(),
            avatar_color: "#123456".into(),
            lat: 1.0,
            lon: 2.0,
            accuracy_m: 3.0,
            speed_mps: 0.0,
            heading_deg: 0.0,
            battery_pct: 50,
            is_charging: false,
            unix_ms: 1,
            member_pubkey: me.pubkey_b64.clone(),
        });
        let json = serde_json::to_value(&view).expect("json");
        assert_eq!(json["avatarColor"], "#123456");
        assert_eq!(json["displayName"], "Ada");
        assert_eq!(json["pubkeyB64"], me.pubkey_b64);
        assert!(json.get("avatar_color").is_none());
    }

    #[test]
    fn closure_requires_the_pinned_host_and_group() {
        let host = identity();
        let mut invite = invite_for(&host.pubkey_b64);
        invite.backend = crate::storage::BackendKind::Nostr;
        invite.group_id = "group-one".into();
        invite.relays = vec!["wss://relay.example".into()];
        let host_state = GroupState::from_invite(&invite, host, prefs(), true).expect("host");
        let guest = GroupState::from_invite(&invite, other_identity(4), prefs(), false).expect("guest");
        let proof = host_state.closure_proof().expect("proof");
        assert!(guest.verifies_closure("group-one", &proof));
        assert!(!guest.verifies_closure("different-group", &proof));
        assert!(guest.closure_proof().is_err());
        assert!(!guest.verifies_closure("group-one", "invalid"));
    }

    #[test]
    fn file_removal_requires_the_original_uploaders_signature() {
        let host = identity();
        let mut invite = invite_for(&host.pubkey_b64);
        invite.backend = crate::storage::BackendKind::Nostr;
        invite.group_id = "group-one".into();
        invite.relays = vec!["wss://relay.example".into()];
        let group = GroupState::from_invite(&invite, host, prefs(), true).expect("group");
        let author = crate::nostr::NostrIdentity::from_secret_bytes([21; 32]).expect("author");
        let attacker = crate::nostr::NostrIdentity::from_secret_bytes([22; 32]).expect("attacker");
        let body = serde_json::to_string(&group.build_file_envelope("blob", 3, "text/plain", "digest", None, 100).expect("envelope")).expect("json");
        let original = crate::nostr::sign_event(&author, crate::nostr::KIND_FILE,
            vec![vec!["d".into(), "group-one".into()]], body, 100).expect("event");
        let payload = serde_json::to_string(&original).expect("original json");
        let forged = crate::nostr::sign_event(&attacker, crate::nostr::KIND_FILE_REMOVED,
            vec![vec!["d".into(), "group-one".into()]], &payload, 101).expect("forged");
        group.apply_chat(&[IssueComment::from_nostr_event(&original)]);
        group.apply_file_removals(&[forged]);
        assert!(matches!(group.chat.read().first(), Some(ChatItem::File { unavailable: false, .. })));
        let valid = crate::nostr::sign_event(&author, crate::nostr::KIND_FILE_REMOVED,
            vec![vec!["d".into(), "group-one".into()]], &payload, 101).expect("notice");
        group.apply_file_removals(&[valid]);
        assert!(matches!(group.chat.read().first(), Some(ChatItem::File { unavailable: true, .. })));
    }

    /// Build a roster entry as the store would return it.
    fn roster_comment(state: &GroupState, author: &Identity, fix: Fix, name: &str) -> IssueComment {
        let key = state.current_group_key().expect("key");
        let payload = LocationState {
            display_name: name.to_string(),
            avatar_color: "#111111".into(),
            lat: fix.lat,
            lon: fix.lon,
            accuracy_m: 3.0,
            speed_mps: 0.0,
            heading_deg: 0.0,
            battery_pct: 50,
            is_charging: false,
            unix_ms: fix.unix_ms,
            member_pubkey: author.pubkey_b64.clone(),
        };
        let envelope = crypto::seal_location(&key, 0, author.signing_key(), &payload).expect("seal");
        IssueComment {
            id: 100,
            body: serde_json::to_string(&envelope).expect("json"),
            created_at_ms: fix.unix_ms - 1_000,
            updated_at_ms: fix.unix_ms,
            author_login: "JaredCH".into(),
            nostr_event_id: None,
        }
    }

    /// Build a text chat comment, sealed by `author`.
        fn chat_comment(
            state: &GroupState,
            author: &Identity,
            text: &str,
            unix_ms: i64,
            id: u64,
        ) -> IssueComment {
            let key = state.current_group_key().expect("key");
            let payload = ChatPayload::TextMessage {
                text: text.to_string(),
                unix_ms,
            };
            let envelope = crypto::seal_chat(&key, state.current_epoch(), author.signing_key(), &payload)
                .expect("seal");
            IssueComment {
                id,
                body: serde_json::to_string(&envelope).expect("json"),
                created_at_ms: unix_ms - 1_000,
                updated_at_ms: unix_ms,
                author_login: "JaredCH".into(),
            nostr_event_id: None,
            }
        }

        /// A `ChatItem::Text` item for the given sender.
        fn text_item(sender: &str, text: &str, unix_ms: i64, comment_id: u64, is_self: bool, blocked: bool) -> ChatItem {
            ChatItem::Text {
                comment_id,
                nostr_event_id: None,
                sender_pubkey_b64: sender.to_string(),
                text: text.to_string(),
                unix_ms,
                is_self,
                is_blocked: blocked,
            }
        }

        #[test]
        fn chat_items_serialize_event_ids_and_fields_for_the_ui() {
            let item = ChatItem::Text {
                comment_id: 1,
                nostr_event_id: Some("a".repeat(64)),
                sender_pubkey_b64: "sender".into(),
                text: "hello".into(),
                unix_ms: 42,
                is_self: true,
                is_blocked: false,
            };
            let value = serde_json::to_value(item).expect("serialize chat item");
            assert_eq!(value["nostrEventId"], "a".repeat(64));
            assert_eq!(value["senderPubkeyB64"], "sender");
            assert_eq!(value["commentId"], 1);
        }

        /// Decrypt an envelope through the state's key table.
        ///
        /// Borrowing the table directly inside a `match` scrutinee would hold the
        /// `RwLock` read guard for the whole arm, so the guard is scoped to this call.
        fn open_with_state(state: &GroupState, envelope: &EncryptedEnvelope) -> InnerPayload {
            let keys = state.keys.read();
            keys.open(envelope).expect("open")
        }

    // -- Identity ------------------------------------------------------------

    #[test]
    fn identity_is_deterministic_from_a_secret() {
        let a = Identity::from_secret([1u8; 32]);
        let b = Identity::from_secret([1u8; 32]);
        assert_eq!(a.pubkey_b64, b.pubkey_b64);
        assert_eq!(a.secret_bytes(), b.secret_bytes());
    }

    #[test]
    fn identity_generate_produces_distinct_keys() {
        let a = Identity::generate().expect("generate");
        let b = Identity::generate().expect("generate");
        assert_ne!(a.pubkey_b64, b.pubkey_b64);
    }

    #[test]
    fn identity_fingerprint_is_stable_and_short() {
        let me = identity();
        let fingerprint = me.fingerprint();
        assert_eq!(fingerprint.len(), 8);
        assert!(fingerprint.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(fingerprint, identity().fingerprint(), "must be stable");
    }

    #[test]
    fn identity_debug_never_prints_the_secret() {
        let me = Identity::from_secret([0xAB; 32]);
        let rendered = format!("{me:?}");
        assert!(rendered.contains("pubkey_b64"));
        assert!(!rendered.contains("abab"), "must not leak key bytes: {rendered}");
    }

    // -- Construction --------------------------------------------------------

    #[test]
    fn state_builds_from_a_valid_invite() {
        let me = Identity::generate().expect("generate");
        let state = GroupState::from_invite(&invite_for(&me.pubkey_b64), me, prefs(), true).expect("state");

        assert_eq!(state.group_id, "group-test");
        assert_eq!(state.current_epoch(), 0);
        assert_eq!(state.current_group_key().expect("key"), TEST_KEY);
        assert!(state.is_host);
    }

    #[test]
    fn state_rejects_an_invite_without_a_host_key_for_a_guest() {
        let me = Identity::generate().expect("generate");
        let mut invite = invite_for("");
        invite.host_pubkey.clear();

        let err = GroupState::from_invite(&invite, me, prefs(), false).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
        assert!(err.to_string().contains("host's public key"));
    }

    #[test]
    fn state_accepts_a_missing_host_key_for_the_host_itself() {
        let me = Identity::generate().expect("generate");
        let mut invite = invite_for("");
        invite.host_pubkey.clear();

        let state = GroupState::from_invite(&invite, me, prefs(), true).expect("host may self-fill");
        assert_eq!(state.host_pubkey_b64, state.identity.pubkey_b64);
    }

    #[test]
    fn state_rejects_a_malformed_host_key() {
        let me = Identity::generate().expect("generate");
        let invite = invite_for("not base64!!");
        let err = GroupState::from_invite(&invite, me, prefs(), true).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::Crypto);
    }

    #[test]
    fn state_rejects_an_invalid_invite() {
        let me = Identity::generate().expect("generate");
        let mut invite = invite_for(&me.pubkey_b64);
        invite.relays.clear();
        let err = GroupState::from_invite(&invite, me, prefs(), true).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InviteFormat);
    }

    #[test]
    fn state_debug_never_prints_the_group_key() {
        let state = state();
        let rendered = format!("{state:?}");
        assert!(rendered.contains("nostr:group-test"));
        assert!(!rendered.contains("070707"), "group key bytes must not appear");
    }

    // -- Preferences ---------------------------------------------------------

    #[test]
    fn preferences_seeded_is_not_onboarded() {
        let preferences = Preferences::seeded();
        assert!(!preferences.accepted_eula);
        assert!(!preferences.is_onboarding_complete());
    }

    #[test]
    fn onboarding_completion_requires_name_and_both_consents() {
        let mut preferences = Preferences::seeded();
        preferences.accepted_eula = true;
        assert!(!preferences.is_onboarding_complete(), "needs disclosure");

        preferences.accepted_location_disclosure = true;
        assert!(!preferences.is_onboarding_complete(), "needs a name");

        preferences.display_name = "  Jared ".into();
        assert!(preferences.is_onboarding_complete());
    }

    #[test]
    fn preferences_round_trip_through_json() {
        let preferences = prefs();
        let json = serde_json::to_string(&preferences).expect("serialize");
        let back: Preferences = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(preferences, back);
    }

    // -- Block list ----------------------------------------------------------

    #[test]
    fn block_and_unblock_change_the_list_once() {
        let state = state();
        let target = "AAAA";

        assert!(!state.is_blocked(target));
        assert!(state.block(target), "first block should change the list");
        assert!(state.is_blocked(target));
        assert!(!state.block(target), "second block is a no-op");
        assert!(state.unblock(target), "unblock should change the list");
        assert!(!state.is_blocked(target));
        assert!(!state.unblock(target), "second unblock is a no-op");
    }

    #[test]
    fn blocking_self_is_ignored() {
        let state = state();
        let own = state.identity.pubkey_b64.clone();
        state.block(&own);
        assert!(
            !state.is_blocked(&own),
            "own content must never be hidden, even if the list is corrupt"
        );
    }

    #[test]
        fn blocked_sorted_is_deterministic() {
            let state = state();
            state.block("zzz");
            state.block("aaa");
            state.block("mmm");
            assert_eq!(state.blocked_sorted(), vec!["aaa", "mmm", "zzz"]);
        }

        // -- Location policy -----------------------------------------------------

    #[test]
    fn first_location_is_published() {
        let state = state();
        let decision = state
            .consider_location(Fix::at(41.0, -87.0, 1_700_000_000_000,))
            .expect("consider");
        assert_eq!(decision, Publish::Yes);
        assert!(state.my_fix.read().is_some(), "self fix is cached for the UI");
    }

    #[test]
    fn location_skipped_during_cooldown_but_self_fix_still_updates() {
        let state = state();
        let first = Fix::at(41.0, -87.0, 1_700_000_000_000,);
        state.consider_location(first).expect("first");
        let second = Fix::at(41.01, -87.0, 1_700_000_005_000,);
        let decision = state.consider_location(second).expect("second");
        assert!(matches!(decision, Publish::No(_)));

        let cached = state.my_fix.read().expect("cached");
        assert_eq!(cached.lat, 41.01, "the UI should still show the newest fix");
    }

    #[test]
    fn invalid_fix_is_rejected_and_not_cached() {
        let state = state();
        let err = state
            .consider_location(Fix::at(999.0, 0.0, 1,))
            .expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InvalidArgument);
        assert!(state.my_fix.read().is_none());
    }

    #[test]
    fn failed_publish_re_arms_the_gate() {
        let state = state();
        let fix = Fix::at(41.0, -87.0, 1_700_000_000_000,);
        assert_eq!(state.consider_location(fix).expect("consider"), Publish::Yes);
        state.record_location_publish_failed();

        // The same fix (or a new one) must be publishable again.
        let decision = state
            .consider_location(Fix::at(41.0, -87.0, 1_700_000_001_000,))
            .expect("consider");
        assert_eq!(decision, Publish::Yes);
    }

    #[test]
    fn a_queued_fix_is_kept_and_recorded_in_the_local_history() {
        let state = state();
        let own = state.identity.pubkey_b64.clone();
        let now = crate::wire::now_unix_ms();

        assert_eq!(state.pending_location_count(), 0);
        assert_eq!(state.queue_location(Fix::at(41.0, -87.0, now)), 1);
        assert_eq!(state.pending_location_count(), 1);

        let newest = state.newest_pending_location().expect("queued");
        assert_eq!(newest.lat, 41.0);
        assert_eq!(newest.unix_ms, now);

        // The offline stretch must appear in the history view, not as a gap.
        let points = state.history_since(&own, 0);
        assert_eq!(points.len(), 1, "the queued fix is recorded locally");
        assert_eq!(points[0].lat, 41.0);
    }

    #[test]
    fn taking_and_restoring_pending_fixes_round_trips() {
        let state = state();
        let now = crate::wire::now_unix_ms();
        state.queue_location(Fix::at(41.0, -87.0, now - 1_000));
        state.queue_location(Fix::at(41.1, -87.0, now));

        let taken = state.take_pending_locations();
        assert_eq!(taken.len(), 2);
        assert_eq!(state.pending_location_count(), 0);

        state.restore_pending_locations(taken);
        assert_eq!(state.pending_location_count(), 2);
        assert_eq!(
            state.newest_pending_location().map(|fix| fix.lat),
            Some(41.1),
            "the newest fix is the one worth publishing"
        );
    }

    #[test]
    fn battery_is_carried_into_the_published_envelope() {
        let me = identity();
        let state = GroupState::from_invite(&invite_for(&me.pubkey_b64), me, prefs(), true).expect("state");

        state.set_battery(37, true);
        assert_eq!(state.battery(), (37, true));

        let envelope = state
            .build_location_envelope(Fix::at(41.0, -87.0, 1_700_000_000_000))
            .expect("seal");
        let opened = state.keys.read().open(&envelope).expect("open");
        match opened {
            InnerPayload::Location(location) => {
                assert_eq!(location.battery_pct, 37);
                assert!(location.is_charging);
            }
            other => panic!("expected location, got {other:?}"),
        }
    }

    #[test]
    fn battery_is_clamped_to_a_percentage() {
        let state = state();
        state.set_battery(250, false);
        assert_eq!(state.battery(), (100, false));
    }

    #[test]
    fn history_records_roster_positions() {
        let state = state();
        let me = identity();
        let now = crate::wire::now_unix_ms();

        state.apply_roster(&[roster_comment(&state, &me, Fix::at(1.0, 1.0, now - 20_000), "Me")]);
        state.apply_roster(&[roster_comment(&state, &me, Fix::at(1.01, 1.0, now), "Me")]);
        let points = state.history_since(&me.pubkey_b64, 0);
        assert_eq!(points.len(), 2, "both positions are kept in the track log");
        assert!(points[0].unix_ms < points[1].unix_ms);
    }

    #[test]
    fn forgetting_history_drops_the_member_and_their_activity() {
        let state = state();
        let me = identity();
        let now = crate::wire::now_unix_ms();
        state.apply_roster(&[roster_comment(&state, &me, Fix::at(1.0, 1.0, now), "Me")]);
        assert!(!state.history_since(&me.pubkey_b64, 0).is_empty());

        state.forget_history(&me.pubkey_b64);
        assert!(state.history_since(&me.pubkey_b64, 0).is_empty());
        assert!(!state.activity.read().contains_key(&me.pubkey_b64));
    }

    #[test]
    fn describe_skip_is_human_readable() {
        let moved = describe_skip(SkipReason::MovedTooLittle {
            moved_m: 3.2,
            required_m: 15.0,
            waited_s: 40,
        });
        assert!(moved.contains("3 m"));
        assert!(moved.contains("15 m"));
        assert!(moved.contains("40 s"));

        let cooldown = describe_skip(SkipReason::CooldownActive {
            waited_s: 5,
            required_s: 30,
        });
        assert!(cooldown.contains("5 s"));
        assert!(cooldown.contains("30 s"));
    }

    // -- Envelope building ----------------------------------------------------

    #[test]
    fn location_envelope_round_trips_through_state_keys() {
        let me = identity();
        let state = GroupState::from_invite(&invite_for(&me.pubkey_b64), me, prefs(), true).expect("state");

        let fix = Fix::at(41.8781, -87.6298, 1_700_000_000_000,);
        let envelope = state.build_location_envelope(fix).expect("seal");
        let opened = state.keys.read().open(&envelope).expect("open");

        match opened {
            InnerPayload::Location(location) => {
                assert_eq!(location.display_name, "Jared");
                assert_eq!(location.member_pubkey, state.identity.pubkey_b64);
                assert!((location.lat - 41.8781).abs() < 1e-9);
            }
            other => panic!("expected location, got {other:?}"),
        }
    }

    #[test]
    fn text_envelope_rejects_empty_and_oversized_messages() {
        let state = state();
        assert_eq!(
            state
                .build_text_envelope("   ", 1)
                .expect_err("must fail")
                .kind(),
            crate::error::AppErrorKind::InvalidArgument
        );

        let too_long = "x".repeat(MAX_TEXT_CHARS + 1);
        let err = state.build_text_envelope(&too_long, 1).expect_err("must fail");
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn text_envelope_trims_and_round_trips() {
        let state = state();
        let envelope = state.build_text_envelope("  hello there  ", 1_700_000_000_000).expect("seal");
        match open_with_state(&state, &envelope) {
            InnerPayload::Chat(ChatPayload::TextMessage { text, .. }) => {
                assert_eq!(text, "hello there");
            }
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn text_length_is_counted_in_characters_not_bytes() {
        let state = state();
        // 4000 multibyte characters is 12000 bytes; the character limit must apply.
        let text = "😀".repeat(MAX_TEXT_CHARS);
        assert!(state.build_text_envelope(&text, 1).is_ok());

        let text = "😀".repeat(MAX_TEXT_CHARS + 1);
        assert!(state.build_text_envelope(&text, 1).is_err());
    }

    #[test]
    fn file_envelope_round_trips() {
        let state = state();
        let envelope = state
            .build_file_envelope(
                "abc.bin",
                2048,
                "image/jpeg",
                &crypto::sha256_b64(b"hello"),
                Some("sunset".into()),
                1_700_000_000_000,
            )
            .expect("seal");

        match open_with_state(&state, &envelope) {
            InnerPayload::Chat(ChatPayload::FileAttachment {
                asset_name,
                size_bytes,
                mime,
                caption,
                ..
            }) => {
                assert_eq!(asset_name, "abc.bin");
                assert_eq!(size_bytes, 2_048);
                assert_eq!(mime, "image/jpeg");
                assert_eq!(caption.as_deref(), Some("sunset"));
            }
            other => panic!("expected file, got {other:?}"),
        }
    }

    #[test]
    fn flag_envelope_requires_a_reason() {
        let state = state();
        assert_eq!(
            state
                .build_flag_envelope(1, "AAAA", "   ", 1)
                .expect_err("must fail")
                .kind(),
            crate::error::AppErrorKind::InvalidArgument
        );

        let envelope = state.build_flag_envelope(1, "AAAA", "spam", 1).expect("seal");
        match open_with_state(&state, &envelope) {
            InnerPayload::Chat(ChatPayload::ModerationFlag {
                target_comment_id,
                target_pubkey,
                reason,
                ..
            }) => {
                assert_eq!(target_comment_id, 1);
                assert_eq!(target_pubkey, "AAAA");
                assert_eq!(reason, "spam");
            }
            other => panic!("expected flag, got {other:?}"),
        }
    }

    #[test]
    fn control_envelope_round_trips_after_rotation() {
        let state = state();
        state.apply_rotation(1, [9u8; 32]).expect("rotate");
        assert_eq!(state.current_epoch(), 1);

        let envelope = state.build_rotation_envelope(1, 0, "member removed", 1).expect("seal");
        assert_eq!(envelope.key_epoch, 1);

        match open_with_state(&state, &envelope) {
            InnerPayload::Control(ControlPayload::KeyRotation {
                new_epoch,
                retired_epoch,
                reason,
                ..
            }) => {
                assert_eq!(new_epoch, 1);
                assert_eq!(retired_epoch, 0);
                assert_eq!(reason, "member removed");
            }
            other => panic!("expected rotation, got {other:?}"),
        }
    }

    #[test]
    fn rotation_envelope_fails_without_the_new_key() {
        let state = state();
        let err = state.build_rotation_envelope(5, 0, "x", 1).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::GroupState);
    }

    // -- Rotation policy ------------------------------------------------------

    #[test]
    fn rotation_advances_and_retains_the_old_epoch() {
        let state = state();
        state.apply_rotation(1, [9u8; 32]).expect("rotate");
        assert_eq!(state.current_group_key().expect("key"), [9u8; 32]);

        let keys = state.keys.read();
        assert_eq!(keys.known_epochs(), vec![0, 1], "epoch 0 must remain readable");
        assert_eq!(keys.get(0), Some(&TEST_KEY));
    }

    #[test]
    fn rotation_rejects_a_non_advancing_epoch() {
        let state = state();
        let err = state.apply_rotation(0, [9u8; 32]).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::GroupState);
    }

    #[test]
    fn observe_rotation_accepts_the_host() {
        let me = identity();
        let state = GroupState::from_invite(&invite_for(&me.pubkey_b64), me, prefs(), true).expect("state");

        let notice = state
            .observe_rotation(&state.host_pubkey_b64.clone(), 1, 0)
            .expect("accept");
        assert_eq!(notice.new_epoch, 1);
        assert!(!notice.already_held, "we do not hold epoch 1 yet");
    }

    #[test]
    fn observe_rotation_reports_when_the_epoch_is_already_held() {
        let state = state();
        state.apply_rotation(1, [9u8; 32]).expect("rotate");
        let host = state.host_pubkey_b64.clone();

        let notice = state.observe_rotation(&host, 1, 0).expect("accept");
        assert!(notice.already_held);
    }

    #[test]
    fn observe_rotation_rejects_a_non_host_sender() {
        let state = state();
        let attacker = other_identity(9);
        let err = state
            .observe_rotation(&attacker.pubkey_b64, 1, 0)
            .expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::GroupState);
        assert!(err.to_string().contains("only the host may rotate"));
    }

    #[test]
    fn observe_rotation_rejects_a_non_advancing_epoch() {
        let state = state();
        let host = state.host_pubkey_b64.clone();
        let err = state.observe_rotation(&host, 2, 5).expect_err("must fail");
        assert!(err.to_string().contains("not an advance"));
    }

    // -- Decoding ------------------------------------------------------------

    #[test]
    fn decode_member_reads_a_self_published_entry() {
        let state = state();
        let me_secret = state.identity.secret_bytes();
        let me = Identity::from_secret(*me_secret);

        let comment = roster_comment(
            &state,
            &me,
            Fix::at(41.5, -87.5, crate::wire::now_unix_ms(),),
            "Jared",
        );

        let member = state.decode_member(&comment).expect("decode");
        assert_eq!(member.display_name, "Jared");
        assert!(member.is_self, "same key means this is us");
        assert!(!member.is_stale);
        assert!(!member.is_blocked);
    }

    #[test]
    fn decode_member_marks_older_fixes_stale() {
        let state = state();
        let me = Identity::from_secret(*state.identity.secret_bytes());
        let old_ms = crate::wire::now_unix_ms() - (MEMBER_STALE_SECS + 60) * 1_000;

        let comment = roster_comment(
            &state,
            &me,
            Fix::at(1.0, 2.0, old_ms,),
            "Jared",
        );
        let member = state.decode_member(&comment).expect("decode");
        assert!(member.is_stale, "a 6-minute-old fix is stale");
    }

    #[test]
    fn decode_member_flags_blocked_members() {
        let state = state();
        let peer = other_identity(11);
        let comment = roster_comment(
            &state,
            &peer,
            Fix::at(1.0, 2.0, crate::wire::now_unix_ms(),),
            "Peer",
        );
        state.block(&peer.pubkey_b64);

        let member = state.decode_member(&comment).expect("decode");
        assert!(member.is_blocked);
        assert!(!member.is_self);
    }

    #[test]
    fn decode_member_rejects_non_envelope_bodies() {
        let state = state();
        let comment = IssueComment {
            id: 1,
            body: "just some text, not an envelope".into(),
            created_at_ms: 0,
            updated_at_ms: 0,
            author_login: "x".into(),
            nostr_event_id: None,
        };
        let failure = state.decode_member(&comment).expect_err("must fail");
        assert!(matches!(failure, DecodeFailure::Crypto(_)));
        assert!(failure.reason().contains("envelope"));
    }

    #[test]
    fn decode_member_reports_an_unknown_epoch() {
        let state = state();
        let me = Identity::from_secret(*state.identity.secret_bytes());
        // Seal with a key this device does not hold, under an epoch it does not know.
        let envelope = crypto::seal_location(
            &[42u8; 32],
            9,
            me.signing_key(),
            &LocationState {
                display_name: "Ghost".into(),
                avatar_color: "#000000".into(),
                lat: 0.0,
                lon: 0.0,
                accuracy_m: 0.0,
                speed_mps: 0.0,
                heading_deg: 0.0,
                battery_pct: 0,
                is_charging: false,
                unix_ms: 1,
                member_pubkey: me.pubkey_b64.clone(),
            },
        )
        .expect("seal");

        let comment = IssueComment {
            id: 1,
            body: serde_json::to_string(&envelope).expect("json"),
            created_at_ms: 0,
            updated_at_ms: 0,
            author_login: "x".into(),
            nostr_event_id: None,
        };
        let failure = state.decode_member(&comment).expect_err("must fail");
        assert_eq!(failure, DecodeFailure::UnknownEpoch(9));
        assert!(failure.reason().contains("epoch 9"));
    }

    #[test]
    fn decode_member_rejects_a_chat_payload_in_a_roster_slot() {
        let state = state();
        let envelope = state.build_text_envelope("wrong place", 1).expect("seal");
        let comment = IssueComment {
            id: 1,
            body: serde_json::to_string(&envelope).expect("json"),
            created_at_ms: 0,
            updated_at_ms: 0,
            author_login: "x".into(),
            nostr_event_id: None,
        };
        assert_eq!(
            state.decode_member(&comment).expect_err("must fail"),
            DecodeFailure::UnexpectedKind
        );
    }

    #[test]
    fn decode_chat_reads_a_text_message() {
        let state = state();
        let comment = chat_comment(&state, &state.identity, "on my way", 1_700_000_000_000, 5);

        match state.decode_chat(&comment).expect("decode") {
            ChatItem::Text {
                text,
                unix_ms,
                is_self,
                is_blocked,
                comment_id,
                ..
            } => {
                assert_eq!(text, "on my way");
                assert_eq!(unix_ms, 1_700_000_000_000);
                assert!(is_self);
                assert!(!is_blocked);
                assert_eq!(comment_id, 5);
            }
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn decode_chat_rejects_a_location_payload_in_a_chat_slot() {
        let state = state();
        let envelope = state
            .build_location_envelope(Fix::at(1.0, 2.0, 1,))
            .expect("seal");
        let comment = IssueComment {
            id: 1,
            body: serde_json::to_string(&envelope).expect("json"),
            created_at_ms: 0,
            updated_at_ms: 0,
            author_login: "x".into(),
            nostr_event_id: None,
        };
        assert_eq!(
            state.decode_chat(&comment).expect_err("must fail"),
            DecodeFailure::UnexpectedKind
        );
    }

    #[test]
    fn decode_failure_reason_is_informative() {
        assert!(DecodeFailure::Crypto("bad tag".into()).reason().contains("bad tag"));
        assert_eq!(DecodeFailure::UnexpectedKind.reason(), "payload was not a chat event");
        assert!(DecodeFailure::UnknownEpoch(3).reason().contains("3"));
    }

    // -- Applying roster and chat ---------------------------------------------

    #[test]
    fn apply_roster_sorts_self_first_then_newest() {
        let state = state();
        let me = Identity::from_secret(*state.identity.secret_bytes());
        let peer_a = other_identity(21);
        let peer_b = other_identity(22);
        let now = crate::wire::now_unix_ms();

        let comments = vec![
            roster_comment(&state, &peer_a, Fix::at(1.0, 1.0, now - 100_000), "A"),
            roster_comment(&state, &peer_b, Fix::at(2.0, 2.0, now - 10_000), "B"),
            roster_comment(&state, &me, Fix::at(3.0, 3.0, now - 500_000), "Me"),
        ];

        assert_eq!(state.apply_roster(&comments), 3);
        let roster = state.roster.read();
        assert!(roster.first().expect("first").is_self, "self pins to the top");
        assert_eq!(roster.get(1).map(|m| m.display_name.as_str()), Some("B"));
        assert_eq!(roster.get(2).map(|m| m.display_name.as_str()), Some("A"));
    }

    #[test]
    fn apply_roster_drops_expired_entries() {
        let state = state();
        let me = Identity::from_secret(*state.identity.secret_bytes());
        let ancient = crate::wire::now_unix_ms() - (MEMBER_EXPIRE_SECS + 600) * 1_000;

        let comments = vec![roster_comment(
            &state,
            &me,
            Fix::at(1.0, 1.0, ancient,),
            "Ancient",
        )];

        assert_eq!(state.apply_roster(&comments), 0, "expired entries are pruned");
    }

    #[test]
    fn apply_roster_skips_malformed_comments() {
        let state = state();
        let comments = vec![
            IssueComment {
                id: 1,
                body: "not an envelope".into(),
                created_at_ms: 0,
                updated_at_ms: 0,
                author_login: "x".into(),
            nostr_event_id: None,
            },
            roster_comment(
                &state,
                &Identity::from_secret(*state.identity.secret_bytes()),
                Fix::at(1.0, 1.0, crate::wire::now_unix_ms(),),
                "Valid",
            ),
        ];

        assert_eq!(state.apply_roster(&comments), 1, "only the valid entry survives");
    }

    #[test]
    fn apply_roster_replaces_rather_than_appends() {
        let state = state();
        let me = Identity::from_secret(*state.identity.secret_bytes());
        let now = crate::wire::now_unix_ms();

        let one = vec![roster_comment(&state, &me, Fix::at(1.0, 1.0, now), "Me")];
        state.apply_roster(&one);
        assert_eq!(state.roster.read().len(), 1);

        let two = vec![
            roster_comment(&state, &me, Fix::at(1.0, 1.0, now), "Me"),
            roster_comment(&state, &other_identity(31), Fix::at(2.0, 2.0, now), "Peer"),
        ];
        state.apply_roster(&two);
        assert_eq!(state.roster.read().len(), 2);
    }

    #[test]
    fn apply_chat_orders_ascending_and_keeps_undecryptable_items() {
        let state = state();
        let comments = vec![
            chat_comment(&state, &state.identity, "second", 2_000, 20),
            IssueComment {
                id: 15,
                body: "garbage".into(),
                created_at_ms: 0,
                updated_at_ms: 0,
                author_login: "x".into(),
            nostr_event_id: None,
            },
            chat_comment(&state, &state.identity, "first", 1_000, 10),
        ];

        assert_eq!(state.apply_chat(&comments), 3);
        let chat = state.chat.read();

        // Undecryptable sorts by comment id with timestamp 0, so it leads.
        assert!(matches!(chat.first(), Some(ChatItem::Undecryptable { comment_id: 15, .. })));
        assert!(matches!(
            chat.get(1),
            Some(ChatItem::Text { text, .. }) if text == "first"
        ));
        assert!(matches!(
            chat.get(2),
            Some(ChatItem::Text { text, .. }) if text == "second"
        ));
    }

    #[test]
    fn append_chat_deduplicates_by_comment_id() {
        let state = state();
        let comment = chat_comment(&state, &state.identity, "hi", 1_000, 7);

        state.append_chat(&comment);
        state.append_chat(&comment);
        assert_eq!(state.chat.read().len(), 1, "the same comment must not appear twice");
    }

    #[test]
    fn append_chat_keeps_ordering() {
        let state = state();
        state.append_chat(&chat_comment(&state, &state.identity, "later", 5_000, 50));
        state.append_chat(&chat_comment(&state, &state.identity, "earlier", 1_000, 10));

        let chat = state.chat.read();
        assert!(
            matches!(chat.first(), Some(ChatItem::Text { text, .. }) if text == "earlier"),
            "an out-of-order append must still sort correctly"
        );
    }

    #[test]
        fn should_display_hides_blocked_content_but_not_moderation() {
            let state = state();
            let peer = other_identity(41);

            // The decode-time flag is ignored; the live block list is authoritative.
            let text = text_item(&peer.pubkey_b64, "hello", 1, 1, false, false);
            assert!(state.should_display(&text), "not blocked yet");

            state.block(&peer.pubkey_b64);
            assert!(!state.should_display(&text), "blocked live");

        let moderation = ChatItem::Moderation {
            comment_id: 2,
            sender_pubkey_b64: peer.pubkey_b64.clone(),
            target_comment_id: 1,
            reason: "spam".into(),
            unix_ms: 1,
        };
        assert!(state.should_display(&moderation), "governance stays visible");

        let undecryptable = ChatItem::Undecryptable {
            comment_id: 3,
            reason: "unknown epoch".into(),
        };
        assert!(state.should_display(&undecryptable), "unreadable content is still shown");
    }

    #[test]
        fn visible_views_filter_blocked_entries() {
            let state = state();
            let peer = other_identity(51);
            let now = crate::wire::now_unix_ms();

            state.apply_roster(&[
                roster_comment(&state, &peer, Fix::at(2.0, 2.0, now), "Peer"),
            ]);
            assert_eq!(state.roster.read().len(), 1, "the peer entry exists");

            // Visible before blocking.
            assert_eq!(state.visible_roster().len(), 1);

            state.block(&peer.pubkey_b64);

            // The roster itself keeps the entry so the block can be undone...
            assert_eq!(state.roster.read().len(), 1);
            // ...but nothing is rendered while the block is in force.
            assert!(
                state.visible_roster().is_empty(),
                "a blocked member must disappear from the map immediately"
            );

            state.unblock(&peer.pubkey_b64);
            assert_eq!(
                state.visible_roster().len(),
                1,
                "unblocking must restore the member without waiting for a poll"
            );
        }

        #[test]
        fn self_is_never_hidden_by_the_block_list() {
            let state = state();
            let me = Identity::from_secret(*state.identity.secret_bytes());
            state.apply_roster(&[roster_comment(
                &state,
                &me,
                Fix::at(1.0, 1.0, crate::wire::now_unix_ms(),),
                "Me",
            )]);

            state.block(&state.identity.pubkey_b64);
            let visible = state.visible_roster();
            assert_eq!(visible.len(), 1, "own pin must always render");
            assert!(visible.first().expect("first").is_self);
        }

    #[test]
        fn visible_chat_filters_blocked_senders() {
                let state = state();
                let blocked_item = text_item("BBBB", "hidden", 1, 1, false, true);
                let visible_item = text_item(&state.identity.pubkey_b64, "shown", 2, 2, true, false);
                *state.chat.write() = vec![blocked_item, visible_item];

                // "BBBB" is not on the block list, so both render; the flag alone must not
                // hide anything, because the live list is what decides.
                assert_eq!(state.visible_chat().len(), 2);

                state.block("BBBB");
                let visible = state.visible_chat();
                assert_eq!(visible.len(), 1, "the blocked sender is filtered out");
                assert!(matches!(
                    visible.first(),
                    Some(ChatItem::Text { text, .. }) if text == "shown"
                ));
        }

    // -- Cadence -------------------------------------------------------------

    #[test]
    fn cadence_starts_at_the_plan_intervals() {
        let state = state();
        let report = state.cadence_report();
        assert_eq!(report.chat_interval_s, CHAT_INTERVAL_SECS);
        assert_eq!(report.roster_interval_s, ROSTER_INTERVAL_SECS);
        assert!(report.halted_until_unix_s.is_none());
    }

    #[tokio::test]
    async fn chat_delay_lengthens_after_repeated_304s() {
        let state = state();

        let base = state.chat_delay(true).await;
        assert!(
            base >= Duration::from_millis(3_750) && base <= Duration::from_millis(6_250),
            "first delay should be 5 s ±25%, got {base:?}"
        );

        state.chat_delay(true).await;
        state.chat_delay(true).await;
        // After the third quiet poll the interval doubles to 10 s before jitter.
        let backed_off = state.chat_delay(true).await;
        assert_eq!(state.chat_backoff.read().current(), Duration::from_secs(10));
        assert!(
            backed_off <= Duration::from_millis(12_500),
            "jitter must stay proportional: {backed_off:?}"
        );
    }

    #[tokio::test]
    async fn changed_response_resets_the_interval() {
        let state = state();
        for _ in 0..6 {
            state.chat_delay(true).await;
        }
        assert!(state.chat_backoff.read().current() > Duration::from_secs(CHAT_INTERVAL_SECS));

        state.chat_delay(false).await;
        assert_eq!(
            state.chat_backoff.read().current(),
            Duration::from_secs(CHAT_INTERVAL_SECS)
        );
    }

    #[test]
    fn reset_cadence_restores_both_channels() {
        let state = state();
        state.chat_backoff.write().observe(true);
        state.chat_backoff.write().observe(true);
        state.chat_backoff.write().observe(true);
        state.roster_backoff.write().observe(true);
        state.roster_backoff.write().observe(true);
        state.roster_backoff.write().observe(true);
        assert!(state.chat_backoff.read().current() > Duration::from_secs(CHAT_INTERVAL_SECS));

        state.reset_cadence();
        assert_eq!(
            state.chat_backoff.read().current(),
            Duration::from_secs(CHAT_INTERVAL_SECS)
        );
        assert_eq!(
            state.roster_backoff.read().current(),
            Duration::from_secs(ROSTER_INTERVAL_SECS)
        );
    }

    #[test]
    fn rate_limit_halt_stops_all_channels() {
        let state = state();
        assert!(!state.is_halted(1_000));

        state.observe_rate_limit(429, Some(1_700_000_000), Some(0), Some(5_000));
        assert!(state.is_halted(1_700_000_000));
        assert_eq!(state.halt_remaining_secs(1_700_000_000), Some(60));

        let report = state.cadence_report();
        assert_eq!(report.halted_until_unix_s, Some(1_700_000_060));
        assert_eq!(report.remaining_requests, Some(0));
        assert_eq!(report.total_requests, Some(5_000));
    }

    #[test]
    fn rate_limit_halt_ignores_a_403_with_budget_left() {
        let state = state();
        state.observe_rate_limit(403, Some(1_700_000_000), Some(4_000), Some(5_000));
        assert!(!state.is_halted(1_700_000_000));
    }

    // -- Helpers -------------------------------------------------------------

    #[test]
    fn shared_and_require_group_round_trip() {
        let shared = shared(state());
        let group = require_group(&shared).expect("group");
        assert_eq!(group.group_label, "Weekend Trip");
    }

    #[test]
    fn require_group_explains_when_there_is_none() {
        let shared: SharedGroup = Arc::new(RwLock::new(None));
        let err = require_group(&shared).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::GroupState);
        assert!(err.to_string().contains("no group is active"));
    }

    #[test]
    fn comment_ids_by_pubkey_maps_members() {
        let state = state();
        let me = Identity::from_secret(*state.identity.secret_bytes());
        state.apply_roster(&[roster_comment(
            &state,
            &me,
            Fix::at(1.0, 1.0, crate::wire::now_unix_ms(),),
            "Me",
        )]);

        let map = comment_ids_by_pubkey(&state.roster.read());
        assert_eq!(map.get(&state.identity.pubkey_b64), Some(&100));
    }


    #[test]
    fn verifying_key_bytes_matches_the_public_key() {
        let me = identity();
        assert_eq!(
            verifying_key_bytes(&me.verifying_key),
            me.verifying_key.to_bytes()
        );
    }
}
