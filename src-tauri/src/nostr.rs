//! Nostr transport: accountless, serverless, ciphertext-only storage.
//!
//! # Why this exists
//!
//! Relays need no account, and the invite carries no credential that could be
//! used to destroy the group's storage. Nostr removes both problems:
//!
//! * Identity is a secp256k1 keypair generated on the device. No email, no
//!   signup, no OAuth app, no token to paste.
//! * Relays store opaque events. They cannot read anything, and there is no
//!   shared store for a guest to delete.
//! * Relays push over WebSocket, so the polling machinery in [`crate::geo_filter`]
//!   is not needed on this path.
//!
//! # What this module does *not* do
//!
//! It does not encrypt. The group key and `XChaCha20-Poly1305` envelope in
//! [`crate::crypto`] stay exactly as they are; this module only moves the
//! resulting ciphertext. NIP-44 is deliberately not used: it is pairwise ECDH,
//! which would mean encrypting once per member instead of once per message.
//!
//! # Schema mapping
//!
//! | Logical table | Nostr primitive |
//! |---|---|
//! | Member roster + live location | addressable event, `d` tag = member pubkey |
//! | Group chat + file pointers | regular event, `d` tag = group id |
//! | Encrypted binary vault | Blossom blob, addressed by SHA-256 |
//!
//! Addressable events (kind 30000–39999) are replaceable per
//! `(pubkey, kind, d-tag)`, which is exactly the "each member owns one slot"
//! property the group schema needs: one event per member.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{AppError, Result};

/// Roster slot: addressable, replaceable per member.
pub const KIND_ROSTER: u64 = 30_078;
/// Chat message: regular, append-only.
pub const KIND_CHAT: u64 = 30_079;
/// Legacy file pointers were addressable and could replace older pointers.
pub const KIND_FILE_LEGACY: u64 = 30_080;
/// File pointer: regular, append-only.
pub const KIND_FILE: u64 = 8_096;
/// Host-authenticated group closure, addressable by group id.
pub const KIND_GROUP_CLOSED: u64 = 30_081;
/// Host role assignments, addressable by group id so the latest set replaces older ones.
pub const KIND_CONTROL: u64 = 30_082;
/// Key-rotation notice. Regular (not addressable) so a newer notice cannot erase
/// the epoch a guest still needs in order to notice they were cut off.
pub const KIND_ROTATION: u64 = 8_098;
/// An uploader's signed notice that a Blossom file was removed.
pub const KIND_FILE_REMOVED: u64 = 8_097;
/// NIP-09 deletion request.
pub const KIND_DELETE: u64 = 5;
/// BUD-11 Blossom authorization event.
pub const KIND_BLOSSOM_AUTH: u64 = 24_242;

/// Default relays. Several are used so one going away does not lose the group.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
];

/// Default Blossom servers for encrypted blobs.
pub const DEFAULT_BLOSSOM_SERVERS: &[&str] = &["https://blossom.nostr.build"];

/// Per-connection timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long to wait for an `OK` acknowledgement before giving up.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// A Nostr identity: a secp256k1 keypair, generated locally.
///
/// The secret is zeroized on drop. There is no account, no recovery, and no
/// server that knows this key exists.
pub struct NostrIdentity {
    secret: Zeroizing<[u8; 32]>,
    pubkey_hex: String,
}

impl std::fmt::Debug for NostrIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrIdentity")
            .field("pubkey", &self.pubkey_hex)
            .finish_non_exhaustive()
    }
}

impl NostrIdentity {
    /// Generate a fresh identity from OS entropy.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| AppError::crypto(format!("could not read entropy: {e}")))?;
        Self::from_secret_bytes(bytes)
    }

    /// Build from raw secret bytes, rejecting anything secp256k1 will not accept.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self> {
        let secret = Zeroizing::new(bytes);
        let key = SecretKey::from_secret_bytes(*secret)
            .map_err(|e| AppError::crypto(format!("invalid Nostr secret key: {e}")))?;
        let keypair = Keypair::from_secret_key(&key);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        Ok(Self {
            secret,
            pubkey_hex: xonly.to_string(),
        })
    }

    /// Parse a 64-character hex secret key.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let trimmed = hex_str.trim();
        if trimmed.len() != 64 {
            return Err(AppError::invalid_argument(
                "a Nostr secret key must be 64 hex characters",
            ));
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(trimmed, &mut bytes)
            .map_err(|e| AppError::invalid_argument(format!("invalid hex secret key: {e}")))?;
        Self::from_secret_bytes(bytes)
    }

    /// The public key as lowercase hex, which is the account identifier.
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// The secret as hex, for the vault. Callers must not log this.
    pub fn secret_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(*self.secret))
    }

    /// Sign a 32-byte digest, returning a 64-byte Schnorr signature as hex.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<String> {
        let key = SecretKey::from_secret_bytes(*self.secret)
            .map_err(|e| AppError::crypto(format!("invalid secret key: {e}")))?;
        let keypair = Keypair::from_secret_key(&key);
        let signature = keypair.sign_schnorr_no_aux_rand(digest);
        Ok(hex::encode(signature.to_byte_array()))
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// A Nostr event, in the shape relays expect.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    /// Event ids this event asks relays to delete, from its `e` tags.
    ///
    /// Only meaningful on a kind 5 deletion request.
    pub fn deleted_event_ids(&self) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|tag| tag.first().map(String::as_str) == Some("e"))
            .filter_map(|tag| tag.get(1))
            .map(String::as_str)
            .collect()
    }

    /// Addressable slots this event asks relays to delete, from its `a` tags.
    ///
    /// The value is `kind:pubkey:d-tag`.
    pub fn deleted_slot_addresses(&self) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|tag| tag.first().map(String::as_str) == Some("a"))
            .filter_map(|tag| tag.get(1))
            .map(String::as_str)
            .collect()
    }

    /// True when this is a NIP-09 deletion request.
    pub fn is_deletion_request(&self) -> bool {
        self.kind == KIND_DELETE
    }

    /// The `d` tag value, which makes an addressable event replaceable.
    pub fn d_tag(&self) -> Option<&str> {
        self.tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some("d"))
            .and_then(|tag| tag.get(1))
            .map(String::as_str)
    }

    /// Serialize for the event id, per NIP-01.
    ///
    /// The id is `sha256` over a JSON array with no whitespace and a fixed field
    /// order. Getting this wrong makes every relay reject the event, so it is
    /// built by hand rather than with `serde_json::to_string` on the struct.
    fn id_preimage(&self) -> String {
        let tags = serde_json::to_string(&self.tags).unwrap_or_else(|_| "[]".into());
        format!(
            "[0,\"{}\",{},{},{},{}]",
            self.pubkey, self.created_at, self.kind, tags, json_string(&self.content)
        )
    }

    /// Recompute the id and confirm it matches.
    pub fn verify_id(&self) -> Result<()> {
        let digest = Sha256::digest(self.id_preimage().as_bytes());
        let expected = hex::encode(digest);
        if expected != self.id {
            return Err(AppError::crypto(
                "event id does not match its contents; the event was altered",
            ));
        }
        Ok(())
    }

    /// Verify the Schnorr signature against the event id.
    pub fn verify_signature(&self) -> Result<()> {
        let pubkey_bytes: [u8; 32] = hex::decode(&self.pubkey)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| AppError::crypto("event pubkey is not 32 bytes"))?;
        let pubkey = XOnlyPublicKey::from_byte_array(pubkey_bytes)
            .map_err(|e| AppError::crypto(format!("invalid event pubkey: {e}")))?;
        let sig_bytes: [u8; 64] = hex::decode(&self.sig)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| AppError::crypto("event signature is not 64 bytes"))?;
        let signature = secp256k1::schnorr::Signature::from_byte_array(sig_bytes);
        let id_bytes: [u8; 32] = hex::decode(&self.id)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| AppError::crypto("event id is not 32 bytes"))?;
        secp256k1::schnorr::verify(&signature, &id_bytes, &pubkey)
            .map_err(|e| AppError::crypto(format!("event signature is invalid: {e}")))
    }
}

/// JSON-escape a string the way NIP-01 requires.
fn json_string(input: &str) -> String {
    serde_json::to_string(input).unwrap_or_else(|_| "\"\"".into())
}

/// Build and sign an event.
pub fn sign_event(
    identity: &NostrIdentity,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: impl Into<String>,
    created_at: i64,
) -> Result<Event> {
    let mut event = Event {
        id: String::new(),
        pubkey: identity.pubkey_hex().to_string(),
        created_at,
        kind,
        tags,
        content: content.into(),
        sig: String::new(),
    };

    let digest = Sha256::digest(event.id_preimage().as_bytes());
    let id_bytes: [u8; 32] = digest.into();
    event.id = hex::encode(id_bytes);
    event.sig = identity.sign_digest(&id_bytes)?;
    Ok(event)
}

/// Build a NIP-09 deletion request for one event.
///
/// Relays **SHOULD** stop serving a referenced event whose author matches the
/// request's author, so this only works for events this device signed. That is
/// exactly the case that matters: a member retracting their own message.
///
/// The request is itself an event, so it must be published and kept — clients
/// that cached the original need to see the retraction to know to hide it.
pub fn build_deletion_request(
    identity: &NostrIdentity,
    target_event_id: &str,
    target_kind: u64,
    reason: &str,
) -> Result<Event> {
    if target_event_id.len() != 64 || !target_event_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::invalid_argument(
            "a deletion target must be a 64-character hex event id",
        ));
    }

    sign_event(
        identity,
        KIND_DELETE,
        vec![
            vec!["e".to_string(), target_event_id.to_string()],
            vec!["k".to_string(), target_kind.to_string()],
        ],
        reason,
        now_unix_s(),
    )
}

/// Build a NIP-09 deletion request for an entire addressable slot.
///
/// Uses an `a` tag (`kind:pubkey:d-tag`), which tells relays to drop every
/// version of that slot up to this request's timestamp. This is how a member
/// removes their roster entry outright rather than blanking it.
pub fn build_slot_deletion_request(
    identity: &NostrIdentity,
    kind: u64,
    d_tag: &str,
    reason: &str,
) -> Result<Event> {
    if d_tag.trim().is_empty() {
        return Err(AppError::invalid_argument(
            "a slot deletion needs a d tag to address",
        ));
    }

    let address = format!("{kind}:{}:{d_tag}", identity.pubkey_hex());
    sign_event(
        identity,
        KIND_DELETE,
        vec![
            vec!["a".to_string(), address],
            vec!["k".to_string(), kind.to_string()],
        ],
        reason,
        now_unix_s(),
    )
}

/// Build a BUD-11 authorization event for a Blossom verb.
///
/// Blossom authenticates with a signed Nostr event rather than a bearer token,
/// so the same keypair that signs group events also authorizes blob operations.
/// `verb` is `upload`, `delete`, or `get`.
pub fn build_blossom_auth(
    identity: &NostrIdentity,
    verb: &str,
    sha256: &str,
    expires_in_s: u64,
) -> Result<Event> {
    if !matches!(verb, "upload" | "delete" | "get") {
        return Err(AppError::invalid_argument(format!(
            "unknown Blossom verb {verb:?}; expected upload, delete, or get"
        )));
    }
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::invalid_argument(
            "a Blossom authorization needs a 64-character hex blob hash",
        ));
    }

    let now = now_unix_s();
    sign_event(
        identity,
        KIND_BLOSSOM_AUTH,
        vec![
            vec!["t".to_string(), verb.to_string()],
            vec!["x".to_string(), sha256.to_string()],
            vec![
                "expiration".to_string(),
                now.saturating_add(expires_in_s as i64).to_string(),
            ],
        ],
        format!("{verb} {sha256}"),
        now,
    )
}

/// Base64-encode a signed event for the `Authorization: Nostr <...>` header.
pub fn blossom_auth_header(event: &Event) -> Result<String> {
    use base64::Engine;
    let json = serde_json::to_vec(event)
        .map_err(|e| AppError::parse("blossom", format!("could not encode auth event: {e}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
}

/// Current unix time in seconds.
pub fn now_unix_s() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Relay messages
// ---------------------------------------------------------------------------

/// A client-to-relay message.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ClientMessage {
    /// `["EVENT", <event>]`
    Event(Event),
    /// `["REQ", <sub-id>, <filter>...]`
    Req(String, Vec<Filter>),
    /// `["CLOSE", <sub-id>]`
    Close(String),
}

impl ClientMessage {
    /// Serialize to the array form relays expect.
    pub fn to_wire(&self) -> Result<String> {
        let value = match self {
            ClientMessage::Event(event) => serde_json::json!(["EVENT", event]),
            ClientMessage::Req(id, filters) => {
                let mut parts = vec![serde_json::json!("REQ"), serde_json::json!(id)];
                for filter in filters {
                    parts.push(serde_json::to_value(filter).map_err(|e| {
                        AppError::parse("nostr", format!("could not encode filter: {e}"))
                    })?);
                }
                serde_json::Value::Array(parts)
            }
            ClientMessage::Close(id) => serde_json::json!(["CLOSE", id]),
        };
        serde_json::to_string(&value)
            .map_err(|e| AppError::parse("nostr", format!("could not encode message: {e}")))
    }
}

/// A relay-to-client message, reduced to what this app cares about.
#[derive(Clone, Debug)]
pub enum RelayMessage {
    /// `["EVENT", <sub-id>, <event>]`
    Event(Box<Event>),
    /// `["EOSE", <sub-id>]` — end of stored events.
    EndOfStoredEvents(String),
    /// `["OK", <event-id>, <accepted>, <message>]`
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    /// `["NOTICE", <message>]`
    Notice(String),
    /// `["CLOSED", <sub-id>, <message>]`
    Closed { subscription: String, message: String },
    /// Anything else, kept so the caller can log it without parsing again.
    Other(String),
}

/// Parse one relay frame.
pub fn parse_relay_message(raw: &str) -> Result<RelayMessage> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| AppError::parse("nostr", format!("relay sent invalid JSON: {e}")))?;
    let array = value
        .as_array()
        .ok_or_else(|| AppError::parse("nostr", "relay message was not an array"))?;
    let kind = array
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::parse("nostr", "relay message had no type"))?;

    match kind {
        "EVENT" => {
            let event = array
                .get(2)
                .ok_or_else(|| AppError::parse("nostr", "EVENT had no payload"))?;
            let parsed: Event = serde_json::from_value(event.clone())
                .map_err(|e| AppError::parse("nostr", format!("invalid event: {e}")))?;
            Ok(RelayMessage::Event(Box::new(parsed)))
        }
        "EOSE" => Ok(RelayMessage::EndOfStoredEvents(
            array
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        )),
        "OK" => Ok(RelayMessage::Ok {
            event_id: array
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            accepted: array.get(2).and_then(|v| v.as_bool()).unwrap_or(false),
            message: array
                .get(3)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        "NOTICE" => Ok(RelayMessage::Notice(
            array
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        )),
        "CLOSED" => Ok(RelayMessage::Closed {
            subscription: array
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            message: array
                .get(2)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        other => Ok(RelayMessage::Other(other.to_string())),
    }
}

/// A relay subscription filter.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u64>>,
    #[serde(rename = "#d", skip_serializing_if = "Option::is_none")]
    pub d_tags: Option<Vec<String>>,
    #[serde(rename = "#e", skip_serializing_if = "Option::is_none")]
    pub event_tags: Option<Vec<String>>,
    #[serde(rename = "#a", skip_serializing_if = "Option::is_none")]
    pub address_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl Filter {
    /// Everything in one group, for a first sync.
    pub fn group(group_id: &str, since: Option<i64>) -> Self {
        Self {
            kinds: Some(vec![KIND_ROSTER, KIND_CHAT, KIND_FILE, KIND_FILE_LEGACY]),
            d_tags: Some(vec![group_id.to_string()]),
            event_tags: None,
            address_tags: None,
            authors: None,
            since,
            limit: Some(500),
        }
    }

    /// One member's roster slot.
    pub fn roster_slot(group_id: &str, author: &str) -> Self {
        Self {
            kinds: Some(vec![KIND_ROSTER]),
            d_tags: Some(vec![group_id.to_string()]),
            event_tags: None,
            address_tags: None,
            authors: Some(vec![author.to_string()]),
            since: None,
            limit: Some(1),
        }
    }
}

// ---------------------------------------------------------------------------
// Blossom (blob storage)
// ---------------------------------------------------------------------------

/// A content-addressed blob reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRef {
    /// Lowercase hex SHA-256 of the ciphertext.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
}

impl BlobRef {
    /// Hash a payload and describe it.
    pub fn of(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        Self {
            sha256: hex::encode(digest),
            size: bytes.len() as u64,
        }
    }

    /// The URL a blob is fetched from on `server`.
    pub fn url_on(&self, server: &str) -> String {
        format!("{}/{}", server.trim_end_matches('/'), self.sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> NostrIdentity {
        NostrIdentity::from_secret_bytes([7u8; 32]).expect("identity")
    }

    #[test]
    fn identity_is_deterministic_from_the_same_secret() {
        let a = NostrIdentity::from_secret_bytes([9u8; 32]).expect("a");
        let b = NostrIdentity::from_secret_bytes([9u8; 32]).expect("b");
        assert_eq!(a.pubkey_hex(), b.pubkey_hex());
        assert_eq!(a.pubkey_hex().len(), 64);
    }

    #[test]
    fn identity_rejects_an_invalid_secret() {
        // All-zero is not a valid secp256k1 scalar.
        assert!(NostrIdentity::from_secret_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn identity_round_trips_through_hex() {
        let original = identity();
        let hex_secret = original.secret_hex();
        let restored = NostrIdentity::from_hex(&hex_secret).expect("restore");
        assert_eq!(original.pubkey_hex(), restored.pubkey_hex());
    }

    #[test]
    fn identity_rejects_a_short_hex_secret() {
        assert!(NostrIdentity::from_hex("abcd").is_err());
        assert!(NostrIdentity::from_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let id = identity();
        let rendered = format!("{id:?}");
        assert!(rendered.contains(id.pubkey_hex()));
        assert!(!rendered.contains(&*id.secret_hex()));
    }

    #[test]
    fn signed_event_verifies() {
        let id = identity();
        let event = sign_event(&id, KIND_CHAT, vec![], "hello", 1_700_000_000).expect("sign");
        event.verify_id().expect("id");
        event.verify_signature().expect("signature");
        assert_eq!(event.pubkey, id.pubkey_hex());
        assert_eq!(event.content, "hello");
    }

    #[test]
    fn tampering_with_content_breaks_the_id() {
        let id = identity();
        let mut event = sign_event(&id, KIND_CHAT, vec![], "hello", 1_700_000_000).expect("sign");
        event.content = "goodbye".into();
        assert!(event.verify_id().is_err());
    }

    #[test]
    fn tampering_with_the_signature_is_detected() {
        let id = identity();
        let mut event = sign_event(&id, KIND_CHAT, vec![], "hello", 1_700_000_000).expect("sign");
        event.sig = "00".repeat(64);
        assert!(event.verify_signature().is_err());
    }

    #[test]
    fn d_tag_is_read_from_tags() {
        let id = identity();
        let event = sign_event(
            &id,
            KIND_ROSTER,
            vec![vec!["d".into(), "group-1".into()]],
            "x",
            1,
        )
        .expect("sign");
        assert_eq!(event.d_tag(), Some("group-1"));
    }

    #[test]
    fn event_without_a_d_tag_reports_none() {
        let id = identity();
        let event = sign_event(&id, KIND_CHAT, vec![], "x", 1).expect("sign");
        assert_eq!(event.d_tag(), None);
    }

    #[test]
    fn event_id_preimage_matches_the_nip01_shape() {
        let id = identity();
        let event = sign_event(&id, 1, vec![], "hi", 1_700_000_000).expect("sign");
        let preimage = event.id_preimage();
        // NIP-01 order: [0, pubkey, created_at, kind, tags, content]
        assert!(preimage.starts_with("[0,\""));
        assert!(preimage.contains(",1700000000,1,[],\"hi\"]"));
    }

    #[test]
    fn content_is_json_escaped_in_the_preimage() {
        let id = identity();
        let event = sign_event(&id, 1, vec![], "a\"b\nc", 1).expect("sign");
        let preimage = event.id_preimage();
        assert!(preimage.contains(r#"a\"b\nc"#));
        event.verify_id().expect("id must still match");
    }

    #[test]
    fn client_event_message_serializes_as_an_array() {
        let id = identity();
        let event = sign_event(&id, KIND_CHAT, vec![], "x", 1).expect("sign");
        let wire = ClientMessage::Event(event).to_wire().expect("wire");
        assert!(wire.starts_with("[\"EVENT\",{"));
    }

    #[test]
    fn client_req_message_includes_every_filter() {
        let message = ClientMessage::Req(
            "sub-1".into(),
            vec![Filter::group("g", None), Filter::roster_slot("g", "abc")],
        );
        let wire = message.to_wire().expect("wire");
        assert!(wire.starts_with("[\"REQ\",\"sub-1\","));
        assert!(wire.contains("\"#d\":[\"g\"]"));
    }

    #[test]
    fn client_close_message_serializes() {
        let wire = ClientMessage::Close("sub-1".into()).to_wire().expect("wire");
        assert_eq!(wire, r#"["CLOSE","sub-1"]"#);
    }

    #[test]
    fn filter_omits_absent_fields() {
        let filter = Filter::roster_slot("g", "abc");
        let json = serde_json::to_string(&filter).expect("json");
        assert!(json.contains("\"authors\":[\"abc\"]"));
        assert!(!json.contains("since"));
    }

    #[test]
    fn relay_event_message_parses() {
        let id = identity();
        let event = sign_event(&id, KIND_CHAT, vec![], "x", 1).expect("sign");
        let raw = serde_json::json!(["EVENT", "sub-1", event]).to_string();
        match parse_relay_message(&raw).expect("parse") {
            RelayMessage::Event(parsed) => assert_eq!(parsed.content, "x"),
            other => panic!("expected an event, got {other:?}"),
        }
    }

    #[test]
    fn relay_eose_message_parses() {
        match parse_relay_message(r#"["EOSE","sub-1"]"#).expect("parse") {
            RelayMessage::EndOfStoredEvents(id) => assert_eq!(id, "sub-1"),
            other => panic!("expected EOSE, got {other:?}"),
        }
    }

    #[test]
    fn relay_ok_message_parses_both_outcomes() {
        match parse_relay_message(r#"["OK","abc",true,""]"#).expect("parse") {
            RelayMessage::Ok { accepted, .. } => assert!(accepted),
            other => panic!("expected OK, got {other:?}"),
        }
        match parse_relay_message(r#"["OK","abc",false,"blocked: spam"]"#).expect("parse") {
            RelayMessage::Ok {
                accepted, message, ..
            } => {
                assert!(!accepted);
                assert_eq!(message, "blocked: spam");
            }
            other => panic!("expected OK, got {other:?}"),
        }
    }

    #[test]
    fn relay_notice_and_closed_parse() {
        match parse_relay_message(r#"["NOTICE","hello"]"#).expect("parse") {
            RelayMessage::Notice(text) => assert_eq!(text, "hello"),
            other => panic!("expected NOTICE, got {other:?}"),
        }
        match parse_relay_message(r#"["CLOSED","sub-1","rate limited"]"#).expect("parse") {
            RelayMessage::Closed { message, .. } => assert_eq!(message, "rate limited"),
            other => panic!("expected CLOSED, got {other:?}"),
        }
    }

    #[test]
    fn unknown_relay_messages_are_kept_not_fatal() {
        match parse_relay_message(r#"["AUTH","challenge"]"#).expect("parse") {
            RelayMessage::Other(kind) => assert_eq!(kind, "AUTH"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn malformed_relay_messages_are_errors() {
        assert!(parse_relay_message("not json").is_err());
        assert!(parse_relay_message(r#"{"a":1}"#).is_err());
        assert!(parse_relay_message(r#"["EVENT"]"#).is_err());
    }

    #[test]
    fn blob_ref_hashes_content() {
        let blob = BlobRef::of(b"hello");
        assert_eq!(blob.size, 5);
        assert_eq!(blob.sha256.len(), 64);
        // Same bytes, same address; different bytes, different address.
        assert_eq!(blob, BlobRef::of(b"hello"));
        assert_ne!(blob, BlobRef::of(b"hello!"));
    }

    #[test]
    fn blob_url_trims_trailing_slashes() {
        let blob = BlobRef::of(b"x");
        assert_eq!(
            blob.url_on("https://blossom.example/"),
            format!("https://blossom.example/{}", blob.sha256)
        );
    }

    #[test]
    fn default_relays_are_websocket_urls() {
        assert!(!DEFAULT_RELAYS.is_empty());
        for relay in DEFAULT_RELAYS {
            assert!(relay.starts_with("wss://"), "{relay} must use wss");
        }
    }

    #[test]
    fn now_unix_s_is_plausible() {
        // Later than 2024-01-01, earlier than 2100.
        let now = now_unix_s();
        assert!(now > 1_704_067_200);
        assert!(now < 4_102_444_800);
    }
}
