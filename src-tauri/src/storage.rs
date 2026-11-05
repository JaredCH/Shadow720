//! Storage backend abstraction.
//!
//! One backend ships: Nostr relays for the roster and chat streams, and Blossom
//! servers for blobs. The three logical tables are:
//!
//! | Logical table | Nostr primitive |
//! |---|---|
//! | roster slot | addressable event, `d` = member pubkey |
//! | chat stream | regular events |
//! | blob vault | Blossom blobs |
//!
//! This module deliberately describes *slots and streams*, not protocol verbs, so
//! the command layer stays backend-agnostic.
//!
//! # Why the enum survives with one variant
//!
//! [`BackendKind`] is still a sum type because it is persisted inside invites and
//! the vault descriptor. Keeping it as an enum means an invite written by an older
//! build that names a backend this build no longer ships fails to parse loudly
//! instead of silently being treated as Nostr.

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

/// Which backend a group is stored on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, zeroize::Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Nostr relays and Blossom blobs. No account.
    #[default]
    Nostr,
}

impl BackendKind {
    /// Stable wire string, matching the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Nostr => "nostr",
        }
    }

    /// True when the backend needs the user to sign in to an account.
    ///
    /// Always false now: Nostr identity is a keypair generated on the device.
    pub fn requires_account(self) -> bool {
        false
    }

    /// Parse from the wire string.
    ///
    /// `github` is rejected with a message that explains the removal rather than
    /// a generic parse error, because the only way to hit it is an invite from an
    /// older build.
    pub fn parse(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "nostr" => Ok(BackendKind::Nostr),
            "github" => Err(AppError::invalid_argument(
                "this invite uses the GitHub backend, which this version no longer supports; \
                 ask the group creator for a Nostr invite",
            )),
            other => Err(AppError::invalid_argument(format!(
                "unknown storage backend {other:?}; expected nostr"
            ))),
        }
    }
}

/// A member's mutable roster slot.
///
/// On Nostr this is the member's own pubkey: "the one place this member may
/// write, which nobody else can overwrite".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotRef {
    /// Backend-specific handle: a pubkey.
    pub handle: String,
}

impl SlotRef {
    pub fn new(handle: impl Into<String>) -> Self {
        Self {
            handle: handle.into(),
        }
    }
}

/// One stored item, already decrypted by the caller.
#[derive(Clone, Debug)]
pub struct StoredItem {
    /// Backend-specific id, used for dedupe and for edits.
    pub id: String,
    /// Author handle: a pubkey on Nostr.
    pub author: String,
    /// Unix milliseconds, for ordering.
    pub created_at_ms: i64,
    /// The envelope ciphertext, exactly as stored.
    pub payload: String,
}

/// What a backend must be able to do.
///
/// Implemented as an enum dispatch rather than a trait so the compiler enforces
/// that every backend handles every operation.
#[derive(Clone, Debug)]
pub enum Backend {
    /// Nostr relays and Blossom blobs.
    Nostr(NostrBackend),
}

/// Nostr connection details.
#[derive(Clone, Debug)]
pub struct NostrBackend {
    /// Group id, used as the `d` tag on every event.
    pub group_id: String,
    /// Relay URLs.
    pub relays: Vec<String>,
    /// Blossom servers for blobs.
    pub blossom_servers: Vec<String>,
}

impl Backend {
    /// Which backend this is.
    pub fn kind(&self) -> BackendKind {
        match self {
            Backend::Nostr(_) => BackendKind::Nostr,
        }
    }

    /// A human-readable location, for diagnostics.
    pub fn location(&self) -> String {
        match self {
            Backend::Nostr(nostr) => format!("nostr:{}", nostr.group_id),
        }
    }

    /// True when the invite must carry a credential for this backend.
    ///
    /// Always false: Nostr embeds only the group key, because each member signs
    /// with their own identity.
    pub fn invite_carries_a_token(&self) -> bool {
        false
    }

    /// Validate the configuration before it is persisted.
    pub fn validate(&self) -> Result<()> {
        match self {
            Backend::Nostr(nostr) => {
                if nostr.group_id.trim().is_empty() {
                    return Err(AppError::invalid_argument(
                        "a Nostr backend needs a group id",
                    ));
                }
                if nostr.relays.is_empty() {
                    return Err(AppError::invalid_argument(
                        "a Nostr backend needs at least one relay",
                    ));
                }
                for relay in &nostr.relays {
                    if !relay.starts_with("wss://") && !relay.starts_with("ws://") {
                        return Err(AppError::invalid_argument(format!(
                            "relay {relay} must be a ws:// or wss:// URL"
                        )));
                    }
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nostr() -> Backend {
        Backend::Nostr(NostrBackend {
            group_id: "g1".into(),
            relays: vec!["wss://relay.example".into()],
            blossom_servers: vec!["https://blossom.example".into()],
        })
    }

    #[test]
    fn kind_reports_the_backend() {
        assert_eq!(nostr().kind(), BackendKind::Nostr);
    }

    #[test]
    fn no_backend_requires_an_account() {
        assert!(!BackendKind::Nostr.requires_account());
    }

    #[test]
    fn no_backend_puts_a_token_in_the_invite() {
        assert!(
            !nostr().invite_carries_a_token(),
            "Nostr members sign with their own key, so no shared token is needed"
        );
    }

    #[test]
    fn location_is_human_readable() {
        assert_eq!(nostr().location(), "nostr:g1");
    }

    #[test]
    fn valid_configurations_pass() {
        nostr().validate().expect("nostr");
    }

    #[test]
    fn nostr_rejects_an_empty_group_or_relay_list() {
        let mut backend = NostrBackend {
            group_id: "".into(),
            relays: vec!["wss://relay.example".into()],
            blossom_servers: vec![],
        };
        assert!(Backend::Nostr(backend.clone()).validate().is_err());

        backend.group_id = "g1".into();
        backend.relays.clear();
        assert!(Backend::Nostr(backend).validate().is_err());
    }

    #[test]
    fn nostr_rejects_a_non_websocket_relay() {
        let backend = NostrBackend {
            group_id: "g1".into(),
            relays: vec!["https://relay.example".into()],
            blossom_servers: vec![],
        };
        assert!(Backend::Nostr(backend).validate().is_err());
    }

    #[test]
    fn backend_kind_round_trips_through_its_wire_string() {
        assert_eq!(
            BackendKind::parse(BackendKind::Nostr.as_str()).expect("parse"),
            BackendKind::Nostr
        );
    }

    #[test]
    fn backend_kind_parse_is_case_insensitive_and_trims() {
        assert_eq!(
            BackendKind::parse("  Nostr ").expect("parse"),
            BackendKind::Nostr
        );
    }

    #[test]
    fn backend_kind_parse_rejects_unknown_values() {
        assert!(BackendKind::parse("gitlab").is_err());
        assert!(BackendKind::parse("").is_err());
    }

    #[test]
    fn a_github_invite_is_rejected_with_an_explanation() {
        // The only way to reach this is an invite from a build that shipped the
        // GitHub backend, so the message has to tell the user what to do.
        let error = BackendKind::parse("github").expect_err("github must not parse");
        assert!(
            error.to_string().contains("no longer supports"),
            "the error should explain the removal, got: {error}"
        );
    }

    #[test]
    fn slot_ref_holds_an_opaque_handle() {
        assert_eq!(SlotRef::new("123").handle, "123");
        assert_eq!(SlotRef::new("abc").handle, "abc");
    }
}
