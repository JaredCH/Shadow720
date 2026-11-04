//! Storage backend abstraction.
//!
//! Two backends exist and they are not interchangeable at the wire level, but
//! they serve the same three logical tables:
//!
//! | Logical table | GitHub | Nostr |
//! |---|---|---|
//! | roster slot | one comment per member on Issue #1 | addressable event, `d` = member pubkey |
//! | chat stream | comments on Issue #2 | regular events |
//! | blob vault | release assets | Blossom blobs |
//!
//! This module defines the shape both satisfy so the command layer can stay
//! backend-agnostic. It deliberately describes *slots and streams*, not HTTP
//! verbs: GitHub's "patch my comment" and Nostr's "replace my addressable event"
//! are the same operation, and naming it after the HTTP method would leak one
//! backend's model into the other.
//!
//! # Why not one trait with async methods
//!
//! The two backends need different construction (a token versus a keypair plus a
//! relay list) and different failure modes, so the enum is a plain sum type
//! rather than a boxed trait object. That keeps `match` exhaustive: adding a
//! backend is a compile error at every call site instead of a silent fallback.

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

/// Which backend a group is stored on.
///
/// `GitHub` is the default so an invite written before this field existed parses
/// as the backend it was actually created on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, zeroize::Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// GitHub Issues and release assets. Requires an account.
    #[default]
    GitHub,
    /// Nostr relays and Blossom blobs. No account.
    Nostr,
}

impl BackendKind {
    /// Stable wire string, matching the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::GitHub => "github",
            BackendKind::Nostr => "nostr",
        }
    }

    /// True when the backend needs the user to sign in to an account.
    pub fn requires_account(self) -> bool {
        matches!(self, BackendKind::GitHub)
    }

    /// Parse from the wire string.
    pub fn parse(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "github" => Ok(BackendKind::GitHub),
            "nostr" => Ok(BackendKind::Nostr),
            other => Err(AppError::invalid_argument(format!(
                "unknown storage backend {other:?}; expected github or nostr"
            ))),
        }
    }
}

/// A member's mutable roster slot.
///
/// On GitHub this is a comment id; on Nostr it is the member's own pubkey. Both
/// mean "the one place this member may write, which nobody else can overwrite".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotRef {
    /// Backend-specific handle: a comment id, or a pubkey.
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
    /// Author handle: a login on GitHub, a pubkey on Nostr.
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
    /// GitHub Issues and release assets.
    GitHub(GitHubBackend),
    /// Nostr relays and Blossom blobs.
    Nostr(NostrBackend),
}

/// GitHub connection details.
#[derive(Clone, Debug)]
pub struct GitHubBackend {
    pub repo_full_name: String,
    pub roster_issue_num: u64,
    pub chat_issue_num: u64,
    pub release_id: u64,
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
            Backend::GitHub(_) => BackendKind::GitHub,
            Backend::Nostr(_) => BackendKind::Nostr,
        }
    }

    /// A human-readable location, for diagnostics.
    pub fn location(&self) -> String {
        match self {
            Backend::GitHub(github) => github.repo_full_name.clone(),
            Backend::Nostr(nostr) => format!("nostr:{}", nostr.group_id),
        }
    }

    /// True when the invite must carry a credential for this backend.
    ///
    /// GitHub embeds a token; Nostr embeds only the group key, because each
    /// member signs with their own identity.
    pub fn invite_carries_a_token(&self) -> bool {
        matches!(self, Backend::GitHub(_))
    }

    /// Validate the configuration before it is persisted.
    pub fn validate(&self) -> Result<()> {
        match self {
            Backend::GitHub(github) => {
                if github.repo_full_name.trim().is_empty() {
                    return Err(AppError::invalid_argument(
                        "a GitHub backend needs a repository",
                    ));
                }
                if github.roster_issue_num == 0 || github.chat_issue_num == 0 {
                    return Err(AppError::invalid_argument(
                        "a GitHub backend needs both schema issue numbers",
                    ));
                }
                if github.release_id == 0 {
                    return Err(AppError::invalid_argument(
                        "a GitHub backend needs a vault release id",
                    ));
                }
                Ok(())
            }
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

    fn github() -> Backend {
        Backend::GitHub(GitHubBackend {
            repo_full_name: "o/r".into(),
            roster_issue_num: 1,
            chat_issue_num: 2,
            release_id: 7,
        })
    }

    fn nostr() -> Backend {
        Backend::Nostr(NostrBackend {
            group_id: "g1".into(),
            relays: vec!["wss://relay.example".into()],
            blossom_servers: vec!["https://blossom.example".into()],
        })
    }

    #[test]
    fn kind_reports_the_backend() {
        assert_eq!(github().kind(), BackendKind::GitHub);
        assert_eq!(nostr().kind(), BackendKind::Nostr);
    }

    #[test]
    fn only_github_requires_an_account() {
        assert!(BackendKind::GitHub.requires_account());
        assert!(!BackendKind::Nostr.requires_account());
    }

    #[test]
    fn only_github_puts_a_token_in_the_invite() {
        assert!(github().invite_carries_a_token());
        assert!(
            !nostr().invite_carries_a_token(),
            "Nostr members sign with their own key, so no shared token is needed"
        );
    }

    #[test]
    fn location_is_human_readable() {
        assert_eq!(github().location(), "o/r");
        assert_eq!(nostr().location(), "nostr:g1");
    }

    #[test]
    fn valid_configurations_pass() {
        github().validate().expect("github");
        nostr().validate().expect("nostr");
    }

    #[test]
    fn github_rejects_missing_schema_pieces() {
        let mut backend = GitHubBackend {
            repo_full_name: "o/r".into(),
            roster_issue_num: 0,
            chat_issue_num: 2,
            release_id: 7,
        };
        assert!(Backend::GitHub(backend.clone()).validate().is_err());

        backend.roster_issue_num = 1;
        backend.chat_issue_num = 0;
        assert!(Backend::GitHub(backend.clone()).validate().is_err());

        backend.chat_issue_num = 2;
        backend.release_id = 0;
        assert!(Backend::GitHub(backend).validate().is_err());
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
        for kind in [BackendKind::GitHub, BackendKind::Nostr] {
            assert_eq!(BackendKind::parse(kind.as_str()).expect("parse"), kind);
        }
    }

    #[test]
    fn backend_kind_parse_is_case_insensitive_and_trims() {
        assert_eq!(
            BackendKind::parse("  GitHub ").expect("parse"),
            BackendKind::GitHub
        );
    }

    #[test]
    fn backend_kind_parse_rejects_unknown_values() {
        assert!(BackendKind::parse("gitlab").is_err());
        assert!(BackendKind::parse("").is_err());
    }

    #[test]
    fn slot_ref_holds_an_opaque_handle() {
        assert_eq!(SlotRef::new("123").handle, "123");
        assert_eq!(SlotRef::new("abc").handle, "abc");
    }
}
