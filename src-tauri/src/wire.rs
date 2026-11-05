//! Wire types shared by the storage backends and the command layer.
//!
//! These used to live in the GitHub REST module. They are backend-neutral: an
//! [`IssueComment`] is just "one stored envelope with a stable id", which is what
//! a Nostr event projects into. Keeping them here means the Nostr path does not
//! depend on a module named after a backend the app no longer ships.
//!
//! Nothing in this module touches the network or the filesystem.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

/// Largest single file accepted into the vault.
pub const MAX_FILE_BYTES: u64 = 15 * 1024 * 1024;
/// Largest total vault size before the pruner starts deleting.
pub const MAX_VAULT_BYTES: u64 = 500 * 1024 * 1024;

/// Milliseconds since the Unix epoch, saturating at 0 before 1970.
pub fn now_unix_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Seconds since the Unix epoch, saturating at 0 before 1970.
pub fn now_unix_s() -> i64 {
    now_unix_ms() / 1_000
}

/// One stored envelope, already in ciphertext form.
///
/// `body` is an opaque envelope string. The Nostr backend converts an event into
/// this shape so the decode path is shared, with [`IssueComment::nostr_event_id`]
/// carrying the real identifier and `id` holding a stable numeric projection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssueComment {
    pub id: u64,
    pub body: String,
    /// Unix milliseconds parsed from `created_at`.
    #[serde(default)]
    pub created_at_ms: i64,
    /// Unix milliseconds parsed from `updated_at`.
    #[serde(default)]
    pub updated_at_ms: i64,
    /// Author handle, for diagnostics only.
    #[serde(default)]
    pub author_login: String,
    /// The Nostr event id, when this came from a relay.
    ///
    /// `id` is only a numeric projection of this, so anything that needs to
    /// address the original event must use this field.
    #[serde(default)]
    pub nostr_event_id: Option<String>,
}

impl IssueComment {
    /// Project a Nostr event into the comment shape the decode path expects.
    ///
    /// The numeric `id` is the first eight bytes of the event id, which is stable
    /// across polls and distinct enough for UI keys and moderation targets. The
    /// real id is preserved in `nostr_event_id`.
    pub fn from_nostr_event(event: &crate::nostr::Event) -> Self {
        Self {
            id: nostr_numeric_id(&event.id),
            body: event.content.clone(),
            created_at_ms: event.created_at.saturating_mul(1_000),
            updated_at_ms: event.created_at.saturating_mul(1_000),
            author_login: event.pubkey.clone(),
            nostr_event_id: Some(event.id.clone()),
        }
    }
}

/// Stable numeric projection of a hex event id.
///
/// Uses the first eight bytes, which is enough to keep a group's events distinct
/// while fitting the `u64` the UI and moderation code already speak.
pub fn nostr_numeric_id(event_id: &str) -> u64 {
    let bytes = event_id.as_bytes();
    let mut out = [0u8; 8];
    for (slot, byte) in out.iter_mut().zip(bytes.iter()) {
        *slot = *byte;
    }
    u64::from_be_bytes(out)
}

/// Reject a file that exceeds the single-file ceiling.
pub fn enforce_file_size(size_bytes: u64) -> Result<()> {
    if size_bytes > MAX_FILE_BYTES {
        return Err(AppError::PayloadTooLarge {
            what: "file",
            actual_bytes: size_bytes,
            limit_bytes: MAX_FILE_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_id_is_stable_and_distinct() {
        let a = nostr_numeric_id("aaaa000000000000000000000000000000000000000000000000000000000000");
        let b = nostr_numeric_id("aaaa000000000000000000000000000000000000000000000000000000000000");
        let c = nostr_numeric_id("bbbb000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(a, b, "the same event id must project to the same number");
        assert_ne!(a, c, "different event ids must not collide on the first bytes");
    }

    #[test]
    fn numeric_id_tolerates_a_short_id() {
        // A truncated id must not panic; the missing bytes stay zero.
        assert_eq!(nostr_numeric_id("ab"), u64::from_be_bytes([b'a', b'b', 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn file_size_ceiling_is_enforced() {
        enforce_file_size(MAX_FILE_BYTES).expect("exactly at the limit is allowed");
        assert!(enforce_file_size(MAX_FILE_BYTES + 1).is_err());
    }

    #[test]
    fn clock_helpers_are_monotonic_enough() {
        let ms = now_unix_ms();
        assert!(ms > 1_600_000_000_000, "the clock should be past 2020");
        assert_eq!(now_unix_s(), ms / 1_000);
    }
}
