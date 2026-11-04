//! GitHub REST v3 storage engine.
//!
//! GitHub is an **untrusted ciphertext store**. This module moves opaque envelope
//! strings and opaque release blobs; it never encrypts, decrypts, or interprets
//! payloads. Keeping crypto out of here means there is exactly one place
//! (`crypto.rs`) where plaintext can exist.
//!
//! Mapping from the plan (§4):
//!
//! | Logical table | GitHub primitive | Operations |
//! |---|---|---|
//! | Member roster + live location | `Issue #1` comments | one comment per member, patched only by its owner |
//! | Group chat + file pointers | `Issue #2` comments | append-only |
//! | Encrypted binary vault | `vault-v1` release assets | upload, list, prune |
//!
//! Concurrency safety comes from the schema, not from locking: each member owns
//! exactly one comment id on Issue #1, so N phones patching their own comment
//! never conflict. Nothing is ever written to the Git tree, so `409 Conflict`
//! cannot occur and `.git` history never grows from chat.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::error::{AppError, Result};
use crate::geo_filter::RateLimitHalt;

/// Default REST base. Overridable for GitHub Enterprise or for test vectors.
pub const DEFAULT_API_BASE: &str = "https://api.github.com";
/// Uploads use a different host, and a different auth path.
pub const DEFAULT_UPLOADS_BASE: &str = "https://uploads.github.com";

/// Largest single file accepted into the vault, per plan §4.
pub const MAX_FILE_BYTES: u64 = 15 * 1024 * 1024;
/// Largest total vault size before the pruner starts deleting, per plan §4.
pub const MAX_VAULT_BYTES: u64 = 500 * 1024 * 1024;
/// GitHub rejects comment bodies above 65536 bytes; leave headroom for the
/// server-side count differing from ours on multibyte content.
pub const MAX_COMMENT_BYTES: usize = 60_000;
/// GitHub's maximum page size for list endpoints.
pub const PER_PAGE: u32 = 100;
/// Hard ceiling on pages followed, so a hostile `Link` header cannot loop us.
pub const MAX_PAGES: usize = 100;
/// Per-request timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
/// Connect timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const USER_AGENT: &str = concat!("shadow720/", env!("CARGO_PKG_VERSION"));

/// Body of the roster issue, created during provisioning.
pub const ROSTER_ISSUE_BODY: &str =
    "Shadow720 member roster. One comment per member; each member only edits its own \
     comment. Contents are encrypted.";
/// Body of the chat issue, created during provisioning.
pub const CHAT_ISSUE_BODY: &str =
    "Shadow720 group chat and file pointers. Append-only. Contents are encrypted.";

// ---------------------------------------------------------------------------
// Repository reference
// ---------------------------------------------------------------------------

/// `owner/name` pair. Kept as a value type so it can be parsed once, at invite
/// unpack time, and validated there rather than on every request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RepoRef {
    pub owner: String,
    pub name: String,
}

impl RepoRef {
    /// Build a reference, rejecting empty or path-escaping components.
    ///
    /// Rejecting `/`, `..`, and whitespace matters because these values are
    /// interpolated into request URLs.
    pub fn new(owner: impl Into<String>, name: impl Into<String>) -> Result<Self> {
        let owner = owner.into();
        let name = name.into();
        validate_path_component("owner", &owner)?;
        validate_path_component("repo name", &name)?;
        Ok(Self { owner, name })
    }

    /// Parse `owner/name`.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let (owner, name) = trimmed.split_once('/').ok_or_else(|| {
            AppError::invalid_argument(format!(
                "repository must be given as owner/name, got {trimmed:?}"
            ))
        })?;
        if name.contains('/') {
            return Err(AppError::invalid_argument(
                        "repository must contain exactly one '/'",
            ));
        }
        Self::new(owner, name)
    }

    /// `owner/name`, as GitHub expects in URL paths.
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

fn validate_path_component(what: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(AppError::invalid_argument(format!("{what} must not be empty")));
    }
    if value.contains('/') || value.contains('\\') {
        return Err(AppError::invalid_argument(format!(
            "{what} must not contain path separators"
        )));
    }
    if value == "." || value == ".." {
        return Err(AppError::invalid_argument(format!(
            "{what} must not be a relative path segment"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(AppError::invalid_argument(format!(
            "{what} must not contain whitespace"
        )));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(AppError::invalid_argument(format!(
            "{what} must not contain control characters"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Scrubs secrets out of anything destined for a log, an error, or a test report.
///
/// Live tests run by default against a real token, so redaction has to be
/// structural rather than best-effort: everything logged goes through this.
#[derive(Clone)]
pub struct Redactor {
    secrets: Vec<Zeroizing<String>>,
}

impl Redactor {
    /// Build a redactor that knows about `token`.
    pub fn new(token: &str) -> Self {
        let mut secrets = Vec::new();
        if !token.is_empty() {
            secrets.push(Zeroizing::new(token.to_string()));
            // GitHub tokens embed a distinctive prefix; scrub bare prefixes too
            // in case only a fragment was logged.
            for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"] {
                secrets.push(Zeroizing::new(prefix.to_string()));
            }
        }
        Self { secrets }
    }

    /// Replace every known secret with `[REDACTED]`.
    pub fn scrub(&self, input: &str) -> String {
        let mut out = input.to_string();
        for secret in &self.secrets {
            if secret.is_empty() {
                continue;
            }
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), "[REDACTED]");
            }
        }
        out
    }

    /// Scrub every string in a slice, for batch logging.
    pub fn scrub_all<'a, I>(&self, inputs: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        inputs.into_iter().map(|s| self.scrub(s)).collect()
    }
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("tracked_secrets", &self.secrets.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ETag cache
// ---------------------------------------------------------------------------

/// A cached conditional-GET response.
///
/// Holds ciphertext only: GitHub bodies are envelope JSON, never plaintext.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub etag: String,
    pub body: Vec<u8>,
    pub stored_at_ms: i64,
    pub status: u16,
}

/// Outcome of a conditional request.
#[derive(Clone, Debug)]
pub enum Conditional {
    /// Server returned `304`; `body` is the previously cached representation.
    NotModified { body: Vec<u8> },
    /// Server returned a fresh representation.
    Fresh { body: Vec<u8>, etag: Option<String> },
}

/// URL-keyed store of `(ETag, body)` pairs.
///
/// A `304 Not Modified` does not count against the 5,000 req/hour budget, which
/// is the entire reason this exists. Bounded by entry count so a long session on
/// a busy group cannot grow it without limit.
#[derive(Debug)]
pub struct ETagCache {
    entries: DashMap<String, CachedResponse>,
    max_entries: usize,
}

impl Default for ETagCache {
    fn default() -> Self {
        Self::with_capacity(256)
    }
}

impl ETagCache {
    /// Cache holding at most `max_entries` URLs.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Current entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The stored ETag for `url`, if any.
    pub fn etag_for(&self, url: &str) -> Option<String> {
        self.entries.get(url).map(|e| e.etag.clone())
    }

    /// The stored body for `url`, if any.
    pub fn body_for(&self, url: &str) -> Option<Vec<u8>> {
        self.entries.get(url).map(|e| e.body.clone())
    }

    /// Record a fresh representation.
    pub fn store(&self, url: &str, etag: Option<&str>, body: Vec<u8>, status: u16) {
        let Some(etag) = etag else {
            // Without an ETag there is nothing to revalidate against, so caching
            // would produce stale reads with no way to refresh them.
            return;
        };
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(url) {
            self.evict_oldest();
        }
        self.entries.insert(
            url.to_string(),
            CachedResponse {
                etag: etag.to_string(),
                body,
                stored_at_ms: now_unix_ms(),
                status,
            },
        );
    }

    /// Refresh the timestamp of an entry that revalidated as `304`.
    pub fn touch(&self, url: &str) {
        if let Some(mut entry) = self.entries.get_mut(url) {
            entry.stored_at_ms = now_unix_ms();
        }
    }

    /// Drop a single entry, e.g. after a write invalidates a listing.
    pub fn invalidate(&self, url: &str) {
        self.entries.remove(url);
    }

    /// Drop every entry under `prefix`, e.g. all listings of one issue.
    pub fn invalidate_prefix(&self, prefix: &str) {
        self.entries.retain(|key, _| !key.starts_with(prefix));
    }

    /// Empty the cache.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Evict the least recently stored entry.
    fn evict_oldest(&self) {
        let mut oldest: Option<(String, i64)> = None;
        for entry in self.entries.iter() {
            let key = entry.key().clone();
            let stored = entry.value().stored_at_ms;
            let replace = match &oldest {
                None => true,
                Some((_, best)) => stored < *best,
            };
            if replace {
                oldest = Some((key, stored));
            }
        }
        if let Some((key, _)) = oldest {
            self.entries.remove(&key);
        }
    }
}

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

// ---------------------------------------------------------------------------
// Data transfer objects
// ---------------------------------------------------------------------------

/// Minimal issue comment shape. `body` is an opaque envelope string.
///
/// The Nostr backend reuses this type so the decode path is shared: an event is
/// converted into one of these, with [`IssueComment::nostr_event_id`] carrying
/// the real identifier and `id` holding a stable numeric projection of it.
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
    /// Author login, for diagnostics only. Guests share one token so this is
    /// almost always the host's login and carries no identity meaning.
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
/// while fitting the `u64` the existing UI and moderation code already speak.
pub fn nostr_numeric_id(event_id: &str) -> u64 {
    let bytes = event_id.as_bytes();
    let mut out = [0u8; 8];
    for (slot, byte) in out.iter_mut().zip(bytes.iter()) {
        *slot = *byte;
    }
    u64::from_be_bytes(out)
}

/// Subset of GitHub's comment payload we depend on.
#[derive(Debug, Deserialize)]
struct RawComment {
    id: u64,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    user: Option<RawUser>,
}

#[derive(Debug, Deserialize)]
struct RawUser {
    #[serde(default)]
    login: String,
}

impl From<RawComment> for IssueComment {
    fn from(raw: RawComment) -> Self {
        Self {
            id: raw.id,
            body: raw.body.unwrap_or_default(),
            created_at_ms: raw
                .created_at
                .as_deref()
                .and_then(parse_rfc3339_ms)
                .unwrap_or(0),
            updated_at_ms: raw
                .updated_at
                .as_deref()
                .and_then(parse_rfc3339_ms)
                .unwrap_or(0),
            author_login: raw.user.map(|u| u.login).unwrap_or_default(),
            nostr_event_id: None,
        }
    }
}

/// A release asset, i.e. one encrypted blob in the vault.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReleaseAsset {
    pub id: u64,
    pub name: String,
    pub size: u64,
    #[serde(default)]
    pub created_at_ms: i64,
}

/// Subset of GitHub's asset payload we depend on.
#[derive(Debug, Deserialize)]
struct RawAsset {
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    created_at: Option<String>,
    /// Present for upload responses; ignored otherwise.
    #[serde(default)]
    #[allow(dead_code)]
    browser_download_url: Option<String>,
}

impl From<RawAsset> for ReleaseAsset {
    fn from(raw: RawAsset) -> Self {
        Self {
            id: raw.id,
            name: raw.name,
            size: raw.size,
            created_at_ms: raw
                .created_at
                .as_deref()
                .and_then(parse_rfc3339_ms)
                .unwrap_or(0),
        }
    }
}

/// A snapshot of GitHub's rate-limit headers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateLimitSnapshot {
    pub limit: Option<u32>,
    pub remaining: Option<u32>,
    /// Unix seconds at which the window resets.
    pub reset_unix_s: Option<i64>,
}

impl RateLimitSnapshot {
    /// True when GitHub reported zero requests left.
    pub fn is_exhausted(&self) -> bool {
        self.remaining == Some(0)
    }
}

/// Result of a vault size check.
#[derive(Clone, Debug, PartialEq)]
pub struct PruneReport {
    /// Assets selected for deletion, oldest first.
    pub to_delete: Vec<ReleaseAsset>,
    /// Total vault size before pruning.
    pub total_before: u64,
    /// Total vault size the vault will have once `to_delete` are removed.
    pub total_after: u64,
}

impl PruneReport {
    /// True when nothing needs deleting.
    pub fn is_noop(&self) -> bool {
        self.to_delete.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Quota policy (pure, so it is testable without a network)
// ---------------------------------------------------------------------------

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

/// Reject an envelope that would exceed GitHub's comment size limit.
pub fn enforce_comment_size(body: &str) -> Result<()> {
    let actual = body.len() as u64;
    if actual > MAX_COMMENT_BYTES as u64 {
        return Err(AppError::PayloadTooLarge {
            what: "message",
            actual_bytes: actual,
            limit_bytes: MAX_COMMENT_BYTES as u64,
        });
    }
    Ok(())
}

/// Choose which assets to delete so that `incoming_bytes` fits.
///
/// Oldest first, so a group keeps the most recent shared media. If even
/// emptying the vault cannot fit `incoming_bytes`, the caller must have already
/// rejected the file via [`enforce_file_size`]; this function still reports
/// honestly rather than looping forever.
pub fn assets_to_prune(
    assets: &[ReleaseAsset],
    incoming_bytes: u64,
    max_total_bytes: u64,
) -> PruneReport {
    let total_before: u64 = assets.iter().map(|a| a.size).sum();
    let mut candidates: Vec<ReleaseAsset> = assets.to_vec();
    // Oldest first. Assets with a missing timestamp sort first so unknown-age
    // blobs are reclaimed before content we can date.
    candidates.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut remaining = total_before;
    let mut to_delete = Vec::new();
    for asset in candidates {
        if remaining.saturating_add(incoming_bytes) <= max_total_bytes {
            break;
        }
        remaining = remaining.saturating_sub(asset.size);
        to_delete.push(asset);
    }

    PruneReport {
        total_after: remaining,
        total_before,
        to_delete,
    }
}

/// Parse an RFC 3339 timestamp into Unix milliseconds.
///
/// Hand-rolled rather than pulling a date crate: the format GitHub emits is
/// fixed (`YYYY-MM-DDTHH:MM:SSZ`), and a permissive parser here would be another
/// surface to fuzz.
pub fn parse_rfc3339_ms(input: &str) -> Option<i64> {
    let bytes = input.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let digits = |start: usize, len: usize| -> Option<i64> {
        let slice = input.get(start..start + len)?;
        if !slice.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        slice.parse::<i64>().ok()
    };

    let year = digits(0, 4)?;
    let month = digits(5, 2)?;
    let day = digits(8, 2)?;
    let hour = digits(11, 2)?;
    let minute = digits(14, 2)?;
    let second = digits(17, 2)?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let millis = days
        .saturating_mul(86_400_000)
        .saturating_add(hour.saturating_mul(3_600_000))
        .saturating_add(minute.saturating_mul(60_000))
        .saturating_add(second.saturating_mul(1_000));

    // GitHub always emits a trailing `Z`; treat any explicit offset as unsupported
    // rather than silently mis-parsing it.
    let tail = input.get(19..)?;
    if !tail.starts_with('Z') && !tail.starts_with('+') && !tail.starts_with('-') {
        return None;
    }
    if tail.starts_with('+') || tail.starts_with('-') {
        // Offset present: not produced by GitHub for these endpoints.
        return None;
    }

    Some(millis)
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Extract a `name` query parameter from an asset upload URL.
pub fn parse_asset_name_from_url(url: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key == "name" {
            return percent_decode(value);
        }
    }
    None
}

/// Minimal percent-decoding for query values. Invalid escapes are preserved
/// literally rather than dropped, so a name round-trips instead of corrupting.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let byte = *bytes.get(i)?;
        if byte == b'%' {
            let hi = *bytes.get(i + 1)?;
            let lo = *bytes.get(i + 2)?;
            let hi = (hi as char).to_digit(16)?;
            let lo = (lo as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else if byte == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(byte);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

/// The storage engine's HTTP client.
///
/// Cloning is cheap and shares the token, the ETag cache, and the request queue,
/// so every member of a group can hold the same handle.
#[derive(Clone)]
pub struct GitHubClient {
    http: reqwest::Client,
    token: Arc<Zeroizing<String>>,
    repo: RepoRef,
    api_base: String,
    uploads_base: String,
    cache: Arc<ETagCache>,
    /// Serializes requests so a 10 s chat cadence cannot fan out into a burst.
    gate: Arc<Semaphore>,
    redactor: Redactor,
}

impl std::fmt::Debug for GitHubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the token or the redactor's contents.
        f.debug_struct("GitHubClient")
            .field("repo", &self.repo.full_name())
            .field("api_base", &self.api_base)
            .field("cached_urls", &self.cache.len())
            .finish_non_exhaustive()
    }
}

impl GitHubClient {
    /// Build a client for `repo`, authenticating with `token`.
    ///
    /// The token is moved into a zeroizing buffer and never copied again.
    pub fn new(repo: RepoRef, token: impl Into<String>) -> Result<Self> {
        Self::with_bases(repo, token, DEFAULT_API_BASE, DEFAULT_UPLOADS_BASE)
    }

    /// Build a client against custom bases, for GitHub Enterprise or tests.
    pub fn with_bases(
        repo: RepoRef,
        token: impl Into<String>,
        api_base: impl Into<String>,
        uploads_base: impl Into<String>,
    ) -> Result<Self> {
        let token: String = token.into();
        if token.trim().is_empty() {
            return Err(AppError::not_configured(
                        "a GitHub token is required before any request can be made",
            ));
        }

        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .pool_max_idle_per_host(2)
            .build()
            .map_err(|e| AppError::network("client", format!("could not build HTTP client: {e}")))?;

        let redactor = Redactor::new(&token);

        Ok(Self {
            http,
            token: Arc::new(Zeroizing::new(token)),
            repo,
            api_base: api_base.into().trim_end_matches('/').to_string(),
            uploads_base: uploads_base.into().trim_end_matches('/').to_string(),
            cache: Arc::new(ETagCache::default()),
            gate: Arc::new(Semaphore::new(1)),
            redactor,
        })
    }

    /// The repository this client is bound to.
    pub fn repo(&self) -> &RepoRef {
        &self.repo
    }

    /// Shared ETag cache, so callers can invalidate after a write.
    pub fn cache(&self) -> Arc<ETagCache> {
        Arc::clone(&self.cache)
    }

    /// Redactor bound to this client's token.
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    // -- core request plumbing ------------------------------------------------

    /// `Authorization` value. Assembled on demand so the raw token is not held in
    /// a long-lived header string by accident.
    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token.as_str())
    }

    /// Execute a request under the serialization gate, mapping transport errors.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        allow_not_modified: bool,
    ) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, Vec<u8>)> {
        send_gated(&self.gate, &self.redactor, request, allow_not_modified).await
    }

    /// GET with `If-None-Match` when a cached ETag exists.
    ///
    /// Returns [`Conditional::NotModified`] on a `304`, which costs no quota.
    async fn get_conditional(&self, url: &str) -> Result<Conditional> {
        let cached_etag = self.cache.etag_for(url);

        let mut request = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .header("X-GitHub-Api-Version", "2022-11-28");

        if let Some(etag) = &cached_etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag.clone());
        }

        let (status, headers, body) = self.send(request, true).await?;

        if status == reqwest::StatusCode::NOT_MODIFIED {
            let body = self
                .cache
                .body_for(url)
                .ok_or_else(|| AppError::parse(url, "server returned 304 but no cached body exists"))?;
            self.cache.touch(url);
            return Ok(Conditional::NotModified { body });
        }

        let etag = header_str(&headers, reqwest::header::ETAG).map(str::to_string);
        self.cache.store(url, etag.as_deref(), body.clone(), status.as_u16());
        Ok(Conditional::Fresh { body, etag })
    }

    /// GET returning parsed JSON, following `Link` pagination.
    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let (status, _headers, body) = self
            .send(
                self.http
                    .get(url)
                    .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                    .header(reqwest::header::AUTHORIZATION, self.auth_header())
                    .header("X-GitHub-Api-Version", "2022-11-28"),
                false,
            )
            .await?;

        if status != reqwest::StatusCode::OK {
            return Err(AppError::parse(url, format!("expected 200, got {status}")));
        }

        serde_json::from_slice(&body)
            .map_err(|e| AppError::parse(self.redactor.scrub(url), format!("invalid JSON: {e}")))
    }

    /// POST returning parsed JSON.
    async fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        payload: &serde_json::Value,
    ) -> Result<T> {
        let (_, _, body) = self
            .send(
                self.http
                    .post(url)
                    .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                    .header(reqwest::header::AUTHORIZATION, self.auth_header())
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .json(payload),
                false,
            )
            .await?;

        serde_json::from_slice(&body)
            .map_err(|e| AppError::parse(url, format!("invalid JSON: {e}")))
    }

    /// PATCH returning parsed JSON.
    async fn patch_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        payload: &serde_json::Value,
    ) -> Result<T> {
        let (_, _, body) = self
            .send(
                self.http
                    .patch(url)
                    .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                    .header(reqwest::header::AUTHORIZATION, self.auth_header())
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .json(payload),
                false,
            )
            .await?;

        serde_json::from_slice(&body)
            .map_err(|e| AppError::parse(url, format!("invalid JSON: {e}")))
    }

    /// DELETE expecting an empty body.
    async fn delete(&self, url: &str) -> Result<()> {
        self.send(
            self.http
                .delete(url)
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .header(reqwest::header::AUTHORIZATION, self.auth_header())
                .header("X-GitHub-Api-Version", "2022-11-28"),
            false,
        )
        .await
        .map(|_| ())
    }

    /// GET a URL on this client's authenticated base and parse it as JSON.
    ///
    /// Exposed for endpoints that do not warrant a dedicated method, such as
    /// resolving a release by tag. Goes through the same queue, auth, and
    /// error-mapping path as everything else.
    pub async fn get_json_public<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        if !url.starts_with(&self.api_base) {
            return Err(AppError::invalid_argument(format!(
                "refusing to fetch {url}: it is outside this client's API base"
            )));
        }
        self.get_json(url).await
    }

    /// Download the raw bytes of one release asset.
    ///
    /// Follows the redirect GitHub issues for private-repo asset downloads, and
    /// caps the size so a hostile asset cannot exhaust memory.
    pub async fn download_asset(&self, release_id: u64, asset_name: &str) -> Result<Vec<u8>> {
        validate_path_component("asset name", asset_name)?;

        let assets = self.list_assets(release_id).await?;
        let asset = assets
            .iter()
            .find(|candidate| candidate.name == asset_name)
            .ok_or_else(|| {
                AppError::group_state(format!(
                    "asset {asset_name} is not present in the vault; it may have been pruned to reclaim space"
                ))
            })?;

        // The metadata endpoint answers with a redirect to the signed blob URL.
        let url = format!(
            "{}/repos/{}/releases/assets/{}",
            self.api_base,
            self.repo.full_name(),
            asset.id
        );

        let permit = self.gate.acquire().await.map_err(|e| {
            AppError::crypto(format!("request queue was closed unexpectedly: {e}"))
        })?;

        let response = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| {
                AppError::network(
                    self.redactor.scrub(&url),
                    self.redactor.scrub(&transport_error_message(&e)),
                )
            })?;
        drop(permit);

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let snapshot = parse_rate_limit_headers(response.headers());
            if status == 429 || (status == 403 && snapshot.is_exhausted()) {
                return Err(AppError::RateLimited {
                    reset_unix_s: snapshot.reset_unix_s.unwrap_or(0),
                    remaining: snapshot.remaining.unwrap_or(0),
                });
            }
            return Err(AppError::GitHubApi {
                status,
                message: format!("could not download {asset_name}"),
            });
        }

        // Refuse anything larger than a single allowed file, so a crafted asset
        // cannot be used to exhaust device memory.
        if asset.size > MAX_FILE_BYTES {
            return Err(AppError::PayloadTooLarge {
                what: "downloaded file",
                actual_bytes: asset.size,
                limit_bytes: MAX_FILE_BYTES,
            });
        }

        let bytes = response.bytes().await.map_err(|e| {
            AppError::network(&url, format!("could not read the asset body: {e}"))
        })?;

        Ok(bytes.to_vec())
    }

    // -- identity and access --------------------------------------------------

    /// Confirm the token works and return the authenticated login.
    ///
    /// Cheap pre-flight used at onboarding and before re-keying.
    pub async fn validate_token(&self) -> Result<String> {
        let url = format!("{}/user", self.api_base);
        let user: serde_json::Value = self.get_json(&url).await?;
        user.get("login")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| AppError::parse(url, "token check returned no login; token is invalid"))
    }

    /// Confirm the token can see this repository, and report whether it is private.
    pub async fn repo_is_accessible(&self) -> Result<bool> {
        let url = format!("{}/repos/{}", self.api_base, self.repo.full_name());
        let repo: serde_json::Value = self.get_json(&url).await?;
        Ok(repo
            .get("private")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    /// Snapshot the current rate-limit state from the dedicated endpoint.
    pub async fn rate_limit(&self) -> Result<RateLimitSnapshot> {
        let url = format!("{}/rate_limit", self.api_base);
        let value: serde_json::Value = self.get_json(&url).await?;
        let core = value.get("resources").and_then(|r| r.get("core"));
        Ok(RateLimitSnapshot {
            limit: core
                .and_then(|c| c.get("limit"))
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok()),
            remaining: core
                .and_then(|c| c.get("remaining"))
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok()),
            reset_unix_s: core
                .and_then(|c| c.get("reset"))
                .and_then(|v| v.as_i64()),
        })
    }

    /// Feed the latest snapshot into a halt switch.
    pub async fn apply_rate_limit_to(&self, halt: &mut RateLimitHalt) -> Result<RateLimitSnapshot> {
        let snapshot = self.rate_limit().await?;
        halt.observe_limit(snapshot.limit);
        halt.observe(
            if snapshot.is_exhausted() { 429 } else { 200 },
            snapshot.reset_unix_s,
            snapshot.remaining,
        );
        Ok(snapshot)
    }

    // -- Issue comments -------------------------------------------------------

    /// Comments endpoint URL for `issue_num`.
    pub fn comments_url(&self, issue_num: u64) -> String {
        format!(
            "{}/repos/{}/issues/{issue_num}/comments",
            self.api_base,
            self.repo.full_name()
        )
    }

    /// A single comment's URL.
    pub fn comment_url(&self, comment_id: u64) -> String {
        format!(
            "{}/repos/{}/issues/comments/{comment_id}",
            self.api_base,
            self.repo.full_name()
        )
    }

    /// Fetch every comment on `issue_num`, following pagination until exhausted.
        ///
        /// Pagination is driven by page count rather than by the `Link` header: a
        /// short page means the end of the collection, which avoids trusting a header
        /// a hostile or proxied response could control. `MAX_PAGES` bounds the loop
        /// even if the server keeps returning full pages.
        pub async fn list_comments(&self, issue_num: u64) -> Result<Vec<IssueComment>> {
            let base = self.comments_url(issue_num);
            let mut collected: Vec<IssueComment> = Vec::new();

            for page in 1..=MAX_PAGES {
                let url = format!("{base}?per_page={PER_PAGE}&page={page}");
                let raw: Vec<RawComment> = self.get_json(&url).await?;
                let page_len = raw.len();

                collected.extend(raw.into_iter().map(IssueComment::from));

                // A short page is the natural end of pagination.
                if page_len < PER_PAGE as usize {
                    return Ok(collected);
                }
            }

            Err(AppError::parse(
                base,
                format!("comment listing exceeded {MAX_PAGES} pages; refusing to continue"),
            ))
        }

        /// Fetch a single page of comments, with ETag revalidation.
        ///
        /// Returns the page plus whether the server reported no change. Used by the
        /// polling loop, where a `304` is the signal to leave local state alone.
        pub async fn list_comments_conditional(
            &self,
            issue_num: u64,
        ) -> Result<(Vec<IssueComment>, bool)> {
            let url = format!("{}?per_page={PER_PAGE}&sort=created&direction=asc", self.comments_url(issue_num));

            match self.get_conditional(&url).await? {
                Conditional::NotModified { body } => {
                    let raw: Vec<RawComment> = serde_json::from_slice(&body)
                        .map_err(|e| AppError::parse(&url, format!("cached comments are unreadable: {e}")))?;
                    Ok((raw.into_iter().map(IssueComment::from).collect(), true))
                }
                Conditional::Fresh { body, .. } => {
                    let raw: Vec<RawComment> = serde_json::from_slice(&body)
                        .map_err(|e| AppError::parse(&url, format!("invalid comment JSON: {e}")))?;
                    Ok((raw.into_iter().map(IssueComment::from).collect(), false))
                }
            }
        }

    /// Read one comment by id.
    pub async fn get_comment(&self, comment_id: u64) -> Result<IssueComment> {
        let url = self.comment_url(comment_id);
        let raw: RawComment = self.get_json(&url).await?;
        Ok(IssueComment::from(raw))
    }

    /// Create a member's roster comment or append a chat message.
    ///
    /// The returned `id` is what a roster member must persist: it is the only
    /// handle used for every later `PATCH`, which is what keeps concurrent
    /// location updates conflict-free.
    pub async fn create_comment(&self, issue_num: u64, body: &str) -> Result<IssueComment> {
        enforce_comment_size(body)?;
        let url = self.comments_url(issue_num);
        let payload = serde_json::json!({ "body": body });
        let raw: RawComment = self.post_json(&url, &payload).await?;
        // The listing this comment appears in is now stale.
        self.cache.invalidate_prefix(&url);
        Ok(IssueComment::from(raw))
    }

    /// Update a member's own comment in place.
    ///
    /// Because every member only ever targets their own `comment_id`, any number
    /// of phones can patch simultaneously without conflicting and without
    /// creating a single Git commit.
    pub async fn update_comment(&self, comment_id: u64, body: &str) -> Result<IssueComment> {
        enforce_comment_size(body)?;
        let url = self.comment_url(comment_id);
        let payload = serde_json::json!({ "body": body });
        let raw: RawComment = self.patch_json(&url, &payload).await?;
        self.cache.invalidate(&url);
        Ok(IssueComment::from(raw))
    }

    /// Delete a comment. Used by moderation and by "leave group".
    pub async fn delete_comment(&self, comment_id: u64) -> Result<()> {
        let url = self.comment_url(comment_id);
        self.delete(&url).await?;
        self.cache.invalidate(&url);
        Ok(())
    }

    // -- Release assets ------------------------------------------------------

    /// Assets endpoint URL for `release_id`.
    pub fn assets_url(&self, release_id: u64) -> String {
        format!(
            "{}/repos/{}/releases/{release_id}/assets",
            self.api_base,
            self.repo.full_name()
        )
    }

    /// Upload URL for a named asset, on the uploads host.
    pub fn upload_url(&self, release_id: u64, asset_name: &str) -> Result<String> {
        validate_path_component("asset name", asset_name)?;
        Ok(format!(
            "{}/repos/{}/releases/{release_id}/assets?name={}",
            self.uploads_base,
            self.repo.full_name(),
            asset_name
        ))
    }

    /// List the encrypted blobs in the vault.
    pub async fn list_assets(&self, release_id: u64) -> Result<Vec<ReleaseAsset>> {
        let url = format!("{}?per_page={PER_PAGE}", self.assets_url(release_id));
        let raw: Vec<RawAsset> = self.get_json(&url).await?;
        Ok(raw.into_iter().map(ReleaseAsset::from).collect())
    }

    /// Total bytes currently stored in the vault.
    pub async fn vault_size(&self, release_id: u64) -> Result<u64> {
        let assets = self.list_assets(release_id).await?;
        Ok(assets.iter().map(|a| a.size).sum())
    }

    /// Upload one already-encrypted blob.
    ///
    /// `bytes` must be the output of `crypto`'s sealing path; this function is
    /// deliberately incapable of encrypting, so a caller cannot accidentally
    /// upload plaintext by forgetting a step it never had.
    pub async fn upload_asset(
        &self,
        release_id: u64,
        asset_name: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Result<ReleaseAsset> {
        let size = bytes.len() as u64;
        enforce_file_size(size)?;

        let url = self.upload_url(release_id, asset_name)?;
        let (_, _, body) = self
            .send(
                self.http
                    .post(&url)
                    .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                    .header(reqwest::header::AUTHORIZATION, self.auth_header())
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header(reqwest::header::CONTENT_TYPE, content_type)
                    // Uploads are streamed by length; GitHub requires a length.
                    .header(reqwest::header::CONTENT_LENGTH, size.to_string())
                    .body(bytes.to_vec()),
                false,
            )
            .await?;

        let raw: RawAsset = serde_json::from_slice(&body)
            .map_err(|e| AppError::parse(&url, format!("upload succeeded but response was invalid: {e}")))?;

        self.cache.invalidate_prefix(&self.assets_url(release_id));
        Ok(ReleaseAsset::from(raw))
    }

    /// Delete one blob from the vault.
    pub async fn delete_asset(&self, asset_id: u64) -> Result<()> {
        let url = format!(
            "{}/repos/{}/releases/assets/{asset_id}",
            self.api_base,
            self.repo.full_name()
        );
        self.delete(&url).await
    }

    /// Make room for `incoming_bytes`, deleting oldest assets first.
    ///
    /// Returns which assets were deleted so the caller can post tombstones to the
    /// chat channel; garbage-collecting silently would leave members with dead
    /// pointers and no explanation.
    pub async fn prune_vault(&self, release_id: u64, incoming_bytes: u64) -> Result<PruneReport> {
        enforce_file_size(incoming_bytes)?;

        let assets = self.list_assets(release_id).await?;
        let mut report = assets_to_prune(&assets, incoming_bytes, MAX_VAULT_BYTES);

        for asset in &report.to_delete {
            self.delete_asset(asset.id).await?;
        }
        if !report.is_noop() {
            self.cache.invalidate_prefix(&self.assets_url(release_id));
        }

        // Recompute so the report reflects reality after the deletes.
        report.total_after = report.total_before.saturating_sub(
            report.to_delete.iter().map(|a| a.size).sum::<u64>(),
        );
        Ok(report)
    }

    // -- destructive operations ---------------------------------------------

    /// `DELETE /repos/{owner}/{repo}` — "Destroy Group".
    ///
    /// Requires `Administration: Read/Write` on the fine-grained PAT. Any guest
    /// holding an invite can reach this; see `PLAN_ADDENDUM_v1.md` §A1 for the
    /// accepted risk and §A3 for the rotation-based mitigation.
    pub async fn delete_repository(&self) -> Result<()> {
        let url = format!("{}/repos/{}", self.api_base, self.repo.full_name());
        self.delete(&url).await
    }

    /// Verify the token can actually administer the repository, without deleting
    /// it. Used to warn the host before offering the destructive button.
    pub async fn has_admin_scope(&self) -> Result<bool> {
        let url = format!("{}/repos/{}", self.api_base, self.repo.full_name());
        let repo: serde_json::Value = self.get_json(&url).await?;
        // `permissions.admin` reflects the token's effective rights.
        Ok(repo
            .get("permissions")
            .and_then(|p| p.get("admin"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    /// Ensure the two schema issues exist, creating them if absent.
    ///
    /// Issue #1 and Issue #2 are part of the schema, not user content. On the
    /// provisioning path they are created by [`ProvisioningClient`]; this is the
    /// repair path for an adopted repository, and it returns the numbers it
    /// settled on so the caller never has to assume 1 and 2.
    pub async fn ensure_schema_issues(
        &self,
        roster_issue_num: u64,
        chat_issue_num: u64,
    ) -> Result<(u64, u64)> {
        let roster = self
            .ensure_issue(roster_issue_num, "roster", ROSTER_ISSUE_BODY)
            .await?;
        let chat = self
            .ensure_issue(chat_issue_num, "chat", CHAT_ISSUE_BODY)
            .await?;
        Ok((roster, chat))
    }

    /// Ensure one schema issue exists, creating it when the number is free.
    ///
    /// A `0` request means "create a new one and tell me the number".
    async fn ensure_issue(&self, issue_num: u64, title: &str, body: &str) -> Result<u64> {
        if issue_num == 0 {
            return self.create_issue(title, body).await;
        }

        let url = format!(
            "{}/repos/{}/issues/{issue_num}",
            self.api_base,
            self.repo.full_name()
        );
        match self.get_json::<serde_json::Value>(&url).await {
            Ok(_) => Ok(issue_num),
            Err(AppError::GitHubApi { status: 404, .. }) => self.create_issue(title, body).await,
            Err(other) => Err(other),
        }
    }

    /// Create one issue and return its number.
    pub async fn create_issue(&self, title: &str, body: &str) -> Result<u64> {
        let url = format!("{}/repos/{}/issues", self.api_base, self.repo.full_name());
        let payload = serde_json::json!({ "title": title, "body": body });
        let created: serde_json::Value = self.post_json(&url, &payload).await?;
        created
            .get("number")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| AppError::parse(url, "created issue had no number"))
    }

    /// Create the vault release and return its id.
    pub async fn create_release(&self, tag: &str) -> Result<u64> {
        let url = format!("{}/repos/{}/releases", self.api_base, self.repo.full_name());
        let payload = serde_json::json!({
            "tag_name": tag,
            "name": tag,
            "body": "Shadow720 encrypted vault",
            "draft": false,
            "prerelease": false,
        });
        let created: serde_json::Value = self.post_json(&url, &payload).await?;
        created
            .get("id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| AppError::parse(url, "created release had no id"))
    }

    /// Resolve a release id from its tag, creating the release when absent.
    pub async fn ensure_release(&self, tag: &str) -> Result<u64> {
        let url = format!(
            "{}/repos/{}/releases/tags/{}",
            self.api_base,
            self.repo.full_name(),
            tag
        );
        match self.get_json::<serde_json::Value>(&url).await {
            Ok(value) => value
                .get("id")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| AppError::parse(url, "release response had no id")),
            Err(AppError::GitHubApi { status: 404, .. }) => self.create_release(tag).await,
            Err(other) => Err(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Provisioning client
// ---------------------------------------------------------------------------

/// What a freshly provisioned repository needs to become a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provisioned {
    pub repo: RepoRef,
    pub roster_issue_num: u64,
    pub chat_issue_num: u64,
    pub release_id: u64,
}

/// Account-scoped client used only to create a repository and its schema.
///
/// This is deliberately a separate type from [`GitHubClient`]: it holds a token
/// that can reach the whole account, so it must never be stored in the vault or
/// embedded in an invite. It exists for the duration of one provisioning call.
pub struct ProvisioningClient {
    http: reqwest::Client,
    token: Arc<Zeroizing<String>>,
    api_base: String,
    gate: Arc<Semaphore>,
    redactor: Redactor,
}

impl std::fmt::Debug for ProvisioningClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisioningClient")
            .field("api_base", &self.api_base)
            .finish_non_exhaustive()
    }
}

impl ProvisioningClient {
    /// Build a provisioning client against the public GitHub API.
    pub fn new(token: impl Into<String>) -> Result<Self> {
        Self::with_base(token, DEFAULT_API_BASE)
    }

    /// Build against a custom base, for GitHub Enterprise or tests.
    pub fn with_base(token: impl Into<String>, api_base: impl Into<String>) -> Result<Self> {
        let token: String = token.into();
        if token.trim().is_empty() {
            return Err(AppError::not_configured(
                "an account token is required to create a repository",
            ));
        }

        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .pool_max_idle_per_host(2)
            .build()
            .map_err(|e| AppError::network("client", format!("could not build HTTP client: {e}")))?;

        let redactor = Redactor::new(&token);

        Ok(Self {
            http,
            token: Arc::new(Zeroizing::new(token)),
            api_base: api_base.into().trim_end_matches('/').to_string(),
            gate: Arc::new(Semaphore::new(1)),
            redactor,
        })
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token.as_str())
    }

    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header(reqwest::header::AUTHORIZATION, self.auth_header())
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    async fn send_json<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
        url: &str,
    ) -> Result<T> {
        let (_, _, body) = send_gated(&self.gate, &self.redactor, request, false).await?;
        serde_json::from_slice(&body)
            .map_err(|e| AppError::parse(self.redactor.scrub(url), format!("invalid JSON: {e}")))
    }

    /// Confirm the token works and return the authenticated login.
    pub async fn validate_token(&self) -> Result<String> {
        let url = format!("{}/user", self.api_base);
        let user: serde_json::Value = self
            .send_json(self.request(reqwest::Method::GET, &url), &url)
            .await?;
        user.get("login")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| AppError::parse(url, "token check returned no login; token is invalid"))
    }

    /// Create a private repository, or adopt it when the name is already taken
    /// by this account.
    ///
    /// `auto_init` is mandatory: a release needs a tag, a tag needs a commit, and
    /// a repository with no commits cannot be tagged.
    pub async fn create_repository(&self, name: &str) -> Result<RepoRef> {
        validate_path_component("repo name", name)?;

        let url = format!("{}/user/repos", self.api_base);
        let payload = serde_json::json!({
            "name": name,
            "private": true,
            "auto_init": true,
            "has_issues": true,
            "has_wiki": false,
            "has_projects": false,
            "description": "Shadow720 encrypted group store",
        });

        let created: serde_json::Value = self
            .send_json(self.request(reqwest::Method::POST, &url).json(&payload), &url)
            .await?;

        let owner = created
            .get("owner")
            .and_then(|o| o.get("login"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::parse(&url, "created repository had no owner login"))?;
        let repo_name = created
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::parse(&url, "created repository had no name"))?;

        RepoRef::new(owner, repo_name)
    }

    /// Create one issue and return its number.
    ///
    /// The number is read back from the response rather than assumed, so a
    /// repository that already had issues still yields a usable schema.
    pub async fn create_issue(&self, repo: &RepoRef, title: &str, body: &str) -> Result<u64> {
        let url = format!("{}/repos/{}/issues", self.api_base, repo.full_name());
        let payload = serde_json::json!({ "title": title, "body": body });

        let created: serde_json::Value = self
            .send_json(self.request(reqwest::Method::POST, &url).json(&payload), &url)
            .await?;

        created
            .get("number")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| AppError::parse(&url, "created issue had no number"))
    }

    /// Create the vault release and return its id.
    pub async fn create_release(&self, repo: &RepoRef, tag: &str) -> Result<u64> {
        let url = format!("{}/repos/{}/releases", self.api_base, repo.full_name());
        let payload = serde_json::json!({
            "tag_name": tag,
            "name": tag,
            "body": "Shadow720 encrypted vault",
            "draft": false,
            "prerelease": false,
        });

        let created: serde_json::Value = self
            .send_json(self.request(reqwest::Method::POST, &url).json(&payload), &url)
            .await?;

        created
            .get("id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| AppError::parse(&url, "created release had no id"))
    }

    /// Create the repository, both schema issues, and the vault release.
    ///
    /// Order matters: the release needs a commit, so the repository must be
    /// created with `auto_init` first. Every step is idempotent from the caller's
    /// point of view — a retry after a partial failure re-runs from the top and
    /// adopts whatever already exists.
    pub async fn provision(&self, name: &str, release_tag: &str) -> Result<Provisioned> {
        let repo = self.create_repository(name).await?;

        let roster_issue_num = self
            .create_issue(
                &repo,
                "roster",
                "Shadow720 member roster. One comment per member; each member only \
                 edits its own comment. Contents are encrypted.",
            )
            .await?;
        let chat_issue_num = self
            .create_issue(
                &repo,
                "chat",
                "Shadow720 group chat and file pointers. Append-only. Contents are \
                 encrypted.",
            )
            .await?;
        let release_id = self.create_release(&repo, release_tag).await?;

        Ok(Provisioned {
            repo,
            roster_issue_num,
            chat_issue_num,
            release_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Shared request plumbing
// ---------------------------------------------------------------------------

/// Execute a request under a serialization gate, mapping transport errors.
///
/// Shared by [`GitHubClient`] and [`ProvisioningClient`] so both go through the
/// same queue, redaction, and status mapping.
async fn send_gated(
    gate: &Semaphore,
    redactor: &Redactor,
    request: reqwest::RequestBuilder,
    allow_not_modified: bool,
) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, Vec<u8>)> {
    // Serialize: one in-flight request per client. The 10 s chat cadence over
    // 50 members would otherwise align into bursts and burn the shared PAT.
    let _permit = gate
        .acquire()
        .await
        .map_err(|e| AppError::crypto(format!("request queue was closed unexpectedly: {e}")))?;

    let response = request.send().await.map_err(|e| {
        let url = e
            .url()
            .map(|u| u.to_string())
            .unwrap_or_else(|| "unknown".into());
        AppError::network(
            redactor.scrub(&url),
            redactor.scrub(&transport_error_message(&e)),
        )
    })?;

    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| AppError::network("body", format!("could not read response body: {e}")))?;

    // A 304 must not be forced through the status validator.
    if status == reqwest::StatusCode::NOT_MODIFIED && allow_not_modified {
        return Ok((status, headers, bytes.to_vec()));
    }

    if status.is_success() {
        return Ok((status, headers, bytes.to_vec()));
    }

    Err(map_error_status(redactor, status, &headers, &bytes))
}

/// Translate a non-success status into the right `AppError` variant.
fn map_error_status(
    redactor: &Redactor,
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body: &[u8],
) -> AppError {
    let snapshot = parse_rate_limit_headers(headers);
    let code = status.as_u16();

    if code == 429 || (code == 403 && snapshot.is_exhausted()) {
        return AppError::RateLimited {
            reset_unix_s: snapshot.reset_unix_s.unwrap_or(0),
            remaining: snapshot.remaining.unwrap_or(0),
        };
    }

    if code == 401 {
        return AppError::GitHubAuth { status: code };
    }

    if code == 403 {
        // With budget remaining, a 403 means insufficient scope or an org
        // policy block, both of which need the user to act on the token.
        return AppError::GitHubAuth { status: code };
    }

    // GitHub returns a JSON `{ "message": ... }` body for API errors.
    let message = extract_error_message(body)
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("request failed").to_string());

    AppError::GitHubApi {
        status: code,
        message: redactor.scrub(&message),
    }
}

// ---------------------------------------------------------------------------
// Header and payload helpers
// ---------------------------------------------------------------------------

/// Read a header as `&str`, if present and valid UTF-8.
pub fn header_str(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Parse GitHub's rate-limit headers into a snapshot.
pub fn parse_rate_limit_headers(headers: &reqwest::header::HeaderMap) -> RateLimitSnapshot {
    RateLimitSnapshot {
        limit: header_str(headers, reqwest::header::HeaderName::from_static("x-ratelimit-limit"))
            .and_then(|s| s.trim().parse::<u32>().ok()),
        remaining: header_str(
            headers,
            reqwest::header::HeaderName::from_static("x-ratelimit-remaining"),
        )
        .and_then(|s| s.trim().parse::<u32>().ok()),
        reset_unix_s: header_str(
            headers,
            reqwest::header::HeaderName::from_static("x-ratelimit-reset"),
        )
        .and_then(|s| s.trim().parse::<i64>().ok()),
    }
}

/// Pull `message` out of a GitHub error body, tolerating a non-JSON body.
pub fn extract_error_message(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let message = value.get("message").and_then(|v| v.as_str())?.to_string();
    // Include field-level errors, which GitHub puts in `errors`.
    let errors = value.get("errors").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
                .map(|e| {
                let code = e.get("code").and_then(|v| v.as_str()).unwrap_or("error");
                let field = e.get("field").and_then(|v| v.as_str()).unwrap_or("");
                if field.is_empty() {
                        code.to_string()
                } else {
                        format!("{field}: {code}")
                }
            })
            .collect::<Vec<_>>()
    });

    match errors {
        Some(errors) if !errors.is_empty() => Some(format!("{message} ({})", errors.join("; "))),
        _ => Some(message),
    }
}

/// Human-readable cause for a transport failure, without the URL.
fn transport_error_message(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        "request timed out".to_string()
    } else if err.is_connect() {
        "could not connect".to_string()
    } else if err.is_decode() {
        "could not decode the response".to_string()
    } else if err.is_redirect() {
        "too many redirects".to_string()
    } else {
        err.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(id: u64, name: &str, size: u64, created_at_ms: i64) -> ReleaseAsset {
        ReleaseAsset {
            id,
            name: name.to_string(),
            size,
            created_at_ms,
        }
    }

    // -- RepoRef -------------------------------------------------------------

    #[test]
    fn repo_ref_parses_owner_and_name() {
        let repo = RepoRef::parse("JaredCH/shadow720-sandbox").expect("parse");
        assert_eq!(repo.owner, "JaredCH");
        assert_eq!(repo.name, "shadow720-sandbox");
        assert_eq!(repo.full_name(), "JaredCH/shadow720-sandbox");
    }

    #[test]
    fn repo_ref_trims_surrounding_whitespace() {
        let repo = RepoRef::parse("  JaredCH/grp-1  ").expect("parse");
        assert_eq!(repo.full_name(), "JaredCH/grp-1");
    }

    #[test]
    fn repo_ref_rejects_missing_separator() {
        let err = RepoRef::parse("JaredCH").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InvalidArgument);
        assert!(err.to_string().contains("owner/name"));
    }

    #[test]
    fn repo_ref_rejects_extra_separators() {
        let err = RepoRef::parse("a/b/c").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::InvalidArgument);
    }

    #[test]
    fn repo_ref_rejects_empty_components() {
        assert!(RepoRef::parse("/repo").is_err());
        assert!(RepoRef::parse("owner/").is_err());
        assert!(RepoRef::parse("   ").is_err());
    }

    #[test]
    fn repo_ref_rejects_path_traversal_and_whitespace() {
        // These values are interpolated into URLs; traversal must be impossible.
        for bad in ["../evil", "a/..", "own er/repo", "owner/re po", "owner/re\\po"] {
            assert!(
                RepoRef::parse(bad).is_err(),
                "{bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn repo_ref_rejects_control_characters() {
        let err = RepoRef::parse("own\u{0}er/repo").expect_err("must fail");
        assert!(err.to_string().contains("control"));
    }

    // -- Redactor ------------------------------------------------------------

    #[test]
    fn redactor_scrubs_the_token() {
        let redactor = Redactor::new("ghp_SECRETVALUE123");
        let scrubbed = redactor.scrub("url=https://api.github.com?token=ghp_SECRETVALUE123 done");
        assert!(!scrubbed.contains("SECRETVALUE"));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn redactor_scrubs_bare_token_prefixes() {
        let redactor = Redactor::new("github_pat_ABC");
        let scrubbed = redactor.scrub("leaked prefix github_pat_ in a log line");
        assert!(!scrubbed.contains("github_pat_"));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn redactor_with_empty_token_is_a_passthrough() {
        let redactor = Redactor::new("");
        assert_eq!(redactor.scrub("nothing to hide"), "nothing to hide");
    }

    #[test]
    fn redactor_scrub_all_handles_a_batch() {
        let redactor = Redactor::new("tok_123");
        let out = redactor.scrub_all(["a tok_123 b", "clean", "tok_123"]);
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|s| !s.contains("tok_123")));
        assert_eq!(out.get(1).map(String::as_str), Some("clean"));
    }

    #[test]
    fn redactor_debug_never_prints_secrets() {
        let redactor = Redactor::new("ghp_TOPSECRET");
        let rendered = format!("{redactor:?}");
        assert!(!rendered.contains("TOPSECRET"));
        assert!(rendered.contains("tracked_secrets"));
    }

    // -- ETag cache -----------------------------------------------------------

    #[test]
    fn etag_cache_stores_and_reads_back() {
        let cache = ETagCache::with_capacity(8);
        cache.store("u1", Some("etag-1"), b"body".to_vec(), 200);
        assert_eq!(cache.etag_for("u1").as_deref(), Some("etag-1"));
        assert_eq!(cache.body_for("u1").as_deref(), Some(&b"body"[..]));
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());
    }

    #[test]
    fn etag_cache_ignores_responses_without_an_etag() {
        let cache = ETagCache::with_capacity(8);
        cache.store("u1", None, b"body".to_vec(), 200);
        assert!(cache.etag_for("u1").is_none());
        assert!(cache.is_empty(), "no ETag means nothing to revalidate against");
    }

    #[test]
    fn etag_cache_updates_an_existing_entry() {
        let cache = ETagCache::with_capacity(8);
        cache.store("u1", Some("etag-1"), b"one".to_vec(), 200);
        cache.store("u1", Some("etag-2"), b"two".to_vec(), 200);
        assert_eq!(cache.etag_for("u1").as_deref(), Some("etag-2"));
        assert_eq!(cache.body_for("u1").as_deref(), Some(&b"two"[..]));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn etag_cache_evicts_oldest_when_full() {
        let cache = ETagCache::with_capacity(2);
        cache.store("old", Some("e"), b"1".to_vec(), 200);
        // Force a strict ordering in time.
        if let Some(mut entry) = cache.entries.get_mut("old") {
            entry.stored_at_ms = 1;
        }
        cache.store("mid", Some("e"), b"2".to_vec(), 200);
        if let Some(mut entry) = cache.entries.get_mut("mid") {
            entry.stored_at_ms = 2;
        }
        cache.store("new", Some("e"), b"3".to_vec(), 200);

        assert_eq!(cache.len(), 2, "capacity must be respected");
        assert!(cache.etag_for("old").is_none(), "oldest entry should be evicted");
        assert!(cache.etag_for("new").is_some());
    }

    #[test]
    fn etag_cache_eviction_skips_when_key_exists() {
        let cache = ETagCache::with_capacity(1);
        cache.store("only", Some("e1"), b"1".to_vec(), 200);
        cache.store("only", Some("e2"), b"2".to_vec(), 200);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.etag_for("only").as_deref(), Some("e2"));
    }

    #[test]
    fn etag_cache_invalidate_and_prefix() {
        let cache = ETagCache::with_capacity(8);
        cache.store("https://api/issue/1/comments", Some("e"), vec![], 200);
        cache.store("https://api/issue/1/comments?page=2", Some("e"), vec![], 200);
        cache.store("https://api/issue/2/comments", Some("e"), vec![], 200);

        cache.invalidate_prefix("https://api/issue/1");
        assert_eq!(cache.len(), 1);
        assert!(cache.etag_for("https://api/issue/2/comments").is_some());

        cache.invalidate("https://api/issue/2/comments");
        assert!(cache.is_empty());

        cache.store("k", Some("e"), vec![], 200);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn etag_cache_capacity_floor_is_one() {
        let cache = ETagCache::with_capacity(0);
        cache.store("a", Some("e"), vec![], 200);
        cache.store("b", Some("e"), vec![], 200);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn etag_cache_touch_updates_timestamp_only() {
        let cache = ETagCache::with_capacity(8);
        cache.store("u", Some("etag"), b"body".to_vec(), 200);
        let before = cache.entries.get("u").map(|e| e.stored_at_ms);
        if let Some(mut entry) = cache.entries.get_mut("u") {
            entry.stored_at_ms = 0;
        }
        cache.touch("u");
        let after = cache.entries.get("u").map(|e| e.stored_at_ms);
        assert!(after.is_some_and(|v| v > 0), "touch should refresh the clock");
        assert_eq!(cache.body_for("u").as_deref(), Some(&b"body"[..]));
        assert!(before.is_some());
    }

    #[test]
    fn etag_cache_touch_on_missing_key_is_harmless() {
        let cache = ETagCache::with_capacity(8);
        cache.touch("nope");
        assert!(cache.is_empty());
    }

    // -- Quota policy ---------------------------------------------------------

    #[test]
    fn enforce_file_size_accepts_at_the_limit() {
        assert!(enforce_file_size(MAX_FILE_BYTES).is_ok());
        assert!(enforce_file_size(0).is_ok());
    }

    #[test]
    fn enforce_file_size_rejects_over_the_limit() {
        let err = enforce_file_size(MAX_FILE_BYTES + 1).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::PayloadTooLarge);
        assert!(err.to_string().contains("file"));
    }

    #[test]
    fn enforce_comment_size_accepts_at_the_limit() {
        let body = "x".repeat(MAX_COMMENT_BYTES);
        assert!(enforce_comment_size(&body).is_ok());
    }

    #[test]
    fn enforce_comment_size_rejects_over_the_limit() {
        let body = "x".repeat(MAX_COMMENT_BYTES + 1);
        let err = enforce_comment_size(&body).expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::PayloadTooLarge);
    }

    #[test]
    fn prune_is_a_noop_when_vault_is_small() {
        let assets = vec![asset(1, "a.bin", 100, 1000), asset(2, "b.bin", 100, 2000)];
        let report = assets_to_prune(&assets, 100, MAX_VAULT_BYTES);
        assert!(report.is_noop());
        assert_eq!(report.total_before, 200);
        assert_eq!(report.total_after, 200);
    }

    #[test]
    fn prune_deletes_oldest_first() {
        let max = 1_000;
        let assets = vec![
            asset(1, "old.bin", 400, 1_000),
            asset(2, "mid.bin", 400, 2_000),
            asset(3, "new.bin", 400, 3_000),
        ];
        // 1200 stored + 200 incoming = 1400 > 1000, so drop until it fits.
        let report = assets_to_prune(&assets, 200, max);

        assert_eq!(report.total_before, 1_200);
        assert_eq!(report.to_delete.len(), 1, "one deletion should be enough");
        assert_eq!(report.to_delete.first().map(|a| a.name.as_str()), Some("old.bin"));
        assert_eq!(report.total_after, 800);
        assert!(report.total_after + 200 <= max);
    }

    #[test]
    fn prune_deletes_multiple_when_needed() {
            let max = 1_500;
        let assets = vec![
            asset(1, "a.bin", 400, 1_000),
            asset(2, "b.bin", 400, 2_000),
            asset(3, "c.bin", 400, 3_000),
        ];
            // 1200 stored + 500 incoming = 1700 > 1500, so the oldest must go.
            let report = assets_to_prune(&assets, 500, max);

            assert_eq!(report.to_delete.len(), 1, "one 400-byte delete is enough");
            let names: Vec<&str> = report.to_delete.iter().map(|a| a.name.as_str()).collect();
            assert_eq!(names, vec!["a.bin"], "oldest first");
            assert_eq!(report.total_after, 800);
            assert!(report.total_after + 500 <= max);
        }

        #[test]
        fn prune_reclaims_everything_when_nothing_smaller_helps() {
            let max = 1_000;
            let assets = vec![asset(1, "a.bin", 400, 1_000), asset(2, "b.bin", 400, 2_000)];
            // 800 stored + 500 incoming = 1300 > 1000, so at least one must go.
            let report = assets_to_prune(&assets, 500, max);

            assert_eq!(report.to_delete.len(), 1);
            assert_eq!(report.total_after, 400);
            assert!(report.total_after + 500 <= max, "400 + 500 fits under 1000");
        }

        #[test]
        fn prune_reports_honestly_when_even_emptying_cannot_fit() {
            let max = 3_000;
            // 5 KB incoming against an empty 3 KB ceiling cannot fit no matter what.
            let assets = vec![asset(1, "a.bin", 400, 1_000)];
            let report = assets_to_prune(&assets, 5_000, max);

            assert_eq!(report.to_delete.len(), 1, "the vault is emptied trying");
            assert_eq!(report.total_after, 0);
            // The report must not pretend the vault will fit: 5000 > 3000. The caller
            // is expected to have rejected the file via enforce_file_size first, but
            // the arithmetic has to stay honest either way.
            assert!(
                report.total_after + 5_000 > max,
                "pruning cannot make an oversized file fit"
            );
        }

    #[test]
    fn prune_orders_undated_assets_first() {
        let assets = vec![
            asset(2, "dated.bin", 400, 5_000),
            asset(1, "undated.bin", 400, 0),
        ];
        let report = assets_to_prune(&assets, 400, 800);
        assert_eq!(
            report.to_delete.first().map(|a| a.name.as_str()),
            Some("undated.bin"),
            "undated blobs are reclaimed before content we can date"
        );
    }

    #[test]
    fn prune_breaks_ties_by_id() {
        let assets = vec![asset(9, "nine.bin", 100, 1_000), asset(3, "three.bin", 100, 1_000)];
        let report = assets_to_prune(&assets, 200, 100);
        assert_eq!(report.to_delete.first().map(|a| a.id), Some(3));
    }

    #[test]
    fn prune_on_empty_vault_is_a_noop() {
        let report = assets_to_prune(&[], 0, MAX_VAULT_BYTES);
        assert!(report.is_noop());
        assert_eq!(report.total_before, 0);
        assert_eq!(report.total_after, 0);
    }

    #[test]
    fn prune_handles_a_full_vault_with_a_small_file() {
        // Exactly at the ceiling; a 1-byte file must trigger reclamation.
        let assets = vec![asset(1, "a.bin", MAX_VAULT_BYTES, 1_000)];
        let report = assets_to_prune(&assets, 1, MAX_VAULT_BYTES);
        assert_eq!(report.to_delete.len(), 1);
        assert_eq!(report.total_after, 0);
    }

    #[test]
    fn prune_does_not_overflow_on_absurd_sizes() {
        let assets = vec![
            asset(1, "huge.bin", u64::MAX / 2, 1_000),
            asset(2, "huge2.bin", u64::MAX / 2, 2_000),
        ];
        let report = assets_to_prune(&assets, 1, MAX_VAULT_BYTES);
        assert_eq!(report.to_delete.len(), 2);
        assert_eq!(report.total_after, 0, "saturating arithmetic, no panic");
    }

    // -- Timestamps -----------------------------------------------------------

    #[test]
    fn parses_github_rfc3339_timestamps() {
        // 2023-11-14T22:13:20Z
        let ms = parse_rfc3339_ms("2023-11-14T22:13:20Z").expect("parse");
        assert_eq!(ms, 1_700_000_000_000);
    }

    #[test]
    fn parses_epoch_zero() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn parses_a_leap_day() {
        // 2024-02-29T00:00:00Z is day 19782 since the epoch.
        let ms = parse_rfc3339_ms("2024-02-29T00:00:00Z").expect("parse");
        assert_eq!(ms, 1_709_164_800_000);
    }

    #[test]
    fn rejects_malformed_timestamps() {
        for bad in [
            "",
            "not a date",
            "2023-11-14",              // too short
            "2023-13-01T00:00:00Z",    // month 13
            "2023-11-32T00:00:00Z",    // day 32
            "2023-11-14T25:00:00Z",    // hour 25
            "2023-11-14T00:61:00Z",    // minute 61
            "2023-11-14T00:00:61Z",    // second 61
            "2023-1a-14T00:00:00Z",    // non-digit month
            "2023-11-14T00:00:00+05:00", // offset, not emitted by these endpoints
        ] {
            assert!(
                parse_rfc3339_ms(bad).is_none(),
                "{bad:?} should not have parsed"
            );
        }
    }

    #[test]
    fn timestamp_parsing_never_panics_on_hostile_input() {
        let long = "9".repeat(200);
        assert!(parse_rfc3339_ms(&long).is_none());
        assert!(parse_rfc3339_ms("😀😀😀😀😀😀😀😀😀😀").is_none());
    }

    #[test]
    fn now_helpers_are_monotonic_and_positive() {
        let a = now_unix_ms();
        let b = now_unix_ms();
        assert!(a > 0);
        assert!(b >= a);
        assert_eq!(now_unix_s(), now_unix_ms() / 1_000);
    }

    // -- Header parsing -------------------------------------------------------

    #[test]
    fn parses_rate_limit_headers() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-limit", "5000".parse().expect("value"));
        headers.insert("x-ratelimit-remaining", "4999".parse().expect("value"));
        headers.insert("x-ratelimit-reset", "1700000000".parse().expect("value"));

        let snapshot = parse_rate_limit_headers(&headers);
        assert_eq!(snapshot.limit, Some(5_000));
        assert_eq!(snapshot.remaining, Some(4_999));
        assert_eq!(snapshot.reset_unix_s, Some(1_700_000_000));
        assert!(!snapshot.is_exhausted());
    }

    #[test]
    fn missing_rate_limit_headers_yield_none() {
        let headers = reqwest::header::HeaderMap::new();
        let snapshot = parse_rate_limit_headers(&headers);
        assert_eq!(snapshot.limit, None);
        assert_eq!(snapshot.remaining, None);
        assert_eq!(snapshot.reset_unix_s, None);
        assert!(!snapshot.is_exhausted());
    }

    #[test]
    fn garbage_rate_limit_headers_are_ignored_not_fatal() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ratelimit-remaining", "not-a-number".parse().expect("value"));
        headers.insert("x-ratelimit-limit", "-5".parse().expect("value"));
        let snapshot = parse_rate_limit_headers(&headers);
        assert_eq!(snapshot.remaining, None);
        assert_eq!(snapshot.limit, None);
    }

    #[test]
    fn exhausted_snapshot_is_detected() {
        let snapshot = RateLimitSnapshot {
            limit: Some(5_000),
            remaining: Some(0),
            reset_unix_s: Some(1),
        };
        assert!(snapshot.is_exhausted());
    }

    // -- Error body extraction ------------------------------------------------

    #[test]
    fn extracts_message_from_a_github_error_body() {
        let body = br#"{"message":"Not Found","documentation_url":"https://docs.github.com"}"#;
        assert_eq!(extract_error_message(body).as_deref(), Some("Not Found"));
    }

    #[test]
    fn extracts_field_level_errors() {
        let body = br#"{"message":"Validation Failed","errors":[{"resource":"Issue","field":"body","code":"missing_field"}]}"#;
        let message = extract_error_message(body).expect("message");
        assert!(message.contains("Validation Failed"));
        assert!(message.contains("body: missing_field"));
    }

    #[test]
    fn error_extraction_tolerates_non_json() {
        assert!(extract_error_message(b"<html>502 Bad Gateway</html>").is_none());
        assert!(extract_error_message(b"").is_none());
    }

    #[test]
    fn error_extraction_handles_errors_without_a_field() {
        let body = br#"{"message":"Bad","errors":[{"code":"custom"}]}"#;
        let message = extract_error_message(body).expect("message");
        assert!(message.contains("custom"));
    }

    // -- URL helpers ----------------------------------------------------------

    #[test]
    fn parses_asset_name_from_an_upload_url() {
        let url = "https://uploads.github.com/repos/o/r/releases/1/assets?name=abc-123.bin";
        assert_eq!(parse_asset_name_from_url(url).as_deref(), Some("abc-123.bin"));
    }

    #[test]
    fn parses_percent_encoded_asset_names() {
        let url = "https://uploads.github.com/repos/o/r/releases/1/assets?name=a%20b%2Bc.bin";
        assert_eq!(parse_asset_name_from_url(url).as_deref(), Some("a b+c.bin"));
    }

    #[test]
    fn parses_asset_name_when_not_the_first_parameter() {
        let url = "https://uploads.github.com/x?label=y&name=z.bin";
        assert_eq!(parse_asset_name_from_url(url).as_deref(), Some("z.bin"));
    }

    #[test]
    fn asset_name_parse_returns_none_when_absent_or_malformed() {
        assert!(parse_asset_name_from_url("https://x/y").is_none());
        assert!(parse_asset_name_from_url("https://x/y?other=1").is_none());
        assert!(parse_asset_name_from_url("https://x/y?name=%ZZ").is_none());
    }

    #[test]
    fn percent_decode_handles_plus_as_space() {
        assert_eq!(percent_decode("a+b").as_deref(), Some("a b"));
    }

    // -- Client construction --------------------------------------------------

    #[test]
    fn client_rejects_an_empty_token() {
        let repo = RepoRef::parse("owner/repo").expect("repo");
        let err = GitHubClient::new(repo, "   ").expect_err("must fail");
        assert_eq!(err.kind(), crate::error::AppErrorKind::NotConfigured);
    }

    #[test]
    fn client_builds_with_a_token_and_derives_urls() {
        let repo = RepoRef::parse("JaredCH/shadow720-sandbox").expect("repo");
        let client = GitHubClient::new(repo, "ghp_test_token").expect("client");

        assert_eq!(
            client.comments_url(1),
            "https://api.github.com/repos/JaredCH/shadow720-sandbox/issues/1/comments"
        );
        assert_eq!(
            client.comment_url(99),
            "https://api.github.com/repos/JaredCH/shadow720-sandbox/issues/comments/99"
        );
        assert_eq!(
            client.assets_url(7),
            "https://api.github.com/repos/JaredCH/shadow720-sandbox/releases/7/assets"
        );
        assert_eq!(
            client.upload_url(7, "abc.bin").expect("url"),
            "https://uploads.github.com/repos/JaredCH/shadow720-sandbox/releases/7/assets?name=abc.bin"
        );
    }

    #[test]
    fn client_upload_url_rejects_unsafe_asset_names() {
        let repo = RepoRef::parse("o/r").expect("repo");
        let client = GitHubClient::new(repo, "t").expect("client");
        assert!(client.upload_url(1, "../escape.bin").is_err());
        assert!(client.upload_url(1, "a/b.bin").is_err());
        assert!(client.upload_url(1, "").is_err());
        assert!(client.upload_url(1, "fine name.bin").is_err(), "whitespace rejected");
    }

    #[test]
    fn client_trims_trailing_slashes_on_custom_bases() {
        let repo = RepoRef::parse("o/r").expect("repo");
        let client = GitHubClient::with_bases(repo, "t", "https://ghe.example.com/api/v3/", "https://ghe.example.com/uploads/")
            .expect("client");
        assert_eq!(
            client.comments_url(1),
            "https://ghe.example.com/api/v3/repos/o/r/issues/1/comments"
        );
    }

    #[test]
    fn client_debug_never_prints_the_token() {
        let repo = RepoRef::parse("o/r").expect("repo");
        let client = GitHubClient::new(repo, "ghp_SUPERSECRET").expect("client");
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("SUPERSECRET"));
        assert!(rendered.contains("o/r"));
    }

    #[test]
    fn client_exposes_a_cache_handle() {
        let repo = RepoRef::parse("o/r").expect("repo");
        let client = GitHubClient::new(repo, "t").expect("client");
        let cache = client.cache();
        cache.store("u", Some("e"), b"b".to_vec(), 200);
        assert_eq!(client.cache().len(), 1, "cache handle must be shared");
    }

    #[test]
    fn client_redactor_knows_the_token() {
        let repo = RepoRef::parse("o/r").expect("repo");
        let client = GitHubClient::new(repo, "ghp_MYTOKEN").expect("client");
        let scrubbed = client.redactor().scrub("failed with ghp_MYTOKEN");
        assert!(!scrubbed.contains("MYTOKEN"));
    }

    // -- DTO conversion -------------------------------------------------------

    #[test]
    fn converts_a_raw_comment() {
        let raw = RawComment {
            id: 42,
            body: Some("{\"v\":1}".into()),
            created_at: Some("2023-11-14T22:13:20Z".into()),
            updated_at: Some("2023-11-14T22:14:20Z".into()),
            user: Some(RawUser {
                login: "JaredCH".into(),
            }),
        };
        let comment = IssueComment::from(raw);
        assert_eq!(comment.id, 42);
        assert_eq!(comment.body, "{\"v\":1}");
        assert_eq!(comment.created_at_ms, 1_700_000_000_000);
        assert_eq!(comment.updated_at_ms, 1_700_000_060_000);
        assert_eq!(comment.author_login, "JaredCH");
    }

    #[test]
    fn converts_a_raw_comment_with_missing_optional_fields() {
        let raw = RawComment {
            id: 1,
            body: None,
            created_at: None,
            updated_at: None,
            user: None,
        };
        let comment = IssueComment::from(raw);
        assert_eq!(comment.body, "");
        assert_eq!(comment.created_at_ms, 0);
        assert_eq!(comment.author_login, "");
    }

    #[test]
    fn converts_a_raw_asset() {
        let raw = RawAsset {
            id: 7,
            name: "abc.bin".into(),
            size: 4096,
            created_at: Some("1970-01-01T00:00:00Z".into()),
            browser_download_url: None,
        };
        let asset = ReleaseAsset::from(raw);
        assert_eq!(asset.id, 7);
        assert_eq!(asset.size, 4_096);
        assert_eq!(asset.created_at_ms, 0);
    }

    #[test]
    fn release_asset_serializes_round_trip() {
        let asset = asset(1, "a.bin", 10, 1_000);
        let json = serde_json::to_string(&asset).expect("serialize");
        let back: ReleaseAsset = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(asset, back);
    }

    #[test]
    fn issue_comment_round_trips_through_json() {
        let comment = IssueComment {
            id: 1,
            body: "envelope".into(),
            created_at_ms: 5,
            updated_at_ms: 6,
            author_login: "x".into(),
            nostr_event_id: Some("abc123".into()),
        };
        let json = serde_json::to_string(&comment).expect("serialize");
        let back: IssueComment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(comment, back);
    }

    #[test]
    fn nostr_numeric_id_is_stable_and_distinct() {
        let a = nostr_numeric_id("aaaa0000bbbb");
        let b = nostr_numeric_id("aaaa0000bbbb");
        let c = nostr_numeric_id("bbbb0000aaaa");
        assert_eq!(a, b, "the same event id must project to the same number");
        assert_ne!(a, c, "different event ids must not collide");
    }

    #[test]
    fn nostr_numeric_id_handles_short_input() {
        // Must not panic on an id shorter than eight bytes.
        assert_eq!(nostr_numeric_id("ab"), nostr_numeric_id("ab"));
        assert_eq!(nostr_numeric_id(""), 0);
    }

    #[test]
    fn issue_comment_from_a_nostr_event_preserves_the_real_id() {
        let identity = crate::nostr::NostrIdentity::from_secret_bytes([3u8; 32]).expect("id");
        let event = crate::nostr::sign_event(
            &identity,
            crate::nostr::KIND_CHAT,
            vec![],
            "ciphertext",
            1_700_000_000,
        )
        .expect("sign");

        let comment = IssueComment::from_nostr_event(&event);
        assert_eq!(comment.body, "ciphertext");
        assert_eq!(comment.author_login, event.pubkey);
        assert_eq!(comment.created_at_ms, 1_700_000_000_000);
        assert_eq!(comment.nostr_event_id.as_deref(), Some(event.id.as_str()));
        assert_eq!(comment.id, nostr_numeric_id(&event.id));
    }

    #[test]
    fn raw_comment_tolerates_extra_unknown_fields() {
        // GitHub adds fields over time; unknown ones must not break parsing.
        let json = r#"{"id":1,"body":"b","node_id":"x","reactions":{"total_count":0},"unknown":42}"#;
        let raw: RawComment = serde_json::from_str(json).expect("deserialize");
        assert_eq!(raw.id, 1);
        assert_eq!(raw.body.as_deref(), Some("b"));
    }

    #[test]
    fn raw_asset_tolerates_extra_unknown_fields() {
        let json = r#"{"id":1,"name":"n","size":2,"state":"uploaded","uploader":{"login":"x"}}"#;
        let raw: RawAsset = serde_json::from_str(json).expect("deserialize");
        assert_eq!(raw.name, "n");
        assert_eq!(raw.size, 2);
    }

    // -- Debug safety ---------------------------------------------------------

    #[test]
    fn rate_limit_snapshot_and_prune_report_debug_are_safe() {
        let snapshot = RateLimitSnapshot {
            limit: Some(1),
            remaining: Some(2),
            reset_unix_s: Some(3),
        };
        assert!(format!("{snapshot:?}").contains("remaining"));

        let report = PruneReport {
            to_delete: vec![],
            total_before: 1,
            total_after: 2,
        };
        assert!(format!("{report:?}").contains("total_before"));
    }
}

// ---------------------------------------------------------------------------
// Live integration tests against a real repository.
//
// These run by default per the plan. They are gated on two environment
// variables so an unconfigured machine fails fast with a clear message rather
// than attempting unauthenticated requests. Destructive coverage additionally
// requires SHADOWTEST_ALLOW_DESTRUCTIVE=1.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod live {
    use super::*;
    use std::env;

    /// Configuration harvested from the environment, or `None` when unset.
    struct LiveConfig {
        repo: RepoRef,
        token: String,
        allow_destructive: bool,
    }

    impl LiveConfig {
        fn from_env() -> Option<Self> {
            let raw_repo = env::var("SHADOWTEST_REPO").ok()?;
            let token = env::var("SHADOWTEST_PAT").ok()?;
            if raw_repo.trim().is_empty() || token.trim().is_empty() {
                return None;
            }
            let repo = RepoRef::parse(&raw_repo).ok()?;
            let allow_destructive = env::var("SHADOWTEST_ALLOW_DESTRUCTIVE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            Some(Self {
                repo,
                token,
                allow_destructive,
            })
        }
    }

    /// Fetch config or skip with a loud message.
    fn config_or_skip(test_name: &str) -> Option<LiveConfig> {
        match LiveConfig::from_env() {
            Some(config) => Some(config),
            None => {
                eprintln!(
                    "skipping live test `{test_name}`: set SHADOWTEST_PAT and SHADOWTEST_REPO \
                     to run the jaredch integration suite"
                );
                None
            }
        }
    }

    fn client_for(config: &LiveConfig) -> GitHubClient {
        let api_base = env::var("SHADOWTEST_API_BASE")
            .unwrap_or_else(|_| DEFAULT_API_BASE.to_string());
        GitHubClient::with_bases(
            config.repo.clone(),
            config.token.clone(),
            api_base,
            DEFAULT_UPLOADS_BASE,
        )
        .unwrap_or_else(|_| panic!("could not build a client from the provided environment"))
    }

    /// Abort early when the shared budget is already low, so a test run cannot
    /// be the thing that exhausts the group's PAT for the hour.
    async fn assert_budget_available(client: &GitHubClient) {
        let snapshot = match client.rate_limit().await {
            Ok(s) => s,
            Err(e) => panic!("could not read the rate limit: {}", e.kind().as_str()),
        };
        if let Some(remaining) = snapshot.remaining {
            assert!(
                remaining > 500,
                "refusing to run live tests: only {remaining} requests remain this hour"
            );
        }
    }

    /// A unique-per-run envelope body, so parallel runs cannot collide.
    fn unique_body(tag: &str) -> String {
        let uuid = uuid::Uuid::new_v4();
        format!("{{\"v\":1,\"test\":\"{tag}\",\"nonce\":\"{uuid}\"}}")
    }

    #[tokio::test]
    async fn live_token_validates_and_repo_is_accessible() {
        let Some(config) = config_or_skip("live_token_validates_and_repo_is_accessible") else {
            return;
        };
        let client = client_for(&config);
        assert_budget_available(&client).await;

        let login = client.validate_token().await.expect("token should be valid");
        assert!(!login.is_empty(), "authenticated login should not be empty");

        // The plan's sandbox is a private repo; assert we can see it either way.
        let _is_private = client
            .repo_is_accessible()
            .await
            .expect("token should be able to read the sandbox repo");
    }

    #[tokio::test]
    async fn live_comment_lifecycle_on_a_sandbox_issue() {
        let Some(config) = config_or_skip("live_comment_lifecycle_on_a_sandbox_issue") else {
            return;
        };
        let client = client_for(&config);
        assert_budget_available(&client).await;

        // Issue #2 is the chat channel in the real schema. Create, read back,
        // update in place, then delete so the sandbox is left clean.
        let issue_num = env::var("SHADOWTEST_CHAT_ISSUE")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(2);

        let created = client
            .create_comment(issue_num, &unique_body("create"))
            .await
            .expect("create should succeed");
        assert!(created.id > 0);

        let fetched = client.get_comment(created.id).await.expect("read back");
        assert_eq!(fetched.id, created.id);
        assert!(fetched.body.contains("\"test\":\"create\""));

        let updated = client
            .update_comment(created.id, &unique_body("update"))
            .await
            .expect("patch should succeed");
        assert!(updated.body.contains("\"test\":\"update\""));

        client
            .delete_comment(created.id)
            .await
            .expect("cleanup should succeed");

        // Confirm it is really gone.
        let err = client
            .get_comment(created.id)
            .await
            .expect_err("deleted comment should not be readable");
        assert_eq!(err.kind(), crate::error::AppErrorKind::GitHubApi);
    }

    #[tokio::test]
    async fn live_comment_patch_does_not_conflict_across_many_writes() {
        let Some(config) = config_or_skip("live_comment_patch_does_not_conflict_across_many_writes")
        else {
            return;
        };
        let client = client_for(&config);
        assert_budget_available(&client).await;

        let issue_num = env::var("SHADOWTEST_ROSTER_ISSUE")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(1);

        let comment = client
            .create_comment(issue_num, &unique_body("roster"))
            .await
            .expect("create roster comment");

        // Simulate a member patching their own comment repeatedly. Each write
        // targets the same id, which is exactly why concurrent members cannot
        // collide: there is no shared resource to contend for.
        for round in 0..5 {
            let body = format!("{{\"v\":1,\"round\":{round}}}");
            client
                .update_comment(comment.id, &body)
                .await
                .unwrap_or_else(|e| panic!("patch round {round} failed: {}", e.kind().as_str()));
        }

        let final_state = client.get_comment(comment.id).await.expect("final read");
        assert!(final_state.body.contains("\"round\":4"));

        client.delete_comment(comment.id).await.expect("cleanup");
    }

    #[tokio::test]
    async fn live_conditional_get_reports_not_modified_and_preserves_body() {
        let Some(config) = config_or_skip("live_conditional_get_reports_not_modified_and_preserves_body")
        else {
            return;
        };
        let client = client_for(&config);
        assert_budget_available(&client).await;

        let issue_num = env::var("SHADOWTEST_CHAT_ISSUE")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(2);
        let url = format!("{}?per_page=1", client.comments_url(issue_num));

        let first = client.get_conditional(&url).await.expect("first fetch");
        let (first_body, first_etag) = match first {
            Conditional::Fresh { body, etag } => (body, etag),
            Conditional::NotModified { .. } => {
                panic!("a cold cache cannot produce a 304")
            }
        };
        assert!(first_etag.is_some(), "GitHub should supply an ETag for listings");

        let second = client.get_conditional(&url).await.expect("second fetch");
        match second {
            Conditional::NotModified { body } => {
                assert_eq!(
                    body, first_body,
                    "a 304 must rehydrate the cached body byte-for-byte"
                );
            }
            Conditional::Fresh { .. } => {
                // A comment posted between the two calls legitimately invalidates
                // the ETag; that is correct behaviour, not a failure.
                eprintln!("note: listing changed between polls, so no 304 was returned");
            }
        }
    }

    #[tokio::test]
    async fn live_vault_upload_and_delete_round_trip() {
        let Some(config) = config_or_skip("live_vault_upload_and_delete_round_trip") else {
            return;
        };
        let client = client_for(&config);
        assert_budget_available(&client).await;

        let release_id = match env::var("SHADOWTEST_RELEASE_ID")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            Some(id) => id,
            None => {
                eprintln!(
                    "skipping live vault test: set SHADOWTEST_RELEASE_ID to the vault-v1 release id"
                );
                return;
            }
        };

        // Opaque bytes standing in for an encrypted blob.
        let payload = vec![0xA5u8; 1024];
        let name = format!("{}.bin", uuid::Uuid::new_v4());

        let asset = client
            .upload_asset(release_id, &name, &payload, "application/octet-stream")
            .await
            .expect("upload should succeed");
        assert_eq!(asset.name, name);
        assert_eq!(asset.size, payload.len() as u64);

        let listed = client.list_assets(release_id).await.expect("list assets");
        assert!(
            listed.iter().any(|a| a.id == asset.id),
            "uploaded asset should appear in the listing"
        );

        client.delete_asset(asset.id).await.expect("cleanup asset");
    }

    #[tokio::test]
    async fn live_pruner_selects_without_deleting_when_vault_is_small() {
        let Some(config) = config_or_skip("live_pruner_selects_without_deleting_when_vault_is_small")
        else {
            return;
        };
        let client = client_for(&config);
        assert_budget_available(&client).await;

        let release_id = match env::var("SHADOWTEST_RELEASE_ID")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            Some(id) => id,
            None => {
                eprintln!("skipping live pruner test: set SHADOWTEST_RELEASE_ID");
                return;
            }
        };

        let assets = client.list_assets(release_id).await.expect("list assets");
        let total: u64 = assets.iter().map(|a| a.size).sum();

        if total + 1_024 <= MAX_VAULT_BYTES {
            let report = client
                .prune_vault(release_id, 1_024)
                .await
                .expect("prune should succeed");
            assert!(
                report.is_noop(),
                "a vault with room must not have anything pruned"
            );
        } else {
            eprintln!("note: sandbox vault is already near its ceiling; skipping the no-op assertion");
        }
    }

    #[tokio::test]
    async fn live_admin_scope_is_detectable() {
        let Some(config) = config_or_skip("live_admin_scope_is_detectable") else {
            return;
        };
        let client = client_for(&config);
        assert_budget_available(&client).await;

        // Report rather than assert: the sandbox token may or may not carry
        // Administration: R/W, and knowing which is the point of the check.
        let admin = client
            .has_admin_scope()
            .await
            .expect("permissions should be readable");
        eprintln!("sandbox token has admin scope: {admin}");
        if !admin {
            eprintln!(
                "note: 'Destroy Group' will fail without Administration: Read/Write on the PAT"
            );
        }
    }

    #[tokio::test]
    async fn live_destructive_destroy_group_is_opt_in_only() {
        let Some(config) = config_or_skip("live_destructive_destroy_group_is_opt_in_only") else {
            return;
        };
        if !config.allow_destructive {
            eprintln!(
                "skipping destructive test: set SHADOWTEST_ALLOW_DESTRUCTIVE=1 and point \
                 SHADOWTEST_REPO at a throwaway repo to run it"
            );
            return;
        }

        // Deliberately never executed against a real repo during a normal run.
        // The guard exists so the default suite cannot delete anything.
        panic!(
            "destructive test was enabled for {}. This test deletes SHADOWTEST_REPO outright; \
             it is intentionally not implemented to avoid accidental data loss.",
            config.repo.full_name()
        );
    }

    // -- provisioning ---------------------------------------------------------

    #[test]
    fn provisioning_client_rejects_an_empty_token() {
        assert!(ProvisioningClient::new("").is_err());
        assert!(ProvisioningClient::new("   ").is_err());
    }

    #[test]
    fn provisioning_client_debug_never_prints_the_token() {
        let client = ProvisioningClient::new("ghp_SUPERSECRET").expect("client");
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("SUPERSECRET"));
    }

    #[test]
    fn provisioning_client_trims_trailing_slashes() {
        let client = ProvisioningClient::with_base("t", "https://ghe.example.com/api/v3/")
            .expect("client");
        assert_eq!(client.api_base, "https://ghe.example.com/api/v3");
    }

    #[test]
    fn provisioned_carries_the_schema_numbers() {
        let provisioned = Provisioned {
            repo: RepoRef::parse("o/r").expect("repo"),
            roster_issue_num: 1,
            chat_issue_num: 2,
            release_id: 7,
        };
        assert_eq!(provisioned.repo.full_name(), "o/r");
        assert_eq!(provisioned.roster_issue_num, 1);
        assert_eq!(provisioned.chat_issue_num, 2);
        assert_eq!(provisioned.release_id, 7);
    }

    #[test]
    fn schema_issue_bodies_are_non_empty() {
        assert!(!ROSTER_ISSUE_BODY.trim().is_empty());
        assert!(!CHAT_ISSUE_BODY.trim().is_empty());
    }
}