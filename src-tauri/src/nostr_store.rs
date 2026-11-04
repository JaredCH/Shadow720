//! Nostr-backed implementation of the roster, chat, and blob operations.
//!
//! This is the Nostr counterpart to [`crate::github_db::GitHubClient`]. It
//! exposes the same *logical* operations — read the roster, read the chat, write
//! my slot, append a message — so the command layer can pick a backend without
//! duplicating policy.
//!
//! # Slot model
//!
//! A member's roster entry is an **addressable** event (kind 30000–39999) whose
//! `d` tag is the group id and whose author is the member's own key. Relays keep
//! only the newest per `(pubkey, kind, d-tag)`, which gives exactly the "each
//! member owns one slot" property the GitHub schema got from one comment per
//! member. Nobody can overwrite anyone else's slot, because the author is part of
//! the address.
//!
//! Chat is a regular event: append-only, never replaced.

use std::sync::Arc;

use crate::error::{AppError, Result};
use crate::github_db::IssueComment;
use crate::nostr::{
    blossom_auth_header, build_blossom_auth, build_deletion_request, sign_event, BlobRef, Event,
    Filter, NostrIdentity, KIND_CHAT, KIND_DELETE, KIND_FILE, KIND_FILE_LEGACY, KIND_FILE_REMOVED,
    KIND_CONTROL, KIND_GROUP_CLOSED, KIND_ROSTER, KIND_ROTATION,
};
use crate::nostr_relay::{newest_per_slot, publish_to_all, query_all};

/// A group's Nostr connection details.
#[derive(Clone, Debug)]
pub struct NostrStore {
    /// Group id, used as the `d` tag on every event.
    pub group_id: String,
    /// Relay URLs.
    pub relays: Vec<String>,
    /// Blossom servers for blobs.
    pub blossom_servers: Vec<String>,
    /// This device's identity, which signs everything it writes.
    pub identity: Arc<NostrIdentity>,
    /// HTTP client for Blossom.
    http: reqwest::Client,
    auth_http: reqwest::Client,
}

#[derive(Debug)]
pub struct UploadedBlob {
    pub blob: BlobRef,
    pub server: String,
}

impl NostrStore {
    /// Build a store, validating the relay list up front.
    pub fn new(
        group_id: impl Into<String>,
        relays: Vec<String>,
        blossom_servers: Vec<String>,
        identity: Arc<NostrIdentity>,
    ) -> Result<Self> {
        let group_id = group_id.into();
        if group_id.trim().is_empty() {
            return Err(AppError::invalid_argument(
                "a Nostr group needs a group id, which is the event `d` tag",
            ));
        }
        if relays.is_empty() {
            return Err(AppError::invalid_argument(
                "a Nostr group needs at least one relay",
            ));
        }
        for relay in &relays {
            if !relay.starts_with("wss://") && !relay.starts_with("ws://") {
                return Err(AppError::invalid_argument(format!(
                    "relay {relay} must be a ws:// or wss:// URL"
                )));
            }
        }

        let http = reqwest::Client::builder()
            .user_agent(concat!("shadow720/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| AppError::network("blossom", format!("could not build client: {e}")))?;
        let auth_http = reqwest::Client::builder()
            .user_agent(concat!("shadow720/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AppError::network("blossom", format!("could not build auth client: {e}")))?;

        Ok(Self {
            group_id,
            relays,
            blossom_servers,
            identity,
            http,
            auth_http,
        })
    }

    /// This device's public key, which is its identity in the group.
    pub fn pubkey_hex(&self) -> &str {
        self.identity.pubkey_hex()
    }

    /// Publish the pinned host's closure proof to the configured relays.
    pub async fn publish_closure(&self, proof: &str) -> Result<Vec<String>> {
        let event = sign_event(
            &self.identity,
            KIND_GROUP_CLOSED,
            vec![vec!["d".into(), self.group_id.clone()]],
            proof,
            crate::nostr::now_unix_s(),
        )?;
        publish_to_all(&self.relays, &event).await
    }

    /// Read closure proofs; the caller must verify them against its pinned host.
    pub async fn read_closures(&self) -> Result<Vec<Event>> {
        let filter = Filter {
            kinds: Some(vec![KIND_GROUP_CLOSED]),
            d_tags: Some(vec![self.group_id.clone()]),
            ..Filter::default()
        };
        Ok(query_all(&self.relays, vec![filter]).await?.into_iter()
            .filter(|event| event.kind == KIND_GROUP_CLOSED && event.d_tag() == Some(&self.group_id))
            .collect())
    }

    /// Read every roster slot in the group.
    ///
    /// Returns one entry per member: the newest addressable event for each
    /// author, already collapsed across relays.
    pub async fn read_roster(&self) -> Result<Vec<IssueComment>> {
        let filter = Filter {
            kinds: Some(vec![KIND_ROSTER]),
            d_tags: Some(vec![self.group_id.clone()]),
            event_tags: None,
            address_tags: None,
            authors: None,
            since: None,
            limit: Some(500),
        };

        let events = query_all(&self.relays, vec![filter]).await?;
        let collapsed = newest_per_slot(events);
        Ok(collapsed
            .iter()
            .filter(|event| event.kind == KIND_ROSTER)
            .map(IssueComment::from_nostr_event)
            .collect())
    }

    /// Read the chat stream, oldest first.
    pub async fn read_chat_events(&self) -> Result<Vec<Event>> {
        let filter = Filter {
            kinds: Some(vec![KIND_CHAT, KIND_FILE, KIND_FILE_LEGACY]),
            d_tags: Some(vec![self.group_id.clone()]),
            event_tags: None,
            address_tags: None,
            authors: None,
            since: None,
            limit: Some(500),
        };

        let events: Vec<Event> = query_all(&self.relays, vec![filter])
            .await?
            .into_iter()
            .filter(|event| {
                (event.kind == KIND_CHAT || event.kind == KIND_FILE || event.kind == KIND_FILE_LEGACY)
                    && event.d_tag() == Some(self.group_id.as_str())
            })
            .collect();
        if events.is_empty() {
            return Ok(events);
        }
        let deletion_filter = Filter {
            kinds: Some(vec![KIND_DELETE]),
            event_tags: Some(events.iter().map(|event| event.id.clone()).collect()),
            ..Filter::default()
        };
        let addresses: Vec<String> = events.iter().filter(|event| is_replaceable(event.kind)).filter_map(|event| {
            event.d_tag().map(|d| format!("{}:{}:{d}", event.kind, event.pubkey))
        }).collect();
        let mut filters = vec![deletion_filter];
        if !addresses.is_empty() {
            filters.push(Filter {
            kinds: Some(vec![KIND_DELETE]),
            address_tags: Some(addresses),
            ..Filter::default()
            });
        }
        let requests = query_all(&self.relays, filters).await?;
        Ok(filter_deleted_events(events, &requests))
    }

    /// Read the chat stream after applying verified author deletion requests.
    pub async fn read_chat(&self) -> Result<Vec<IssueComment>> {
        Ok(self.read_chat_events().await?.iter().map(IssueComment::from_nostr_event).collect())
    }

    /// Request deletion of an event signed by this device.
    pub async fn delete_own_event(&self, event_id: &str) -> Result<Vec<String>> {
        let events = self.read_chat_events().await?;
        let event = events.iter().find(|event| event.id == event_id)
            .ok_or_else(|| AppError::invalid_argument("message was not found in the current group"))?;
        if event.pubkey != self.pubkey_hex() {
            return Err(AppError::invalid_argument("only the event author can request deletion"));
        }
        let request = build_deletion_request(&self.identity, &event.id, event.kind, "")?;
        publish_to_all(&self.relays, &request).await
    }

    /// Publish the host's latest role set. Addressable, so it replaces the previous set.
    pub async fn publish_control(&self, envelope_json: &str) -> Result<String> {
        let event = sign_event(
            &self.identity,
            KIND_CONTROL,
            vec![vec!["d".to_string(), self.group_id.clone()]],
            envelope_json,
            crate::nostr::now_unix_s(),
        )?;
        publish_to_all(&self.relays, &event).await?;
        Ok(event.id)
    }

    /// Read role-set events for this group.
    pub async fn read_control(&self) -> Result<Vec<IssueComment>> {
        let filter = Filter {
            kinds: Some(vec![KIND_CONTROL]),
            d_tags: Some(vec![self.group_id.clone()]),
            ..Filter::default()
        };
        let events = query_all(&self.relays, vec![filter]).await?;
        let collapsed = newest_per_slot(events);
        Ok(collapsed
            .iter()
            .filter(|event| event.kind == KIND_CONTROL && event.d_tag() == Some(self.group_id.as_str()))
            .map(IssueComment::from_nostr_event)
            .collect())
    }

    /// Publish a key-rotation notice. Append-only, so guests can still see the epoch.
    pub async fn publish_rotation(&self, envelope_json: &str) -> Result<String> {
        let event = sign_event(
            &self.identity,
            KIND_ROTATION,
            vec![vec!["d".to_string(), self.group_id.clone()]],
            envelope_json,
            crate::nostr::now_unix_s(),
        )?;
        publish_to_all(&self.relays, &event).await?;
        Ok(event.id)
    }

    /// Read rotation notices for this group.
    pub async fn read_rotations(&self) -> Result<Vec<IssueComment>> {
        let filter = Filter {
            kinds: Some(vec![KIND_ROTATION]),
            d_tags: Some(vec![self.group_id.clone()]),
            ..Filter::default()
        };
        Ok(query_all(&self.relays, vec![filter]).await?.into_iter()
            .filter(|event| event.kind == KIND_ROTATION && event.d_tag() == Some(self.group_id.as_str()))
            .map(|event| IssueComment::from_nostr_event(&event))
            .collect())
    }

    /// Publish this device's roster slot.
    ///
    /// Addressable, so a repeat publish replaces the previous one rather than
    /// appending. Returns the event id.
    pub async fn publish_roster(&self, envelope_json: &str) -> Result<String> {
        let event = sign_event(
            &self.identity,
            KIND_ROSTER,
            vec![
                vec!["d".to_string(), self.group_id.clone()],
                // Marks the slot as replaceable for clients that read the tag.
                vec!["t".to_string(), "shadow720-roster".to_string()],
            ],
            envelope_json,
            crate::nostr::now_unix_s(),
        )?;

        publish_to_all(&self.relays, &event).await?;
        Ok(event.id)
    }

    /// Append a chat message.
    pub async fn publish_chat(&self, envelope_json: &str) -> Result<String> {
        let event = sign_event(
            &self.identity,
            KIND_CHAT,
            vec![
                vec!["d".to_string(), self.group_id.clone()],
                vec!["t".to_string(), "shadow720-chat".to_string()],
            ],
            envelope_json,
            crate::nostr::now_unix_s(),
        )?;

        publish_to_all(&self.relays, &event).await?;
        Ok(event.id)
    }

    /// Append a file pointer.
    pub fn file_event(&self, envelope_json: &str) -> Result<Event> {
        sign_event(
            &self.identity,
            KIND_FILE,
            vec![
                vec!["d".to_string(), self.group_id.clone()],
                vec!["t".to_string(), "shadow720-file".to_string()],
            ],
            envelope_json,
            crate::nostr::now_unix_s(),
        )
    }

    pub async fn publish_file(&self, event: &Event) -> Result<Vec<String>> {
        publish_to_all(&self.relays, event).await
    }

    pub async fn publish_file_removal(&self, original: &Event) -> Result<Vec<String>> {
        if original.pubkey != self.pubkey_hex() || !matches!(original.kind, KIND_FILE | KIND_FILE_LEGACY)
            || original.d_tag() != Some(self.group_id.as_str())
        {
            return Err(AppError::invalid_argument("the file event is not owned by this device"));
        }
        original.verify_id()?;
        original.verify_signature()?;
        let content = serde_json::to_string(original)
            .map_err(|error| AppError::parse("file removal", error.to_string()))?;
        let notice = sign_event(&self.identity, KIND_FILE_REMOVED,
            vec![vec!["d".into(), self.group_id.clone()]], content, crate::nostr::now_unix_s())?;
        publish_to_all(&self.relays, &notice).await
    }

    pub async fn read_file_removals(&self) -> Result<Vec<Event>> {
        let filter = Filter {
            kinds: Some(vec![KIND_FILE_REMOVED]),
            d_tags: Some(vec![self.group_id.clone()]),
            ..Filter::default()
        };
        Ok(query_all(&self.relays, vec![filter]).await?.into_iter()
            .filter(|event| event.kind == KIND_FILE_REMOVED && event.d_tag() == Some(self.group_id.as_str()))
            .collect())
    }

    fn blossom_authorization(&self, server: &str, verb: &str, sha256: &str) -> Result<String> {
        let url = url::Url::parse(server)
            .map_err(|error| AppError::invalid_argument(format!("invalid Blossom server URL: {error}")))?;
        let host = url.host_str().ok_or_else(|| AppError::invalid_argument("Blossom server has no host"))?;
        let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1");
        if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
            || !url.username().is_empty() || url.password().is_some()
            || url.query().is_some() || url.fragment().is_some()
        {
            return Err(AppError::invalid_argument("Blossom servers require HTTPS and must not contain credentials, query parameters, or fragments"));
        }
        let mut auth = build_blossom_auth(&self.identity, verb, sha256, 120)?;
        auth.tags.push(vec!["server".into(), host.to_ascii_lowercase()]);
        let signed = sign_event(&self.identity, auth.kind, auth.tags, auth.content, auth.created_at.saturating_sub(1))?;
        Ok(format!("Nostr {}", blossom_auth_header(&signed)?))
    }

    /// Upload a sealed blob to the first Blossom server that accepts it.
    ///
    /// Returns the content address, which is what the file pointer references.
    pub async fn upload_blob(&self, sealed: &[u8]) -> Result<UploadedBlob> {
        if self.blossom_servers.is_empty() {
            return Err(AppError::not_configured(
                "no Blossom server is configured, so files cannot be shared",
            ));
        }

        let blob = BlobRef::of(sealed);
        let mut last_error: Option<AppError> = None;

        for server in &self.blossom_servers {
            let url = format!("{}/upload", server.trim_end_matches('/'));
            let authorization = self.blossom_authorization(server, "upload", &blob.sha256)?;
            let response = self
                .auth_http
                .put(&url)
                .header("Content-Type", "application/octet-stream")
                .header("X-SHA-256", &blob.sha256)
                .header("Authorization", authorization)
                .body(sealed.to_vec())
                .send()
                .await;

            match response {
                Ok(response) if matches!(response.status(), reqwest::StatusCode::OK | reqwest::StatusCode::CREATED) => {
                    #[derive(serde::Deserialize)]
                    struct Descriptor { sha256: String, size: u64 }
                    let descriptor: Descriptor = response.json().await.map_err(|error| {
                        AppError::parse(server, format!("invalid upload descriptor: {error}"))
                    })?;
                    if descriptor.sha256 != blob.sha256 || descriptor.size != blob.size {
                        return Err(AppError::crypto(format!("{server} returned an inconsistent upload descriptor")));
                    }
                    return Ok(UploadedBlob { blob, server: server.clone() });
                }
                Ok(response) => {
                    last_error = Some(AppError::GitHubApi {
                        status: response.status().as_u16(),
                        message: format!("{server} rejected the upload"),
                    })
                }

                Err(e) => {
                    last_error = Some(AppError::network(
                        server.clone(),
                        format!("could not upload: {e}"),
                    ))
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            AppError::network("blossom", "no Blossom server accepted the blob")
        }))
    }

    pub async fn delete_blob(&self, server: &str, sha256: &str) -> Result<()> {
        if !self.blossom_servers.iter().any(|entry| entry == server) {
            return Err(AppError::invalid_argument("the upload server is not configured for this group"));
        }
        let authorization = self.blossom_authorization(server, "delete", sha256)?;
        let url = format!("{}/{}", server.trim_end_matches('/'), sha256);
        let response = self.auth_http.delete(&url).header("Authorization", authorization)
            .send().await.map_err(|error| AppError::network(server, format!("could not delete blob: {error}")))?;
        if !matches!(response.status(), reqwest::StatusCode::OK | reqwest::StatusCode::NO_CONTENT) {
            return Err(AppError::network(server, format!("blob deletion was rejected (HTTP {})", response.status())));
        }
        Ok(())
    }

    /// Download a sealed blob by its content address.
    pub async fn download_blob(&self, sha256: &str) -> Result<Vec<u8>> {
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::invalid_argument(
                "a blob address must be 64 hex characters",
            ));
        }
        if self.blossom_servers.is_empty() {
            return Err(AppError::not_configured(
                "no Blossom server is configured, so files cannot be fetched",
            ));
        }

        let mut last_error: Option<AppError> = None;

        for server in &self.blossom_servers {
            let url = format!("{}/{}", server.trim_end_matches('/'), sha256);
            match self.http.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    let bytes = response.bytes().await.map_err(|e| {
                        AppError::network(server.clone(), format!("could not read body: {e}"))
                    })?;
                    // Content addressing means the bytes must hash to the name.
                    let actual = BlobRef::of(&bytes);
                    if actual.sha256 != sha256 {
                        return Err(AppError::crypto(
                            "the downloaded blob does not match its content address",
                        ));
                    }
                    return Ok(bytes.to_vec());
                }
                Ok(response) => {
                    last_error = Some(AppError::GitHubApi {
                        status: response.status().as_u16(),
                        message: format!("{server} does not have that blob"),
                    })
                }
                Err(e) => {
                    last_error = Some(AppError::network(
                        server.clone(),
                        format!("could not download: {e}"),
                    ))
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            AppError::network("blossom", "no Blossom server had the blob")
        }))
    }

    /// True when this device already has a roster slot in the group.
    pub async fn has_own_slot(&self) -> Result<bool> {
        let filter = Filter::roster_slot(&self.group_id, self.pubkey_hex());
        let events = query_all(&self.relays, vec![filter]).await?;
        Ok(events.iter().any(|event| event.pubkey == self.pubkey_hex()))
    }
}

fn filter_deleted_events(events: Vec<Event>, requests: &[Event]) -> Vec<Event> {
    events.into_iter().filter(|event| {
        let address = if is_replaceable(event.kind) {
            event.d_tag().map(|d| format!("{}:{}:{d}", event.kind, event.pubkey))
        } else {
            None
        };
        !requests.iter().any(|request| {
            request.kind == KIND_DELETE
                && request.verify_id().is_ok()
                && request.verify_signature().is_ok()
                && request.pubkey == event.pubkey
                && (request.deleted_event_ids().contains(&event.id.as_str())
                    || (request.created_at >= event.created_at
                        && address.as_deref().is_some_and(|address| {
                            request.deleted_slot_addresses().contains(&address)
                        })))
        })
    }).collect()
}

fn is_replaceable(kind: u64) -> bool {
    (10_000..20_000).contains(&kind) || (30_000..40_000).contains(&kind)
}

/// Build a store from a group's stored configuration.
pub fn store_for(
    group_id: &str,
    relays: &[String],
    blossom_servers: &[String],
    identity: Arc<NostrIdentity>,
) -> Result<NostrStore> {
    NostrStore::new(
        group_id,
        relays.to_vec(),
        blossom_servers.to_vec(),
        identity,
    )
}

/// Extract the blob address from a file-pointer envelope.
///
/// The envelope is opaque to this module, so the caller passes the already
/// decrypted payload; this only pulls the field out.
pub fn blob_address_from_payload(payload: &serde_json::Value) -> Option<&str> {
    payload
        .get("FileAttachment")
        .and_then(|v| v.get("asset_name"))
        .and_then(|v| v.as_str())
}

/// A published event, for diagnostics.
#[derive(Clone, Debug)]
pub struct Published {
    pub event_id: String,
    pub relays: Vec<String>,
}

/// Publish an already-signed event to the group's relays.
pub async fn publish_event(relays: &[String], event: &Event) -> Result<Published> {
    let accepted = publish_to_all(relays, event).await?;
    Ok(Published {
        event_id: event.id.clone(),
        relays: accepted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blossom_upload_and_delete_use_scoped_signed_authorization() {
        use base64::Engine;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let address = listener.local_addr().expect("address");
        let server = format!("http://{address}");
        let bytes = b"sealed file";
        let sha256 = BlobRef::of(bytes).sha256;
        let expected = sha256.clone();
        let mock = tokio::spawn(async move {
            for verb in ["upload", "delete"] {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                let header_end = loop {
                    let count = socket.read(&mut buffer).await.expect("read");
                    assert_ne!(count, 0);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(position) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break position + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let authorization = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization").then(|| value.trim().to_string())
                }).expect("authorization");
                let token = authorization.strip_prefix("Nostr ").expect("scheme");
                let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token).expect("base64url");
                let event: Event = serde_json::from_slice(&json).expect("auth event");
                event.verify_id().expect("auth id");
                event.verify_signature().expect("auth signature");
                assert!(event.tags.contains(&vec!["t".into(), verb.into()]));
                assert!(event.tags.contains(&vec!["x".into(), expected.clone()]));
                assert!(event.tags.contains(&vec!["server".into(), "127.0.0.1".into()]));
                let response = if verb == "upload" {
                    assert!(headers.starts_with("PUT /upload "));
                    let body = format!("{{\"sha256\":\"{expected}\",\"size\":11}}");
                    format!("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                } else {
                    assert!(headers.starts_with(&format!("DELETE /{expected} ")));
                    "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_string()
                };
                socket.write_all(response.as_bytes()).await.expect("response");
            }
        });
        let store = NostrStore::new("group", vec!["wss://relay.example".into()], vec![server.clone()], identity()).expect("store");
        let uploaded = store.upload_blob(bytes).await.expect("upload");
        assert_eq!(uploaded.blob.sha256, sha256);
        assert_eq!(uploaded.server, server);
        store.delete_blob(&server, &sha256).await.expect("delete");
        mock.await.expect("mock");
    }

    fn identity() -> Arc<NostrIdentity> {
        Arc::new(NostrIdentity::from_secret_bytes([11u8; 32]).expect("identity"))
    }

    #[test]
    fn deletion_requests_only_hide_events_from_the_same_verified_author() {
        let author = identity();
        let attacker = NostrIdentity::from_secret_bytes([12u8; 32]).expect("attacker");
        let event = sign_event(&author, KIND_CHAT, vec![vec!["d".into(), "group-1".into()]], "message", 100).expect("event");
        let forged = build_deletion_request(&attacker, &event.id, event.kind, "").expect("request");
        assert_eq!(filter_deleted_events(vec![event.clone()], &[forged]).len(), 1);

        let mut tampered = build_deletion_request(&author, &event.id, event.kind, "").expect("request");
        tampered.content = "tampered".into();
        assert_eq!(filter_deleted_events(vec![event.clone()], &[tampered]).len(), 1);

        let valid = build_deletion_request(&author, &event.id, event.kind, "").expect("request");
        assert!(filter_deleted_events(vec![event], &[valid]).is_empty());
    }

    #[test]
    fn address_deletions_only_hide_versions_at_or_before_the_request() {
        let author = identity();
        let event = sign_event(&author, KIND_CHAT, vec![vec!["d".into(), "group-1".into()]], "message", 100).expect("event");
        let address = format!("{}:{}:group-1", event.kind, event.pubkey);
        let old = sign_event(&author, KIND_DELETE, vec![vec!["a".into(), address.clone()]], "", 99).expect("request");
        assert_eq!(filter_deleted_events(vec![event.clone()], &[old]).len(), 1);
        let valid = sign_event(&author, KIND_DELETE, vec![vec!["a".into(), address]], "", 100).expect("request");
        assert!(filter_deleted_events(vec![event], &[valid]).is_empty());
    }

    fn store() -> NostrStore {
        NostrStore::new(
            "group-1",
            vec!["wss://relay.example".into()],
            vec!["https://blossom.example".into()],
            identity(),
        )
        .expect("store")
    }

    #[test]
    fn store_rejects_an_empty_group_id() {
        let result = NostrStore::new("", vec!["wss://r.example".into()], vec![], identity());
        assert!(result.is_err());
    }

    #[test]
    fn store_rejects_an_empty_relay_list() {
        let result = NostrStore::new("g", vec![], vec![], identity());
        assert!(result.is_err());
    }

    #[test]
    fn store_rejects_a_non_websocket_relay() {
        let result = NostrStore::new(
            "g",
            vec!["https://relay.example".into()],
            vec![],
            identity(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn store_exposes_its_own_pubkey() {
        let store = store();
        assert_eq!(store.pubkey_hex(), identity().pubkey_hex());
        assert_eq!(store.pubkey_hex().len(), 64);
    }

    #[test]
    fn download_rejects_a_malformed_blob_address() {
        let store = store();
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        assert!(runtime.block_on(store.download_blob("short")).is_err());
        assert!(runtime
            .block_on(store.download_blob(&"z".repeat(64)))
            .is_err());
    }

    #[test]
    fn upload_without_a_blossom_server_is_a_clear_error() {
        let store = NostrStore::new("g", vec!["wss://r.example".into()], vec![], identity())
            .expect("store");
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let error = runtime.block_on(store.upload_blob(b"x")).expect_err("must fail");
        assert_eq!(error.kind(), crate::error::AppErrorKind::NotConfigured);
    }

    #[test]
    fn blob_address_is_read_from_a_file_payload() {
        let payload = serde_json::json!({
            "FileAttachment": { "asset_name": "abc123", "size_bytes": 5 }
        });
        assert_eq!(blob_address_from_payload(&payload), Some("abc123"));
    }

    #[test]
    fn blob_address_is_absent_for_a_text_payload() {
        let payload = serde_json::json!({ "TextMessage": { "text": "hi" } });
        assert_eq!(blob_address_from_payload(&payload), None);
    }

    #[test]
    fn store_for_builds_from_group_configuration() {
        let store = store_for(
            "g",
            &["wss://r.example".to_string()],
            &[],
            identity(),
        )
        .expect("store");
        assert_eq!(store.group_id, "g");
        assert_eq!(store.relays.len(), 1);
    }
}
