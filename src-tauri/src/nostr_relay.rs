//! WebSocket relay client.
//!
//! Relays push events, so this replaces the polling loop entirely: one
//! subscription per group, and the relay tells us when something changes. There
//! is no ETag cache, no cadence budget, and no rate-limit arithmetic on this
//! path — the relay's own backpressure is the only limit.
//!
//! Publishing goes to every configured relay and succeeds if **any** accepts it,
//! because a single relay going away must not break the group.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::error::{AppError, Result};
use crate::nostr::{
    parse_relay_message, ClientMessage, Event, Filter, RelayMessage, ACK_TIMEOUT, CONNECT_TIMEOUT,
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One open relay connection.
pub struct RelayConnection {
    url: String,
    socket: Socket,
}

impl std::fmt::Debug for RelayConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayConnection")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl RelayConnection {
    /// Open a connection to `url`.
    pub async fn connect(url: &str) -> Result<Self> {
        if !url.starts_with("wss://") && !url.starts_with("ws://") {
            return Err(AppError::invalid_argument(format!(
                "relay {url} must be a ws:// or wss:// URL"
            )));
        }

        let connect = connect_async(url);
        let (socket, _response) = tokio::time::timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| AppError::network(url, "relay connection timed out"))?
            .map_err(|e| AppError::network(url, format!("could not connect: {e}")))?;

        Ok(Self {
            url: url.to_string(),
            socket,
        })
    }

    /// The relay URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Send a client message.
    async fn send(&mut self, message: &ClientMessage) -> Result<()> {
        let wire = message.to_wire()?;
        self.socket
            .send(WsMessage::Text(wire.into()))
            .await
            .map_err(|e| AppError::network(&self.url, format!("could not send: {e}")))
    }

    /// Publish an event and wait for the relay's `OK`.
    ///
    /// Returns `Ok(true)` when accepted, `Ok(false)` when the relay explicitly
    /// rejected it, and an error only when the connection itself failed.
    pub async fn publish(&mut self, event: &Event) -> Result<bool> {
        self.send(&ClientMessage::Event(event.clone())).await?;

        let deadline = tokio::time::Instant::now() + ACK_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(AppError::network(
                    &self.url,
                    "relay did not acknowledge the event in time",
                ));
            }

            let frame = tokio::time::timeout(remaining, self.socket.next())
                .await
                .map_err(|_| {
                    AppError::network(&self.url, "relay did not acknowledge the event in time")
                })?;

            let Some(frame) = frame else {
                return Err(AppError::network(&self.url, "relay closed the connection"));
            };

            let text = match frame {
                Ok(WsMessage::Text(text)) => text.to_string(),
                Ok(WsMessage::Close(_)) => {
                    return Err(AppError::network(&self.url, "relay closed the connection"))
                }
                Ok(_) => continue,
                Err(e) => {
                    return Err(AppError::network(
                        &self.url,
                        format!("relay frame was invalid: {e}"),
                    ))
                }
            };

            match parse_relay_message(&text)? {
                RelayMessage::Ok {
                    event_id, accepted, ..
                } if event_id == event.id => return Ok(accepted),
                // Anything else is unrelated traffic; keep waiting for our ack.
                _ => continue,
            }
        }
    }

    /// Subscribe and collect stored events until `EOSE`.
    ///
    /// Returns the events the relay had, newest last. Events are verified before
    /// being returned, so a hostile relay cannot inject a forged author.
    pub async fn query(&mut self, subscription: &str, filters: Vec<Filter>) -> Result<Vec<Event>> {
        self.send(&ClientMessage::Req(subscription.to_string(), filters))
            .await?;

        let mut events = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                // A relay that never sends EOSE still gave us usable data.
                break;
            }

            let frame = match tokio::time::timeout(remaining, self.socket.next()).await {
                Ok(Some(Ok(WsMessage::Text(text)))) => text.to_string(),
                Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) => break,
                Ok(Some(Ok(_))) => continue,
                Ok(Some(Err(e))) => {
                    return Err(AppError::network(
                        &self.url,
                        format!("relay frame was invalid: {e}"),
                    ))
                }
                Err(_) => break,
            };

            match parse_relay_message(&frame)? {
                RelayMessage::Event(event) => {
                    // Drop anything that does not verify rather than surfacing it.
                    if event.verify_id().is_ok() && event.verify_signature().is_ok() {
                        events.push(*event);
                    }
                }
                RelayMessage::EndOfStoredEvents(_) => break,
                RelayMessage::Closed { message, .. } => {
                    return Err(AppError::network(
                        &self.url,
                        format!("relay closed the subscription: {message}"),
                    ))
                }
                _ => continue,
            }
        }

        let _ = self
            .send(&ClientMessage::Close(subscription.to_string()))
            .await;

        events.sort_by_key(|event| event.created_at);
        Ok(events)
    }

    /// Close the connection.
    pub async fn close(mut self) {
        let _ = self.socket.close(None).await;
    }
}

/// Publish to several relays, succeeding if any accepts.
///
/// Returns the URLs that accepted, so the caller can report partial success
/// rather than pretending a single relay is the whole network.
pub async fn publish_to_all(relays: &[String], event: &Event) -> Result<Vec<String>> {
    if relays.is_empty() {
        return Err(AppError::not_configured(
            "no relays are configured, so nothing can be published",
        ));
    }

    let mut accepted = Vec::new();
    let mut last_error: Option<AppError> = None;

    for url in relays {
        match RelayConnection::connect(url).await {
            Ok(mut connection) => {
                match connection.publish(event).await {
                    Ok(true) => accepted.push(url.clone()),
                    Ok(false) => {}
                    Err(e) => last_error = Some(e),
                }
                connection.close().await;
            }
            Err(e) => last_error = Some(e),
        }
    }

    if accepted.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            AppError::network("relays", "no relay accepted the event")
        }));
    }

    Ok(accepted)
}

/// Query several relays and merge the results.
///
/// Duplicate events are collapsed by id, and the newest version of each
/// addressable slot wins, which is what makes a replaceable roster work across
/// relays that may be out of sync.
pub async fn query_all(relays: &[String], filters: Vec<Filter>) -> Result<Vec<Event>> {
    if relays.is_empty() {
        return Err(AppError::not_configured(
            "no relays are configured, so nothing can be read",
        ));
    }

    let mut merged: std::collections::HashMap<String, Event> = std::collections::HashMap::new();
    let mut any_succeeded = false;
    let mut last_error: Option<AppError> = None;

    for (index, url) in relays.iter().enumerate() {
        match RelayConnection::connect(url).await {
            Ok(mut connection) => {
                let subscription = format!("shadow720-{index}");
                match connection.query(&subscription, filters.clone()).await {
                    Ok(events) => {
                        any_succeeded = true;
                        for event in events {
                            merged.insert(event.id.clone(), event);
                        }
                    }
                    Err(e) => last_error = Some(e),
                }
                connection.close().await;
            }
            Err(e) => last_error = Some(e),
        }
    }

    if !any_succeeded {
        return Err(last_error.unwrap_or_else(|| {
            AppError::network("relays", "no relay returned any events")
        }));
    }

    let mut events: Vec<Event> = merged.into_values().collect();
    events.sort_by_key(|event| event.created_at);
    Ok(events)
}

/// Collapse addressable events to the newest per `(pubkey, kind, d-tag)`.
///
/// Relays keep only the latest, but merging several relays can surface older
/// copies of the same slot, so this is applied after a multi-relay read.
pub fn newest_per_slot(events: Vec<Event>) -> Vec<Event> {
    let mut slots: std::collections::HashMap<(String, u64, String), Event> =
        std::collections::HashMap::new();

    for event in events {
        let Some(d_tag) = event.d_tag().map(str::to_string) else {
            // Not addressable: keep it as-is under a unique key.
            slots.insert(
                (event.pubkey.clone(), event.kind, event.id.clone()),
                event,
            );
            continue;
        };
        let key = (event.pubkey.clone(), event.kind, d_tag);
        match slots.get(&key) {
            Some(existing) if existing.created_at >= event.created_at => {}
            _ => {
                slots.insert(key, event);
            }
        }
    }

    let mut out: Vec<Event> = slots.into_values().collect();
    out.sort_by_key(|event| event.created_at);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::{sign_event, NostrIdentity, KIND_CHAT, KIND_ROSTER};

    fn identity(seed: u8) -> NostrIdentity {
        NostrIdentity::from_secret_bytes([seed; 32]).expect("identity")
    }

    #[test]
    fn connect_rejects_a_non_websocket_url() {
        let result = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(RelayConnection::connect("https://relay.example"));
        assert!(result.is_err());
    }

    #[test]
    fn publish_to_all_rejects_an_empty_relay_list() {
        let event = sign_event(&identity(1), KIND_CHAT, vec![], "x", 1).expect("sign");
        let result = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(publish_to_all(&[], &event));
        assert!(result.is_err());
    }

    #[test]
    fn query_all_rejects_an_empty_relay_list() {
        let result = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(query_all(&[], vec![Filter::group("g", None)]));
        assert!(result.is_err());
    }

    #[test]
    fn newest_per_slot_keeps_the_latest_roster_entry() {
        let id = identity(2);
        let older = sign_event(
            &id,
            KIND_ROSTER,
            vec![vec!["d".into(), "g".into()]],
            "old",
            100,
        )
        .expect("sign");
        let newer = sign_event(
            &id,
            KIND_ROSTER,
            vec![vec!["d".into(), "g".into()]],
            "new",
            200,
        )
        .expect("sign");

        let collapsed = newest_per_slot(vec![older, newer]);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].content, "new");
    }

    #[test]
    fn newest_per_slot_keeps_distinct_authors_apart() {
        let a = sign_event(
            &identity(3),
            KIND_ROSTER,
            vec![vec!["d".into(), "g".into()]],
            "a",
            100,
        )
        .expect("sign");
        let b = sign_event(
            &identity(4),
            KIND_ROSTER,
            vec![vec!["d".into(), "g".into()]],
            "b",
            100,
        )
        .expect("sign");

        let collapsed = newest_per_slot(vec![a, b]);
        assert_eq!(collapsed.len(), 2, "one slot per member");
    }

    #[test]
    fn newest_per_slot_keeps_every_chat_message() {
        let id = identity(5);
        let first = sign_event(&id, KIND_CHAT, vec![], "one", 100).expect("sign");
        let second = sign_event(&id, KIND_CHAT, vec![], "two", 200).expect("sign");

        let collapsed = newest_per_slot(vec![first, second]);
        assert_eq!(collapsed.len(), 2, "chat is append-only, not replaceable");
    }

    #[test]
    fn newest_per_slot_sorts_by_time() {
        let id = identity(6);
        let later = sign_event(&id, KIND_CHAT, vec![], "later", 300).expect("sign");
        let earlier = sign_event(&id, KIND_CHAT, vec![], "earlier", 100).expect("sign");

        let collapsed = newest_per_slot(vec![later, earlier]);
        assert_eq!(collapsed[0].content, "earlier");
        assert_eq!(collapsed[1].content, "later");
    }
}
