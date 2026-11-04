//! Live relay round-trip check.
//!
//! Publishes one signed event to a public relay and reads it back, proving the
//! transport works end to end. Run with:
//!
//! ```text
//! cargo run --example nostr_selftest
//! ```

use shadow720_lib::nostr::{now_unix_s, sign_event, Filter, NostrIdentity, KIND_CHAT};
use shadow720_lib::nostr_relay::{publish_to_all, query_all};

#[tokio::main]
async fn main() {
    let relays = vec!["wss://relay.damus.io".to_string()];
    let identity = match NostrIdentity::generate() {
        Ok(identity) => identity,
        Err(e) => {
            println!("could not generate an identity: {e}");
            return;
        }
    };
    println!("pubkey: {}", identity.pubkey_hex());

    let group = format!("shadow720-selftest-{}", std::process::id());
    let event = match sign_event(
        &identity,
        KIND_CHAT,
        vec![vec!["d".to_string(), group.clone()]],
        "hello from shadow720",
        now_unix_s(),
    ) {
        Ok(event) => event,
        Err(e) => {
            println!("could not sign: {e}");
            return;
        }
    };
    println!("event id: {}", event.id);

    match publish_to_all(&relays, &event).await {
        Ok(accepted) => println!("PUBLISH OK -> {accepted:?}"),
        Err(e) => println!("PUBLISH FAILED: {e}"),
    }

    let filter = Filter {
        kinds: Some(vec![KIND_CHAT]),
        d_tags: Some(vec![group]),
        event_tags: None,
        address_tags: None,
        authors: Some(vec![identity.pubkey_hex().to_string()]),
        since: None,
        limit: Some(10),
    };

    match query_all(&relays, vec![filter]).await {
        Ok(events) => {
            println!("QUERY OK -> {} events", events.len());
            for event in &events {
                println!(
                    "  {} verified={} content={:?}",
                    event.id,
                    event.verify_signature().is_ok(),
                    event.content
                );
            }
        }
        Err(e) => println!("QUERY FAILED: {e}"),
    }
}
