//! Process-local hub of WebSocket connections. Handlers
//! publish after their commit; revocations close the affected connections.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::Value;
use tokio::sync::{Notify, mpsc};

/// At most this many connections per account (close `4429`).
pub const MAX_PER_USER: usize = 20;
/// Messages queued per connection before it is closed with `1013`.
pub const QUEUE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// The session was revoked or became invalid: `session_revoked`, `4401`.
    Revoked,
    /// The client does not read its messages: `1013`.
    QueueFull,
    /// The server is shutting down: `1001`.
    Shutdown,
}

/// Tells a connection task to close; the first reason wins.
#[derive(Default)]
pub struct CloseSignal {
    reason: Mutex<Option<CloseReason>>,
    notify: Notify,
}

impl CloseSignal {
    fn trigger(&self, reason: CloseReason) {
        let mut current = self
            .reason
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.is_none() {
            *current = Some(reason);
            self.notify.notify_one();
        }
    }

    /// Waits until the connection has to close.
    pub async fn wait(&self) -> CloseReason {
        loop {
            let notified = self.notify.notified();
            if let Some(reason) = *self
                .reason
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
            {
                return reason;
            }
            notified.await;
        }
    }
}

struct Connection {
    id: u64,
    session_id: String,
    queue: mpsc::Sender<String>,
    close: Arc<CloseSignal>,
}

/// A registered connection: its messages and its close signal.
pub struct Registration {
    pub id: u64,
    pub messages: mpsc::Receiver<String>,
    pub close: Arc<CloseSignal>,
}

#[derive(Default)]
pub struct Hub {
    by_user: Mutex<HashMap<String, Vec<Connection>>>,
    next_id: AtomicU64,
}

impl Hub {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Vec<Connection>>> {
        self.by_user
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Adds a connection; `None` if the account already has [`MAX_PER_USER`].
    pub fn register(&self, user_id: &str, session_id: &str) -> Option<Registration> {
        let mut by_user = self.lock();
        let connections = by_user.entry(user_id.to_string()).or_default();
        if connections.len() >= MAX_PER_USER {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (queue, messages) = mpsc::channel(QUEUE);
        let close = Arc::new(CloseSignal::default());
        connections.push(Connection {
            id,
            session_id: session_id.to_string(),
            queue,
            close: close.clone(),
        });
        Some(Registration {
            id,
            messages,
            close,
        })
    }

    pub fn unregister(&self, user_id: &str, id: u64) {
        let mut by_user = self.lock();
        if let Some(connections) = by_user.get_mut(user_id) {
            connections.retain(|c| c.id != id);
            if connections.is_empty() {
                by_user.remove(user_id);
            }
        }
    }

    /// Sends an event to every connection of these accounts.
    pub fn publish<'a>(&self, user_ids: impl IntoIterator<Item = &'a str>, event: &Value) {
        let text = event.to_string();
        let by_user = self.lock();
        for user_id in user_ids {
            for connection in by_user.get(user_id).into_iter().flatten() {
                if connection.queue.try_send(text.clone()).is_err() {
                    connection.close.trigger(CloseReason::QueueFull);
                }
            }
        }
    }

    /// Closes the connections of these sessions (`session_revoked`, `4401`).
    pub fn revoke_sessions(&self, session_ids: &[String]) {
        if session_ids.is_empty() {
            return;
        }
        for connection in self.lock().values().flatten() {
            if session_ids.contains(&connection.session_id) {
                connection.close.trigger(CloseReason::Revoked);
            }
        }
    }

    /// Closes every connection of an account (`session_revoked`, `4401`).
    pub fn revoke_user(&self, user_id: &str) {
        for connection in self.lock().get(user_id).into_iter().flatten() {
            connection.close.trigger(CloseReason::Revoked);
        }
    }

    /// The distinct sessions with an open connection (for the 30-s check).
    pub fn sessions(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .lock()
            .values()
            .flatten()
            .map(|c| c.session_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    pub fn connections(&self, user_id: &str) -> usize {
        self.lock().get(user_id).map_or(0, Vec::len)
    }

    /// Closes every connection with `1001`.
    pub fn shutdown(&self) {
        for connection in self.lock().values().flatten() {
            connection.close.trigger(CloseReason::Shutdown);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn publishes_to_the_accounts_and_closes_slow_readers() {
        let hub = Hub::default();
        let mut a = hub.register("alice", "s1").unwrap();
        let mut b = hub.register("bob", "s2").unwrap();
        hub.publish(["alice"], &json!({ "type": "vaults_changed" }));
        assert_eq!(
            a.messages.recv().await.unwrap(),
            r#"{"type":"vaults_changed"}"#
        );
        assert!(b.messages.try_recv().is_err());
        for _ in 0..=QUEUE {
            hub.publish(["bob"], &json!({ "type": "vaults_changed" }));
        }
        assert_eq!(b.close.wait().await, CloseReason::QueueFull);
    }

    #[tokio::test]
    async fn limits_connections_and_revokes_sessions() {
        let hub = Hub::default();
        let registrations: Vec<Registration> = (0..MAX_PER_USER)
            .map(|i| hub.register("alice", &format!("s{}", i % 2)).unwrap())
            .collect();
        assert!(hub.register("alice", "s0").is_none());
        assert_eq!(hub.sessions(), vec!["s0".to_string(), "s1".to_string()]);
        hub.revoke_sessions(&["s1".to_string()]);
        assert_eq!(registrations[1].close.wait().await, CloseReason::Revoked);
        hub.shutdown();
        assert_eq!(registrations[0].close.wait().await, CloseReason::Shutdown);
        // The first reason wins.
        assert_eq!(registrations[1].close.wait().await, CloseReason::Revoked);
        hub.unregister("alice", registrations[0].id);
        assert_eq!(hub.connections("alice"), MAX_PER_USER - 1);
    }
}
